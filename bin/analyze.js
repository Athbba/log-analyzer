#!/usr/bin/env node
// Command-line entry point. Analyzes an auth.log (or stdin) and prints a
// report, or, with --follow, watches a log as it is written and reports
// incidents as they happen, optionally sending Discord alerts.
//
// Exit codes: 0 nothing high-severity found (or live mode stopped cleanly),
// 1 high-severity findings, 2 bad arguments, a bad config, or unreadable input.

import { existsSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { toConfig } from '../src/core/config.js';
import { resolveOptions } from '../src/core/options.js';
import { DEFAULTS } from '../src/detectors.js';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { errorMessage, fail } from '../src/io/cli.js';
import { ConfigError, DEFAULT_CONFIG_PATH, loadConfig } from '../src/io/config.js';
import { startLive } from '../src/io/live.js';
import { createDiscordSink } from '../src/io/sinks/discord.js';
import { createJsonLinesSink, createTerminalSink } from '../src/io/sinks/terminal.js';
import { duration, formatJson, formatText } from '../src/report.js';

/** @typedef {import('../src/types.js').AnalyzerOptions} AnalyzerOptions */
/** @typedef {import('../src/types.js').Incident} Incident */
/** @typedef {import('../src/io/live.js').Sink} Sink */

const USAGE = `Usage: node bin/analyze.js [options] <auth.log | ->
       node bin/analyze.js --follow [options] <auth.log>

Finds SSH brute force, password spraying, distributed attacks on one account,
logins that follow failed attempts, logins from new networks or at unusual
hours, new or newly-admin accounts, and signs of log tampering. Pass - to read
the log from stdin.

Options:
  --json              Print the results as JSON (with --follow: one JSON object per line)
  --follow            Keep watching the log, through rotation, and report incidents as they happen
  --from-start        With --follow, read what is already in the file first
  --discord           Send alerts to the Discord webhook in DISCORD_WEBHOOK_URL (or .env)
  --db <file>         Also store the lines, events, incidents and findings in this SQLite file
  --config <file>     Settings file (default ${DEFAULT_CONFIG_PATH}, if it exists)
  --print-config      Print the effective settings as a config file and exit
  --threshold <n>     Failed logins from one IP that count as brute force (default ${DEFAULTS.threshold})
  --window <time>     ...within this window, e.g. 90s, 10m, 1h (default ${duration(DEFAULTS.windowMs)})
  --lookback <time>   How far before a login to look for failures (default ${duration(DEFAULTS.lookbackMs)})
  --night <from-to>   Unusual login hours on a 24h clock, end excluded (default ${DEFAULTS.night.join('-')})
  --admin-groups <g>  Comma-separated groups that grant admin rights (default ${DEFAULTS.adminGroups.join(',')})
  --year <yyyy>       Year of the first line; syslog timestamps have none (default: guessed)
  -h, --help          Show this help

Exit status: 0 if nothing high-severity was found (or --follow was stopped),
1 if something was, 2 on error.`;

/**
 * @param {string} message
 * @returns {never}
 */
function usageError(message) {
  return fail(message, USAGE);
}

const { values, positionals } = readArgs();
if (values.help) {
  console.log(USAGE);
  process.exit(0);
}
// Secrets (the webhook URL) come from the environment or a .env file in the
// working directory. Variables already set in the environment win.
if (existsSync('.env')) {
  try {
    process.loadEnvFile('.env');
  } catch (err) {
    fail(`can't read .env: ${errorMessage(err)}`);
  }
}
/** @type {ReturnType<typeof loadConfig>} */
let config;
try {
  config = loadConfig(values.config);
} catch (err) {
  if (!(err instanceof ConfigError)) throw err;
  fail(err.message);
}
// Flags override the config file, which overrides the defaults.
/** @type {AnalyzerOptions} */
const options = {
  ...config.options,
  threshold: values.threshold === undefined ? config.options.threshold : positiveInt(values.threshold, '--threshold'),
  windowMs: values.window === undefined ? config.options.windowMs : parseDuration(values.window, '--window'),
  lookbackMs: values.lookback === undefined ? config.options.lookbackMs : parseDuration(values.lookback, '--lookback'),
  night: values.night === undefined ? config.options.night : parseHours(values.night),
  adminGroups: values['admin-groups'] === undefined ? config.options.adminGroups : parseGroups(values['admin-groups']),
};
if (values['print-config']) {
  console.log(JSON.stringify(toConfig(resolveOptions(options), config.settings), null, 2));
  process.exit(0);
}
if (positionals.length !== 1) usageError('give exactly one log file, or - for stdin');
if (values.year !== undefined && !/^\d{4}$/.test(values.year)) usageError('--year must be a four-digit year');
if (values['from-start'] && !values.follow) usageError('--from-start only makes sense with --follow');
const year = values.year === undefined ? undefined : Number(values.year);
const source = positionals[0];

/** @type {ReturnType<typeof createDiscordSink> | null} */
let discord = null;
if (values.discord) {
  const url = process.env.DISCORD_WEBHOOK_URL;
  if (!url) fail('--discord needs DISCORD_WEBHOOK_URL, in the environment or in .env');
  try {
    discord = createDiscordSink({ url, ...config.settings.discord });
  } catch (err) {
    fail(errorMessage(err));
  }
}

// Exit quietly if the reader goes away early, e.g. when piped into `head`.
process.stdout.on('error', (err) => {
  if (/** @type {NodeJS.ErrnoException} */ (err).code === 'EPIPE') process.exit(process.exitCode ?? 0);
  throw err;
});

// The store is loaded only when asked for: node:sqlite still prints an
// experimental warning on Node 22.
/** @type {import('../src/io/store.js').Store | null} */
let store = null;
if (values.db !== undefined) {
  const { openStore } = await import('../src/io/store.js');
  try {
    store = openStore(values.db);
  } catch (err) {
    fail(`can't open ${values.db}: ${errorMessage(err)}`);
  }
}

if (values.follow) {
  if (source === '-') usageError('--follow needs a file, not stdin');
  await follow(source, discord);
} else {
  await analyzeOnce(source, discord);
}

/**
 * Starts a stored run, if --db was given.
 * @param {'file' | 'follow'} mode
 * @param {string} name
 */
function beginStoredRun(mode, name) {
  if (!store) return null;
  const resolved = resolveOptions(options);
  const run = store.beginRun({ source: name, mode, options: toConfig(resolved, config.settings) });
  return { run, tap: store.tap(run, resolved.ipv6Prefix) };
}

/**
 * Records a stored run's totals and closes the database, if --db was given.
 * @param {{ run: number } | null} stored
 * @param {Parameters<NonNullable<typeof store>['finishRun']>[1]} totals
 */
function finishStoredRun(stored, totals) {
  if (!store || !stored) return;
  store.finishRun(stored.run, totals);
  store.close();
  console.error(`stored as run ${stored.run} in ${values.db}`);
}

/** Whether to colour terminal output. */
function useColor() {
  return Boolean(process.stdout.isTTY && !process.env.NO_COLOR);
}

/**
 * @param {string} path
 * @param {ReturnType<typeof createDiscordSink> | null} alerts
 */
async function follow(path, alerts) {
  /** @param {string} text */
  const write = (text) => { process.stdout.write(text); };
  /** @type {Sink[]} */
  const sinks = [values.json ? createJsonLinesSink({ write }) : createTerminalSink({ write, color: useColor() })];
  if (alerts) sinks.push(alerts);
  const stored = beginStoredRun('follow', path);
  if (store && stored) {
    const db = store;
    sinks.push({ name: 'sqlite', onIncident: (event) => db.saveLiveEvent(stored.run, event), close: async () => db.flush() });
  }
  const live = startLive({
    path, sinks, options, year, fromStart: values['from-start'] ?? false,
    pollMs: config.settings.live.pollMs, idleMs: config.settings.live.idleMs, tap: stored?.tap,
  });
  let stopping = false;
  for (const signal of /** @type {const} */ (['SIGINT', 'SIGTERM'])) {
    process.on(signal, () => {
      if (stopping) process.exit(130); // a second signal: stop now
      stopping = true;
      console.error(`${signal}: stopping (sending pending alerts for up to 5s)`);
      void live.stop();
    });
  }
  if (!values.json) console.error(`following ${path} (Ctrl+C to stop)`);
  let result;
  try {
    result = await live.done;
  } catch (err) {
    fail(`can't follow ${path}: ${errorMessage(err)}`);
  }
  const report = alerts ? result.sinks[1] : null;
  finishStoredRun(stored, { stats: result.stats, health: result.health });
  console.error(`stopped after ${result.lines.toLocaleString('en-US')} lines${report ? `; Discord: ${JSON.stringify(report)}` : ''}`);
  process.exit(0);
}

/**
 * @param {string} path
 * @param {ReturnType<typeof createDiscordSink> | null} alerts
 */
async function analyzeOnce(path, alerts) {
  let analysis;
  const stored = beginStoredRun('file', path === '-' ? 'stdin' : path);
  try {
    analysis = await analyzeStream(await openInput(path), { options, year, tap: stored?.tap });
  } catch (err) {
    fail(`can't read ${path}: ${errorMessage(err)}`);
  }
  const { stats, incidents, health } = analysis;
  if (store && stored) store.saveIncidents(stored.run, incidents);
  finishStoredRun(stored, { stats, health });
  const result = { source: path === '-' ? 'stdin' : path, stats, options: analysis.options, incidents, health };
  process.stdout.write(values.json
    ? formatJson(result)
    : formatText(result, { color: useColor() }));
  process.exitCode = incidents.some((i) => i.severity === 'high') ? 1 : 0;
  if (alerts) {
    // One alert per incident in the report, at or above the alert threshold.
    for (const incident of incidents) alerts.onIncident(asOpened(incident));
    const delivery = await alerts.close(10_000);
    console.error(`Discord: ${JSON.stringify(delivery)}`);
  }
}

/**
 * A report incident as the "opened" event alerting expects.
 * @param {Incident} incident
 * @returns {import('../src/core/live-incidents.js').IncidentEvent}
 */
function asOpened(incident) {
  const key = incident.ip !== null ? `ip ${incident.ip}` : `subject ${incident.subject}`;
  const last = Math.max(...incident.findings.map((f) => ('until' in f ? f.until : f.time)));
  return {
    type: 'opened',
    finding: incident.findings[0],
    incident: { ...incident, id: `${key} (report)`, key, last, droppedFindings: 0 },
  };
}

function readArgs() {
  try {
    return parseArgs({
      allowPositionals: true,
      options: {
        json: { type: 'boolean' },
        follow: { type: 'boolean' },
        'from-start': { type: 'boolean' },
        discord: { type: 'boolean' },
        db: { type: 'string' },
        config: { type: 'string' },
        'print-config': { type: 'boolean' },
        threshold: { type: 'string' },
        window: { type: 'string' },
        lookback: { type: 'string' },
        night: { type: 'string' },
        'admin-groups': { type: 'string' },
        year: { type: 'string' },
        help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (err) {
    return usageError(errorMessage(err));
  }
}

/** @param {string} path */
async function openInput(path) {
  if (path === '-') return process.stdin;
  // Opening first makes a missing file fail here, with a clear message.
  const file = await open(path);
  return file.createReadStream();
}

/**
 * @param {string} value
 * @param {string} flag
 */
function positiveInt(value, flag) {
  if (!/^\d+$/.test(value) || Number(value) < 1) usageError(`${flag} must be a whole number of 1 or more`);
  return Number(value);
}

/**
 * @param {string} value
 * @param {string} flag
 */
function parseDuration(value, flag) {
  // Local, not module-level: this runs from top-level code above any
  // module-level const below it, which would still be uninitialized.
  /** @type {Record<string, number>} */
  const unitMs = { s: 1000, m: 60_000, h: 3_600_000 };
  const m = /^(\d+)(s|m|h)?$/.exec(value);
  if (!m || Number(m[1]) === 0) return usageError(`${flag} must be a duration like 90s, 10m or 1h`);
  return Number(m[1]) * unitMs[m[2] ?? 'm'];
}

/** @param {string} value */
function parseGroups(value) {
  if (!/^[\w.-]+(,[\w.-]+)*$/.test(value)) usageError('--admin-groups must be group names separated by commas, e.g. sudo,wheel');
  return value.split(',');
}

/**
 * @param {string} value
 * @returns {[number, number]}
 */
function parseHours(value) {
  const m = /^(\d{1,2})-(\d{1,2})$/.exec(value);
  const [from, to] = m ? [Number(m[1]), Number(m[2])] : [NaN, NaN];
  if (!m || from > 23 || to > 24 || from === to) {
    return usageError('--night must be two different hours like 1-5 (01:00-04:59) or 22-6');
  }
  return [from, to];
}
