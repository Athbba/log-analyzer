#!/usr/bin/env node
// Command-line entry point: reads an auth.log (or stdin), runs the detectors
// and prints a report.
//
// Exit codes: 0 nothing high-severity found, 1 high-severity findings,
// 2 bad arguments or unreadable input.

import { open } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { toConfig } from '../src/core/config.js';
import { resolveOptions } from '../src/core/options.js';
import { DEFAULTS } from '../src/detectors.js';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { ConfigError, DEFAULT_CONFIG_PATH, loadConfig } from '../src/io/config.js';
import { duration, formatJson, formatText } from '../src/report.js';

/** @typedef {import('../src/types.js').AnalyzerOptions} AnalyzerOptions */

const USAGE = `Usage: node bin/analyze.js [options] <auth.log | ->

Finds SSH brute force, password spraying, distributed attacks on one account,
logins that follow failed attempts, logins from new networks or at unusual
hours, new or newly-admin accounts, and signs of log tampering. Pass - to read
the log from stdin.

Options:
  --json              Print the results as JSON
  --config <file>     Settings file (default ${DEFAULT_CONFIG_PATH}, if it exists)
  --print-config      Print the effective settings as a config file and exit
  --threshold <n>     Failed logins from one IP that count as brute force (default ${DEFAULTS.threshold})
  --window <time>     ...within this window, e.g. 90s, 10m, 1h (default ${duration(DEFAULTS.windowMs)})
  --lookback <time>   How far before a login to look for failures (default ${duration(DEFAULTS.lookbackMs)})
  --night <from-to>   Unusual login hours on a 24h clock, end excluded (default ${DEFAULTS.night.join('-')})
  --admin-groups <g>  Comma-separated groups that grant admin rights (default ${DEFAULTS.adminGroups.join(',')})
  --year <yyyy>       Year of the first line; syslog timestamps have none (default: guessed)
  -h, --help          Show this help

Exit status: 0 if nothing high-severity was found, 1 if something was, 2 on error.`;

/**
 * @param {string} message
 * @returns {never}
 */
function usageError(message) {
  console.error(`error: ${message}\n\n${USAGE}`);
  process.exit(2);
}

const { values, positionals } = readArgs();
if (values.help) {
  console.log(USAGE);
  process.exit(0);
}
let config;
try {
  config = loadConfig(values.config);
} catch (err) {
  if (!(err instanceof ConfigError)) throw err;
  console.error(`error: ${err.message}`);
  process.exit(2);
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
  console.log(JSON.stringify(toConfig(resolveOptions(options)), null, 2));
  process.exit(0);
}
if (positionals.length !== 1) usageError('give exactly one log file, or - for stdin');
if (values.year !== undefined && !/^\d{4}$/.test(values.year)) usageError('--year must be a four-digit year');
const year = values.year === undefined ? undefined : Number(values.year);

const source = positionals[0];
let analysis;
try {
  analysis = await analyzeStream(await openInput(source), { options, year });
} catch (err) {
  console.error(`error: can't read ${source}: ${errorMessage(err)}`);
  process.exit(2);
}

const { stats, incidents, health } = analysis;
const result = { source: source === '-' ? 'stdin' : source, stats, options: analysis.options, incidents, health };

// Exit quietly if the reader goes away early, e.g. when piped into `head`.
process.stdout.on('error', (err) => {
  if (err.code === 'EPIPE') process.exit(process.exitCode ?? 0);
  throw err;
});
process.stdout.write(values.json
  ? formatJson(result)
  : formatText(result, { color: process.stdout.isTTY && !process.env.NO_COLOR }));
process.exitCode = incidents.some((i) => i.severity === 'high') ? 1 : 0;

function readArgs() {
  try {
    return parseArgs({
      allowPositionals: true,
      options: {
        json: { type: 'boolean' },
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

/** @param {unknown} err */
function errorMessage(err) {
  return err instanceof Error ? err.message : String(err);
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

/** @type {Record<string, number>} */
const UNIT_MS = { s: 1000, m: 60_000, h: 3_600_000 };

/**
 * @param {string} value
 * @param {string} flag
 */
function parseDuration(value, flag) {
  const m = /^(\d+)(s|m|h)?$/.exec(value);
  if (!m || Number(m[1]) === 0) return usageError(`${flag} must be a duration like 90s, 10m or 1h`);
  return Number(m[1]) * UNIT_MS[m[2] ?? 'm'];
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
