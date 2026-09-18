#!/usr/bin/env node
// Command-line entry point: reads an auth.log (or stdin), runs the detectors
// and prints a report.
//
// Exit codes: 0 nothing high-severity found, 1 high-severity findings,
// 2 bad arguments or unreadable input.

import { open } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { DEFAULTS, analyze } from '../src/detectors.js';
import { parseLines } from '../src/parse.js';
import { duration, formatJson, formatText } from '../src/report.js';

const USAGE = `Usage: node bin/analyze.js [options] <auth.log | ->

Finds SSH brute-force attempts, logins that follow failed attempts, logins at
unusual hours, and new or newly-admin accounts. Pass - to read the log from stdin.

Options:
  --json              Print the results as JSON
  --threshold <n>     Failed logins from one IP that count as brute force (default ${DEFAULTS.threshold})
  --window <time>     ...within this window, e.g. 90s, 10m, 1h (default ${duration(DEFAULTS.windowMs)})
  --lookback <time>   How far before a login to look for failures (default ${duration(DEFAULTS.lookbackMs)})
  --night <from-to>   Unusual login hours on a 24h clock, end excluded (default ${DEFAULTS.night.join('-')})
  --admin-groups <g>  Comma-separated groups that grant admin rights (default ${DEFAULTS.adminGroups.join(',')})
  --year <yyyy>       Year of the first line; syslog timestamps have none (default: guessed)
  -h, --help          Show this help

Exit status: 0 if nothing high-severity was found, 1 if something was, 2 on error.`;

function usageError(message) {
  console.error(`error: ${message}\n\n${USAGE}`);
  process.exit(2);
}

let values, positionals;
try {
  ({ values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'boolean' },
      threshold: { type: 'string' },
      window: { type: 'string' },
      lookback: { type: 'string' },
      night: { type: 'string' },
      'admin-groups': { type: 'string' },
      year: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  }));
} catch (err) {
  usageError(err.message);
}
if (values.help) {
  console.log(USAGE);
  process.exit(0);
}
if (positionals.length !== 1) usageError('give exactly one log file, or - for stdin');

const options = {
  threshold: values.threshold === undefined ? DEFAULTS.threshold : positiveInt(values.threshold, '--threshold'),
  windowMs: values.window === undefined ? DEFAULTS.windowMs : parseDuration(values.window, '--window'),
  lookbackMs: values.lookback === undefined ? DEFAULTS.lookbackMs : parseDuration(values.lookback, '--lookback'),
  night: values.night === undefined ? DEFAULTS.night : parseHours(values.night),
  adminGroups: values['admin-groups'] === undefined ? DEFAULTS.adminGroups : parseGroups(values['admin-groups']),
};
if (values.year !== undefined && !/^\d{4}$/.test(values.year)) usageError('--year must be a four-digit year');
const year = values.year === undefined ? undefined : Number(values.year);

const source = positionals[0];
let parsed;
try {
  parsed = await parseLines(await openLines(source), { year });
} catch (err) {
  console.error(`error: can't read ${source}: ${err.message}`);
  process.exit(2);
}

const incidents = analyze(parsed.events, options);
const result = { source: source === '-' ? 'stdin' : source, stats: parsed.stats, options, incidents };

// Exit quietly if the reader goes away early, e.g. when piped into `head`.
process.stdout.on('error', (err) => {
  if (err.code === 'EPIPE') process.exit(process.exitCode ?? 0);
  throw err;
});
process.stdout.write(values.json
  ? formatJson(result)
  : formatText(result, { color: process.stdout.isTTY && !process.env.NO_COLOR }));
process.exitCode = incidents.some((i) => i.severity === 'high') ? 1 : 0;

async function openLines(path) {
  if (path === '-') return createInterface({ input: process.stdin, crlfDelay: Infinity });
  // Opening first makes a missing file fail here, with a clear message.
  const file = await open(path);
  return createInterface({ input: file.createReadStream(), crlfDelay: Infinity });
}

function positiveInt(value, flag) {
  if (!/^\d+$/.test(value) || Number(value) < 1) usageError(`${flag} must be a whole number of 1 or more`);
  return Number(value);
}

function parseDuration(value, flag) {
  const m = /^(\d+)(s|m|h)?$/.exec(value);
  if (!m || Number(m[1]) === 0) usageError(`${flag} must be a duration like 90s, 10m or 1h`);
  return Number(m[1]) * { s: 1000, m: 60_000, h: 3_600_000 }[m[2] ?? 'm'];
}

function parseGroups(value) {
  if (!/^[\w.-]+(,[\w.-]+)*$/.test(value)) usageError('--admin-groups must be group names separated by commas, e.g. sudo,wheel');
  return value.split(',');
}

function parseHours(value) {
  const m = /^(\d{1,2})-(\d{1,2})$/.exec(value);
  const [from, to] = m ? [Number(m[1]), Number(m[2])] : [];
  if (!m || from > 23 || to > 24 || from === to) {
    usageError('--night must be two different hours like 1-5 (01:00-04:59) or 22-6');
  }
  return [from, to];
}
