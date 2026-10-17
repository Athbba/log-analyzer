#!/usr/bin/env node
// Speed and memory benchmark. Generates a deterministic synthetic auth.log in
// memory (no file) and analyzes it, reporting throughput and resident memory
// at each quarter of the run, so you can see whether memory stays flat.
//
// The traffic is deliberately hostile to memory: most lines are single
// password guesses from ever-new random IPs (as from a large botnet), mixed
// with brute-force bursts, normal logins and logouts, and sudo noise.
//
// Usage: node scripts/bench.js [--lines N] [--collect] [--json]
//   --collect  the pre-streaming way: parse every event into an array, then analyze
//
// Numbers depend on the machine; compare runs on the same one.

import { Readable } from 'node:stream';
import { parseArgs } from 'node:util';
import { analyze } from '../src/detectors.js';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { parseLines } from '../src/parse.js';

const { values } = parseArgs({
  options: { lines: { type: 'string', default: '1000000' }, collect: { type: 'boolean' }, json: { type: 'boolean' } },
});
const TOTAL = Number(values.lines);
const START = Date.UTC(2026, 8, 1);
const STEP_MS = 50; // 1M lines span about 14 hours of log time

// mulberry32: small, fast, seeded.
let seed = 20261017;
const rand = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
/** @param {number} n */
const int = (n) => Math.floor(rand() * n);
/** @param {number} n @param {number} [w] */
const pad = (n, w = 2) => String(n).padStart(w, '0');
/** @param {number} ms */
const stamp = (ms) => {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(d.getUTCMilliseconds(), 3)}000+00:00`;
};
const USERS = ['root', 'admin', 'test', 'ubuntu', 'oracle', 'git', 'deploy', 'postgres'];
/** Open sessions as [pid, user]; each login is closed by a later logout. */
/** @type {[number, string][]} */
const open = [];
let nextSessionPid = 100_000;

/** @param {number} i */
function line(i) {
  const t = stamp(START + i * STEP_MS);
  const pid = 1000 + (i % 30000);
  const r = rand();
  if (r < 0.70) {
    const ip = `${1 + int(222)}.${int(256)}.${int(256)}.${1 + int(254)}`;
    return `${t} web01 sshd-session[${pid}]: Failed password for invalid user ${USERS[int(USERS.length)]} from ${ip} port ${1024 + int(60000)} ssh2`;
  }
  if (r < 0.80) {
    const ip = `198.51.100.${1 + int(200)}`;
    return `${t} web01 sshd-session[${pid}]: Failed password for root from ${ip} port ${1024 + int(60000)} ssh2`;
  }
  if (r < 0.88 && open.length < 500) {
    const n = int(400);
    const sessionPid = nextSessionPid++;
    open.push([sessionPid, `user${n % 40}`]);
    return `${t} web01 sshd-session[${sessionPid}]: Accepted publickey for user${n % 40} from 10.0.${n % 16}.${n % 250 + 1} port 5000${n % 10} ssh2`;
  }
  if (r < 0.95 && open.length > 0) {
    const [sessionPid, user] = open.splice(int(open.length), 1)[0];
    return `${t} web01 sshd-session[${sessionPid}]: pam_unix(sshd:session): session closed for user ${user}`;
  }
  return `${t} web01 sudo:   user${int(40)} : TTY=pts/0 ; PWD=/home/u ; USER=root ; COMMAND=/usr/bin/systemctl status nginx`;
}

const marks = [0.25, 0.5, 0.75, 1].map((q) => Math.floor(TOTAL * q));
/** @type {{ lines: number, rssMB: number, heapMB?: number }[]} */
const samples = [];
/** @param {number} bytes */
const mb = (bytes) => Math.round(bytes / (1 << 20));

function* text() {
  const BATCH = 1000;
  for (let i = 0; i < TOTAL; i += BATCH) {
    const lines = [];
    for (let j = i; j < Math.min(i + BATCH, TOTAL); j++) lines.push(line(j));
    yield `${lines.join('\n')}\n`;
    const done = Math.min(i + BATCH, TOTAL);
    if (marks.includes(done)) {
      // With --expose-gc, also record the live heap: what is really retained.
      const gc = /** @type {(() => void) | undefined} */ (globalThis.gc);
      gc?.();
      const { rss, heapUsed } = process.memoryUsage();
      samples.push({ lines: done, rssMB: mb(rss), ...(gc && { heapMB: mb(heapUsed) }) });
    }
  }
}

const started = performance.now();
let incidents;
if (values.collect) {
  const parsed = await parseLines((function* () { for (const chunk of text()) yield* chunk.slice(0, -1).split('\n'); })(), { now: START });
  incidents = analyze(parsed.events);
} else {
  ({ incidents } = await analyzeStream(Readable.from(text()), { now: START }));
}
const seconds = (performance.now() - started) / 1000;
const result = {
  mode: values.collect ? 'collect' : 'streaming',
  lines: TOTAL,
  seconds: Number(seconds.toFixed(2)),
  linesPerSecond: Math.round(TOTAL / seconds),
  peakRssMB: mb(process.resourceUsage().maxRSS * 1024),
  rssAt: samples,
  incidents: incidents.length,
  node: process.version,
};
if (values.json) console.log(JSON.stringify(result));
else {
  console.log(`${result.mode}: ${TOTAL.toLocaleString('en-US')} lines in ${result.seconds}s (${result.linesPerSecond.toLocaleString('en-US')} lines/s), ${result.incidents} incidents`);
  console.log(`RSS: ${samples.map((s) => `${s.rssMB} MB at ${s.lines.toLocaleString('en-US')}`).join(', ')}; peak ${result.peakRssMB} MB`);
  if (samples[0]?.heapMB !== undefined) console.log(`live heap after GC: ${samples.map((s) => `${s.heapMB} MB`).join(', ')}`);
}
