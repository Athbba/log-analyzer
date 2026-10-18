import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { openStore } from '../src/io/store.js';
import { incidentCounts, incidentDetail, incidentsFor, incidentSummary, runSummary } from '../src/dashboard/queries.js';
import { incidentPage } from '../src/dashboard/views.js';
import { parseRangeTime } from '../src/dashboard/server.js';

const filters = { severities: [], rule: null, q: '' };

test('time boundaries select overlapping incidents inclusively and totals ignore display limits', async () => {
  const store = openStore(':memory:');
  try {
    const run = store.beginRun({ source: 'synthetic.log', mode: 'file', options: {} });
    const lines = [10, 11].flatMap((hour, n) => Array.from({ length: 5 }, (_, i) =>
      `Sep  7 ${hour}:00:0${i} host sshd[1]: Failed password for root from 192.0.2.${n + 1} port 1 ssh2`));
    const { incidents } = await analyzeStream(Readable.from([lines.join('\n') + '\n']), { year: 2026, tap: store.tap(run, 64) });
    store.saveIncidents(run, incidents);
    const first = Date.UTC(2026, 8, 7, 10);
    assert.equal(incidentsFor(store.db, run, { ...filters, from: first, to: first })[0].ip, '192.0.2.1');
    assert.equal(incidentsFor(store.db, run, { ...filters, from: first + 5_000, to: first + 3_600_000 - 1 }).length, 0);
    assert.equal(incidentCounts(store.db, run, { ...filters, q: '192.0.2.2' }).total, 1);
    const copies = Array.from({ length: 520 }, (_, i) => ({ ...incidents[0], ip: `10.0.${i >> 8}.${i & 255}` }));
    const largeRun = store.beginRun({ source: 'large.log', mode: 'file', options: {} });
    store.saveIncidents(largeRun, copies);
    assert.equal(incidentsFor(store.db, largeRun, filters).length, 500);
    assert.equal(incidentCounts(store.db, largeRun, filters).total, 520);
    assert.equal(incidentCounts(store.db, largeRun, { ...filters, from: first + 5000 }).total, 0);
  } finally { store.close(); }
});

test('time input accepts exact server-clock dates and rejects normalization or unsafe values', () => {
  assert.equal(parseRangeTime(null), null);
  assert.equal(parseRangeTime(''), null);
  assert.equal(parseRangeTime('2026-09-07T10:00'), Date.UTC(2026, 8, 7, 10));
  assert.equal(parseRangeTime('2026-09-07T10:00:00.123'), Date.UTC(2026, 8, 7, 10, 0, 0, 123));
  assert.equal(parseRangeTime('2026-09-07T10:00:00.1'), Date.UTC(2026, 8, 7, 10, 0, 0, 100));
  assert.equal(parseRangeTime('2026-09-07T10:00:00.12'), Date.UTC(2026, 8, 7, 10, 0, 0, 120));
  assert.equal(parseRangeTime('0'), 0);
  for (const invalid of ['2026-02-30T12:00', '2026-09-07T24:00', '-1', '9999999999999999', '<script>', 'NaN']) {
    assert.throws(() => parseRangeTime(invalid), /invalid time range/, invalid);
  }
});

/** A syslog timestamp, `ms` after Jan 1 2026 00:00 on the server clock. @param {number} ms */
const syslogTime = (ms) => {
  const d = new Date(Date.UTC(2026, 0, 1) + ms);
  return `${d.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' })} ${String(d.getUTCDate()).padStart(2, ' ')} ${d.toISOString().slice(11, 19)}`;
};

/** Stores `lines` as one run in an in-memory store. @param {string[]} lines */
async function storeRun(lines) {
  const store = openStore(':memory:');
  const run = store.beginRun({ source: 'synthetic.log', mode: 'file', options: {} });
  const { incidents } = await analyzeStream(Readable.from([lines.join('\n') + '\n']), { year: 2026, tap: store.tap(run, 5000) });
  store.saveIncidents(run, incidents);
  store.finishRun(run, {});
  return { store, run };
}

test('the incident summary covers every finding, not just the 200 the page lists', async () => {
  // One IP guessing in 205 bursts, 30 minutes apart: 205 brute-force findings
  // in one incident. Only the last burst tries "zed".
  const lines = [];
  for (let b = 0; b < 205; b++) {
    const user = b === 204 ? 'zed' : 'root';
    for (let g = 0; g < 6; g++) lines.push(`${syslogTime(b * 30 * 60_000 + g * 1000)} web01 sshd[1]: Failed password for ${user} from 198.51.100.7 port 1 ssh2`);
  }
  const { store } = await storeRun(lines);
  try {
    const { id } = /** @type {{ id: number }} */ (store.db.prepare('SELECT id FROM incidents').get());
    const detail = /** @type {NonNullable<ReturnType<typeof incidentDetail>>} */ (incidentDetail(store.db, id));
    assert.equal(detail.findings.length, 200);
    assert.equal(detail.total, 205);

    const summary = incidentSummary(store.db, id);
    assert.deepEqual(summary.rules, ['brute-force']);
    assert.deepEqual(summary.users, ['root', 'zed'], 'a user seen only after the first 200 findings is still listed');
    assert.equal(summary.userCount, 2);
    assert.deepEqual(summary.techniques.map((t) => t.id), ['T1110.001']);

    const capped = incidentSummary(store.db, id, 1);
    assert.deepEqual(capped.users, ['root'], 'users are capped');
    assert.equal(capped.userCount, 2, 'with the real count');
  } finally { store.close(); }
});

test('the incident summary reads users from every kind of finding and techniques from account changes', async () => {
  const { store } = await storeRun([
    ...Array.from({ length: 6 }, (_, g) => `${syslogTime(g * 1000)} web01 sshd[1]: Failed password for admin from 192.0.2.9 port 1 ssh2`),
    `${syslogTime(10_000)} web01 sshd[1]: Accepted password for deploy from 192.0.2.9 port 1 ssh2`,
    `${syslogTime(20_000)} web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -G sudo backdoor`,
    `${syslogTime(20_000)} web01 useradd[9]: new user: name=backdoor, UID=1200, GID=1200, home=/home/backdoor, shell=/bin/bash`,
  ]);
  try {
    const ids = /** @type {{ id: number }[]} */ (store.db.prepare('SELECT id FROM incidents ORDER BY id').all()).map((r) => r.id);
    const all = ids.map((id) => incidentSummary(store.db, id));
    const users = new Set(all.flatMap((s) => s.users));
    for (const user of ['admin', 'deploy', 'backdoor']) assert.ok(users.has(user), `${user} is listed`);
    const techniques = new Set(all.flatMap((s) => s.techniques.map((t) => t.id)));
    assert.ok(techniques.has('T1136.001'), 'account creation is mapped from the stored finding');
  } finally { store.close(); }
});

test('evidence reports its line range and the real total when the page shows only the first lines', async () => {
  // 70 guesses inside one minute and a bit: one brute-force finding backed by 70 lines.
  const lines = Array.from({ length: 70 }, (_, g) => `${syslogTime(g * 1000)} web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2`);
  const { store, run } = await storeRun(lines);
  try {
    const { id } = /** @type {{ id: number }} */ (store.db.prepare('SELECT id FROM incidents').get());
    const detail = /** @type {NonNullable<ReturnType<typeof incidentDetail>>} */ (incidentDetail(store.db, id));
    const [first] = detail.findings;
    assert.equal(first.lines.length, 60);
    assert.equal(first.more, true);
    assert.equal(first.count, 70, 'the real number of lines behind the finding');

    const page = incidentPage({ run: /** @type {any} */ (runSummary(store.db, run)), ...detail, summary: incidentSummary(store.db, id) });
    assert.match(page, /First 60 of 70 log lines, lines 1–60/);
    assert.match(page, /<details open>/, 'the first finding opens with its evidence showing');
    assert.match(page, /<dt>Users<\/dt>\s*<dd>root<\/dd>/);
  } finally { store.close(); }
});
