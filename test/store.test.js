// SQLite storage: what a run stores, drill-down to raw lines, hostile strings,
// the schema version, and read-only access.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { evidence, openStore, SCHEMA_VERSION } from '../src/io/store.js';

const BIN = fileURLToPath(new URL('../bin/analyze.js', import.meta.url));
const SAMPLE = fileURLToPath(new URL('../samples/auth.log', import.meta.url));

/** @param {import('node:test').TestContext} t */
function tempDb(t) {
  const dir = mkdtempSync(join(tmpdir(), 'store-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return join(dir, 'runs.db');
}

/**
 * Analyzes `text` with a store attached, as the CLI does with --db.
 * @param {ReturnType<typeof openStore>} store
 * @param {string} text
 */
async function analyzeInto(store, text) {
  const run = store.beginRun({ source: 'test', mode: 'file', options: {} });
  const { incidents, stats } = await analyzeStream(Readable.from([text]), { year: 2026, tap: store.tap(run, 64) });
  store.saveIncidents(run, incidents);
  store.finishRun(run, { stats });
  return { run, incidents };
}

test('CLI --db stores the run: every line, the events, and the incidents of the report', (t) => {
  const file = tempDb(t);
  const json = spawnSync(process.execPath, [BIN, SAMPLE, '--year', '2026', '--json', '--db', file], { encoding: 'utf8' });
  assert.equal(json.status, 1);
  assert.match(json.stderr, /stored as run 1 in /);
  const report = JSON.parse(json.stdout);
  const store = openStore(file, { readOnly: true });
  const count = (/** @type {string} */ table) => /** @type {any} */ (store.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get()).n;
  assert.equal(count('lines'), report.stats.lines);
  assert.equal(count('incidents'), report.incidents.length);
  assert.equal(count('findings'), report.incidents.reduce((n, i) => n + i.findings.length, 0));
  const stored = /** @type {any[]} */ (store.db.prepare('SELECT severity, ip, subject FROM incidents ORDER BY id').all());
  assert.deepEqual(stored.map((i) => [i.severity, i.ip ?? i.subject]), report.incidents.map((i) => [i.severity, i.ip ?? i.subject]));
  store.close();
});

test('drill-down: a finding leads back to the raw log lines behind it', async (t) => {
  const store = openStore(':memory:');
  t.after(() => store.close());
  const { readFileSync } = await import('node:fs');
  const { run, incidents } = await analyzeInto(store, readFileSync(SAMPLE, 'utf8'));
  const b = incidents.find((i) => i.ip === '198.51.100.23');
  const brute = b?.findings.find((f) => f.rule === 'brute-force');
  assert.ok(brute);
  const lines = evidence(store.db, run, brute);
  assert.equal(lines.filter((l) => l.text.includes('Failed password')).length, 14, 'all 14 guesses');
  assert.ok(lines.some((l) => l.text.includes('Accepted password for deploy from 198.51.100.23')), 'and the login that followed');
  const change = b?.findings.find((f) => f.rule === 'account-change');
  assert.ok(change && evidence(store.db, run, change).some((l) => l.text.includes('useradd -m -s /bin/bash -G sudo sysupdate')));
});

test('hostile strings are stored and read back as data, never as SQL', async (t) => {
  const store = openStore(':memory:');
  t.after(() => store.close());
  const evil = "x'); DROP TABLE runs; --";
  const lines = ['00', '10', '20', '30', '40'].map((s) => `Sep  7 10:00:${s} web01 sshd[1]: Failed password for invalid user ${evil} from 192.0.2.1 port 1 ssh2`);
  const { run } = await analyzeInto(store, lines.join('\n'));
  const users = /** @type {any[]} */ (store.db.prepare('SELECT DISTINCT user FROM events WHERE run = ?').all(run));
  assert.deepEqual(users.map((u) => u.user), [evil]);
  const finding = JSON.parse(/** @type {any} */ (store.db.prepare('SELECT data FROM findings').get()).data);
  assert.deepEqual(finding.users, [{ user: evil, attempts: 5 }]);
  assert.equal(/** @type {any} */ (store.db.prepare('SELECT COUNT(*) AS n FROM runs').get()).n, 1, 'the runs table is still there');
});

test('schema: versioned, reopened as is, refused when newer; read-only is read-only', (t) => {
  const file = tempDb(t);
  openStore(file).close();
  const again = openStore(file);
  assert.equal(/** @type {any} */ (again.db.prepare('PRAGMA user_version').get()).user_version, SCHEMA_VERSION);
  again.db.exec(`PRAGMA user_version = ${SCHEMA_VERSION + 1}`);
  again.close();
  assert.throws(() => openStore(file), /newer than this analyzer/);
  assert.throws(() => openStore(file, { readOnly: true }), /schema is version 2, expected 1/);

  const fresh = tempDb(t).replace('runs.db', 'other.db');
  openStore(fresh).close();
  const reader = openStore(fresh, { readOnly: true });
  try {
    assert.throws(() => reader.db.exec("INSERT INTO runs (source, mode, started_at, options) VALUES ('x', 'file', 'now', '{}')"), /readonly/i);
  } finally {
    reader.close();
  }
});

test('live mode stores each incident once, updates it as it changes, and marks it closed at shutdown', async (t) => {
  const { appendFileSync, writeFileSync } = await import('node:fs');
  const { setTimeout: sleep } = await import('node:timers/promises');
  const { startLive } = await import('../src/io/live.js');
  const dir = mkdtempSync(join(tmpdir(), 'store-live-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'auth.log');
  writeFileSync(file, '');
  const store = openStore(':memory:');
  const run = store.beginRun({ source: file, mode: 'follow', options: {} });
  const live = startLive({
    path: file, pollMs: 20, tap: store.tap(run, 64),
    sinks: [{ name: 'sqlite', onIncident: (e) => store.saveLiveEvent(run, e), close: async () => store.flush() }],
  });
  await sleep(60);
  const at = (s) => `2026-10-17T13:00:${String(s).padStart(2, '0')}.000000+00:00 web01 sshd-session[9]:`;
  for (let s = 0; s < 6; s++) appendFileSync(file, `${at(s)} Failed password for deploy from 198.51.100.23 port 1 ssh2\n`);
  await sleep(120);
  appendFileSync(file, `${at(10)} Accepted password for deploy from 198.51.100.23 port 2 ssh2\n`);
  await sleep(120);
  await live.stop();
  const incidents = /** @type {any[]} */ (store.db.prepare('SELECT ip, severity, closed FROM incidents').all());
  assert.deepEqual(incidents.map((i) => ({ ...i })), [{ ip: '198.51.100.23', severity: 'high', closed: 1 }]);
  const rules = /** @type {any[]} */ (store.db.prepare('SELECT rule, severity FROM findings ORDER BY id').all());
  assert.deepEqual(rules.map((r) => `${r.rule} ${r.severity}`), ['brute-force high', 'possible-breach high']);
  assert.equal(/** @type {any} */ (store.db.prepare('SELECT COUNT(*) AS n FROM lines').get()).n, 7);
  store.close();
});
