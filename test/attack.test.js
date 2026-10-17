// MITRE ATT&CK labels: the mapping itself, and that every output carries it
// (terminal, JSON, JSON lines, SQLite, dashboard).

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { TECHNIQUES, techniquesFor, withAttack } from '../src/core/attack.js';
import { LABELS, attackLine } from '../src/report.js';
import { createJsonLinesSink } from '../src/io/sinks/terminal.js';

const BIN = fileURLToPath(new URL('../bin/analyze.js', import.meta.url));
const SAMPLE = fileURLToPath(new URL('../samples/auth.log', import.meta.url));
const DOCS = new URL('../docs/detections.md', import.meta.url);

/** Minimal findings: the mapping reads only `rule` and, for account changes, what changed. */
const base = { severity: 'medium', ip: '192.0.2.1', time: 0 };
/** @type {Record<string, any>} */
const SAMPLES = {
  'brute-force': { ...base, rule: 'brute-force' },
  'possible-breach': { ...base, rule: 'possible-breach' },
  'unusual-hour': { ...base, rule: 'unusual-hour' },
  'password-spray': { ...base, rule: 'password-spray' },
  'distributed-brute-force': { ...base, ip: null, rule: 'distributed-brute-force' },
  'new-source': { ...base, rule: 'new-source' },
  'log-tampering': { ...base, ip: null, rule: 'log-tampering' },
};
const change = (/** @type {boolean} */ created, /** @type {string[]} */ privilegedGroups) =>
  /** @type {any} */ ({ ...base, rule: 'account-change', created, privilegedGroups });

const ids = (/** @type {any} */ f) => techniquesFor(f).map((t) => t.id);

test('each rule maps to the ATT&CK techniques it detects', () => {
  assert.deepEqual(ids(SAMPLES['brute-force']), ['T1110.001']);
  assert.deepEqual(ids(SAMPLES['possible-breach']), ['T1110.001', 'T1078.003']);
  assert.deepEqual(ids(SAMPLES['unusual-hour']), ['T1078.003']);
  assert.deepEqual(ids(SAMPLES['password-spray']), ['T1110.003']);
  assert.deepEqual(ids(SAMPLES['distributed-brute-force']), ['T1110.001']);
  assert.deepEqual(ids(SAMPLES['new-source']), ['T1078.003', 'T1021.004']);
  assert.deepEqual(ids(SAMPLES['log-tampering']), ['T1685.006']);
});

test('an account change maps by what changed: a new account, admin rights, or both', () => {
  assert.deepEqual(ids(change(true, [])), ['T1136.001']);
  assert.deepEqual(ids(change(false, ['sudo'])), ['T1098.007']);
  assert.deepEqual(ids(change(true, ['sudo', 'adm'])), ['T1136.001', 'T1098.007']);
});

test('every rule is mapped, every technique is named, and IDs are well formed', () => {
  for (const rule of Object.keys(LABELS)) {
    const finding = rule === 'account-change' ? change(true, []) : SAMPLES[rule];
    assert.ok(techniquesFor(finding).length > 0, `${rule} has a technique`);
  }
  for (const [id, { name, tactics }] of Object.entries(TECHNIQUES)) {
    assert.match(id, /^T\d{4}(\.\d{3})?$/);
    assert.ok(name.length > 0 && tactics.length > 0, id);
  }
  const f = withAttack(SAMPLES['brute-force']);
  assert.deepEqual(f.attack, [{ id: 'T1110.001', name: 'Brute Force: Password Guessing' }]);
  assert.equal(/** @type {any} */ (SAMPLES['brute-force']).attack, undefined, 'the finding itself is not changed');
});

test('terminal and JSON reports carry the techniques of every finding', () => {
  const text = spawnSync(process.execPath, [BIN, SAMPLE, '--year', '2026'], { encoding: 'utf8' });
  assert.match(text.stdout, /ATT&CK T1110\.001 Brute Force: Password Guessing/);
  assert.match(text.stdout, /ATT&CK T1136\.001 Create Account: Local Account, T1098\.007 Account Manipulation: Additional Local or Domain Groups/);
  const json = JSON.parse(spawnSync(process.execPath, [BIN, SAMPLE, '--year', '2026', '--json'], { encoding: 'utf8' }).stdout);
  for (const finding of json.incidents.flatMap((/** @type {any} */ i) => i.findings)) {
    assert.deepEqual(finding.attack, techniquesFor(finding), finding.rule);
  }
});

test('live JSON lines carry the techniques too', () => {
  /** @type {string[]} */
  const out = [];
  const sink = createJsonLinesSink({ write: (s) => out.push(s) });
  const finding = SAMPLES['password-spray'];
  sink.onIncident?.(/** @type {any} */ ({ type: 'opened', incident: { key: 'k', ip: '192.0.2.1', severity: 'medium', findings: [finding] }, finding }));
  const event = JSON.parse(out[0]);
  assert.equal(event.finding.attack[0].id, 'T1110.003');
  assert.equal(event.incident.findings[0].attack[0].id, 'T1110.003');
});

test('SQLite stores the techniques with each finding', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'attack-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'runs.db');
  spawnSync(process.execPath, [BIN, SAMPLE, '--year', '2026', '--json', '--db', file], { encoding: 'utf8' });
  const { openStore } = await import('../src/io/store.js');
  const store = openStore(file, { readOnly: true });
  const rows = /** @type {{ rule: string, ids: string }[]} */ (store.db.prepare(
    "SELECT rule, (SELECT group_concat(json_extract(value, '$.id')) FROM json_each(data, '$.attack')) AS ids FROM findings").all());
  store.close();
  assert.ok(rows.length > 0);
  for (const row of rows) assert.ok(row.ids, `${row.rule} stored with techniques`);
  assert.ok(rows.some((r) => r.rule === 'brute-force' && r.ids === 'T1110.001'));
});

test('docs/detections.md explains every rule and links every technique, and its local links resolve', () => {
  const docs = readFileSync(DOCS, 'utf8');
  for (const id of Object.keys(TECHNIQUES)) {
    assert.ok(docs.includes(`(https://attack.mitre.org/techniques/${id.replace('.', '/')}/)`), `${id} is linked`);
  }
  for (const rule of Object.keys(LABELS)) assert.ok(docs.includes(`| \`${rule}\` |`), `${rule} is in the mapping table`);
  for (const [, target] of docs.matchAll(/\]\((?!https?:|#)([^)#]+)/g)) {
    assert.ok(existsSync(new URL(target, DOCS)), `${target} exists`);
  }
});

test('a stored finding with an unknown or inherited rule name gets no techniques, and no empty label', () => {
  for (const rule of ['constructor', 'toString', '__proto__', 'no-such-rule']) {
    assert.deepEqual(techniquesFor(/** @type {any} */ ({ ...base, rule })), [], rule);
  }
  assert.equal(attackLine(change(false, [])), '');
});
