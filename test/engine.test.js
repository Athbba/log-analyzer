// The streaming engine itself: incremental findings, bounded state, eviction,
// and the edge cases the random equivalence test can't reach.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createEngine } from '../src/core/engine.js';
import { analyze } from '../src/detectors.js';
import { parseLines } from '../src/parse.js';
import { analyze as reference } from './reference/batch-detectors.js';

/** @typedef {import('../src/types.js').AuthEvent} AuthEvent */

const at = (hms, pid = 100) => `Sep  7 ${hms} web01 sshd[${pid}]:`;
const fail = (hms, ip, user = 'root') => `${at(hms)} Failed password for ${user} from ${ip} port 40000 ssh2`;
const login = (hms, ip, user = 'deploy', pid = 200) => `${at(hms, pid)} Accepted password for ${user} from ${ip} port 40000 ssh2`;
const logout = (hms, user, pid) => `${at(hms, pid)} pam_unix(sshd:session): session closed for user ${user}`;
/** @param {string[]} lines */
const events = async (lines) => (await parseLines(lines, { year: 2026 })).events;

test('findings are reported as they are detected, and updated when evidence arrives', async () => {
  /** @type {string[]} */
  const seen = [];
  const engine = createEngine({}, {
    onFinding: (f, isNew) => seen.push(`${isNew ? 'new' : 'updated'} ${f.rule} ${f.severity}`),
  });
  const lines = [...['00', '10', '20', '30', '40'].map((s) => fail(`13:00:${s}`, '198.51.100.23', 'deploy')), login('13:01:00', '198.51.100.23')];
  const evs = await events(lines);

  for (const e of evs.slice(0, 5)) engine.push(e);
  engine.flush();
  assert.deepEqual(seen, ['new brute-force medium'], 'the attack is reported once the fifth failure arrives');

  engine.push(evs[5]);
  engine.flush();
  assert.deepEqual(seen.slice(1), ['updated brute-force high', 'new possible-breach high'], 'the login escalates it');
});

test('a session that logs out in the same second as an account change still counts', async () => {
  // The random equivalence test never puts two actions in the same second, so
  // this case is checked here, against the batch rules too.
  const ATTACKER = '198.51.100.23';
  const lines = [
    ...['00', '10', '20', '30', '40'].map((s) => fail(`03:00:${s}`, ATTACKER, 'deploy')),
    login('03:01:00', ATTACKER),
    'Sep  7 03:02:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo erin',
    logout('03:02:00', 'deploy', 200),
    "Sep  7 03:02:00 web01 usermod[900]: add 'erin' to group 'sudo'",
  ];
  const evs = await events(lines);
  const change = (incidents) => incidents.flatMap((i) => i.findings).find((f) => f.rule === 'account-change');
  assert.equal(change(analyze(evs)).severity, 'high');
  assert.deepEqual(change(analyze(evs)), change(reference(evs)));
});

test('state stays under its caps however many IPs attack, and the drops are counted', () => {
  const limits = { maxKeys: 1_000, maxEntriesPerKey: 50, maxUsersPerFinding: 20 };
  const engine = createEngine({ limits }, { keepFindings: false });
  const start = Date.UTC(2026, 8, 7);
  // 200,000 failures from 100,000 IPs in one minute (so nothing ages out), plus
  // one IP with 5,000 failures for 2,000 usernames.
  for (let i = 0; i < 200_000; i++) {
    const ip = `2001:db8::${(i % 100_000).toString(16)}`;
    engine.push({ type: 'failure', time: start + Math.floor(i / 4_000) * 1000, host: 'web01', pid: 1, line: i, ip, user: 'root', invalidUser: false, method: 'password', count: 1 });
  }
  for (let i = 0; i < 5_000; i++) {
    engine.push({ type: 'failure', time: start + 50_000, host: 'web01', pid: 1, line: i, ip: '203.0.113.9', user: `u${i % 2_000}`, invalidUser: true, method: 'password', count: 1 });
  }
  for (const [rule, { keys, entries }] of Object.entries(engine.size())) {
    assert.ok(keys <= 3 * limits.maxKeys, `${rule}: ${keys} keys`);
    assert.ok(entries <= limits.maxKeys * limits.maxEntriesPerKey, `${rule}: ${entries} entries`);
  }
  assert.ok(engine.health.evicted['brute-force: IPs'] > 0);
  assert.ok(engine.health.evicted['brute-force: failures per IP'] > 0);
  assert.ok(engine.health.evicted['brute-force: usernames per attack'] > 0);
});

test('state for IPs that have gone quiet is evicted as the log clock moves on', () => {
  const engine = createEngine({}, { keepFindings: false });
  const start = Date.UTC(2026, 8, 7);
  // One failure per IP every second for 10 hours: 36,000 IPs, none ever reaching
  // a brute force. Only the last lookback (30 minutes) of IPs should be held.
  for (let i = 0; i < 36_000; i++) {
    engine.push({ type: 'failure', time: start + i * 1000, host: 'web01', pid: 1, line: i, ip: `10.${i >> 16}.${(i >> 8) & 255}.${i & 255}`, user: 'root', invalidUser: false, method: 'password', count: 1 });
  }
  const size = engine.size();
  assert.ok(size['possible-breach'].keys <= 2 * 30 * 60, `possible-breach holds ${size['possible-breach'].keys} IPs`);
  assert.ok(size['brute-force'].keys <= 2 * 10 * 60, `brute-force holds ${size['brute-force'].keys} IPs`);
  assert.equal(engine.health.total, 0, 'nothing was dropped for lack of room');
});

test('an attacker IP is remembered for limits.memoryMs, then forgotten', async () => {
  const day = 24 * 60 * 60_000;
  const attack = await events(['00', '10', '20', '30', '40'].map((s) => fail(`03:00:${s}`, '198.51.100.23', 'deploy')));
  /** @param {number} ms @returns {AuthEvent} */
  const laterLogin = (ms) => ({
    type: 'success', time: attack[0].time + ms, host: 'web01', pid: 300, line: 99,
    ip: '198.51.100.23', user: 'deploy', method: 'password', count: 1,
  });
  const severity = (ms) => analyze([...attack, laterLogin(ms)]).find((i) => i.ip === '198.51.100.23')?.findings[0].severity;
  assert.equal(severity(6 * day), 'high', 'a login 6 days later still escalates the attack');
  assert.equal(severity(8 * day), 'medium', 'after the default 7 days it does not');
  assert.equal(analyze([...attack, laterLogin(8 * day)], { limits: { memoryMs: 9 * day } })
    .find((i) => i.ip === '198.51.100.23')?.findings[0].severity, 'high', 'memoryMs is configurable');
});
