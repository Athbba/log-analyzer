// The rules added in M2b: each with what it must catch and the lookalikes it
// must not alert on. Events are built directly so each case states exactly
// what happens and when.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createEngine } from '../src/core/engine.js';

/** @typedef {import('../src/types.js').AuthEvent} AuthEvent */
/** @typedef {import('../src/types.js').AnalyzerOptions} AnalyzerOptions */

const T0 = Date.UTC(2026, 8, 7, 12);
const MIN = 60_000;
let line = 0;
/** @returns {AuthEvent} */
const fail = (ip, user, minute, { invalid = false, count = 1 } = {}) =>
  ({ type: 'failure', time: T0 + minute * MIN, host: 'web01', pid: 10, line: ++line, ip, user, invalidUser: invalid, method: 'password', count });
/** @returns {AuthEvent} */
const ok = (ip, user, minute, method = 'password') =>
  ({ type: 'success', time: T0 + minute * MIN, host: 'web01', pid: 20, line: ++line, ip, user, method, count: 1 });

/**
 * Runs events through the engine and returns "rule severity key" per finding.
 * @param {AuthEvent[]} events
 * @param {AnalyzerOptions} [options]
 * @param {string} [only]  Keep only this rule's findings.
 */
function run(events, options = {}, only) {
  const engine = createEngine(options);
  for (const e of events) engine.push(e);
  return engine.findings()
    .filter((f) => !only || f.rule === only)
    .map((f) => `${f.rule} ${f.severity} ${f.ip ?? ('user' in f ? f.user : '-')}`);
}
const ACCOUNTS = ['alice', 'bob', 'carol', 'dave', 'deploy', 'backup', 'www-data', 'mail', 'erin', 'frank'];

// --- Password spraying ---

test('spray: one guess at each of six real accounts, slowly enough to stay under brute force', () => {
  // One guess every 3 minutes: never 5 in 10 minutes, so brute force stays quiet.
  const events = ACCOUNTS.slice(0, 6).map((u, i) => fail('198.51.100.7', u, i * 3));
  assert.deepEqual(run(events), ['password-spray medium 198.51.100.7']);
});

test('spray: five accounts is below the default; minUsers is tunable', () => {
  const events = ACCOUNTS.slice(0, 5).map((u, i) => fail('198.51.100.7', u, i * 3));
  assert.deepEqual(run(events, {}, 'password-spray'), []);
  assert.deepEqual(run(events, { spray: { minUsers: 5 } }, 'password-spray'), ['password-spray medium 198.51.100.7']);
});

test('spray lookalike: a scanner cycling nonexistent usernames is not a spray', () => {
  const names = ['admin', 'oracle', 'test', 'ubuntu', 'pi', 'guest', 'git', 'ftpuser'];
  const events = names.map((u, i) => fail('203.0.113.9', u, i * 3, { invalid: true }));
  assert.deepEqual(run(events, {}, 'password-spray'), []);
  assert.equal(run(events, { spray: { countInvalidUsers: true } }, 'password-spray').length, 1, 'unless asked to count them');
});

test('spray lookalike: an office behind one NAT where people mistype their passwords', () => {
  // Eight people, each mistypes once and logs in seconds later.
  const events = ACCOUNTS.slice(0, 8).flatMap((u, i) => [fail('10.0.2.1', u, i * 5), ok('10.0.2.1', u, i * 5 + 0.1)]);
  assert.deepEqual(run(events, {}, 'password-spray'), []);
});

test('spray lookalike: a dictionary attack hammering one account is brute force, not a spray', () => {
  const events = Array.from({ length: 20 }, (_, i) => fail('203.0.113.45', i % 4 === 0 ? 'deploy' : 'root', i * 0.2));
  assert.deepEqual(run(events), ['brute-force medium 203.0.113.45']);
});

test('spray: a login as one of the sprayed accounts makes it high', () => {
  const events = [...ACCOUNTS.slice(0, 6).map((u, i) => fail('198.51.100.7', u, i * 3)), ok('198.51.100.7', 'carol', 20)];
  assert.ok(run(events).includes('password-spray high 198.51.100.7'));
});

// --- Distributed brute force ---

const botnet = (n, user = 'deploy', perIp = 2) =>
  Array.from({ length: n * perIp }, (_, i) => fail(`192.0.2.${10 + (i % n)}`, user, i * 2));

test('distributed: one account guessed from four sources, each well under brute force', () => {
  assert.deepEqual(run(botnet(4)), ['distributed-brute-force medium deploy']);
});

test('distributed lookalike: three sources, or too few attempts, is not an attack', () => {
  assert.deepEqual(run(botnet(3)), []);
  assert.deepEqual(run(botnet(5, 'deploy', 1)), [], '5 sources but only 5 attempts');
});

test('distributed lookalike: a user failing from laptop, phone and VPN in one hour', () => {
  const events = [fail('10.8.0.14', 'carol', 0), fail('198.51.100.200', 'carol', 20), fail('2001:db8:4a2::1c', 'carol', 40)];
  assert.deepEqual(run(events), []);
});

test('distributed: nonexistent accounts, ignored users and trusted networks are left out', () => {
  const invalid = Array.from({ length: 10 }, (_, i) => fail(`192.0.2.${10 + i}`, 'oracle', i, { invalid: true }));
  assert.deepEqual(run(invalid, {}, 'distributed-brute-force'), []);
  assert.deepEqual(run(botnet(5, 'root'), { distributed: { ignoreUsers: ['root'] } }), []);
  // A misconfigured internal service: the documented false positive, muted by trusting the network.
  const service = Array.from({ length: 12 }, (_, i) => fail(`10.0.5.${20 + (i % 6)}`, 'deploy', i * 4));
  assert.deepEqual(run(service), ['distributed-brute-force medium deploy']);
  assert.deepEqual(run(service, { trustedNetworks: ['10.0.0.0/8'] }), []);
});

test('distributed: one IPv6 /64 rotating addresses is one source, not many', () => {
  const rotating = Array.from({ length: 8 }, (_, i) => fail(`2001:db8:66:1::${i + 1}`, 'deploy', i * 3));
  assert.deepEqual(run(rotating, {}, 'distributed-brute-force'), []);
});

test('distributed: a login from an attacking source makes it high', () => {
  assert.ok(run([...botnet(4), ok('192.0.2.11', 'deploy', 30)]).includes('distributed-brute-force high deploy'));
  assert.ok(!run([...botnet(4), ok('10.0.1.5', 'deploy', 30)]).includes('distributed-brute-force high deploy'),
    'not when the account owner logs in from their usual place');
});

// --- First login from a new source ---

const DAY = 24 * 60;
test('new source: after the learning day, a login from a network the user never used', () => {
  const events = [ok('10.0.1.23', 'alice', 0, 'publickey'), ok('10.0.1.23', 'alice', DAY + 60, 'publickey'),
    ok('198.51.100.23', 'alice', DAY + 120, 'publickey'), ok('198.51.100.24', 'alice', DAY + 180, 'password')];
  assert.deepEqual(run(events), ['new-source low 198.51.100.23'], 'once per network, and the same /24 is the same place');
  const password = [ok('10.0.1.23', 'deploy', 0, 'publickey'), ok('198.51.100.23', 'deploy', DAY + 1)];
  assert.deepEqual(run(password), ['new-source medium 198.51.100.23'], 'a password login is medium');
});

test('new source lookalikes: the learning period, a first-ever login, a trusted network', () => {
  assert.deepEqual(run([ok('10.0.1.23', 'alice', 0), ok('198.51.100.23', 'alice', 60)]), [], 'still learning');
  assert.deepEqual(run([ok('10.0.1.23', 'alice', 0), ok('198.51.100.23', 'erin', DAY + 60)]), [], 'erin has no baseline');
  assert.deepEqual(run([ok('10.0.1.23', 'dave', 0), ok('10.8.0.22', 'dave', DAY + 60)], { trustedNetworks: ['10.0.0.0/8'] }), []);
});

// --- Log tampering ---

/**
 * Feeds line timestamps (minutes from T0, optional RFC 3339 offset) and returns tampering findings.
 * @param {(number | [number, number])[]} lines
 * @param {AnalyzerOptions} [options]
 */
function timeline(lines, options = {}) {
  const engine = createEngine(options);
  lines.forEach((l, i) => {
    const [minute, offsetMinutes] = Array.isArray(l) ? l : [l, null];
    engine.line({ time: T0 + minute * MIN, line: i + 1, offsetMinutes, hasNul: false });
  });
  return engine.findings().map((f) => (f.rule === 'log-tampering' ? `${f.kind} ${f.severity}` : f.rule));
}

test('tampering: hours of silence, and time going backwards', () => {
  assert.deepEqual(timeline([0, 60, 120, 400, 460]), ['gap low'], 'nearly 5 hours with no lines');
  assert.deepEqual(timeline([0, 60, 120, 180]), [], 'hourly cron lines are normal');
  assert.deepEqual(timeline([600, 601, 420, 421, 602]), ['backwards medium'], 'lines from 3 hours earlier spliced in, reported once');
});

test('tampering lookalikes: a clock step of seconds, and the end of daylight saving time', () => {
  assert.deepEqual(timeline([10, 10.05, 10.01, 11]), [], 'NTP stepping the clock back 3 s');
  // RFC 3339: 02:59 at +02:00, then 02:00 at +01:00. The offset shows it is DST.
  assert.deepEqual(timeline([[179, 120], [120, 60], [121, 60]]), []);
  assert.deepEqual(timeline([[179, 120], [120, 120]]), ['backwards medium'], 'the same step without the offset change');
  // Classic syslog has no offset; a one-hour step is let through unless disabled.
  assert.deepEqual(timeline([179, 120]), []);
  assert.deepEqual(timeline([179, 120], { tampering: { allowDstJumps: false } }), ['backwards medium']);
});

test('tampering: NUL-damaged lines are one finding, and truncation in live mode is high', () => {
  const engine = createEngine();
  for (const [i, hasNul] of [false, true, true, true, false].entries()) engine.line({ time: T0 + i * 1000, line: i + 1, offsetMinutes: null, hasNul });
  engine.signal({ type: 'truncated', time: T0 + 9000, line: 6, fromBytes: 52_000, toBytes: 800 });
  assert.deepEqual(engine.findings().map((f) => f.rule === 'log-tampering' && `${f.kind} ${f.severity} ${f.detail}`), [
    'nul-bytes low 3 lines with NUL bytes, as left by truncating a file that is still being written',
    'truncated high the log file shrank from 52000 to 800 bytes without being rotated',
  ]);
});

// --- Possible breach on a shared IP ---

test('breach: a key login after someone else mistyped from the same IP is not reported', () => {
  const office = '10.0.1.20';
  assert.deepEqual(run([fail(office, 'bob', 0), ok(office, 'dave', 0.05, 'publickey')], {}, 'possible-breach'), []);
  assert.deepEqual(run([fail(office, 'bob', 0), ok(office, 'dave', 0.05, 'password')], {}, 'possible-breach'),
    ['possible-breach low 10.0.1.20'], 'a password login still is');
  assert.deepEqual(run([fail(office, 'bob', 0), ok(office, 'dave', 0.05, 'publickey')], { ignoreKeyLoginsAfterOthersFailures: false }, 'possible-breach'),
    ['possible-breach low 10.0.1.20'], 'and the old behaviour can be restored');
  // Four failures, the key login, then a fifth failure makes a brute force that covers it.
  const later = [0, 1, 2, 3].map((m) => fail(office, 'root', m * 0.1));
  assert.deepEqual(run([...later, ok(office, 'dave', 0.5, 'publickey'), fail(office, 'root', 0.6)], {}, 'possible-breach'),
    ['possible-breach high 10.0.1.20'], 'held back, then reported high once a brute force covers it');
});
