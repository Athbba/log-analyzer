// End-to-end checks against samples/auth.log. The expected results come from the
// answer key in scripts/generate-sample-log.js.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { analyze } from '../src/detectors.js';
import { parseLines } from '../src/parse.js';

const SAMPLE = fileURLToPath(new URL('../samples/auth.log', import.meta.url));
const BIN = fileURLToPath(new URL('../bin/analyze.js', import.meta.url));
const cli = (args, input) => spawnSync(process.execPath, [BIN, ...args], { input, encoding: 'utf8' });

const { events, stats } = await parseLines(readFileSync(SAMPLE, 'utf8').split('\n'), { year: 2026 });
const incidents = analyze(events);
// Typed loosely on purpose: tests read fields specific to each rule.
/** @param {string} ip @returns {any} */
const incident = (ip) => incidents.find((i) => i.ip === ip);

test('finds exactly the injected attacks in the sample log', () => {
  assert.equal(stats.unrecognized, 0);
  assert.equal(stats.failures, 116);
  assert.equal(stats.successes, 44);

  assert.deepEqual(incidents.map((i) => [i.ip, i.severity, i.findings.map((f) => `${f.rule}:${f.severity}`)]), [
    // B: the new-source rule adds that deploy had never logged in from there.
    ['198.51.100.23', 'high', ['brute-force:high', 'possible-breach:high', 'new-source:medium', 'unusual-hour:low', 'account-change:high']],
    ['203.0.113.45', 'medium', ['brute-force:medium']], // A
    ['10.0.1.81', 'medium', ['account-change:low', 'account-change:medium']], // G: dave onboards erin
    ['10.0.1.57', 'low', ['possible-breach:low', 'possible-breach:low', 'possible-breach:low']], // F: bob's typos
    // Benign lookalikes for the new-source rule, at low: carol from home over
    // IPv6, and on-call dave over the VPN (C), each a first for that user.
    ['2001:db8:4a2::/64', 'low', ['new-source:low']],
    ['10.8.0.22', 'low', ['new-source:low', 'unusual-hour:low']],
  ]);

  const [a, b] = [incident('203.0.113.45').findings[0], incident('198.51.100.23').findings[0]];
  assert.equal(a.attempts, 36);
  assert.equal(a.loggedIn, null);
  assert.equal(b.attempts, 14);
  assert.deepEqual(b.loggedIn, { time: Date.UTC(2026, 8, 9, 3, 39, 12), user: 'deploy', method: 'password' });
});

test("links attacker B's backdoor sudo user to the break-in", () => {
  const backdoor = incident('198.51.100.23').findings.find((f) => f.rule === 'account-change');
  assert.deepEqual(backdoor, {
    rule: 'account-change',
    severity: 'high',
    ip: '198.51.100.23',
    time: Date.UTC(2026, 8, 9, 3, 40, 56),
    user: 'sysupdate',
    created: true,
    uid: 1101,
    groups: ['sudo'],
    privilegedGroups: ['sudo'],
    by: 'deploy',
    sessionIps: ['198.51.100.23'],
    afterBreach: { time: Date.UTC(2026, 8, 9, 3, 39, 12), user: 'deploy', attempts: 14 },
  });
});

test("dave's legitimate account changes are flagged but not high, and bob joining docker is ignored", () => {
  const changes = incidents.flatMap((i) => i.findings).filter((f) => f.rule === 'account-change');
  assert.deepEqual(changes.map((f) => [f.user, f.groups, f.severity, f.by]), [
    ['sysupdate', ['sudo'], 'high', 'deploy'],
    ['erin', [], 'low', 'dave'],
    ['erin', ['sudo'], 'medium', 'dave'],
  ]);
});

test('CLI prints a report and exits 1 when something is high severity', () => {
  const { status, stdout } = cli([SAMPLE, '--year', '2026']);
  assert.equal(status, 1);
  assert.match(stdout, /^HIGH {4}198\.51\.100\.23$/m);
  assert.match(stdout, /then logged in as deploy \(password\) at 2026-09-09 03:39:12/);
  assert.match(stdout, /account change {3}new user sysupdate, member of sudo\n +by deploy via sudo, in a session from 198\.51\.100\.23/);
  assert.match(stdout, /6 incidents: 1 high, 2 medium, 3 low/);
});

test('CLI --json reads stdin and prints wall-clock times', () => {
  const { status, stdout } = cli(['-', '--json', '--year', '2026'], readFileSync(SAMPLE));
  assert.equal(status, 1);
  const report = JSON.parse(stdout);
  assert.equal(report.source, 'stdin');
  assert.deepEqual(report.summary, { high: 1, medium: 2, low: 3 });
  assert.equal(report.incidents[0].findings[0].time, '2026-09-09T03:21:40');
  assert.equal(report.incidents[0].findings.find((f) => f.rule === 'account-change').afterBreach.time, '2026-09-09T03:39:12');
});

test('CLI exits 0 on a clean log and 2 on bad input', () => {
  const clean = cli(['-'], 'Sep  7 09:00:00 web01 sshd[1]: Accepted publickey for alice from 10.0.1.23 port 5 ssh2\n');
  assert.equal(clean.status, 0);
  assert.match(clean.stdout, /No suspicious activity found\./);

  const missing = cli(['no-such-file.log']);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /can't read no-such-file\.log/);

  assert.equal(cli([]).status, 2, 'no log file');
  const badArgs = [['--threshold', '0'], ['--night', '5-5'], ['--window', 'soon'], ['--admin-groups', 'sudo,'], ['--bogus']];
  for (const args of badArgs) assert.equal(cli([...args, SAMPLE]).status, 2, args.join(' '));
});
