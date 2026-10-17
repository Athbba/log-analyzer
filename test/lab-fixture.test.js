// Tests against a real auth.log recorded in the Docker lab (OpenSSH 10.0,
// sudo 1.9, rsyslog 8.2504 on Debian 13). See lab/README.md for the scenarios
// and test/fixtures/lab/labels.json for what each one must produce.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { morningTz } from '../scripts/lab.js';
import { checkLabels, loadLabels } from '../scripts/lib/labels.js';
import { parseLines } from '../src/parse.js';

const LOG = readFileSync(new URL('./fixtures/lab/auth.log', import.meta.url), 'utf8');
const LABELS = loadLabels(fileURLToPath(new URL('./fixtures/lab/labels.json', import.meta.url)));

test('the lab log produces exactly the labelled incidents', async () => {
  assert.deepEqual(await checkLabels(LOG, LABELS), []);
});

test('the label check fails when an attack step is missing', async () => {
  // Without the attacker's successful login, the break-in is only a brute force.
  const withoutLogin = LOG.split('\n').filter((line) => !line.includes('Accepted password for deploy')).join('\n');
  const problems = await checkLabels(withoutLogin, LABELS);
  assert.ok(problems.some((p) => p.startsWith('break-in: 172.30.0.77 has brute-force:medium,')), problems.join('\n'));
});

test('the label check fails on an incident nobody labelled', async () => {
  const extra = ['01', '02', '03', '04', '05'].map((s) =>
    `2026-10-17T10:20:${s}.000000+10:00 lab-target sshd-session[9${s}]: Failed password for root from 172.30.0.99 port 4000${s} ssh2`);
  const problems = await checkLabels(`${LOG}${extra.join('\n')}\n`, LABELS);
  assert.deepEqual(problems, ['unexpected incident for 172.30.0.99: brute-force:medium']);
});

test('reads the current OpenSSH, sudo and shadow-utils formats the lab records', async () => {
  const { events, stats } = await parseLines(LOG.split('\n'));
  assert.equal(stats.unrecognized, 0);

  // sshd-session (OpenSSH 9.8+) logs the login and, from the same PID, the logout.
  const login = events.find((e) => e.type === 'success' && e.user === 'deploy');
  const logout = events.find((e) => e.type === 'logout' && e.user === 'deploy');
  assert.ok(login && logout);
  assert.equal(login.pid, logout.pid);

  // sudo 1.9 leaves out TTY= when there is no terminal; the line starts at PWD=.
  const sudo = events.filter((e) => e.type === 'sudo').map((e) => e.type === 'sudo' && `${e.user}: ${e.command}`);
  assert.ok(sudo.includes('deploy: /usr/sbin/useradd -m -s /bin/bash -G sudo sysupdate'), sudo.join('\n'));

  // RFC 3339 timestamps keep the server clock, whatever the offset.
  const raw = LOG.split('\n')[login.line - 1];
  assert.match(raw, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+[+-]\d\d:\d\d /);
  assert.equal(new Date(login.time).toISOString().slice(0, 19), raw.slice(0, 19));
});

test('the lab clock is set to about 10:00 whatever time the lab runs', () => {
  for (let hour = 0; hour < 24; hour++) {
    const tz = morningTz(new Date(Date.UTC(2026, 9, 17, hour, 30)));
    const m = /^LAB(?:0|([+-])(\d+))$/.exec(tz);
    assert.ok(m, tz);
    const east = m[1] === undefined ? 0 : (m[1] === '-' ? 1 : -1) * Number(m[2]);
    assert.ok(east >= -12 && east <= 14, `${tz} is a real offset`);
    assert.equal((hour + east + 24) % 24, 10, `${hour}:30 UTC with ${tz}`);
  }
});
