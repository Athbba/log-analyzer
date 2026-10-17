import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseLines } from '../src/parse.js';

// Typed loosely on purpose: tests read fields specific to each event type.
/**
 * @param {string} text
 * @param {{ year?: number }} [options]
 * @returns {Promise<{ events: any[], stats: import('../src/types.js').ParseStats }>}
 */
const parse = (text, options = { year: 2026 }) => parseLines(text.trim().split('\n'), options);

test('reads failed and accepted logins and skips the duplicate PAM lines', async () => {
  const { events, stats } = await parse(`
Sep  7 03:12:44 web01 sshd[3456]: Invalid user admin from 203.0.113.9 port 44321
Sep  7 03:12:44 web01 sshd[3456]: pam_unix(sshd:auth): check pass; user unknown
Sep  7 03:12:44 web01 sshd[3456]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9
Sep  7 03:12:46 web01 sshd[3456]: Failed password for invalid user admin from 203.0.113.9 port 44321 ssh2
Sep  7 03:12:48 web01 sshd[3456]: Disconnected from invalid user admin 203.0.113.9 port 44321 [preauth]
Sep 17 08:14:22 web01 sshd[2345]: Accepted publickey for alice from 10.0.1.23 port 51234 ssh2: ED25519 SHA256:Xk3a/bc+de
Sep 17 08:14:22 web01 sshd[2345]: pam_unix(sshd:session): session opened for user alice(uid=1001) by (uid=0)
Sep 17 08:15:01 web01 CRON[99]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
`);
  assert.deepEqual(events, [
    { type: 'failure', time: Date.UTC(2026, 8, 7, 3, 12, 46), host: 'web01', pid: 3456, ip: '203.0.113.9', user: 'admin', invalidUser: true, method: 'password', count: 1, line: 4 },
    { type: 'success', time: Date.UTC(2026, 8, 17, 8, 14, 22), host: 'web01', pid: 2345, ip: '10.0.1.23', user: 'alice', method: 'publickey', count: 1, line: 6 },
  ]);
  assert.deepEqual(stats, {
    lines: 8, unrecognized: 0, failures: 1, successes: 1,
    first: Date.UTC(2026, 8, 7, 3, 12, 44), last: Date.UTC(2026, 8, 17, 8, 15, 1),
  });
});

test('reads logouts, sudo commands and account changes, skipping refusals and shadow-group twins', async () => {
  const { events } = await parse(`
Sep  9 03:40:56 web01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m -G sudo sysupdate
Sep  9 03:40:56 web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1100)
Sep  9 03:40:56 web01 useradd[5490]: new group: name=sysupdate, GID=1101
Sep  9 03:40:56 web01 useradd[5490]: new user: name=sysupdate, UID=1101, GID=1101, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/1
Sep  9 03:40:56 web01 useradd[5490]: add 'sysupdate' to group 'sudo'
Sep  9 03:40:56 web01 useradd[5490]: add 'sysupdate' to shadow group 'sudo'
Sep  9 03:42:00 web01 gpasswd[5501]: user erin added by root to group wheel
Sep  9 03:43:00 web01 sudo:  mallory : 3 incorrect password attempts ; TTY=pts/3 ; PWD=/home/mallory ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo mallory
Sep  9 03:50:12 web01 sshd[5452]: pam_unix(sshd:session): session closed for user deploy
`);
  assert.deepEqual(events.map(({ time, host, ...rest }) => rest), [
    { type: 'sudo', pid: null, line: 1, user: 'deploy', command: '/usr/sbin/useradd -m -G sudo sysupdate' },
    { type: 'account', pid: 5490, line: 4, program: 'useradd', action: 'user-created', user: 'sysupdate', uid: 1101 },
    { type: 'account', pid: 5490, line: 5, program: 'useradd', action: 'group-added', user: 'sysupdate', group: 'sudo' },
    { type: 'account', pid: 5501, line: 7, program: 'gpasswd', action: 'group-added', user: 'erin', group: 'wheel' },
    { type: 'logout', pid: 5452, line: 9, user: 'deploy' },
  ]);
});

test('counts "message repeated N times" as N more failures', async () => {
  const { events, stats } = await parse(`
Sep  8 02:14:30 web01 sshd[2862]: Failed password for root from 203.0.113.45 port 55931 ssh2
Sep  8 02:14:40 web01 sshd[2862]: message repeated 5 times: [ Failed password for root from 203.0.113.45 port 55931 ssh2]
Sep  8 02:14:41 web01 sshd[2862]: PAM 5 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.45  user=root
`);
  assert.deepEqual(events.map((e) => e.count), [1, 5]);
  assert.equal(stats.failures, 6);
});

test('takes the address from the last "from … port", so a username cannot spoof it', async () => {
  // The ": y" part would otherwise pass for the key suffix that ends real lines.
  const { events } = await parse(
    'Sep  8 02:14:30 web01 sshd[1]: Failed password for invalid user x from 10.0.1.23 port 22 ssh2: y from 203.0.113.45 port 5555 ssh2');
  assert.equal(events[0].ip, '203.0.113.45');
  assert.equal(events[0].user, 'x from 10.0.1.23 port 22 ssh2: y');
});

test('handles IPv6, sshd-session, key suffixes on failures and CRLF line endings', async () => {
  const { events } = await parse([
    'Sep  7 10:00:00 web01 sshd-session[12]: Accepted password for carol from 2001:db8:4a2::1c port 50000 ssh2\r',
    'Sep  7 10:00:05 web01 sshd[13]: Failed publickey for root from 2001:db8::7 port 4000 ssh2: RSA SHA256:abc\r',
  ].join('\n'));
  assert.deepEqual(events.map((e) => [e.type, e.user, e.ip, e.method]), [
    ['success', 'carol', '2001:db8:4a2::1c', 'password'],
    ['failure', 'root', '2001:db8::7', 'publickey'],
  ]);
});

test('reads RFC 3339 timestamps as the server clock, ignoring the offset', async () => {
  const { events } = await parse(
    '2026-09-09T03:39:12.123456+02:00 web01 sshd[5]: Accepted password for deploy from 198.51.100.23 port 33951 ssh2');
  assert.equal(events[0].time, Date.UTC(2026, 8, 9, 3, 39, 12));
});

test('moves to the next year when a syslog file crosses New Year', async () => {
  const { events } = await parse(`
Dec 31 23:59:58 web01 sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2
Jan  1 00:00:03 web01 sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2
`, { year: 2025 });
  assert.deepEqual(events.map((e) => e.time), [Date.UTC(2025, 11, 31, 23, 59, 58), Date.UTC(2026, 0, 1, 0, 0, 3)]);
});

test('without --year, a log starting in a later month than now is taken to be from last year', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.UTC(2027, 0, 5, 12) });
  const { events } = await parse(`
Dec 30 10:00:00 web01 sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2
Jan  4 10:00:00 web01 sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2
`, {});
  assert.deepEqual(events.map((e) => new Date(e.time).getUTCFullYear()), [2026, 2027]);
});

test('counts lines it cannot read, and ignores blank ones', async () => {
  const { events, stats } = await parse('not a log line\n\nSep 99 bad\nSep  7 10:00:00 web01 sshd[1]: Server listening on :: port 22.');
  assert.deepEqual(events, []);
  assert.equal(stats.lines, 3);
  assert.equal(stats.unrecognized, 2);
});
