import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyze } from '../src/detectors.js';
import { parseLines } from '../src/parse.js';

const at = (hms, pid = 100) => `Sep  7 ${hms} web01 sshd[${pid}]:`;
const fail = (hms, ip, user = 'root') => `${at(hms)} Failed password for ${user} from ${ip} port 40000 ssh2`;
const login = (hms, ip, user = 'alice', pid = 100) => `${at(hms, pid)} Accepted password for ${user} from ${ip} port 40000 ssh2`;
const logout = (hms, user, pid) => `${at(hms, pid)} pam_unix(sshd:session): session closed for user ${user}`;
const sudo = (hms, user, command) =>
  `Sep  7 ${hms} web01 sudo: ${user.padStart(8)} : TTY=pts/0 ; PWD=/home/${user} ; USER=root ; COMMAND=${command}`;
const useradd = (hms, user, { uid = 1200, groups = [], pid = 900 } = {}) => [
  `Sep  7 ${hms} web01 useradd[${pid}]: new user: name=${user}, UID=${uid}, GID=${uid}, home=/home/${user}, shell=/bin/bash`,
  ...groups.flatMap((g) => [
    `Sep  7 ${hms} web01 useradd[${pid}]: add '${user}' to group '${g}'`,
    `Sep  7 ${hms} web01 useradd[${pid}]: add '${user}' to shadow group '${g}'`,
  ]),
];
const usermod = (hms, user, group, pid = 901) => [
  `Sep  7 ${hms} web01 usermod[${pid}]: add '${user}' to group '${group}'`,
  `Sep  7 ${hms} web01 usermod[${pid}]: add '${user}' to shadow group '${group}'`,
];

// Five failures then a login as deploy: a high-severity possible breach whose
// session (sshd PID 200) stays open until it logs out.
const ATTACKER = '198.51.100.23';
const breakIn = [
  ...['00', '10', '20', '30', '40'].map((s) => fail(`03:00:${s}`, ATTACKER, 'deploy')),
  login('03:01:00', ATTACKER, 'deploy', 200),
];

async function findings(lines, options) {
  const { events } = await parseLines(lines, { year: 2026 });
  return analyze(events, options).flatMap((incident) => incident.findings);
}
const summarize = (list) => list.map((f) => `${f.rule} ${f.severity} ${f.ip}`);

// --- Brute force ---

test('brute force needs 5 failures from one IP', async () => {
  const four = ['10:00:00', '10:00:10', '10:00:20', '10:00:30'].map((t) => fail(t, '192.0.2.1'));
  assert.deepEqual(await findings(four), []);

  const [found] = await findings([...four, fail('10:00:40', '192.0.2.1')]);
  assert.equal(found.rule, 'brute-force');
  assert.equal(found.attempts, 5);
  assert.equal(found.time, Date.UTC(2026, 8, 7, 10, 0, 0));
  assert.equal(found.until, Date.UTC(2026, 8, 7, 10, 0, 40));
});

test('brute force needs the failures within the window, edges included', async () => {
  const spread = ['10:00', '10:03', '10:06', '10:09', '10:12'].map((t) => fail(`${t}:00`, '192.0.2.1'));
  assert.deepEqual(await findings(spread), [], '5 failures over 12 minutes');
  assert.equal((await findings(spread, { windowMs: 15 * 60_000 })).length, 1, 'same failures, 15 minute window');

  const exactly10m = ['10:00:00', '10:02:30', '10:05:00', '10:07:30', '10:10:00'].map((t) => fail(t, '192.0.2.1'));
  assert.equal((await findings(exactly10m)).length, 1);
});

test('brute force counts collapsed "message repeated" failures', async () => {
  const lines = [fail('10:00:00', '192.0.2.1'),
    `${at('10:00:12')} message repeated 4 times: [ Failed password for root from 192.0.2.1 port 40000 ssh2]`];
  assert.deepEqual(summarize(await findings(lines)), ['brute-force medium 192.0.2.1']);
});

test('separate bursts from one IP are separate findings; unrelated IPs never mix', async () => {
  const burst = (hh, ip) => ['00', '10', '20', '30', '40'].map((s) => fail(`${hh}:00:${s}`, ip));
  assert.equal((await findings([...burst('10', '192.0.2.1'), ...burst('11', '192.0.2.1')])).length, 2);

  const neighbours = ['00', '10', '20'].flatMap((s) => [fail(`10:00:${s}`, '203.0.113.44'), fail(`10:00:${s}`, '203.0.113.45')]);
  assert.deepEqual(await findings(neighbours), [], '3 + 3 failures from two IPs is not a brute force');
});

test('a brute force that is followed by a login is high severity', async () => {
  const lines = ['00', '10', '20', '30', '40'].map((s) => fail(`10:00:${s}`, '192.0.2.1', 'deploy'));
  const [bruteForce] = await findings([...lines, login('14:00:00', '192.0.2.1', 'deploy')]);
  assert.equal(bruteForce.severity, 'high');
  assert.deepEqual(bruteForce.loggedIn, { time: Date.UTC(2026, 8, 7, 14), user: 'deploy', method: 'password' });
});

// --- Possible breach ---

test('a login after one failure is a low-severity possible breach', async () => {
  const [found] = await findings([fail('09:00:00', '10.0.1.57', 'bob'), login('09:00:06', '10.0.1.57', 'bob')]);
  assert.equal(found.rule, 'possible-breach');
  assert.equal(found.severity, 'low');
  assert.equal(found.attempts, 1);
  assert.equal(found.sameUser, true);
});

test('a login after 5+ failures is a high-severity possible breach', async () => {
  const lines = ['00', '10', '20', '30', '40'].map((s) => fail(`09:00:${s}`, '192.0.2.1', 'deploy'));
  const list = await findings([...lines, login('09:01:00', '192.0.2.1', 'deploy')]);
  assert.deepEqual(summarize(list), ['brute-force high 192.0.2.1', 'possible-breach high 192.0.2.1']);
});

test('possible breach only looks back 30 minutes, at the same IP, before the login', async () => {
  assert.deepEqual(await findings([fail('09:00:00', '192.0.2.1'), login('09:31:00', '192.0.2.1')]), [], 'too long ago');
  assert.deepEqual(await findings([fail('09:00:00', '192.0.2.2'), login('09:00:30', '192.0.2.1')]), [], 'other IP');
  assert.deepEqual(await findings([login('09:00:00', '192.0.2.1'), fail('09:00:00', '192.0.2.1')]), [], 'failure logged after');
  assert.equal((await findings([fail('09:00:00', '192.0.2.1'), login('09:30:00', '192.0.2.1')])).length, 1, 'exactly 30m');
});

test('possible breach notes when the failures were for other usernames', async () => {
  const [found] = await findings([fail('09:00:00', '192.0.2.1', 'root'), login('09:00:30', '192.0.2.1', 'alice')]);
  assert.equal(found.sameUser, false);
  assert.deepEqual(found.users, [{ user: 'root', attempts: 1 }]);
});

// --- Unusual hours ---

test('unusual hour flags logins from 01:00 to 04:59, and ignores failures', async () => {
  const lines = ['00:59:59', '01:00:00', '04:59:59', '05:00:00', '05:30:00'].map((t) => login(t, '10.0.5.10', 'deploy'));
  lines.push(fail('03:00:00', '192.0.2.9'));
  const list = await findings(lines);
  assert.deepEqual(list.map((f) => [f.rule, new Date(f.time).toISOString().slice(11, 19)]),
    [['unusual-hour', '01:00:00'], ['unusual-hour', '04:59:59']]);
});

test('unusual hour windows can wrap past midnight', async () => {
  const lines = ['21:59:59', '22:00:00', '23:30:00', '05:59:59', '06:00:00'].map((t) => login(t, '10.0.1.23'));
  const list = await findings(lines, { night: [22, 6] });
  assert.deepEqual(list.map((f) => new Date(f.time).toISOString().slice(11, 19)), ['05:59:59', '22:00:00', '23:30:00']);
});

// --- Account changes ---

const accountChanges = async (lines, options) => (await findings(lines, options)).filter((f) => f.rule === 'account-change');

test('a new sudo user made from a session that broke in is high, and reported once', async () => {
  const list = await accountChanges([
    ...breakIn,
    sudo('03:02:00', 'deploy', '/usr/sbin/useradd -m -G sudo backdoor'),
    ...useradd('03:02:00', 'backdoor', { groups: ['sudo'] }),
  ]);
  assert.deepEqual(list, [{
    rule: 'account-change',
    severity: 'high',
    ip: ATTACKER,
    time: Date.UTC(2026, 8, 7, 3, 2),
    user: 'backdoor',
    created: true,
    uid: 1200,
    groups: ['sudo'],
    privilegedGroups: ['sudo'],
    by: 'deploy',
    sessionIps: [ATTACKER],
    afterBreach: { time: Date.UTC(2026, 8, 7, 3, 1), user: 'deploy', attempts: 5 },
  }]);
});

test('from a clean session: medium for admin rights, low for a plain user, nothing for other groups', async () => {
  const list = await accountChanges([
    login('11:00:00', '10.0.1.81', 'dave', 300),
    sudo('11:02:00', 'dave', '/usr/sbin/adduser erin'), ...useradd('11:02:01', 'erin'),
    sudo('11:03:00', 'dave', '/usr/sbin/usermod -aG sudo erin'), ...usermod('11:03:00', 'erin', 'sudo'),
    sudo('11:04:00', 'dave', '/usr/sbin/usermod -aG docker bob'), ...usermod('11:04:00', 'bob', 'docker', 902),
  ]);
  assert.deepEqual(list.map((f) => [f.user, f.created, f.severity, f.ip, f.by]), [
    ['erin', true, 'low', '10.0.1.81', 'dave'],
    ['erin', false, 'medium', '10.0.1.81', 'dave'],
  ]);
});

test('only the sudo user\'s sessions count, even while an attacker is logged in', async () => {
  const list = await accountChanges([
    ...breakIn,
    login('03:05:00', '10.0.1.81', 'dave', 300),
    sudo('03:06:00', 'dave', '/usr/sbin/usermod -aG sudo erin'), ...usermod('03:06:00', 'erin', 'sudo'),
  ]);
  assert.deepEqual(list.map((f) => [f.severity, f.ip, f.by, f.sessionIps]), [['medium', '10.0.1.81', 'dave', ['10.0.1.81']]]);
});

test('with no sudo record, any open session is a candidate, but not one that has logged out', async () => {
  const change = usermod('03:30:00', 'toor', 'sudo');
  const [open] = await accountChanges([...breakIn, ...change]);
  assert.deepEqual([open.severity, open.ip, open.by], ['high', ATTACKER, null]);

  const [closed] = await accountChanges([...breakIn, logout('03:20:00', 'deploy', 200), ...change]);
  assert.deepEqual([closed.severity, closed.ip, closed.sessionIps], ['medium', null, []]);
});

test('a sudo line only identifies who made a change to the same user, within a minute', async () => {
  const session = login('11:00:00', '10.0.1.81', 'dave', 300);
  const [late] = await accountChanges([session,
    sudo('11:00:10', 'dave', '/usr/sbin/usermod -aG sudo erin'), ...usermod('11:01:11', 'erin', 'sudo')]);
  const [otherUser] = await accountChanges([session,
    sudo('11:00:10', 'dave', '/usr/sbin/usermod -aG sudo frank'), ...usermod('11:00:10', 'erin', 'sudo')]);
  assert.deepEqual([late.by, otherUser.by], [null, null]);
});

test('a break-in that comes after the change does not escalate it', async () => {
  const [found] = await accountChanges([
    login('02:00:00', ATTACKER, 'deploy', 150),
    sudo('02:01:00', 'deploy', '/usr/sbin/usermod -aG sudo erin'), ...usermod('02:01:00', 'erin', 'sudo'),
    ...breakIn,
  ]);
  assert.deepEqual([found.severity, found.ip, found.afterBreach], ['medium', ATTACKER, null]);
});

test('a low-severity possible breach (a mistyped password) does not make a change high', async () => {
  const [found] = await accountChanges([
    fail('09:00:00', '10.0.1.57', 'bob'), login('09:00:06', '10.0.1.57', 'bob', 400),
    sudo('09:10:00', 'bob', '/usr/sbin/usermod -aG sudo carol'), ...usermod('09:10:00', 'carol', 'sudo'),
  ]);
  assert.deepEqual([found.severity, found.ip, found.afterBreach], ['medium', '10.0.1.57', null]);
});

test('UID 0 counts as admin rights, and the admin groups are configurable', async () => {
  const [rootTwin] = await accountChanges(useradd('12:00:00', 'toor', { uid: 0 }));
  assert.equal(rootTwin.severity, 'medium');

  const wheel = usermod('12:00:00', 'erin', 'wheel');
  assert.equal((await accountChanges(wheel)).length, 1);
  assert.equal((await accountChanges(wheel, { adminGroups: ['sudo'] })).length, 0);
});

// --- Grouping ---

test('findings are grouped by IP, most severe incident first', async () => {
  const { events } = await parseLines([
    login('02:00:00', '10.8.0.22', 'dave'),
    ...['00', '10', '20', '30', '40'].map((s) => fail(`03:00:${s}`, '198.51.100.23', 'deploy')),
    login('03:01:00', '198.51.100.23', 'deploy'),
  ], { year: 2026 });
  const incidents = analyze(events);
  assert.deepEqual(incidents.map((i) => [i.ip, i.severity, i.findings.map((f) => f.rule)]), [
    ['198.51.100.23', 'high', ['brute-force', 'possible-breach', 'unusual-hour']],
    ['10.8.0.22', 'low', ['unusual-hour']],
  ]);
});
