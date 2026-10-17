#!/usr/bin/env node
// Generates a realistic Linux SSH auth.log (Debian/Ubuntu rsyslog format) to test
// the analyzer against: four weekdays of ordinary activity on a small web server,
// with a few known attacks and edge cases mixed in. A fixed seed makes the output
// identical on every run, so the answer key printed at the end always holds.
//
// Usage: node scripts/generate-sample-log.js [output-path]   (default: samples/auth.log)
//
// External addresses all come from the RFC 5737 documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no real host is implicated.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';

const OUT_PATH = resolve(process.argv[2] ?? 'samples/auth.log');
const HOST = 'web01';
const YEAR = 2026;
const MONTH = 8; // September, 0-based
const DAYS = [7, 8, 9, 10]; // Mon Sep 7 – Thu Sep 10
const LOGIND_PID = 612;
const MAX_AUTH_TRIES = 6; // sshd default

const ATTACK_A_IP = '203.0.113.45';
const ATTACK_B_IP = '198.51.100.23';
const DECOY_IP = '192.0.2.77';

// --- Seeded randomness ------------------------------------------------------

/** @param {number} seed */
function mulberry32(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(20260907);
/** @param {number} min @param {number} max */
const int = (min, max) => min + Math.floor(rand() * (max - min + 1));
/** @template T @param {T[]} items @returns {T} */
const pick = (items) => items[Math.floor(rand() * items.length)];
/** @param {number} p */
const chance = (p) => rand() < p;
/** @template T @param {T[]} items @param {number} n @returns {T[]} */
const sample = (items, n) => {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy.slice(0, n);
};
const port = () => int(32768, 60999);

// --- Time -------------------------------------------------------------------

// Times are Unix seconds holding server-local wall-clock time. All Date math is
// done in UTC so the timezone of the machine running this script never leaks in.
/** @param {number} day @param {number} h @param {number} [m] @param {number} [s] */
const at = (day, h, m = 0, s = 0) => Date.UTC(YEAR, MONTH, day, h, m, s) / 1000;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** @param {number} n */
const pad2 = (n) => String(n).padStart(2, '0');
/** @param {number} t Unix seconds of server wall-clock time. */
function syslogTime(t) {
  const d = new Date(t * 1000);
  return `${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ` +
    `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
}

// --- Log buffer -------------------------------------------------------------

// Scenarios are generated one at a time, not in time order, then sorted. PIDs and
// logind session numbers are assigned while rendering in time order, so they
// climb through the file the way they do on a real host. `ctx` is shared by all
// lines of one process or session; `msg` may be a function of it.
/** @typedef {{ pid?: number, session?: number }} Ctx */
/** @typedef {{ t: number, seq: number, proc: string, ctx: Ctx | null, msg: string | ((ctx: Ctx) => string) }} Entry */
/** @type {Entry[]} */
const entries = [];
/** @param {number} t @param {string} proc @param {Ctx | null} ctx @param {Entry['msg']} msg */
const emit = (t, proc, ctx, msg) => entries.push({ t, seq: entries.length, proc, ctx, msg });

function render() {
  entries.sort((a, b) => a.t - b.t || a.seq - b.seq);
  let nextPid = 1187;
  let nextSession = 212;
  return entries.map(({ t, proc, ctx, msg }) => {
    let tag = proc;
    const c = ctx ?? {};
    if (proc === 'systemd-logind') {
      tag += `[${LOGIND_PID}]`;
      c.session ??= nextSession++;
    } else if (proc !== 'sudo') {
      tag += `[${(c.pid ??= (nextPid += int(3, 41)))}]`;
    }
    return `${syslogTime(t)} ${HOST} ${tag}: ${typeof msg === 'function' ? msg(c) : msg}`;
  });
}

// --- Actors -----------------------------------------------------------------

const B64 = [...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'];
const fingerprint = () => Array.from({ length: 43 }, () => pick(B64)).join('');
/** @typedef {{ uid: number, auth: string, key?: string, fp?: string }} LabUser */
/** @type {Record<string, LabUser>} */
const USERS = {
  alice: { uid: 1001, auth: 'publickey', key: 'ED25519', fp: fingerprint() },
  bob: { uid: 1002, auth: 'password' },
  carol: { uid: 1003, auth: 'publickey', key: 'RSA', fp: fingerprint() },
  dave: { uid: 1004, auth: 'publickey', key: 'ED25519', fp: fingerprint() },
  deploy: { uid: 1100, auth: 'publickey', key: 'ED25519', fp: fingerprint() },
};
/** @type {Record<string, string[]>} */
const SUDO = {
  alice: ['/usr/bin/systemctl reload nginx', '/usr/bin/tail -n 200 /var/log/nginx/error.log', '/usr/bin/journalctl -u webapp --since today'],
  bob: ['/usr/bin/apt update', '/usr/bin/docker ps', '/usr/bin/docker logs webapp --tail 50'],
  dave: ['/usr/bin/apt upgrade -y', '/usr/bin/systemctl status postgresql', '/usr/sbin/ufw status', '/usr/bin/du -sh /var/lib/postgresql'],
};
const PROBE_USERS = ['admin', 'test', 'user', 'ubuntu', 'oracle', 'postgres', 'git', 'ftpuser', 'pi', 'guest',
  'support', 'hadoop', 'jenkins', 'nagios', 'minecraft', 'steam', 'dev', 'www'];

/** @type {{ name: string, ip: string, t: number }[]} */
const typos = []; // normal logins preceded by a mistyped password, for the answer key

/** @param {number} t @param {string} name @param {string} tty @param {string} cmd @param {number} [secs] */
function sudoCmd(t, name, tty, cmd, secs = int(1, 20)) {
  emit(t, 'sudo', null, `${name.padStart(8)} : TTY=${tty} ; PWD=/home/${name} ; USER=root ; COMMAND=${cmd}`);
  emit(t, 'sudo', null, `pam_unix(sudo:session): session opened for user root(uid=0) by ${name}(uid=${USERS[name].uid})`);
  emit(t + secs, 'sudo', null, 'pam_unix(sudo:session): session closed for user root');
}

// A successful SSH login: an optional mistyped password on the same connection,
// the session itself with any sudo commands, then a clean logout.
/**
 * @param {string} name @param {string} ip @param {number} start @param {number} minutes
 * @param {{ method?: string, typo?: boolean, sudo?: string[] }} [options]
 */
function login(name, ip, start, minutes, { method = USERS[name].auth, typo = false, sudo = [] } = {}) {
  const u = USERS[name];
  /** @type {Ctx} */
  const c = {};
  const p = port();
  const end = start + minutes * 60;
  let t = start;
  if (typo) {
    typos.push({ name, ip, t });
    emit(t, 'sshd', c, `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=${ip}  user=${name}`);
    emit((t += int(1, 2)), 'sshd', c, `Failed password for ${name} from ${ip} port ${p} ssh2`);
    t += int(4, 9);
  }
  const how = method === 'publickey' ? `${u.key} SHA256:${u.fp}` : '';
  emit(t, 'sshd', c, `Accepted ${method} for ${name} from ${ip} port ${p} ssh2${how && `: ${how}`}`);
  emit(t, 'sshd', c, `pam_unix(sshd:session): session opened for user ${name}(uid=${u.uid}) by (uid=0)`);
  emit(t, 'systemd-logind', c, (s) => `New session ${s.session} of user ${name}.`);
  const tty = `pts/${int(0, 3)}`;
  for (const cmd of sudo) sudoCmd(int(t + 30, end - 30), name, tty, cmd);
  emit(end, 'sshd', c, `Received disconnect from ${ip} port ${p}:11: disconnected by user`);
  emit(end, 'sshd', c, `Disconnected from user ${name} ${ip} port ${p}`);
  emit(end, 'sshd', c, `pam_unix(sshd:session): session closed for user ${name}`);
  emit(end, 'systemd-logind', c, (s) => `Session ${s.session} logged out. Waiting for processes to exit.`);
  emit(end, 'systemd-logind', c, (s) => `Removed session ${s.session}.`);
}

// One pre-auth connection that fails `tries` password guesses and is dropped.
// Repeated guesses collapse into rsyslog's "message repeated N times" line, and
// PAM adds its own summary lines — both of which the analyzer must not
// double-count. Returns the time the connection ended.
/** @param {string} ip @param {string} user @param {number} t @param {number} [tries] */
function failedConn(ip, user, t, tries = 1) {
  /** @type {Ctx} */
  const c = {};
  const p = port();
  const valid = user === 'root' || user in USERS;
  const target = valid ? user : `invalid user ${user}`;
  const rhost = `logname= uid=0 euid=0 tty=ssh ruser= rhost=${ip}${valid ? `  user=${user}` : ''}`;
  const failed = `Failed password for ${target} from ${ip} port ${p} ssh2`;
  if (!valid) {
    emit(t, 'sshd', c, `Invalid user ${user} from ${ip} port ${p}`);
    emit(t, 'sshd', c, 'pam_unix(sshd:auth): check pass; user unknown');
  }
  emit(t, 'sshd', c, `pam_unix(sshd:auth): authentication failure; ${rhost}`);
  emit((t += int(2, 3)), 'sshd', c, failed);
  if (tries > 1) emit((t += (tries - 1) * int(2, 3)), 'sshd', c, `message repeated ${tries - 1} times: [ ${failed}]`);
  t += int(0, 2);
  const who = valid ? `authenticating user ${user}` : target;
  if (tries >= MAX_AUTH_TRIES) {
    emit(t, 'sshd', c, `error: maximum authentication attempts exceeded for ${target} from ${ip} port ${p} ssh2 [preauth]`);
    emit(t, 'sshd', c, `Disconnecting ${who} ${ip} port ${p}: Too many authentication failures [preauth]`);
  } else {
    emit(t, 'sshd', c, `Received disconnect from ${ip} port ${p}:11: Bye Bye [preauth]`);
    emit(t, 'sshd', c, `Disconnected from ${who} ${ip} port ${p} [preauth]`);
  }
  if (tries > 1) emit(t, 'sshd', c, `PAM ${tries - 1} more authentication failures; ${rhost}`);
  return t;
}

// Internet background noise that never gets as far as a password guess.
/** @param {string} ip @param {number} t */
function scannerProbe(ip, t) {
  /** @type {Ctx} */
  const c = {};
  const p = port();
  switch (int(1, 4)) {
    case 1: // hangs up before the SSH handshake
      emit(t, 'sshd', c, 'error: kex_exchange_identification: Connection closed by remote host');
      emit(t, 'sshd', c, `Connection closed by ${ip} port ${p}`);
      break;
    case 2: // old client or scanner library
      emit(t, 'sshd', c, `Unable to negotiate with ${ip} port ${p}: no matching key exchange method found. Their offer: diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 [preauth]`);
      break;
    case 3: // finishes the handshake, never authenticates
      emit(t, 'sshd', c, `Connection closed by ${ip} port ${p} [preauth]`);
      break;
    case 4: { // username probe without a password
      const user = pick(PROBE_USERS);
      emit(t, 'sshd', c, `Invalid user ${user} from ${ip} port ${p}`);
      emit(t + int(0, 1), 'sshd', c, `Connection closed by invalid user ${user} ${ip} port ${p} [preauth]`);
    }
  }
}

/** @param {number} t */
function cronJob(t) {
  /** @type {Ctx} */
  const c = {};
  emit(t, 'CRON', c, 'pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)');
  emit(t + int(0, 1), 'CRON', c, 'pam_unix(cron:session): session closed for user root');
}

// --- Normal activity --------------------------------------------------------

for (const day of DAYS) {
  for (let h = 0; h < 24; h++) cronJob(at(day, h, 17, 1));
  cronJob(at(day, 6, 25, 1));

  // alice: developer in the office, key auth
  login('alice', '10.0.1.23', at(day, 8, int(25, 55), int(0, 59)), int(150, 200), { sudo: sample(SUDO.alice, int(0, 2)) });
  login('alice', '10.0.1.23', at(day, 13, int(5, 40), int(0, 59)), int(180, 230), { sudo: sample(SUDO.alice, int(0, 1)) });

  // bob: office, still on password auth, sometimes fat-fingers it
  login('bob', '10.0.1.57', at(day, 9, int(0, 45), int(0, 59)), int(60, 140), { typo: chance(0.4) });
  if (chance(0.7)) {
    login('bob', '10.0.1.57', at(day, 14, int(0, 59), int(0, 59)), int(30, 120), { typo: chance(0.3), sudo: sample(SUDO.bob, int(0, 2)) });
  }

  // carol: remote, over the VPN (once from her home IPv6), sometimes works evenings
  const carolIp = day === 9 ? '2001:db8:4a2::1c' : '10.8.0.14';
  login('carol', carolIp, at(day, 10, int(0, 40), int(0, 59)), int(60, 120));
  if (chance(0.6)) login('carol', '10.8.0.14', at(day, 20, int(10, 59), int(0, 59)), int(40, 110));

  // dave: ops, in the office all day
  login('dave', '10.0.1.81', at(day, 9, int(10, 50), int(0, 59)), int(240, 300), { sudo: sample(SUDO.dave, int(1, 3)) });

  // deploy: CI runner ships releases during the day, and runs a nightly backup
  // at 05:30 — just outside a 01:00–04:59 "unusual hours" window.
  login('deploy', '10.0.5.10', at(day, 5, 30, int(2, 9)), 2, { sudo: ['/usr/local/bin/db-backup.sh'] });
  for (let n = int(2, 5); n > 0; n--) {
    login('deploy', '10.0.5.10', at(day, int(10, 17), int(0, 59), int(0, 59)), int(2, 4), { sudo: ['/usr/bin/systemctl restart webapp'] });
  }
}

// Internet background noise: a pool of scanner IPs, each of which makes at most
// two password guesses across the whole log, so none of them should be flagged.
/** @type {string[]} */
const scanners = [];
while (scanners.length < 60) {
  const ip = `${pick(['192.0.2', '198.51.100', '203.0.113'])}.${int(2, 254)}`;
  if (![ATTACK_A_IP, ATTACK_B_IP, DECOY_IP].includes(ip) && !scanners.includes(ip)) scanners.push(ip);
}
const guessesLeft = new Map(scanners.map((ip) => [ip, 2]));
for (const day of DAYS) {
  for (let n = int(30, 45); n > 0; n--) {
    const ip = pick(scanners);
    const t = at(day, 0) + int(0, 86399);
    const left = guessesLeft.get(ip) ?? 0;
    if (left > 0 && chance(0.4)) {
      failedConn(ip, chance(0.5) ? 'root' : pick(PROBE_USERS), t);
      guessesLeft.set(ip, left - 1);
    } else {
      scannerProbe(ip, t);
    }
  }
}

// --- Injected scenarios -----------------------------------------------------

/** @type {{ id: string, ip: string, when: string, text: string }[]} */
const key = [];
/** @param {string} id @param {string} ip @param {string} when @param {string} text */
const note = (id, ip, when, text) => key.push({ id, ip, when, text });
/** @param {number} t */
const clock = (t) => syslogTime(t).slice(7);

// A: loud dictionary attack against root and common service accounts, Tuesday
// 02:14. Never gets in.
{
  /** @type {[string, number][]} */
  const plan = [['root', 3], ['admin', 1], ['root', 6], ['test', 1], ['ubuntu', 1], ['oracle', 1], ['postgres', 1],
    ['root', 3], ['user', 1], ['git', 1], ['ftpuser', 1], ['pi', 1], ['guest', 1], ['admin', 3], ['support', 1],
    ['root', 6], ['hadoop', 1], ['jenkins', 1], ['test1', 1], ['administrator', 1]];
  const start = at(8, 2, 14, 7);
  let t = start;
  let guesses = 0;
  for (const [user, tries] of plan) {
    t = failedConn(ATTACK_A_IP, user, t, tries) + int(1, 6);
    guesses += tries;
  }
  note('A', ATTACK_A_IP, `${syslogTime(start)}–${clock(t)}`,
    `Brute force: ${guesses} failed passwords over ${plan.length} connections (root + invalid users). Never succeeds.`);
}

// B: slower attack aimed at the `deploy` account, Wednesday night. It guesses
// the password, logs in at an odd hour and creates a backdoor sudo user.
{
  const start = at(9, 3, 21, 38);
  const targets = ['root', 'root', ...Array(12).fill('deploy')];
  let t = start;
  for (const user of targets) t = failedConn(ATTACK_B_IP, user, t) + int(50, 95);
  login('deploy', ATTACK_B_IP, t, 11, { method: 'password' });
  sudoCmd(t + 38, 'deploy', 'pts/1', '/usr/bin/id');
  sudoCmd(t + 104, 'deploy', 'pts/1', '/usr/sbin/useradd -m -s /bin/bash -G sudo sysupdate');
  const useradd = {};
  emit(t + 104, 'useradd', useradd, 'new group: name=sysupdate, GID=1101');
  emit(t + 104, 'useradd', useradd, 'new user: name=sysupdate, UID=1101, GID=1101, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/1');
  emit(t + 104, 'useradd', useradd, "add 'sysupdate' to group 'sudo'");
  emit(t + 104, 'useradd', useradd, "add 'sysupdate' to shadow group 'sudo'");
  sudoCmd(t + 131, 'deploy', 'pts/1', '/usr/bin/passwd sysupdate', 15);
  emit(t + 139, 'passwd', {}, 'pam_unix(passwd:chauthtok): password changed for sysupdate');
  note('B', ATTACK_B_IP, `${syslogTime(start)}–${clock(t)}`,
    `Brute force: ${targets.length} failed passwords (2x root, 12x deploy), then "Accepted password for deploy" ` +
    `at ${clock(t)} (breach + off-hours). Attacker then adds sudo user "sysupdate".`);
}

// C: dave, the on-call admin, fixes the database over the VPN in the middle of
// the night. Off-hours by the rule, but legitimate.
{
  const t = at(10, 1, 52, 13);
  login('dave', '10.8.0.22', t, 24);
  sudoCmd(t + 170, 'dave', 'pts/0', '/usr/bin/journalctl -u postgresql -n 100');
  sudoCmd(t + 305, 'dave', 'pts/0', '/usr/bin/systemctl restart postgresql');
  note('C', '10.8.0.22', syslogTime(t), 'On-call login by dave over VPN (key auth). Off-hours, but benign.');
}

// D: a scanner that guesses root four times: one short of the threshold.
{
  const start = at(10, 14, 3, 51);
  let t = start;
  for (let i = 0; i < 4; i++) t = failedConn(DECOY_IP, 'root', t) + int(20, 40);
  note('D', DECOY_IP, `${syslogTime(start)}–${clock(t)}`, '4 failed passwords for root. One below the brute-force threshold.');
}

// G: dave onboards a new hire from the office: creates her account, gives her
// sudo, and adds bob to the docker group. The same kind of change attacker B
// made, but legitimate and from a clean session.
{
  const t = at(10, 11, 20, 5);
  login('dave', '10.0.1.81', t, 25);
  const start = t + 131;
  sudoCmd(start, 'dave', 'pts/2', '/usr/sbin/adduser erin', 42);
  const groupadd = {};
  emit(start + 1, 'groupadd', groupadd, 'group added to /etc/group: name=erin, GID=1005');
  emit(start + 1, 'groupadd', groupadd, 'group added to /etc/gshadow: name=erin');
  emit(start + 1, 'groupadd', groupadd, 'new group: name=erin, GID=1005');
  emit(start + 1, 'useradd', {}, 'new user: name=erin, UID=1005, GID=1005, home=/home/erin, shell=/bin/bash, from=/dev/pts/2');
  emit(start + 19, 'passwd', {}, 'pam_unix(passwd:chauthtok): password changed for erin');
  emit(start + 35, 'chfn', {}, "changed user 'erin' information");
  /** @type {[number, string, string][]} */
  const changes = [[97, 'erin', 'sudo'], [160, 'bob', 'docker']];
  for (const [offset, user, group] of changes) {
    sudoCmd(start + offset, 'dave', 'pts/2', `/usr/sbin/usermod -aG ${group} ${user}`, 1);
    const usermod = {};
    emit(start + offset, 'usermod', usermod, `add '${user}' to group '${group}'`);
    emit(start + offset, 'usermod', usermod, `add '${user}' to shadow group '${group}'`);
  }
  note('G', '10.0.1.81', syslogTime(start), 'dave creates user erin and adds her to sudo, and adds bob to docker. Legitimate admin work.');
}

note('E', '10.0.5.10', 'daily 05:30', 'Nightly CI backup login. Just outside a 01:00–04:59 window.');
note('F', '10.0.1.57', typos.map((x) => syslogTime(x.t)).join(', '),
  `bob mistypes his password once, then logs in (${typos.length}x). Normal user error.`);

// --- Output -----------------------------------------------------------------

const lines = render();
mkdirSync(dirname(OUT_PATH), { recursive: true });
writeFileSync(OUT_PATH, lines.join('\n') + '\n');

console.log(`Wrote ${lines.length} lines to ${relative(process.cwd(), OUT_PATH)}`);
console.log(`Span: ${syslogTime(entries[0].t)} to ${syslogTime(entries[entries.length - 1].t)} (${YEAR}, server-local time)\n`);
console.log('Answer key:');
for (const { id, ip, when, text } of key) console.log(`  ${id}  ${ip.padEnd(14)} ${when}\n     ${text}`);
console.log(`\n  Background: ${scanners.length} scanner IPs, each with at most 2 failed passwords in total.`);
