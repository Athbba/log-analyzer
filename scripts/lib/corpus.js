// A labelled corpus for measuring detection quality. Each dataset is three
// days of a small server's auth.log, generated from a seed, with:
//
// - background: users logging in from their usual places, typos, cron, and
//   internet scanners making one or two guesses each;
// - attacks with randomized size, some deliberately below the default
//   thresholds, so recall is measured rather than assumed;
// - benign lookalikes: office NAT typos, roaming users, a misconfigured
//   internal service, travelling users, maintenance gaps, clock steps and,
//   in the RFC 3339 datasets, the end of daylight saving time.
//
// Ground truth says what is malicious, not what a rule should fire on. Each
// malicious item names its primary rule (the one meant to catch it, for
// recall) and the other rules that are also right to fire on it (for
// precision). Anything else a rule reports is a false positive.
//
// External addresses use the RFC 5737 / 3849 documentation ranges.

/**
 * @typedef {object} Truth
 * @property {string} id
 * @property {string} kind  Scenario name.
 * @property {string} primary  The rule meant to catch it.
 * @property {string[]} accept  Rules that are also right to fire on it.
 * @property {string} key  What matching findings are about: an IP or /64, "user <name>", "<user> <ip>", or "log".
 * @property {number} from  Wall-clock ms.
 * @property {number} to
 * @property {Record<string, number>} params  Scenario size, for sensitivity tables.
 */

/**
 * @typedef {object} Dataset
 * @property {string} name
 * @property {'syslog' | 'rfc3339'} format
 * @property {number} year
 * @property {string[]} lines
 * @property {Truth[]} truth
 * @property {Benign[]} benign  Lookalikes present, so false positives can be traced to them.
 */

/**
 * @typedef {object} Benign
 * @property {string} kind
 * @property {string} key  As in Truth.
 * @property {number} from
 * @property {number} to
 */

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const START = Date.UTC(2026, 9, 23); // Fri 23 Oct 2026; EU DST ends Sun 25 Oct, 01:00 UTC
const DST_END = Date.UTC(2026, 9, 25, 1);
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const USERS = {
  alice: { home: '10.0.1.23', method: 'publickey' },
  bob: { home: '10.0.1.57', method: 'password' },
  carol: { home: '10.8.0.14', method: 'publickey' },
  dave: { home: '10.0.1.81', method: 'publickey' },
  deploy: { home: '10.0.5.10', method: 'publickey' },
  erin: { home: '10.0.1.90', method: 'password' },
};
/** Accounts that exist on the server besides the people (sshd says "Failed password for", not "invalid user"). */
const SYSTEM = ['root', 'backup', 'www-data', 'mail', 'news', 'proxy', 'list', 'irc', 'sync', 'games', 'nobody', 'sshd'];
/** Office staff who only ever log in through the office NAT. */
const STAFF = ['frank', 'grace', 'heidi', 'ivan'];
const VALID = new Set([...Object.keys(USERS), ...SYSTEM, ...STAFF]);
const PROBES = ['admin', 'test', 'user', 'ubuntu', 'oracle', 'postgres', 'git', 'ftpuser', 'pi', 'guest', 'support', 'jenkins'];

/** @param {number} seed */
function prng(seed) {
  let s = seed >>> 0;
  const next = () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    /** @param {number} a @param {number} b */
    int: (a, b) => a + Math.floor(next() * (b - a + 1)),
    /** @template T @param {T[]} items @returns {T} */
    pick: (items) => items[Math.floor(next() * items.length)],
    /** @param {number} p */
    chance: (p) => next() < p,
    /** @template T @param {T[]} items @param {number} n @returns {T[]} */
    sample: (items, n) => {
      const copy = [...items];
      for (let i = copy.length - 1; i > 0; i--) {
        const j = Math.floor(next() * (i + 1));
        [copy[i], copy[j]] = [copy[j], copy[i]];
      }
      return copy.slice(0, n);
    },
  };
}

/**
 * @param {number} seed
 * @returns {Dataset}
 */
export function generateDataset(seed) {
  const r = prng(seed * 7919 + 13);
  const format = seed % 2 === 0 ? 'rfc3339' : 'syslog';
  // RFC 3339 datasets run on a CEST/CET server clock; syslog ones on UTC.
  /** @param {number} instant */
  const offsetMin = (instant) => (format === 'rfc3339' ? (instant < DST_END ? 120 : 60) : 0);
  /** @param {number} instant */
  const wall = (instant) => instant + offsetMin(instant) * MIN;

  /** @type {{ at: number, proc: string, pid: number | null, msg: string }[]} */
  let entries = [];
  let nextPid = 1200;
  /** @param {number} at @param {string} proc @param {number | null} pid @param {string} msg */
  const emit = (at, proc, pid, msg) => entries.push({ at, proc, pid, msg });
  const port = () => r.int(32768, 60999);
  /** @type {Truth[]} */
  const truth = [];
  /** @type {Benign[]} */
  const benign = [];
  /** @param {string} kind @param {string} key @param {number} from @param {number} to */
  const lookalike = (kind, key, from, to) => benign.push({ kind, key, from: wall(from), to: wall(to) });

  /** @param {string} ip @param {string} user @param {number} at */
  const failure = (ip, user, at) => {
    const pid = nextPid++;
    const p = port();
    if (!VALID.has(user)) emit(at, 'sshd', pid, `Invalid user ${user} from ${ip} port ${p}`);
    emit(at + 2000, 'sshd', pid, `Failed password for ${VALID.has(user) ? '' : 'invalid user '}${user} from ${ip} port ${p} ssh2`);
    emit(at + 2500, 'sshd', pid, `Connection closed by ${VALID.has(user) ? 'authenticating user' : 'invalid user'} ${user} ${ip} port ${p} [preauth]`);
  };
  /** @param {string} ip @param {string} user @param {number} at @param {string} method @param {number} minutes */
  const session = (ip, user, at, method, minutes) => {
    const pid = nextPid++;
    emit(at, 'sshd', pid, `Accepted ${method} for ${user} from ${ip} port ${port()} ssh2`);
    emit(at, 'sshd', pid, `pam_unix(sshd:session): session opened for user ${user}(uid=1000) by (uid=0)`);
    emit(at + minutes * MIN, 'sshd', pid, `pam_unix(sshd:session): session closed for user ${user}`);
  };

  // --- Background -----------------------------------------------------------

  // cron writes to auth.log every hour, so silence means something.
  let cronDown = /** @type {[number, number] | null} */ (null);
  if (r.chance(0.25)) {
    // A planned maintenance window: the box is off for 2.5–4 hours.
    const from = START + r.int(1, 2) * DAY + r.int(1, 5) * HOUR;
    cronDown = [from, from + r.int(150, 240) * MIN];
    lookalike('maintenance downtime', 'log', from - HOUR, cronDown[1] + HOUR);
  }
  for (let h = 0; h < 72; h++) {
    const at = START + h * HOUR + 17 * MIN;
    if (cronDown && at >= cronDown[0] && at <= cronDown[1]) continue;
    const pid = nextPid++;
    emit(at, 'CRON', pid, 'pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)');
    emit(at + 1000, 'CRON', pid, 'pam_unix(cron:session): session closed for user root');
  }
  /** @param {number} at */
  const down = (at) => cronDown !== null && at >= cronDown[0] && at <= cronDown[1];

  for (let day = 0; day < 3; day++) {
    for (const [user, { home, method }] of Object.entries(USERS)) {
      for (let n = r.int(1, 3); n > 0; n--) {
        const at = START + day * DAY + r.int(8 * 60, 18 * 60) * MIN;
        if (down(at)) continue;
        if (method === 'password' && r.chance(0.3)) failure(home, user, at - 8000);
        session(home, user, at, method, r.int(10, 120));
      }
    }
    // Internet scanners: one or two guesses each.
    for (let n = r.int(15, 30); n > 0; n--) {
      const ip = `203.0.113.${r.int(100, 254)}`;
      const at = START + day * DAY + r.int(0, DAY / MIN - 1) * MIN;
      if (down(at)) continue;
      for (let k = r.int(1, 2); k > 0; k--) failure(ip, r.chance(0.3) ? 'root' : r.pick(PROBES), at + k * 4000);
    }
  }

  // --- Benign lookalikes ----------------------------------------------------

  if (r.chance(0.6)) {
    // Office NAT: several people mistype once, each logs in seconds later.
    const people = r.sample([...Object.keys(USERS), ...STAFF], r.int(4, 9));
    const morning = START + r.int(0, 2) * DAY + 8 * HOUR + r.int(0, 40) * MIN;
    let at = morning;
    for (const u of people) {
      at += r.int(2, 6) * MIN;
      failure('10.0.2.1', u, at);
      session('10.0.2.1', u, at + 6000, 'password', r.int(20, 90));
    }
    lookalike('office NAT typos', '10.0.2.1', morning, at + HOUR);
  }
  if (r.chance(0.5)) {
    // A roaming user fails once from three places, then gets in.
    const user = r.pick(['bob', 'erin']);
    const at = START + r.int(1, 2) * DAY + r.int(9, 16) * HOUR;
    ['10.8.0.31', '198.51.100.201', '10.0.1.57'].forEach((ip, i) => failure(ip, user, at + i * 12 * MIN));
    session('10.0.1.57', user, at + 40 * MIN, 'password', 30);
    lookalike('roaming user', `user ${user}`, at, at + 2 * HOUR);
    lookalike('roaming user', `${user} 10.0.1.57`, at, at + 2 * HOUR);
  }
  if (r.chance(0.3)) {
    // A misconfigured internal service: deploy keys expired on several runners.
    const runners = r.int(4, 8);
    const rounds = r.int(2, 4);
    const at = START + r.int(0, 2) * DAY + r.int(9, 15) * HOUR;
    for (let k = 0; k < rounds; k++) {
      for (let i = 0; i < runners; i++) failure(`10.0.5.${30 + i}`, 'deploy', at + k * 10 * MIN + i * 7000);
    }
    lookalike('misconfigured service', 'user deploy', at, at + rounds * 10 * MIN + HOUR);
  }
  if (r.chance(0.5)) {
    // A user travelling: a key login from a hotel network on day 2 or 3.
    const user = r.pick(['alice', 'dave', 'carol']);
    const ip = `198.51.100.${r.int(150, 199)}`;
    const at = START + r.int(1, 2) * DAY + r.int(9, 20) * HOUR;
    session(ip, user, at, 'publickey', 40);
    lookalike('travelling user', `${user} ${ip}`, at, at);
  }
  if (r.chance(0.4)) {
    // NTP steps the clock back a few seconds: lines arrive slightly out of order.
    const at = START + r.int(0, 2) * DAY + r.int(1, 23) * HOUR;
    emit(at, 'CRON', nextPid++, 'pam_unix(cron:session): session closed for user root');
    emit(at - 3000, 'CRON', nextPid++, 'pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)');
    lookalike('NTP clock step', 'log', at - HOUR, at + HOUR);
  }
  if (format === 'rfc3339') lookalike('end of DST', 'log', DST_END - 2 * HOUR, DST_END + 2 * HOUR);

  // --- Attacks --------------------------------------------------------------

  /** @param {number} day */
  const attackStart = (day) => START + day * DAY + r.int(0, 22) * HOUR + r.int(0, 59) * MIN;
  let attackerNo = 0;
  const attacker = () => `198.51.100.${10 + attackerNo++ * 3 + r.int(0, 2)}`;

  for (let n = r.int(0, 2); n > 0; n--) {
    // Password spraying: a few tries at each of many real accounts.
    const ip = attacker();
    const accounts = r.sample([...SYSTEM, ...Object.keys(USERS)], r.int(3, 14));
    const tries = r.int(1, 2);
    const gap = r.int(1, 8) * MIN;
    const from = attackStart(r.int(1, 2));
    let at = from;
    for (let t = 0; t < tries; t++) for (const u of accounts) failure(ip, u, (at += gap));
    truth.push({ id: `spray-${ip}`, kind: 'password spray', primary: 'password-spray', accept: ['brute-force'], key: ip, from: wall(from), to: wall(at), params: { accounts: accounts.length, tries, gapMinutes: gap / MIN } });
  }
  for (let n = r.int(0, 2); n > 0; n--) {
    // Distributed brute force: one account, a handful of sources.
    const user = r.pick(['deploy', 'bob', 'erin', 'backup']);
    const sources = r.int(2, 9);
    const perSource = r.int(1, 3);
    const from = attackStart(r.int(1, 2));
    const spread = r.int(15, 60) * MIN;
    let last = from;
    for (let s = 0; s < sources; s++) {
      for (let k = 0; k < perSource; k++) {
        const at = from + Math.floor(r.next() * spread);
        failure(`192.0.2.${20 + s * 7 + n}`, user, at);
        last = Math.max(last, at);
      }
    }
    truth.push({ id: `distributed-${user}-${n}`, kind: 'distributed brute force', primary: 'distributed-brute-force', accept: ['brute-force'], key: `user ${user}`, from: wall(from), to: wall(last), params: { sources, attempts: sources * perSource } });
  }
  if (r.chance(0.7)) {
    // A dictionary attack from one source, from timid to loud. Some datasets
    // use an IPv6 /64, a new address for every guess.
    const v6 = r.chance(0.3);
    const ip = v6 ? '2001:db8:bad:1::' : attacker();
    const attempts = r.int(3, 40);
    const from = attackStart(r.int(0, 2));
    let at = from;
    for (let k = 0; k < attempts; k++) failure(v6 ? `${ip}${(k + 1).toString(16)}` : ip, r.chance(0.5) ? 'root' : r.pick(PROBES), (at += r.int(5, 40) * 1000));
    truth.push({ id: `bruteforce-${ip}`, kind: v6 ? 'brute force (IPv6 rotating)' : 'brute force', primary: 'brute-force', accept: ['password-spray', 'distributed-brute-force'], key: v6 ? `${ip}/64` : ip, from: wall(from), to: wall(at), params: { attempts } });
  }
  if (r.chance(0.6)) {
    // Stolen credentials: a clean login, from the attacker's own network.
    const user = r.pick(['bob', 'erin', 'deploy']);
    const ip = `198.51.100.${r.int(60, 90)}`;
    const at = attackStart(r.int(1, 2));
    session(ip, user, at, USERS[/** @type {keyof typeof USERS} */ (user)].method === 'password' ? 'password' : 'publickey', 30);
    truth.push({ id: `stolen-${user}`, kind: 'stolen credentials', primary: 'new-source', accept: ['unusual-hour'], key: `${user} ${ip}`, from: wall(at), to: wall(at), params: {} });
  }

  // Tampering happens last, to the log as written.
  if (r.chance(0.35)) {
    // Lines wiped from the log, leaving a hole of one to six hours.
    const hours = r.int(60, 360);
    const from = START + r.int(1, 2) * DAY + r.int(0, 12) * HOUR + 30 * MIN;
    entries = entries.filter((e) => e.at < from || e.at > from + hours * MIN);
    truth.push({ id: 'wipe', kind: 'lines wiped', primary: 'log-tampering', accept: [], key: 'log', from: wall(from - HOUR), to: wall(from + hours * MIN + HOUR), params: { gapMinutes: hours } });
  } else if (r.chance(0.3)) {
    // Old lines spliced in later: timestamps jump back by hours.
    const at = START + 2 * DAY + r.int(1, 10) * HOUR;
    const back = r.int(3, 10) * HOUR;
    // Copied in their original order, as a block of real-looking lines.
    const copied = entries.filter((e) => e.at >= at - back && e.proc === 'sshd').sort((a, b) => a.at - b.at).slice(0, 8);
    if (copied.length > 0) {
      entries.push(...copied.map((e, i) => ({ ...e, at: at + i, spliced: e.at })));
      truth.push({ id: 'splice', kind: 'lines spliced in', primary: 'log-tampering', accept: [], key: 'log', from: wall(at - HOUR), to: wall(at + HOUR), params: { backHours: back / HOUR } });
    }
  }

  // --- Render ---------------------------------------------------------------

  entries.sort((a, b) => a.at - b.at);
  const pad = (/** @type {number} */ n, w = 2) => String(n).padStart(w, '0');
  const lines = entries.map((e) => {
    const shown = /** @type {{ spliced?: number }} */ (e).spliced ?? e.at;
    const d = new Date(wall(shown));
    const tag = e.pid === null ? e.proc : `${e.proc}[${e.pid}]`;
    const stamp = format === 'syslog'
      ? `${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
      : `${d.toISOString().slice(0, 19)}.${pad(d.getUTCMilliseconds(), 3)}000+${pad(offsetMin(shown) / 60)}:00`;
    return `${stamp} web01 ${tag}: ${e.msg}`;
  });
  return { name: `synthetic-${String(seed).padStart(2, '0')}`, format, year: 2026, lines, truth, benign };
}

/**
 * @param {number} count
 * @returns {Dataset[]}
 */
export function generateCorpus(count) {
  return Array.from({ length: count }, (_, i) => generateDataset(i + 1));
}
