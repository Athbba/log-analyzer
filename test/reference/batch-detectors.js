// REFERENCE ORACLE. A frozen copy of the original batch implementation of the
// four rules (v0.1.0, src/detectors.js before the streaming engine). Tests
// compare the streaming engine against it; it is not used by the analyzer.
// Do not edit, except to keep it type-checking.

/** @typedef {import('../../src/types.js').AuthEvent} AuthEvent */
/** @typedef {import('../../src/types.js').FailureEvent} FailureEvent */
/** @typedef {import('../../src/types.js').SuccessEvent} SuccessEvent */
/** @typedef {import('../../src/types.js').SudoEvent} SudoEvent */
/** @typedef {import('../../src/types.js').AccountEvent} AccountEvent */
/** @typedef {import('../../src/types.js').Options} Options */
/** @typedef {import('../../src/types.js').Severity} Severity */
/** @typedef {import('../../src/types.js').UserTally} UserTally */
/** @typedef {import('../../src/types.js').Finding} Finding */
/** @typedef {import('../../src/types.js').BruteForceFinding} BruteForceFinding */
/** @typedef {import('../../src/types.js').PossibleBreachFinding} PossibleBreachFinding */
/** @typedef {import('../../src/types.js').UnusualHourFinding} UnusualHourFinding */
/** @typedef {import('../../src/types.js').AccountChangeFinding} AccountChangeFinding */
/** @typedef {import('../../src/types.js').Incident} Incident */

const MINUTE = 60_000;

/** @type {Options} */
export const DEFAULTS = {
  threshold: 5, // failed logins from one IP that count as brute force…
  windowMs: 10 * MINUTE, // …within this sliding window (fail2ban's defaults)
  lookbackMs: 30 * MINUTE, // how far before a login to look for failures
  night: [1, 5], // unusual login hours [from, to): 01:00–04:59
  adminGroups: ['sudo', 'wheel', 'admin'], // Debian/Ubuntu, RHEL/Fedora/Arch, old Ubuntu
};

/** @type {Severity[]} */
export const SEVERITIES = ['high', 'medium', 'low'];
const RULE_ORDER = ['brute-force', 'possible-breach', 'unusual-hour', 'account-change'];

// Commands whose sudo line identifies who made an account change.
const ACCOUNT_TOOLS = new Set(['useradd', 'adduser', 'usermod', 'gpasswd']);
// adduser prompts for a password and details, so allow for a slow typist.
const SUDO_MATCH_MS = MINUTE;

/**
 * Runs every rule and returns incidents (one per IP), most severe first.
 * @param {AuthEvent[]} events
 * @param {Partial<Options>} [options]
 * @returns {Incident[]}
 */
export function analyze(events, options = {}) {
  /** @type {Options} */
  const opts = { ...DEFAULTS, ...options };
  const sorted = [...events].sort((a, b) => a.time - b.time || a.line - b.line);
  const successes = sorted.filter((e) => e.type === 'success');
  const successesByIp = groupByIp(successes);
  const failuresByIp = groupByIp(sorted.filter((e) => e.type === 'failure'));

  const bruteForce = detectBruteForce(failuresByIp, successesByIp, opts);
  const breaches = detectPossibleBreaches(failuresByIp, successes, groupByIp(bruteForce), opts);
  return toIncidents([
    ...bruteForce,
    ...breaches,
    ...detectUnusualHours(successes, opts),
    ...detectAccountChanges(sorted, breaches, opts),
  ]);
}

/**
 * Rule 1: `threshold` or more failures from one IP within `windowMs`. Every
 * failure that falls inside such a window is "hot"; runs of hot failures no
 * more than a window apart are merged into one finding per attack.
 * @param {Map<string, FailureEvent[]>} failuresByIp
 * @param {Map<string, SuccessEvent[]>} successesByIp
 * @param {Options} options
 * @returns {BruteForceFinding[]}
 */
function detectBruteForce(failuresByIp, successesByIp, { threshold, windowMs }) {
  /** @typedef {{ rule: 'brute-force', ip: string, time: number, until: number, attempts: number, fails: FailureEvent[] }} Run */
  /** @type {Run[]} */
  const findings = [];
  for (const [ip, fails] of failuresByIp) {
    const hot = new Array(fails.length).fill(false);
    let start = 0;
    let inWindow = 0;
    let markedTo = 0;
    for (let end = 0; end < fails.length; end++) {
      inWindow += fails[end].count;
      while (fails[end].time - fails[start].time > windowMs) inWindow -= fails[start++].count;
      if (inWindow >= threshold) {
        hot.fill(true, Math.max(start, markedTo), end + 1);
        markedTo = end + 1;
      }
    }

    /** @type {Run | null} */
    let current = null;
    fails.forEach((f, i) => {
      if (!hot[i]) return;
      if (!current || f.time - current.until > windowMs) {
        current = { rule: 'brute-force', ip, time: f.time, until: f.time, attempts: 0, fails: [] };
        findings.push(current);
      }
      current.until = f.time;
      current.attempts += f.count;
      current.fails.push(f);
    });
  }

  return findings.map(({ fails, ...finding }) => {
    const login = successesByIp.get(finding.ip)?.find((s) => s.time >= finding.time);
    return {
      ...finding,
      severity: login ? 'high' : 'medium',
      users: tallyUsers(fails),
      invalidUsers: new Set(fails.filter((f) => f.invalidUser).map((f) => f.user)).size,
      loggedIn: login ? { time: login.time, user: login.user, method: login.method } : null,
    };
  });
}

/**
 * Rule 2: a successful login from an IP that failed within the previous
 * `lookbackMs`. High when those failures amount to a brute force; low for the
 * odd mistyped password.
 * @param {Map<string, FailureEvent[]>} failuresByIp
 * @param {SuccessEvent[]} successes
 * @param {Map<string, BruteForceFinding[]>} bruteForceByIp
 * @param {Options} options
 * @returns {PossibleBreachFinding[]}
 */
function detectPossibleBreaches(failuresByIp, successes, bruteForceByIp, { threshold, lookbackMs }) {
  return successes.flatMap((login) => {
    const fails = failuresByIp.get(login.ip) ?? [];
    /** @type {FailureEvent[]} */
    const before = [];
    for (let i = firstAtOrAfter(fails, login.time - lookbackMs); i < fails.length; i++) {
      const f = fails[i];
      if (f.time > login.time || (f.time === login.time && f.line > login.line)) break;
      before.push(f);
    }
    if (before.length === 0) return [];

    const attempts = before.reduce((sum, f) => sum + f.count, 0);
    const duringBruteForce = (bruteForceByIp.get(login.ip) ?? []).some((b) =>
      b.time <= login.time && b.until >= login.time - lookbackMs);
    const users = tallyUsers(before);
    /** @type {PossibleBreachFinding} */
    const finding = {
      rule: 'possible-breach',
      severity: attempts >= threshold || duringBruteForce ? 'high' : 'low',
      ip: login.ip,
      time: login.time,
      user: login.user,
      method: login.method,
      attempts,
      firstFailure: before[0].time,
      users,
      sameUser: users.some((u) => u.user === login.user),
    };
    return [finding];
  });
}

/**
 * Rule 3: a successful login during the night window. Hours come straight from
 * the log, i.e. the server's clock. A window like [22, 6] wraps past midnight.
 * @param {SuccessEvent[]} successes
 * @param {Options} options
 * @returns {UnusualHourFinding[]}
 */
function detectUnusualHours(successes, { night: [from, to] }) {
  /** @param {number} h */
  const atNight = (h) => (from < to ? h >= from && h < to : h >= from || h < to);
  return successes
    .filter((login) => atNight(new Date(login.time).getUTCHours()))
    .map((login) => ({
      rule: /** @type {const} */ ('unusual-hour'),
      severity: /** @type {const} */ ('low'),
      ip: login.ip,
      time: login.time,
      user: login.user,
      method: login.method,
    }));
}

/**
 * Rule 4: a new user, or a user added to an admin group. The account tools
 * don't log who ran them, so the IP is worked out: the sudo line that ran the
 * tool names the user, and that user's SSH sessions open at the time give the
 * IP. With no sudo line (a root shell), every open session is a candidate.
 * High when a candidate IP had already broken in (a high-severity possible
 * breach); otherwise medium for admin rights (or UID 0), low for a plain user.
 * @param {AuthEvent[]} events
 * @param {PossibleBreachFinding[]} breaches
 * @param {Options} options
 * @returns {AccountChangeFinding[]}
 */
function detectAccountChanges(events, breaches, { adminGroups }) {
  const sessions = sshSessions(events);
  const sudo = /** @type {SudoEvent[]} */ (events.filter((e) => e.type === 'sudo'));
  const breachesByIp = groupByIp(breaches.filter((b) => b.severity === 'high'));

  // One change per tool run: useradd -G logs the new user and each group separately.
  /** @typedef {{ host: string, time: number, line: number, user: string, created: boolean, uid: number | null, groups: string[] }} Change */
  /** @type {Map<string, Change>} */
  const changes = new Map();
  for (const e of /** @type {AccountEvent[]} */ (events.filter((e) => e.type === 'account'))) {
    const key = `${e.host} ${e.program} ${e.pid ?? e.time} ${e.user}`;
    let change = changes.get(key);
    if (!change) {
      change = { host: e.host, time: e.time, line: e.line, user: e.user, created: false, uid: null, groups: [] };
      changes.set(key, change);
    }
    if (e.action === 'user-created') [change.created, change.uid] = [true, e.uid ?? null];
    else if (e.group !== undefined && !change.groups.includes(e.group)) change.groups.push(e.group);
  }

  return [...changes.values()].flatMap((change) => {
    const privilegedGroups = change.groups.filter((g) => adminGroups.includes(g));
    const privileged = privilegedGroups.length > 0 || change.uid === 0;
    if (!change.created && !privileged) return [];

    const by = sudo.findLast((s) =>
      s.host === change.host && s.line < change.line && change.time - s.time <= SUDO_MATCH_MS &&
      runsAccountToolOn(s.command, change.user))?.user ?? null;
    const open = sessions.filter((s) =>
      s.host === change.host && s.start <= change.time && change.time <= s.end && (by === null || s.user === by));
    const sessionIps = [...new Set(open.map((s) => s.ip))];
    const breach = sessionIps
      .flatMap((ip) => breachesByIp.get(ip) ?? [])
      .filter((b) => b.time <= change.time)
      .sort((a, b) => b.time - a.time)[0];

    /** @type {AccountChangeFinding} */
    const finding = {
      rule: 'account-change',
      severity: breach ? 'high' : privileged ? 'medium' : 'low',
      ip: breach?.ip ?? (sessionIps.length === 1 ? sessionIps[0] : null),
      time: change.time,
      user: change.user,
      created: change.created,
      uid: change.uid,
      groups: change.groups,
      privilegedGroups,
      by,
      sessionIps,
      afterBreach: breach ? { time: breach.time, user: breach.user, attempts: breach.attempts } : null,
    };
    return [finding];
  });
}

/**
 * @param {string} command
 * @param {string} user
 */
function runsAccountToolOn(command, user) {
  const [program, ...args] = command.trim().split(/\s+/);
  return ACCOUNT_TOOLS.has(program.split('/').pop() ?? '') && args.includes(user);
}

/**
 * SSH sessions as login–logout intervals. A logout is matched to the login with
 * the same sshd PID and user; a session with no logout is open to the end.
 * @param {AuthEvent[]} events
 */
function sshSessions(events) {
  /** @typedef {{ host: string, ip: string, user: string, start: number, end: number }} Session */
  /** @type {Session[]} */
  const sessions = [];
  /** @type {Map<string, Session>} */
  const open = new Map();
  for (const e of events) {
    const key = `${e.host} ${e.pid} ${'user' in e ? e.user : ''}`;
    if (e.type === 'success') {
      const session = { host: e.host, ip: e.ip, user: e.user, start: e.time, end: Infinity };
      sessions.push(session);
      if (e.pid !== null) open.set(key, session);
    } else if (e.type === 'logout' && e.pid !== null) {
      const session = open.get(key);
      if (session) {
        session.end = e.time;
        open.delete(key);
      }
    }
  }
  return sessions;
}

/**
 * @param {Finding[]} findings
 * @returns {Incident[]}
 */
function toIncidents(findings) {
  /** @param {Severity} severity */
  const rank = (severity) => SEVERITIES.indexOf(severity);
  return [...groupByIp(findings)]
    .map(([ip, list]) => {
      list.sort((a, b) => a.time - b.time || RULE_ORDER.indexOf(a.rule) - RULE_ORDER.indexOf(b.rule));
      const severity = SEVERITIES[Math.min(...list.map((f) => rank(f.severity)))];
      return { ip, severity, time: list[0].time, findings: list };
    })
    .sort((a, b) => rank(a.severity) - rank(b.severity) || a.time - b.time);
}

/**
 * Keeps each IP's items in the order given.
 * @template {{ ip: string | null }} T
 * @param {T[]} items
 * @returns {Map<T['ip'], T[]>}
 */
function groupByIp(items) {
  /** @type {Map<T['ip'], T[]>} */
  const byIp = new Map();
  for (const item of items) {
    const list = byIp.get(item.ip);
    if (list) list.push(item);
    else byIp.set(item.ip, [item]);
  }
  return byIp;
}

/**
 * Attempts per username, most-tried first.
 * @param {FailureEvent[]} fails
 * @returns {UserTally[]}
 */
function tallyUsers(fails) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const f of fails) counts.set(f.user, (counts.get(f.user) ?? 0) + f.count);
  return [...counts]
    .map(([user, attempts]) => ({ user, attempts }))
    .sort((a, b) => b.attempts - a.attempts || a.user.localeCompare(b.user));
}

/**
 * Binary search: index of the first event at or after `time` in a sorted list.
 * @param {{ time: number }[]} events
 * @param {number} time
 */
function firstAtOrAfter(events, time) {
  let lo = 0;
  let hi = events.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (events[mid].time < time) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
