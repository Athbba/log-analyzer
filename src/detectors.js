// The detection rules, run over the events from parse.js. Each rule produces
// findings; `analyze` then groups them by IP into incidents, so one attacker's
// brute force, break-in, night-time login and backdoor account read as one story.

const MINUTE = 60_000;

export const DEFAULTS = {
  threshold: 5, // failed logins from one IP that count as brute force…
  windowMs: 10 * MINUTE, // …within this sliding window (fail2ban's defaults)
  lookbackMs: 30 * MINUTE, // how far before a login to look for failures
  night: [1, 5], // unusual login hours [from, to): 01:00–04:59
  adminGroups: ['sudo', 'wheel', 'admin'], // Debian/Ubuntu, RHEL/Fedora/Arch, old Ubuntu
};

export const SEVERITIES = ['high', 'medium', 'low'];
const RULE_ORDER = ['brute-force', 'possible-breach', 'unusual-hour', 'account-change'];

// Commands whose sudo line identifies who made an account change.
const ACCOUNT_TOOLS = new Set(['useradd', 'adduser', 'usermod', 'gpasswd']);
// adduser prompts for a password and details, so allow for a slow typist.
const SUDO_MATCH_MS = MINUTE;

/** Runs every rule and returns incidents (one per IP), most severe first. */
export function analyze(events, options = {}) {
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

// Rule 1: `threshold` or more failures from one IP within `windowMs`. Every
// failure that falls inside such a window is "hot"; runs of hot failures no
// more than a window apart are merged into one finding per attack.
function detectBruteForce(failuresByIp, successesByIp, { threshold, windowMs }) {
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

// Rule 2: a successful login from an IP that failed within the previous
// `lookbackMs`. High when those failures amount to a brute force; low for the
// odd mistyped password.
function detectPossibleBreaches(failuresByIp, successes, bruteForceByIp, { threshold, lookbackMs }) {
  return successes.flatMap((login) => {
    const fails = failuresByIp.get(login.ip) ?? [];
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
    return [{
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
    }];
  });
}

// Rule 3: a successful login during the night window. Hours come straight from
// the log, i.e. the server's clock. A window like [22, 6] wraps past midnight.
function detectUnusualHours(successes, { night: [from, to] }) {
  const atNight = (h) => (from < to ? h >= from && h < to : h >= from || h < to);
  return successes
    .filter((login) => atNight(new Date(login.time).getUTCHours()))
    .map((login) => ({
      rule: 'unusual-hour',
      severity: 'low',
      ip: login.ip,
      time: login.time,
      user: login.user,
      method: login.method,
    }));
}

// Rule 4: a new user, or a user added to an admin group. The account tools
// don't log who ran them, so the IP is worked out: the sudo line that ran the
// tool names the user, and that user's SSH sessions open at the time give the
// IP. With no sudo line (a root shell), every open session is a candidate.
// High when a candidate IP had already broken in (a high-severity possible
// breach); otherwise medium for admin rights (or UID 0), low for a plain user.
function detectAccountChanges(events, breaches, { adminGroups }) {
  const sessions = sshSessions(events);
  const sudo = events.filter((e) => e.type === 'sudo');
  const breachesByIp = groupByIp(breaches.filter((b) => b.severity === 'high'));

  // One change per tool run: useradd -G logs the new user and each group separately.
  const changes = new Map();
  for (const e of events.filter((e) => e.type === 'account')) {
    const key = `${e.host} ${e.program} ${e.pid ?? e.time} ${e.user}`;
    if (!changes.has(key)) {
      changes.set(key, { host: e.host, time: e.time, line: e.line, user: e.user, created: false, uid: null, groups: [] });
    }
    const change = changes.get(key);
    if (e.action === 'user-created') [change.created, change.uid] = [true, e.uid];
    else if (!change.groups.includes(e.group)) change.groups.push(e.group);
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

    return [{
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
    }];
  });
}

function runsAccountToolOn(command, user) {
  const [program, ...args] = command.trim().split(/\s+/);
  return ACCOUNT_TOOLS.has(program.split('/').pop()) && args.includes(user);
}

// SSH sessions as login–logout intervals. A logout is matched to the login with
// the same sshd PID and user; a session with no logout is open to the end.
function sshSessions(events) {
  const sessions = [];
  const open = new Map();
  for (const e of events) {
    const key = `${e.host} ${e.pid} ${e.user}`;
    if (e.type === 'success') {
      const session = { host: e.host, ip: e.ip, user: e.user, start: e.time, end: Infinity };
      sessions.push(session);
      if (e.pid !== null) open.set(key, session);
    } else if (e.type === 'logout' && e.pid !== null && open.has(key)) {
      open.get(key).end = e.time;
      open.delete(key);
    }
  }
  return sessions;
}

function toIncidents(findings) {
  const rank = (severity) => SEVERITIES.indexOf(severity);
  return [...groupByIp(findings)]
    .map(([ip, list]) => {
      list.sort((a, b) => a.time - b.time || RULE_ORDER.indexOf(a.rule) - RULE_ORDER.indexOf(b.rule));
      const severity = SEVERITIES[Math.min(...list.map((f) => rank(f.severity)))];
      return { ip, severity, time: list[0].time, findings: list };
    })
    .sort((a, b) => rank(a.severity) - rank(b.severity) || a.time - b.time);
}

// Keeps each IP's items in the order given.
function groupByIp(items) {
  const byIp = new Map();
  for (const item of items) {
    if (!byIp.has(item.ip)) byIp.set(item.ip, []);
    byIp.get(item.ip).push(item);
  }
  return byIp;
}

// Attempts per username, most-tried first.
function tallyUsers(fails) {
  const counts = new Map();
  for (const f of fails) counts.set(f.user, (counts.get(f.user) ?? 0) + f.count);
  return [...counts]
    .map(([user, attempts]) => ({ user, attempts }))
    .sort((a, b) => b.attempts - a.attempts || a.user.localeCompare(b.user));
}

// Binary search: index of the first event at or after `time` in a sorted list.
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
