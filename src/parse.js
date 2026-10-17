// Turns auth.log lines into the events the detectors need: failed and
// successful SSH logins, SSH logouts, sudo commands, and account changes (new
// users, users added to groups). Every other line is skipped on purpose. In
// particular the PAM "authentication failure" and "Invalid user" lines describe
// the same attempts as the "Failed …" lines, so counting them would double up.
//
// Times are the server's wall clock, stored as UTC milliseconds so that nothing
// is shifted by the timezone of the machine running the analyzer: 03:00 in the
// log is 03:00 here, which is what the unusual-hours rule needs.

/** @typedef {import('./types.js').AuthEvent} AuthEvent */
/** @typedef {import('./types.js').EventBase} EventBase */
/** @typedef {import('./types.js').ParseStats} ParseStats */

/** @type {Record<string, number>} */
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

// "Sep  7 03:39:12 web01 …": classic syslog, which has no year.
const SYSLOG_RE = /^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) (.*)$/;
// "2026-09-07T03:39:12.123456+00:00 web01 …": RFC 3339, used by newer Debian/Ubuntu.
const ISO_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})? (\S+) (.*)$/;
// "sshd[5452]: message" or "sudo: message".
const PROGRAM_RE = /^([^\s[:]+)(?:\[(\d+)\])?: (.*)$/;

// OpenSSH 9.8+ logs from sshd-session, and 10.0+ also from sshd-auth.
const SSHD_PROGRAMS = new Set(['sshd', 'sshd-session', 'sshd-auth']);
// rsyslog collapses identical consecutive lines; N counts the repeats after the first.
const REPEATED_RE = /^message repeated (\d+) times: \[ (.*)\]$/;
// The username is attacker-controlled and may itself contain "from 10.0.0.1 port 22",
// so it is matched greedily: the address is always the last "from … port …".
const FAILED_RE = /^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)(?: ssh2)?(?::.*?)?(?: \[preauth\])?$/;
const ACCEPTED_RE = /^Accepted (\S+) for (.*) from (\S+) port (\d+)(?: ssh2)?(?::.*)?$/;
// Logged by the same sshd process as the "Accepted" line, however the session ends.
const SESSION_CLOSED_RE = /^pam_unix\(sshd:session\): session closed for user (\S+)$/;

// A command sudo ran. Refusals ("3 incorrect password attempts ; TTY=…") put
// text before the first key, so they don't match.
const SUDO_RE = /^ *(\S+) : (?:TTY|PWD)=.*? ; COMMAND=(.*)$/;

// shadow-utils account tools. adduser and addgroup are wrappers around these.
const ACCOUNT_PROGRAMS = new Set(['useradd', 'usermod', 'gpasswd']);
const NEW_USER_RE = /^new user: name=([^,]+), UID=(\d+),/;
// From useradd -G and usermod -aG. The "shadow group" twin line is skipped.
const ADDED_TO_GROUP_RE = /^add '([^']+)' to group '([^']+)'$/;
// From gpasswd -a, which `adduser <user> <group>` uses.
const GPASSWD_ADDED_RE = /^user (\S+) added by \S+ to group (\S+)$/;

/**
 * Reads lines from any iterable or async iterable (an array, a readline
 * interface, …) and returns the events in file order plus counters.
 * `year` is the year of the first syslog line; by default it's the current
 * year, or last year if the log starts in a month that hasn't come yet.
 * @param {Iterable<string> | AsyncIterable<string>} lines
 * @param {{ year?: number }} [options]
 * @returns {Promise<{ events: AuthEvent[], stats: ParseStats }>}
 */
export async function parseLines(lines, { year } = {}) {
  /** @type {AuthEvent[]} */
  const events = [];
  /** @type {ParseStats} */
  const stats = { lines: 0, unrecognized: 0, failures: 0, successes: 0, first: null, last: null };
  const syslogTime = yearTracker(year);
  let lineNo = 0;

  for await (const raw of lines) {
    lineNo++;
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (line === '') continue;
    stats.lines++;

    /** @type {RegExpExecArray | null} */
    let m;
    /** @type {number} */
    let time;
    /** @type {string} */
    let host;
    /** @type {string} */
    let rest;
    if ((m = SYSLOG_RE.exec(line)) && m[1] in MONTHS) {
      time = syslogTime(MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]);
      [host, rest] = [m[6], m[7]];
    } else if ((m = ISO_RE.exec(line))) {
      time = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
      [host, rest] = [m[7], m[8]];
    } else {
      stats.unrecognized++;
      continue;
    }
    if (stats.first === null || time < stats.first) stats.first = time;
    if (stats.last === null || time > stats.last) stats.last = time;

    const program = PROGRAM_RE.exec(rest);
    if (!program) continue;
    const [, name, pid, msg] = program;
    /** @type {EventBase} */
    const base = { time, host, pid: pid === undefined ? null : Number(pid), line: lineNo };
    const event = SSHD_PROGRAMS.has(name) ? sshdEvent(msg, base)
      : name === 'sudo' ? sudoEvent(msg, base)
      : ACCOUNT_PROGRAMS.has(name) ? accountEvent(msg, { ...base, program: name })
      : null;
    if (!event) continue;
    if (event.type === 'failure') stats.failures += event.count;
    if (event.type === 'success') stats.successes++;
    events.push(event);
  }
  return { events, stats };
}

/**
 * @param {string} msg
 * @param {EventBase} base
 * @returns {AuthEvent | null}
 */
function sshdEvent(msg, base) {
  let count = 1;
  const repeated = REPEATED_RE.exec(msg);
  if (repeated) [count, msg] = [Number(repeated[1]), repeated[2]];

  let m;
  if ((m = FAILED_RE.exec(msg))) {
    return { type: 'failure', ...base, ip: m[4], user: m[3], invalidUser: Boolean(m[2]), method: m[1], count };
  }
  if (repeated) return null;
  if ((m = ACCEPTED_RE.exec(msg))) return { type: 'success', ...base, ip: m[3], user: m[2], method: m[1], count: 1 };
  if ((m = SESSION_CLOSED_RE.exec(msg))) return { type: 'logout', ...base, user: m[1] };
  return null;
}

/**
 * @param {string} msg
 * @param {EventBase} base
 * @returns {AuthEvent | null}
 */
function sudoEvent(msg, base) {
  const m = SUDO_RE.exec(msg);
  return m ? { type: 'sudo', ...base, user: m[1], command: m[2] } : null;
}

/**
 * @param {string} msg
 * @param {EventBase & { program: string }} base
 * @returns {AuthEvent | null}
 */
function accountEvent(msg, base) {
  let m;
  if ((m = NEW_USER_RE.exec(msg))) return { type: 'account', ...base, action: 'user-created', user: m[1], uid: Number(m[2]) };
  if ((m = ADDED_TO_GROUP_RE.exec(msg))) return { type: 'account', ...base, action: 'group-added', user: m[1], group: m[2] };
  if ((m = GPASSWD_ADDED_RE.exec(msg))) return { type: 'account', ...base, action: 'group-added', user: m[1], group: m[2] };
  return null;
}

// Syslog timestamps have no year, so track it: start from `year` (or a guess)
// and move to the next year whenever the month goes backwards (Dec → Jan).
/**
 * @param {number | undefined} year
 * @returns {(month: number, day: number, h: number, m: number, s: number) => number}
 */
function yearTracker(year) {
  /** @type {number | null} */
  let lastMonth = null;
  return (month, day, h, m, s) => {
    if (year === undefined) {
      const now = new Date();
      year = month > now.getMonth() ? now.getFullYear() - 1 : now.getFullYear();
    } else if (lastMonth !== null && month < lastMonth) {
      year++;
    }
    lastMonth = month;
    return Date.UTC(year, month, day, h, m, s);
  };
}
