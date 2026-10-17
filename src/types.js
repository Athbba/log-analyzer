// Shared JSDoc types. This module has no runtime code; `export {}` makes it a
// module so other files can `import('./types.js').Name` the definitions.
//
// Times are the server's wall clock stored as UTC milliseconds (see parse.js).

/**
 * Fields every parsed event has.
 * @typedef {object} EventBase
 * @property {number} time  Server wall-clock time, as UTC milliseconds.
 * @property {string} host  Host name from the syslog line.
 * @property {number | null} pid  Process ID, when the line has one.
 * @property {number} line  1-based line number in the input.
 */

/**
 * A failed SSH authentication ("Failed password for …"). `count` is more than
 * one for rsyslog's "message repeated N times" lines.
 * @typedef {EventBase & {
 *   type: 'failure', ip: string, user: string, invalidUser: boolean, method: string, count: number,
 * }} FailureEvent
 */

/**
 * A successful SSH login ("Accepted publickey for …").
 * @typedef {EventBase & { type: 'success', ip: string, user: string, method: string, count: 1 }} SuccessEvent
 */

/**
 * The end of an SSH session, logged by the same sshd process as its login.
 * @typedef {EventBase & { type: 'logout', user: string }} LogoutEvent
 */

/**
 * A command run through sudo.
 * @typedef {EventBase & { type: 'sudo', user: string, command: string }} SudoEvent
 */

/**
 * A line from useradd, usermod or gpasswd.
 * @typedef {EventBase & {
 *   type: 'account', program: string,
 *   action: 'user-created' | 'group-added', user: string, uid?: number, group?: string,
 * }} AccountEvent
 */

/** @typedef {FailureEvent | SuccessEvent | LogoutEvent | SudoEvent | AccountEvent} AuthEvent */

/**
 * Counters from parsing.
 * @typedef {object} ParseStats
 * @property {number} lines  Non-blank lines read.
 * @property {number} unrecognized  Lines in no recognized syslog format.
 * @property {number} failures  Failed logins, counting "message repeated" lines as N.
 * @property {number} successes  Successful logins.
 * @property {number | null} first  Earliest time seen.
 * @property {number | null} last  Latest time seen.
 */

/** @typedef {'high' | 'medium' | 'low'} Severity */

/**
 * Detector settings. All durations are milliseconds.
 * @typedef {object} Options
 * @property {number} threshold  Failed logins from one IP that count as brute force…
 * @property {number} windowMs  …within this sliding window.
 * @property {number} lookbackMs  How far before a login to look for failures.
 * @property {[number, number]} night  Unusual login hours [from, to), on a 24h clock.
 * @property {string[]} adminGroups  Groups that grant admin rights.
 */

/**
 * Ceilings on detector state (see core/options.js).
 * @typedef {object} Limits
 * @property {number} maxKeys  IPs, users, sessions or changes tracked by each rule.
 * @property {number} maxEntriesPerKey  Recent failures kept per IP.
 * @property {number} maxUsersPerFinding  Distinct usernames tallied per attack.
 * @property {number} memoryMs  How long attacker IPs, breaches and unclosed sessions are remembered.
 */

/** @typedef {Options & { limits: Limits }} ResolvedOptions */

/** @typedef {{ user: string, attempts: number }} UserTally */

/**
 * @typedef {object} BruteForceFinding
 * @property {'brute-force'} rule
 * @property {Severity} severity
 * @property {string} ip
 * @property {number} time  First failure of the attack.
 * @property {number} until  Last failure of the attack.
 * @property {number} attempts
 * @property {UserTally[]} users  Attempts per username, most-tried first.
 * @property {number} invalidUsers  How many of the usernames don't exist.
 * @property {{ time: number, user: string, method: string } | null} loggedIn  The IP's next login, if any.
 */

/**
 * @typedef {object} PossibleBreachFinding
 * @property {'possible-breach'} rule
 * @property {Severity} severity
 * @property {string} ip
 * @property {number} time  The login.
 * @property {string} user
 * @property {string} method
 * @property {number} attempts  Failed logins in the lookback before it.
 * @property {number} firstFailure
 * @property {UserTally[]} users
 * @property {boolean} sameUser  Whether any failure was for the user who logged in.
 */

/**
 * @typedef {object} UnusualHourFinding
 * @property {'unusual-hour'} rule
 * @property {'low'} severity
 * @property {string} ip
 * @property {number} time
 * @property {string} user
 * @property {string} method
 */

/**
 * @typedef {object} AccountChangeFinding
 * @property {'account-change'} rule
 * @property {Severity} severity
 * @property {string | null} ip  The breached IP, or the only session IP, or null.
 * @property {number} time
 * @property {string} user  The account that was created or changed.
 * @property {boolean} created
 * @property {number | null} uid
 * @property {string[]} groups
 * @property {string[]} privilegedGroups
 * @property {string | null} by  The sudo user who ran the tool, if known.
 * @property {string[]} sessionIps  IPs of that user's SSH sessions open at the time.
 * @property {{ time: number, user: string, attempts: number } | null} afterBreach
 */

/** @typedef {BruteForceFinding | PossibleBreachFinding | UnusualHourFinding | AccountChangeFinding} Finding */

/**
 * Findings grouped by source IP.
 * @typedef {object} Incident
 * @property {string | null} ip
 * @property {Severity} severity  The most severe of its findings.
 * @property {number} time  Its earliest finding.
 * @property {Finding[]} findings  In time order.
 */

export {};
