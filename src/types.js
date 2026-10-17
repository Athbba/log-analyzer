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

/**
 * Password spraying: many accounts, few guesses each, from one source.
 * @typedef {object} SprayOptions
 * @property {boolean} enabled
 * @property {number} minUsers  Distinct accounts that make a spray…
 * @property {number} windowMs  …within this window…
 * @property {number} maxAttemptsPerUser  …each guessed at most this many times.
 * @property {boolean} countInvalidUsers  Count usernames that don't exist (default: only real accounts).
 */

/**
 * Distributed brute force: one account, many sources.
 * @typedef {object} DistributedOptions
 * @property {boolean} enabled
 * @property {number} minSources  Distinct sources that make an attack…
 * @property {number} minAttempts  …with at least this many failures in total…
 * @property {number} windowMs  …within this window.
 * @property {boolean} countInvalidUsers  Also watch usernames that don't exist.
 * @property {string[]} ignoreUsers  Accounts not to watch (e.g. root, if it is under constant attack).
 */

/**
 * First login from a new source network for a user.
 * @typedef {object} NewSourceOptions
 * @property {boolean} enabled
 * @property {number} learningMs  From the first line, logins only build the baseline.
 * @property {number} prefixV4  Network size that counts as "the same place" for IPv4…
 * @property {number} prefixV6  …and for IPv6.
 * @property {number} rememberMs  How long a known network stays known without logins.
 * @property {number} sharedNetworkUsers  A network this many other users log in from is known for everyone (0 = off).
 */

/**
 * Log tampering: gaps, time going backwards, truncation, NUL bytes.
 * @typedef {object} TamperingOptions
 * @property {boolean} enabled
 * @property {number} maxGapMs  A longer silence is reported.
 * @property {number} maxBackwardsMs  Time going back further than this is reported…
 * @property {boolean} allowDstJumps  …except a jump of one hour, as at the end of DST.
 */

/**
 * Settings beyond the original five.
 * @typedef {object} ExtendedOptions
 * @property {string[]} trustedNetworks  CIDRs never counted by spray, distributed and new-source rules.
 * @property {number} ipv6Prefix  IPv6 attempts are counted per prefix of this length (128 = exact address).
 * @property {boolean} ignoreKeyLoginsAfterOthersFailures  A key login after a few failures for
 *   other usernames from the same IP (a shared office IP) is not a possible breach.
 * @property {SprayOptions} spray
 * @property {DistributedOptions} distributed
 * @property {NewSourceOptions} newSource
 * @property {TamperingOptions} tampering
 */

/** @typedef {Options & ExtendedOptions & { limits: Limits }} ResolvedOptions */

/**
 * What callers may pass: any subset, nested settings included.
 * @typedef {Partial<Options> & Partial<Omit<ExtendedOptions, 'spray' | 'distributed' | 'newSource' | 'tampering'>> & {
 *   limits?: Partial<Limits>, spray?: Partial<SprayOptions>, distributed?: Partial<DistributedOptions>,
 *   newSource?: Partial<NewSourceOptions>, tampering?: Partial<TamperingOptions>,
 * }} AnalyzerOptions
 */

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

/**
 * @typedef {object} PasswordSprayFinding
 * @property {'password-spray'} rule
 * @property {Severity} severity
 * @property {string} ip  The source (an IPv6 /64 when ipv6Prefix is 64).
 * @property {number} time
 * @property {number} until
 * @property {number} attempts
 * @property {number} userCount  Accounts tried no more than maxAttemptsPerUser times.
 * @property {UserTally[]} users
 * @property {{ time: number, user: string, method: string } | null} loggedIn
 */

/**
 * @typedef {object} DistributedBruteForceFinding
 * @property {'distributed-brute-force'} rule
 * @property {Severity} severity
 * @property {null} ip  No single source.
 * @property {string} user  The account under attack.
 * @property {number} time
 * @property {number} until
 * @property {number} attempts
 * @property {number} sourceCount
 * @property {{ ip: string, attempts: number }[]} sources  Most active first.
 * @property {{ time: number, ip: string, method: string } | null} loggedIn
 */

/**
 * @typedef {object} NewSourceFinding
 * @property {'new-source'} rule
 * @property {Severity} severity
 * @property {string} ip
 * @property {number} time
 * @property {string} user
 * @property {string} method
 * @property {string} network  The new network, e.g. 198.51.100.0/24.
 * @property {number} knownNetworks  How many networks this user had logged in from before.
 */

/**
 * @typedef {object} LogTamperingFinding
 * @property {'log-tampering'} rule
 * @property {Severity} severity
 * @property {null} ip
 * @property {'gap' | 'backwards' | 'truncated' | 'nul-bytes'} kind
 * @property {number} time  When it starts (the last line before a gap or jump).
 * @property {number} until  When it ends.
 * @property {number} line  The input line where it was noticed.
 * @property {string} detail  Plain-language description.
 */

/** @typedef {BruteForceFinding | PossibleBreachFinding | UnusualHourFinding | AccountChangeFinding
 *   | PasswordSprayFinding | DistributedBruteForceFinding | NewSourceFinding | LogTamperingFinding} Finding */

/**
 * Metadata for every recognized line, for rules that look at the log itself
 * rather than at authentication events (log tampering).
 * @typedef {{ time: number, line: number, offsetMinutes: number | null, hasNul: boolean }} LineInfo
 */

/**
 * Something the shell observed about the input itself (live mode).
 * @typedef {{ type: 'truncated', time: number, line: number, fromBytes: number, toBytes: number }} SourceSignal
 */

/**
 * Findings grouped by where they come from: one source IP (or IPv6 /64), or,
 * for findings with no single source, a subject such as "user deploy".
 * @typedef {object} Incident
 * @property {string | null} ip
 * @property {string | null} subject  Set when ip is null and the findings share a subject.
 * @property {Severity} severity  The most severe of its findings.
 * @property {number} time  Its earliest finding.
 * @property {Finding[]} findings  In time order.
 */

export {};
