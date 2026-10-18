// Detector settings and state limits, with their defaults.

/** @typedef {import('../types.js').Options} Options */
/** @typedef {import('../types.js').Limits} Limits */
/** @typedef {import('../types.js').ResolvedOptions} ResolvedOptions */
/** @typedef {import('../types.js').AnalyzerOptions} AnalyzerOptions */
/** @typedef {import('../types.js').ExtendedOptions} ExtendedOptions */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** @type {Options} */
export const DEFAULTS = {
  threshold: 5, // failed logins from one IP that count as brute force…
  windowMs: 10 * MINUTE, // …within this sliding window (fail2ban's defaults)
  lookbackMs: 30 * MINUTE, // how far before a login to look for failures
  night: [1, 5], // unusual login hours [from, to): 01:00–04:59
  adminGroups: ['sudo', 'wheel', 'admin'], // Debian/Ubuntu, RHEL/Fedora/Arch, old Ubuntu
};

/**
 * Ceilings on detector state. Reaching one drops the oldest state, counts it
 * in the health report, and may cost a detection; none is reached by normal
 * traffic. Memory per tracked key is a few hundred bytes plus its entries.
 * @type {Limits}
 */
export const DEFAULT_LIMITS = {
  maxKeys: 100_000, // IPs (or users, sessions, changes) tracked by each rule
  maxEntriesPerKey: 5_000, // recent failures kept per IP
  maxUsersPerFinding: 1_000, // distinct usernames tallied per attack
  memoryMs: 7 * DAY, // how long an attacker IP, a breach, or a session without logout is remembered
};

/**
 * Settings for the rules added after v0.1.0. The defaults are argued for in
 * docs/detections.md and measured in docs/evaluation.md.
 * @type {ExtendedOptions}
 */
const EXTENDED_DEFAULTS = {
  trustedNetworks: [],
  ipv6Prefix: 64,
  ignoreKeyLoginsAfterOthersFailures: true,
  spray: { enabled: true, minUsers: 6, windowMs: HOUR, maxAttemptsPerUser: 2, countInvalidUsers: false },
  distributed: { enabled: true, minSources: 4, minAttempts: 8, windowMs: HOUR, countInvalidUsers: false, ignoreUsers: [] },
  newSource: { enabled: true, learningMs: DAY, prefixV4: 24, prefixV6: 64, rememberMs: 90 * DAY, sharedNetworkUsers: 2 },
  tampering: { enabled: true, maxGapMs: 2 * HOUR, maxBackwardsMs: 5 * MINUTE, allowDstJumps: true },
};

/** @type {Severity[]} */
export const SEVERITIES = ['high', 'medium', 'low'];
/** @typedef {import('../types.js').Severity} Severity */

/**
 * Fills in defaults, merging nested rule settings key by key. Explicit
 * `undefined` values fall back to the default too.
 * @param {AnalyzerOptions} [options]
 * @returns {ResolvedOptions}
 */
export function resolveOptions(options = {}) {
  const { limits = {}, spray = {}, distributed = {}, newSource = {}, tampering = {}, ...rest } = options;
  return {
    ...DEFAULTS,
    ...EXTENDED_DEFAULTS,
    ...definedOnly(rest),
    spray: { ...EXTENDED_DEFAULTS.spray, ...definedOnly(spray) },
    distributed: { ...EXTENDED_DEFAULTS.distributed, ...definedOnly(distributed) },
    newSource: { ...EXTENDED_DEFAULTS.newSource, ...definedOnly(newSource) },
    tampering: { ...EXTENDED_DEFAULTS.tampering, ...definedOnly(tampering) },
    limits: { ...DEFAULT_LIMITS, ...definedOnly(limits) },
  };
}

/**
 * @template {Record<string, unknown>} T
 * @param {T} object
 * @returns {Partial<T>}
 */
function definedOnly(object) {
  return /** @type {Partial<T>} */ (Object.fromEntries(Object.entries(object).filter(([, v]) => v !== undefined)));
}
