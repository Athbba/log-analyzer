// Detector settings and state limits, with their defaults.

/** @typedef {import('../types.js').Options} Options */
/** @typedef {import('../types.js').Limits} Limits */
/** @typedef {import('../types.js').ResolvedOptions} ResolvedOptions */

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

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

/** @type {Severity[]} */
export const SEVERITIES = ['high', 'medium', 'low'];
/** @typedef {import('../types.js').Severity} Severity */

/**
 * Fills in defaults. Explicit `undefined` values fall back to the default too.
 * @param {Partial<Options> & { limits?: Partial<Limits> }} [options]
 * @returns {ResolvedOptions}
 */
export function resolveOptions(options = {}) {
  const { limits = {}, ...rest } = options;
  return {
    ...DEFAULTS,
    ...definedOnly(rest),
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
