// The config file: one JSON object, every key optional, validated strictly so
// a typo ("treshold") is an error instead of a silently ignored setting.
// Durations are strings with a unit ("90s", "10m", "1h", "7d") so seconds and
// milliseconds can't be confused. Keys starting with "$" (such as "$schema"
// or "$comment") are ignored.
//
// parseConfig maps the file's shape onto the engine's options; toConfig does
// the reverse, for `--print-config`.

import { parseCidr } from './net.js';

/** @typedef {import('../types.js').AnalyzerOptions} AnalyzerOptions */
/** @typedef {import('../types.js').ResolvedOptions} ResolvedOptions */

const UNITS = /** @type {Record<string, number>} */ ({ s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 });

/**
 * "90s", "10m", "1h", "7d" → milliseconds, or null.
 * @param {unknown} text
 */
export function parseDuration(text) {
  if (typeof text !== 'string') return null;
  const m = /^(\d{1,9})(s|m|h|d)$/.exec(text);
  return m && Number(m[1]) > 0 ? Number(m[1]) * UNITS[m[2]] : null;
}

/**
 * The shortest exact form of a duration: 600000 → "10m".
 * @param {number} ms
 */
export function formatDuration(ms) {
  for (const unit of ['d', 'h', 'm']) if (ms % UNITS[unit] === 0) return `${ms / UNITS[unit]}${unit}`;
  return `${Math.round(ms / 1000)}s`;
}

/**
 * "1-5" → [1, 5]; the end hour is excluded and may be 24.
 * @param {unknown} text
 * @returns {[number, number] | null}
 */
export function parseHours(text) {
  const m = typeof text === 'string' ? /^(\d{1,2})-(\d{1,2})$/.exec(text) : null;
  if (!m) return null;
  const [from, to] = [Number(m[1]), Number(m[2])];
  return from <= 23 && to <= 24 && from !== to ? [from, to] : null;
}

/**
 * @typedef {(value: unknown) => { ok: true, value: unknown } | { ok: false, expected: string }} Check
 */

/** @param {number} min @param {number} [max] @returns {Check} */
const int = (min, max = Number.MAX_SAFE_INTEGER) => (v) =>
  Number.isInteger(v) && /** @type {number} */ (v) >= min && /** @type {number} */ (v) <= max
    ? { ok: true, value: v }
    : { ok: false, expected: `a whole number from ${min}${max === Number.MAX_SAFE_INTEGER ? ' up' : ` to ${max}`}` };
/** @type {Check} */
const bool = (v) => (typeof v === 'boolean' ? { ok: true, value: v } : { ok: false, expected: 'true or false' });
/** @type {Check} */
const duration = (v) => {
  const ms = parseDuration(v);
  return ms === null ? { ok: false, expected: 'a duration like "90s", "10m", "1h" or "7d"' } : { ok: true, value: ms };
};
/** @type {Check} */
const hours = (v) => {
  const range = parseHours(v);
  return range ? { ok: true, value: range } : { ok: false, expected: 'two different hours like "1-5" or "22-6"' };
};
/** @param {RegExp} pattern @param {string} what @returns {Check} */
const strings = (pattern, what) => (v) =>
  Array.isArray(v) && v.every((s) => typeof s === 'string' && pattern.test(s))
    ? { ok: true, value: [...v] }
    : { ok: false, expected: `a list of ${what}` };
/** @type {Check} */
const cidrs = (v) =>
  Array.isArray(v) && v.every((s) => typeof s === 'string' && parseCidr(s) !== null)
    ? { ok: true, value: [...v] }
    : { ok: false, expected: 'a list of networks like "10.0.0.0/8" or "2001:db8::/32"' };

/**
 * For each config key: how to check it, and where it goes in the options.
 * @type {Record<string, Record<string, [Check, string]> | [Check, string]>}
 */
const SPEC = {
  bruteForce: {
    threshold: [int(1), 'threshold'],
    window: [duration, 'windowMs'],
    ipv6Prefix: [int(1, 128), 'ipv6Prefix'],
  },
  possibleBreach: {
    lookback: [duration, 'lookbackMs'],
    ignoreKeyLoginsAfterOthersFailures: [bool, 'ignoreKeyLoginsAfterOthersFailures'],
  },
  unusualHour: { night: [hours, 'night'] },
  accountChange: { adminGroups: [strings(/^[\w.-]+$/, 'group names'), 'adminGroups'] },
  passwordSpray: {
    enabled: [bool, 'spray.enabled'],
    minUsers: [int(2), 'spray.minUsers'],
    window: [duration, 'spray.windowMs'],
    maxAttemptsPerUser: [int(1), 'spray.maxAttemptsPerUser'],
    countInvalidUsers: [bool, 'spray.countInvalidUsers'],
  },
  distributedBruteForce: {
    enabled: [bool, 'distributed.enabled'],
    minSources: [int(2), 'distributed.minSources'],
    minAttempts: [int(2), 'distributed.minAttempts'],
    window: [duration, 'distributed.windowMs'],
    countInvalidUsers: [bool, 'distributed.countInvalidUsers'],
    ignoreUsers: [strings(/^\S+$/, 'usernames'), 'distributed.ignoreUsers'],
  },
  newSource: {
    enabled: [bool, 'newSource.enabled'],
    learning: [duration, 'newSource.learningMs'],
    prefixV4: [int(1, 32), 'newSource.prefixV4'],
    prefixV6: [int(1, 128), 'newSource.prefixV6'],
    remember: [duration, 'newSource.rememberMs'],
    sharedNetworkUsers: [int(0), 'newSource.sharedNetworkUsers'],
  },
  logTampering: {
    enabled: [bool, 'tampering.enabled'],
    maxGap: [duration, 'tampering.maxGapMs'],
    maxBackwards: [duration, 'tampering.maxBackwardsMs'],
    allowDstJumps: [bool, 'tampering.allowDstJumps'],
  },
  trustedNetworks: [cidrs, 'trustedNetworks'],
  limits: {
    maxKeys: [int(1), 'limits.maxKeys'],
    maxEntriesPerKey: [int(1), 'limits.maxEntriesPerKey'],
    maxUsersPerFinding: [int(1), 'limits.maxUsersPerFinding'],
    memory: [duration, 'limits.memoryMs'],
  },
};

/** @param {unknown} v @returns {v is Record<string, unknown>} */
const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Validates a parsed config file and turns it into engine options.
 * @param {unknown} raw
 * @returns {{ options: AnalyzerOptions, errors: string[] }}
 */
export function parseConfig(raw) {
  /** @type {Record<string, any>} */
  const options = {};
  /** @type {string[]} */
  const errors = [];
  if (!isObject(raw)) return { options, errors: ['the config must be a JSON object'] };

  /**
   * @param {string} path  Where the value goes, e.g. "spray.minUsers".
   * @param {unknown} value
   */
  const set = (path, value) => {
    const keys = path.split('.');
    let target = options;
    for (const key of keys.slice(0, -1)) target = target[key] ??= {};
    target[keys[keys.length - 1]] = value;
  };

  for (const [section, value] of Object.entries(raw)) {
    if (section.startsWith('$')) continue;
    const spec = SPEC[section];
    if (spec === undefined) {
      errors.push(`unknown setting "${section}"`);
    } else if (Array.isArray(spec)) {
      const [check, path] = spec;
      const result = check(value);
      if (result.ok) set(path, result.value);
      else errors.push(`"${section}" must be ${result.expected}`);
    } else if (!isObject(value)) {
      errors.push(`"${section}" must be an object`);
    } else {
      for (const [key, inner] of Object.entries(value)) {
        if (key.startsWith('$')) continue;
        const entry = spec[key];
        if (entry === undefined) {
          errors.push(`unknown setting "${section}.${key}"`);
          continue;
        }
        const result = entry[0](inner);
        if (result.ok) set(entry[1], result.value);
        else errors.push(`"${section}.${key}" must be ${result.expected}`);
      }
    }
  }
  return { options, errors };
}

/**
 * The config-file form of resolved options, for `--print-config`.
 * @param {ResolvedOptions} o
 */
export function toConfig(o) {
  return {
    bruteForce: { threshold: o.threshold, window: formatDuration(o.windowMs), ipv6Prefix: o.ipv6Prefix },
    possibleBreach: { lookback: formatDuration(o.lookbackMs), ignoreKeyLoginsAfterOthersFailures: o.ignoreKeyLoginsAfterOthersFailures },
    unusualHour: { night: o.night.join('-') },
    accountChange: { adminGroups: o.adminGroups },
    passwordSpray: {
      enabled: o.spray.enabled, minUsers: o.spray.minUsers, window: formatDuration(o.spray.windowMs),
      maxAttemptsPerUser: o.spray.maxAttemptsPerUser, countInvalidUsers: o.spray.countInvalidUsers,
    },
    distributedBruteForce: {
      enabled: o.distributed.enabled, minSources: o.distributed.minSources, minAttempts: o.distributed.minAttempts,
      window: formatDuration(o.distributed.windowMs), countInvalidUsers: o.distributed.countInvalidUsers,
      ignoreUsers: o.distributed.ignoreUsers,
    },
    newSource: {
      enabled: o.newSource.enabled, learning: formatDuration(o.newSource.learningMs),
      prefixV4: o.newSource.prefixV4, prefixV6: o.newSource.prefixV6, remember: formatDuration(o.newSource.rememberMs),
      sharedNetworkUsers: o.newSource.sharedNetworkUsers,
    },
    logTampering: {
      enabled: o.tampering.enabled, maxGap: formatDuration(o.tampering.maxGapMs),
      maxBackwards: formatDuration(o.tampering.maxBackwardsMs), allowDstJumps: o.tampering.allowDstJumps,
    },
    trustedNetworks: o.trustedNetworks,
    limits: {
      maxKeys: o.limits.maxKeys, maxEntriesPerKey: o.limits.maxEntriesPerKey,
      maxUsersPerFinding: o.limits.maxUsersPerFinding, memory: formatDuration(o.limits.memoryMs),
    },
  };
}
