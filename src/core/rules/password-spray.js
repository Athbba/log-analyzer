// Password spraying: one source trying many real accounts a few times each,
// typically one or two common passwords, to stay under lockout thresholds.
// It is the attack the brute-force rule misses, because no single account
// (and, done slowly, no ten-minute window) gets many guesses.
//
// Fires when, within `windowMs`, one source has failed against at least
// `minUsers` existing accounts that it tried no more than
// `maxAttemptsPerUser` times each. Nonexistent usernames are left out by
// default: internet scanners cycle through names like "admin" and "oracle",
// while a spray aimed at you uses accounts that exist.
//
// A failure followed by a login as the same user from the same source before
// the spray is detected is a typo, not a spray, and is taken back out: an
// office behind one NAT address, where several people mistype their password
// in the same hour, must not look like a spray. After detection, such a login
// is the spray succeeding, and makes the finding high.

import { BoundedMap, TimeWindow } from '../bounded.js';
import { networkMatcher, parseCidr, sourceOf } from '../net.js';

/** @typedef {import('../../types.js').PasswordSprayFinding} PasswordSprayFinding */
/** @typedef {import('../engine.js').RuleContext} RuleContext */
/** @typedef {import('../engine.js').Rule} Rule */

/** @typedef {{ time: number, user: string, count: number }} Failure */

/**
 * @typedef {object} SourceState
 * @property {TimeWindow<Failure>} failures  Counted failures within the window.
 * @property {Map<string, number>} users  Attempts per account within the window.
 * @property {number} light  Accounts with 1..maxAttemptsPerUser attempts.
 * @property {PasswordSprayFinding | null} finding  The spray in progress.
 * @property {Map<string, number>} sprayed  Every account the spray in progress has tried.
 * @property {number} last
 */

/**
 * @param {RuleContext} ctx
 * @returns {Rule}
 */
export function createPasswordSpray(ctx) {
  const { spray, ipv6Prefix, trustedNetworks, limits } = ctx.options;
  const { minUsers, windowMs, maxAttemptsPerUser, countInvalidUsers } = spray;
  const trusted = networkMatcher(trustedNetworks.flatMap((c) => parseCidr(c) ?? []));
  /** @type {BoundedMap<string, SourceState>} */
  const sources = new BoundedMap('password-spray: sources', limits.maxKeys, ctx.health, {
    keep: (s) => s.finding !== null || s.users.size > 1,
  });
  /** Each spray's tally of accounts, kept with the finding it belongs to. */
  /** @type {WeakMap<PasswordSprayFinding, Map<string, number>>} */
  const tallies = new WeakMap();
  let nextSweep = -Infinity;

  /** @returns {SourceState} */
  const newState = () => ({
    failures: new TimeWindow('password-spray: failures per source', limits.maxEntriesPerKey, ctx.health),
    users: new Map(),
    light: 0,
    finding: null,
    sprayed: new Map(),
    last: -Infinity,
  });

  /**
   * Changes an account's attempt count, keeping `light` in step.
   * @param {SourceState} state
   * @param {string} user
   * @param {number} delta
   */
  function adjust(state, user, delta) {
    const before = state.users.get(user) ?? 0;
    const after = before + delta;
    const wasLight = before >= 1 && before <= maxAttemptsPerUser;
    const isLight = after >= 1 && after <= maxAttemptsPerUser;
    if (after <= 0) state.users.delete(user);
    else state.users.set(user, after);
    state.light += Number(isLight) - Number(wasLight);
  }

  /** @param {SourceState} state */
  const evictOld = (state, /** @type {number} */ time) =>
    state.failures.dropBefore(time - windowMs, (f) => adjust(state, f.user, -f.count));

  return {
    name: 'password-spray',

    onEvent(event) {
      if (!spray.enabled || (event.type !== 'failure' && event.type !== 'success') || trusted(event.ip)) return;
      const key = sourceOf(event.ip, ipv6Prefix);

      if (event.type === 'success') {
        const state = sources.get(key);
        if (!state) return;
        if (state.finding && state.sprayed.has(event.user) && !state.finding.loggedIn) {
          state.finding.loggedIn = { time: event.time, user: event.user, method: event.method };
          state.finding.severity = 'high';
          ctx.update(state.finding);
        } else if (!state.finding && state.users.has(event.user)) {
          // A mistyped password, then the right one: not part of a spray.
          adjust(state, event.user, -(state.users.get(event.user) ?? 0));
          const kept = [...state.failures].filter((f) => f.user !== event.user);
          state.failures = new TimeWindow(state.failures.name, state.failures.maxLength, ctx.health);
          for (const f of kept) state.failures.push(f);
        }
        return;
      }

      if (event.invalidUser && !countInvalidUsers) return;
      const state = sources.touch(key, newState);
      state.last = event.time;
      evictOld(state, event.time);
      if (!state.users.has(event.user) && state.users.size >= limits.maxUsersPerFinding) {
        ctx.health.drop('password-spray: accounts per source');
        return;
      }
      state.failures.push({ time: event.time, user: event.user, count: event.count }, (f) => adjust(state, f.user, -f.count));
      adjust(state, event.user, event.count);

      const finding = state.finding;
      if (finding && event.time - finding.until <= windowMs) {
        finding.until = event.time;
        finding.attempts += event.count;
        if (state.sprayed.has(event.user) || state.sprayed.size < limits.maxUsersPerFinding) {
          state.sprayed.set(event.user, (state.sprayed.get(event.user) ?? 0) + event.count);
        }
        finding.userCount = Math.max(finding.userCount, state.light);
        ctx.update(finding);
      } else if (state.light >= minUsers) {
        const window = [...state.failures];
        state.sprayed = new Map();
        for (const f of window) state.sprayed.set(f.user, (state.sprayed.get(f.user) ?? 0) + f.count);
        state.finding = {
          rule: 'password-spray',
          severity: 'medium',
          ip: key,
          time: window[0].time,
          until: event.time,
          attempts: window.reduce((sum, f) => sum + f.count, 0),
          userCount: state.light,
          users: [],
          loggedIn: null,
        };
        tallies.set(state.finding, state.sprayed);
        ctx.emit(state.finding);
      }
    },

    onAdvance(time) {
      if (time < nextSweep) return;
      nextSweep = time + windowMs;
      sources.sweep((state) => {
        evictOld(state, time);
        if (state.finding && time - state.finding.until > windowMs) state.finding = null;
        return state.failures.length === 0 && state.finding === null;
      });
    },

    materialize(finding) {
      if (finding.rule !== 'password-spray') return;
      const tally = tallies.get(finding);
      if (!tally) return;
      finding.users = [...tally]
        .map(([user, attempts]) => ({ user, attempts }))
        .sort((a, b) => b.attempts - a.attempts || a.user.localeCompare(b.user));
    },

    size() {
      let entries = 0;
      for (const s of sources.values()) entries += s.failures.length + s.users.size + s.sprayed.size;
      return { keys: sources.size, entries };
    },
  };
}
