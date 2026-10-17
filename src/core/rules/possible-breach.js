// Possible breach: a successful login from an IP that failed within the
// previous `lookbackMs`. High when those failures reach the brute-force
// threshold or a brute force from that IP covers the login; low for the odd
// mistyped password.
//
// A brute force can become visible only after the login (four failures, the
// login, then a fifth failure within the window makes all five hot). The
// original batch rule saw the whole file at once; here a low finding is kept
// for one window and escalated if such a brute force turns up.
//
// A key login after a few password failures for *other* usernames from the
// same IP is not reported (`ignoreKeyLoginsAfterOthersFailures`). That is a
// colleague behind the same office NAT, not a guessed password: a key can't
// be the payoff of guessing someone else's password. The Docker lab found
// this false positive. If a brute force from the IP covers the login after
// all, it is reported, at high.

import { BoundedMap, TimeWindow } from '../bounded.js';
import { sourceOf } from '../net.js';

/** @typedef {import('../../types.js').BruteForceFinding} BruteForceFinding */
/** @typedef {import('../../types.js').PossibleBreachFinding} PossibleBreachFinding */
/** @typedef {import('../../types.js').UserTally} UserTally */
/** @typedef {import('../engine.js').RuleContext} RuleContext */
/** @typedef {import('../engine.js').Rule} Rule */

/** @typedef {{ time: number, count: number, user: string }} Failure */

/**
 * @typedef {object} IpState
 * @property {TimeWindow<Failure>} failures  Failures within the lookback.
 * @property {BruteForceFinding[]} attacks  Brute forces from this IP that can still matter.
 * @property {PossibleBreachFinding[]} low  Low findings that a later brute force could escalate.
 * @property {number} last
 */

/**
 * @param {RuleContext} ctx
 * @returns {Rule}
 */
export function createPossibleBreach(ctx) {
  const { threshold, windowMs, lookbackMs, limits, ipv6Prefix, ignoreKeyLoginsAfterOthersFailures } = ctx.options;
  /** @type {BoundedMap<string, IpState>} */
  const ips = new BoundedMap('possible-breach: IPs', limits.maxKeys, ctx.health, {
    keep: (s) => s.failures.length > 1 || s.attacks.length > 0 || s.low.length > 0,
  });
  /** Low findings not reported (yet): key logins after other users' failures. */
  /** @type {WeakSet<PossibleBreachFinding>} */
  const held = new WeakSet();
  let nextSweep = -Infinity;

  /** @returns {IpState} */
  const newState = () => ({
    failures: new TimeWindow('possible-breach: failures per IP', limits.maxEntriesPerKey, ctx.health),
    attacks: [],
    low: [],
    last: -Infinity,
  });

  /**
   * Whether brute force `b` covers a login at `time`: it started by then and
   * its last failure is within the lookback.
   * @param {BruteForceFinding} b
   * @param {number} time
   */
  const covers = (b, time) => b.time <= time && b.until >= time - lookbackMs;

  return {
    name: 'possible-breach',

    onEvent(event) {
      if (event.type !== 'failure' && event.type !== 'success') return;
      // Counted per source, like brute force: an IPv6 /64 by default.
      const source = sourceOf(event.ip, ipv6Prefix);
      if (event.type === 'failure') {
        const state = ips.touch(source, newState);
        state.last = event.time;
        state.failures.dropBefore(event.time - lookbackMs);
        state.failures.push({ time: event.time, count: event.count, user: event.user });
        return;
      }
      const state = ips.get(source);
      if (!state) return;
      state.failures.dropBefore(event.time - lookbackMs);
      const before = [...state.failures];
      if (before.length === 0) return;

      const attempts = before.reduce((sum, f) => sum + f.count, 0);
      const users = tallyUsers(before);
      /** @type {PossibleBreachFinding} */
      const finding = {
        rule: 'possible-breach',
        severity: attempts >= threshold || state.attacks.some((b) => covers(b, event.time)) ? 'high' : 'low',
        ip: event.ip,
        time: event.time,
        user: event.user,
        method: event.method,
        attempts,
        firstFailure: before[0].time,
        users,
        sameUser: users.some((u) => u.user === event.user),
      };
      state.last = event.time;
      if (finding.severity === 'low') {
        state.low.push(finding);
        if (ignoreKeyLoginsAfterOthersFailures && event.method === 'publickey' && !finding.sameUser) {
          held.add(finding);
          return;
        }
      }
      ctx.emit(finding);
    },

    onFinding(finding, isNew) {
      if (finding.rule !== 'brute-force') return;
      const state = ips.touch(finding.ip, newState);
      if (isNew) state.attacks.push(finding);
      // A new or longer brute force may cover a login that looked like a typo.
      state.low = state.low.filter((low) => {
        if (!covers(finding, low.time)) return true;
        low.severity = 'high';
        if (held.delete(low)) ctx.emit(low);
        else ctx.update(low);
        return false;
      });
    },

    onAdvance(time) {
      if (time < nextSweep) return;
      nextSweep = time + windowMs;
      // A brute force that ended more than a window ago can't grow any more;
      // once it is also outside the lookback it can't cover a future login.
      // A low finding can only be escalated by a brute force that is still
      // within a window of it.
      const attackCutoff = time - Math.max(windowMs, lookbackMs);
      ips.sweep((state) => {
        state.failures.dropBefore(time - lookbackMs);
        state.attacks = state.attacks.filter((b) => b.until >= attackCutoff);
        state.low = state.low.filter((f) => f.time >= time - windowMs);
        return state.failures.length === 0 && state.attacks.length === 0 && state.low.length === 0;
      });
    },

    size() {
      let entries = 0;
      for (const s of ips.values()) entries += s.failures.length + s.attacks.length + s.low.length;
      return { keys: ips.size, entries };
    },
  };
}

/**
 * Attempts per username, most-tried first.
 * @param {Failure[]} failures
 * @returns {UserTally[]}
 */
function tallyUsers(failures) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const f of failures) counts.set(f.user, (counts.get(f.user) ?? 0) + f.count);
  return [...counts]
    .map(([user, attempts]) => ({ user, attempts }))
    .sort((a, b) => b.attempts - a.attempts || a.user.localeCompare(b.user));
}
