// First login from a new source: a user logs in from a network they have
// never logged in from before. Stolen credentials are usually used from the
// attacker's own infrastructure, so this catches logins that look normal in
// every other way (no failures, daytime, the right password or key).
//
// "Network" is the /24 (IPv4) or /64 (IPv6) around the address, so a home
// connection that changes address within its ISP block isn't new each time.
// The first `learningMs` of the log only build the baseline. A user's very
// first login is never reported (there's no baseline to compare with; new
// accounts are the account-change rule's job). Logins from trusted networks
// are never reported. Password logins are medium, key logins low: a key
// can't be guessed, so a key login from somewhere new is more likely the
// user travelling.
//
// This rule has inherent false positives (travel, a new ISP, a new VPN exit),
// which is why it is low or medium and never high on its own.

import { BoundedMap } from '../bounded.js';
import { networkMatcher, parseCidr, prefixOf } from '../net.js';

/** @typedef {import('../../types.js').NewSourceFinding} NewSourceFinding */
/** @typedef {import('../engine.js').RuleContext} RuleContext */
/** @typedef {import('../engine.js').Rule} Rule */

/** Networks remembered per user; older ones are forgotten first. */
const MAX_NETWORKS_PER_USER = 100;

/**
 * @param {RuleContext} ctx
 * @returns {Rule}
 */
export function createNewSource(ctx) {
  const { newSource, trustedNetworks, limits } = ctx.options;
  const { learningMs, prefixV4, prefixV6, rememberMs } = newSource;
  const trusted = networkMatcher(trustedNetworks.flatMap((c) => parseCidr(c) ?? []));
  /** Per user: network → last login time, least recent first. */
  /** @type {BoundedMap<string, Map<string, number>>} */
  const users = new BoundedMap('new-source: users', limits.maxKeys, ctx.health);
  let start = -Infinity;
  let nextSweep = -Infinity;

  return {
    name: 'new-source',

    onEvent(event) {
      if (start === -Infinity) start = event.time;
      if (!newSource.enabled || event.type !== 'success' || trusted(event.ip)) return;
      const network = prefixOf(event.ip, prefixV4, prefixV6);
      const isFirstLogin = !users.has(event.user);
      const known = users.touch(event.user, () => new Map());
      const seenBefore = known.has(network);
      known.delete(network);
      known.set(network, event.time);
      if (known.size > MAX_NETWORKS_PER_USER) known.delete(/** @type {string} */ (known.keys().next().value));

      if (seenBefore || isFirstLogin || event.time < start + learningMs) return;
      ctx.emit({
        rule: 'new-source',
        severity: event.method === 'password' ? 'medium' : 'low',
        ip: event.ip,
        time: event.time,
        user: event.user,
        method: event.method,
        network,
        knownNetworks: known.size - 1,
      });
    },

    onAdvance(time) {
      if (time < nextSweep) return;
      nextSweep = time + 60 * 60_000;
      users.sweep((known) => {
        for (const [network, last] of known) if (last < time - rememberMs) known.delete(network);
        return known.size === 0;
      });
    },

    size() {
      let entries = 0;
      for (const known of users.values()) entries += known.size;
      return { keys: users.size, entries };
    },
  };
}
