// Distributed brute force: one account guessed from many sources, each of
// which stays under the per-source brute-force threshold. Botnets do this to
// defeat per-IP defences such as fail2ban.
//
// Fires when, within `windowMs`, one account has failed logins from at least
// `minSources` sources (IPv6 counted per prefix) totalling at least
// `minAttempts`. Nonexistent usernames are left out by default: there is
// nothing to break into. The finding becomes high if one of the attacking
// sources then logs in as that account.
//
// Known noise: on an internet-facing server root is guessed by many unrelated
// scanners all the time. That is a real distributed attack, but a constant
// one; `ignoreUsers` (e.g. ["root"] with PermitRootLogin no) mutes it.

import { BoundedMap, TimeWindow } from '../bounded.js';
import { networkMatcher, parseCidr, sourceOf } from '../net.js';

/** @typedef {import('../../types.js').DistributedBruteForceFinding} DistributedBruteForceFinding */
/** @typedef {import('../engine.js').RuleContext} RuleContext */
/** @typedef {import('../engine.js').Rule} Rule */

/** @typedef {{ time: number, source: string, count: number }} Failure */

/**
 * @typedef {object} AccountState
 * @property {TimeWindow<Failure>} failures  Within the window.
 * @property {Map<string, number>} sources  Attempts per source within the window.
 * @property {number} total
 * @property {DistributedBruteForceFinding | null} finding  The attack in progress.
 * @property {Map<string, number>} attackers  Every source of the attack in progress.
 * @property {number} last
 */

/** Sources listed in a finding; the count covers the rest. */
const LISTED_SOURCES = 20;

/**
 * @param {RuleContext} ctx
 * @returns {Rule}
 */
export function createDistributedBruteForce(ctx) {
  const { distributed, ipv6Prefix, trustedNetworks, limits } = ctx.options;
  const { minSources, minAttempts, windowMs, countInvalidUsers } = distributed;
  const ignored = new Set(distributed.ignoreUsers);
  const trusted = networkMatcher(trustedNetworks.flatMap((c) => parseCidr(c) ?? []));
  /** @type {BoundedMap<string, AccountState>} */
  const accounts = new BoundedMap('distributed-brute-force: accounts', limits.maxKeys, ctx.health, {
    keep: (s) => s.finding !== null || s.sources.size > 1,
  });
  /** @type {WeakMap<DistributedBruteForceFinding, Map<string, number>>} */
  const tallies = new WeakMap();
  let nextSweep = -Infinity;

  /** @returns {AccountState} */
  const newState = () => ({
    failures: new TimeWindow('distributed-brute-force: failures per account', limits.maxEntriesPerKey, ctx.health),
    sources: new Map(),
    total: 0,
    finding: null,
    attackers: new Map(),
    last: -Infinity,
  });

  /**
   * @param {AccountState} state
   * @param {Failure} f
   */
  function forget(state, f) {
    const n = (state.sources.get(f.source) ?? 0) - f.count;
    if (n <= 0) state.sources.delete(f.source);
    else state.sources.set(f.source, n);
    state.total -= f.count;
  }

  return {
    name: 'distributed-brute-force',

    onEvent(event) {
      if (!distributed.enabled || (event.type !== 'failure' && event.type !== 'success')) return;
      if (ignored.has(event.user) || trusted(event.ip)) return;
      const source = sourceOf(event.ip, ipv6Prefix);

      if (event.type === 'success') {
        const finding = accounts.get(event.user)?.finding;
        const attackers = finding && tallies.get(finding);
        if (finding && attackers?.has(source) && !finding.loggedIn) {
          finding.loggedIn = { time: event.time, ip: event.ip, method: event.method };
          finding.severity = 'high';
          ctx.update(finding);
        }
        return;
      }

      if (event.invalidUser && !countInvalidUsers) return;
      const state = accounts.touch(event.user, newState);
      state.last = event.time;
      state.failures.dropBefore(event.time - windowMs, (f) => forget(state, f));
      state.failures.push({ time: event.time, source, count: event.count }, (f) => forget(state, f));
      state.sources.set(source, (state.sources.get(source) ?? 0) + event.count);
      state.total += event.count;

      const finding = state.finding;
      if (finding && event.time - finding.until <= windowMs) {
        finding.until = event.time;
        finding.attempts += event.count;
        if (state.attackers.has(source) || state.attackers.size < limits.maxKeys) {
          state.attackers.set(source, (state.attackers.get(source) ?? 0) + event.count);
        }
        finding.sourceCount = state.attackers.size;
        ctx.update(finding);
      } else if (state.sources.size >= minSources && state.total >= minAttempts) {
        const window = [...state.failures];
        state.attackers = new Map();
        for (const f of window) state.attackers.set(f.source, (state.attackers.get(f.source) ?? 0) + f.count);
        state.finding = {
          rule: 'distributed-brute-force',
          severity: 'medium',
          ip: null,
          user: event.user,
          time: window[0].time,
          until: event.time,
          attempts: state.total,
          sourceCount: state.attackers.size,
          sources: [],
          loggedIn: null,
        };
        tallies.set(state.finding, state.attackers);
        ctx.emit(state.finding);
      }
    },

    onAdvance(time) {
      if (time < nextSweep) return;
      nextSweep = time + windowMs;
      accounts.sweep((state) => {
        state.failures.dropBefore(time - windowMs, (f) => forget(state, f));
        // A finished attack is kept a while longer, for a late login.
        if (state.finding && time - state.finding.until > ctx.options.lookbackMs + windowMs) state.finding = null;
        return state.failures.length === 0 && state.finding === null;
      });
    },

    materialize(finding) {
      if (finding.rule !== 'distributed-brute-force') return;
      const tally = tallies.get(finding);
      if (!tally) return;
      finding.sources = [...tally]
        .map(([ip, attempts]) => ({ ip, attempts }))
        .sort((a, b) => b.attempts - a.attempts || a.ip.localeCompare(b.ip))
        .slice(0, LISTED_SOURCES);
    },

    size() {
      let entries = 0;
      for (const s of accounts.values()) entries += s.failures.length + s.sources.size + s.attackers.size;
      return { keys: accounts.size, entries };
    },
  };
}
