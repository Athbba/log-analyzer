// Brute force: `threshold` or more failed logins from one IP within
// `windowMs`. Every failure inside such a window is "hot"; hot failures no more
// than a window apart belong to one attack, reported as one finding. The
// finding is high as soon as the IP logs in, at or after the attack's start.
//
// Streaming version of the original batch rule, with the same results on
// in-order input. Per IP it keeps only the failures of the last window, the
// logins of the last window, and attacks still waiting for a login.

import { BoundedMap, TimeWindow } from '../bounded.js';

/** @typedef {import('../../types.js').AuthEvent} AuthEvent */
/** @typedef {import('../../types.js').SuccessEvent} SuccessEvent */
/** @typedef {import('../../types.js').BruteForceFinding} BruteForceFinding */
/** @typedef {import('../engine.js').RuleContext} RuleContext */
/** @typedef {import('../engine.js').Rule} Rule */

/** @typedef {{ time: number, count: number, user: string, invalid: boolean }} Failure */

/**
 * @typedef {object} Attack  One finding plus its full tallies.
 * @property {BruteForceFinding} finding
 * @property {Map<string, number>} users  Attempts per username.
 * @property {Set<string>} invalid  Usernames that don't exist.
 */

/**
 * @typedef {object} IpState
 * @property {TimeWindow<Failure>} window  Failures within `windowMs` of the newest.
 * @property {number} inWindow  Their total count.
 * @property {number} unmarked  How many of the newest failures aren't hot yet.
 * @property {Attack | null} attack  The latest attack, which new hot failures may join.
 * @property {TimeWindow<SuccessEvent>} logins  Logins within the last window.
 * @property {Attack[]} waiting  Attacks with no login yet.
 * @property {number} last  Time of this IP's latest event.
 */

/**
 * @param {RuleContext} ctx
 * @returns {Rule}
 */
export function createBruteForce(ctx) {
  const { threshold, windowMs, limits } = ctx.options;
  /** @type {BoundedMap<string, IpState>} */
  // An IP with an attack, or more than one recent failure, outlives one-off IPs.
  const ips = new BoundedMap('brute-force: IPs', limits.maxKeys, ctx.health, {
    keep: (s) => s.attack !== null || s.waiting.length > 0 || s.inWindow > 1,
  });
  /** @type {WeakMap<BruteForceFinding, Attack>} */
  const attacks = new WeakMap();
  let nextSweep = -Infinity;

  /** @returns {IpState} */
  const newState = () => ({
    window: new TimeWindow('brute-force: failures per IP', limits.maxEntriesPerKey, ctx.health),
    inWindow: 0,
    unmarked: 0,
    attack: null,
    logins: new TimeWindow('brute-force: logins per IP', limits.maxEntriesPerKey, ctx.health),
    waiting: [],
    last: -Infinity,
  });

  /**
   * Adds a newly hot failure to the latest attack, or starts a new one.
   * @param {string} ip
   * @param {IpState} state
   * @param {Failure} failure
   */
  function addHot(ip, state, failure) {
    let attack = state.attack;
    const isNew = !attack || failure.time - attack.finding.until > windowMs;
    if (!attack || isNew) {
      /** @type {BruteForceFinding} */
      const finding = {
        rule: 'brute-force',
        ip,
        time: failure.time,
        until: failure.time,
        attempts: 0,
        severity: 'medium',
        users: [],
        invalidUsers: 0,
        loggedIn: null,
      };
      attack = { finding, users: new Map(), invalid: new Set() };
      attacks.set(finding, attack);
      state.attack = attack;
    }
    const { finding } = attack;
    finding.until = failure.time;
    finding.attempts += failure.count;
    tally(attack, failure);

    if (isNew) {
      // The first login at or after the attack's start, if it came already.
      const login = [...state.logins].find((s) => s.time >= finding.time);
      if (login) loggedIn(finding, login);
      else state.waiting.push(attack);
      ctx.emit(finding);
    } else {
      ctx.update(finding);
    }
  }

  /**
   * @param {Attack} attack
   * @param {Failure} failure
   */
  function tally({ users, invalid }, failure) {
    const known = users.get(failure.user);
    if (known === undefined && users.size >= limits.maxUsersPerFinding) {
      ctx.health.drop('brute-force: usernames per attack');
      return;
    }
    users.set(failure.user, (known ?? 0) + failure.count);
    if (failure.invalid) invalid.add(failure.user);
  }

  /**
   * @param {BruteForceFinding} finding
   * @param {SuccessEvent} login
   */
  function loggedIn(finding, login) {
    finding.loggedIn = { time: login.time, user: login.user, method: login.method };
    finding.severity = 'high';
  }

  return {
    name: 'brute-force',

    onEvent(event) {
      if (event.type === 'failure') {
        const state = ips.touch(event.ip, newState);
        state.last = event.time;
        /** @param {Failure} f */
        const evicted = (f) => {
          state.inWindow -= f.count;
        };
        state.window.dropBefore(event.time - windowMs, evicted);
        state.window.push({ time: event.time, count: event.count, user: event.user, invalid: event.invalidUser }, evicted);
        state.inWindow += event.count;
        state.unmarked = Math.min(state.unmarked + 1, state.window.length);
        if (state.inWindow >= threshold) {
          // Every failure in a window that reaches the threshold is hot. Earlier
          // ones are already hot, so only the newest `unmarked` need adding.
          const newlyHot = [...state.window.tail(state.unmarked)];
          state.unmarked = 0;
          for (const failure of newlyHot) addHot(event.ip, state, failure);
        }
      } else if (event.type === 'success') {
        const state = ips.touch(event.ip, newState);
        state.last = event.time;
        state.logins.dropBefore(event.time - windowMs);
        state.logins.push(event);
        const stillWaiting = [];
        for (const attack of state.waiting) {
          // Checked here, not only in the sweep, so the memory limit holds
          // even when the sweep is late (see the clock guard in engine.js).
          if (attack.finding.time < event.time - limits.memoryMs) continue;
          if (attack.finding.time <= event.time) {
            loggedIn(attack.finding, event);
            ctx.update(attack.finding);
          } else {
            stillWaiting.push(attack);
          }
        }
        state.waiting = stillWaiting;
      }
    },

    onAdvance(time) {
      if (time < nextSweep) return;
      nextSweep = time + windowMs;
      const recent = time - windowMs;
      const remembered = time - limits.memoryMs;
      ips.sweep((state) => {
        state.waiting = state.waiting.filter((a) => a.finding.time >= remembered);
        return state.last < recent && state.waiting.length === 0;
      });
    },

    materialize(finding) {
      if (finding.rule !== 'brute-force') return;
      const attack = attacks.get(finding);
      if (!attack) return;
      finding.users = [...attack.users]
        .map(([user, attempts]) => ({ user, attempts }))
        .sort((a, b) => b.attempts - a.attempts || a.user.localeCompare(b.user));
      finding.invalidUsers = attack.invalid.size;
    },

    size() {
      let entries = 0;
      for (const s of ips.values()) entries += s.window.length + s.logins.length + s.waiting.length;
      return { keys: ips.size, entries };
    },
  };
}
