// Account change: a new user, or a user added to an admin group. The account
// tools don't log who ran them, so the source IP is worked out: the sudo line
// that ran the tool names the user, and that user's SSH sessions open at the
// time give the IP. With no sudo line (a root shell), every open session is a
// candidate. High when a candidate IP had already broken in (a high-severity
// possible breach); otherwise medium for admin rights (or UID 0), low for a
// plain user.
//
// State: sudo lines from the last minute, open SSH sessions, the tool runs of
// the last minute (useradd -G logs the user and each group on separate lines),
// high-severity breaches per IP, and recent changes that a breach escalated
// after the fact could still affect.

import { BoundedMap, TimeWindow } from '../bounded.js';

/** @typedef {import('../../types.js').AuthEvent} AuthEvent */
/** @typedef {import('../../types.js').SudoEvent} SudoEvent */
/** @typedef {import('../../types.js').AccountEvent} AccountEvent */
/** @typedef {import('../../types.js').PossibleBreachFinding} PossibleBreachFinding */
/** @typedef {import('../../types.js').AccountChangeFinding} AccountChangeFinding */
/** @typedef {import('../engine.js').RuleContext} RuleContext */
/** @typedef {import('../engine.js').Rule} Rule */

const MINUTE = 60_000;
// adduser prompts for a password and details, so allow for a slow typist.
const SUDO_MATCH_MS = MINUTE;
// Lines of one useradd/usermod run arrive within moments of each other.
const CHANGE_GROUP_MS = MINUTE;
// Commands whose sudo line identifies who made an account change.
const ACCOUNT_TOOLS = new Set(['useradd', 'adduser', 'usermod', 'gpasswd']);

/** @typedef {{ host: string, ip: string, user: string, start: number, end: number, seq: number }} Session */

/**
 * One run of an account tool.
 * @typedef {object} Change
 * @property {string} host
 * @property {number} time  Its first line.
 * @property {string} user  The account created or changed.
 * @property {boolean} created
 * @property {number | null} uid
 * @property {string[]} groups
 * @property {string | null} by  The sudo user, if a sudo line matched.
 * @property {string[]} sessionIps
 * @property {AccountChangeFinding | null} finding
 */

/**
 * @param {RuleContext} ctx
 * @returns {Rule}
 */
export function createAccountChange(ctx) {
  const { adminGroups, windowMs, limits } = ctx.options;
  /** @type {TimeWindow<SudoEvent>} */
  const sudo = new TimeWindow('account-change: sudo lines', limits.maxKeys, ctx.health);
  /** Open SSH sessions by host, sshd PID and user; sessions that can't be closed get a unique key. */
  /** @type {BoundedMap<string, Session>} */
  const sessions = new BoundedMap('account-change: open SSH sessions', limits.maxKeys, ctx.health);
  /** Sessions that closed at the current time still count as open at that time. */
  /** @type {Session[]} */
  let closedNow = [];
  /** @type {BoundedMap<string, Change>} */
  const changes = new BoundedMap('account-change: tool runs', limits.maxKeys, ctx.health);
  /** High-severity possible breaches per IP, oldest first. */
  /** @type {BoundedMap<string, PossibleBreachFinding[]>} */
  const breaches = new BoundedMap('account-change: breached IPs', limits.maxKeys, ctx.health);
  /** Changes a breach escalated after the fact could still affect. */
  /** @type {Change[]} */
  let recent = [];
  let seq = 0;
  let clock = -Infinity;
  let nextSweep = -Infinity;

  /**
   * @param {string} host
   * @param {number | null} pid
   * @param {string} user
   */
  const sessionKey = (host, pid, user) => `${host} ${pid} ${user}`;

  /**
   * The most recent high-severity breach from any of `ips` at or before `time`.
   * @param {string[]} ips
   * @param {number} time
   */
  function breachBefore(ips, time) {
    /** @type {PossibleBreachFinding | undefined} */
    let latest;
    for (const ip of ips) {
      for (const b of breaches.get(ip) ?? []) {
        if (b.time <= time && (!latest || b.time > latest.time)) latest = b;
      }
    }
    return latest;
  }

  /**
   * Creates or updates the finding for a change, if it is one worth reporting.
   * @param {Change} change
   */
  function evaluate(change) {
    const privilegedGroups = change.groups.filter((g) => adminGroups.includes(g));
    const privileged = privilegedGroups.length > 0 || change.uid === 0;
    if (!change.created && !privileged) return;
    const breach = breachBefore(change.sessionIps, change.time);
    /** @type {AccountChangeFinding} */
    const fields = {
      rule: 'account-change',
      severity: breach ? 'high' : privileged ? 'medium' : 'low',
      ip: breach?.ip ?? (change.sessionIps.length === 1 ? change.sessionIps[0] : null),
      time: change.time,
      user: change.user,
      created: change.created,
      uid: change.uid,
      groups: [...change.groups],
      privilegedGroups,
      by: change.by,
      sessionIps: change.sessionIps,
      afterBreach: breach ? { time: breach.time, user: breach.user, attempts: breach.attempts } : null,
    };
    if (change.finding) {
      Object.assign(change.finding, fields);
      ctx.update(change.finding);
    } else {
      change.finding = fields;
      recent.push(change);
      ctx.emit(fields);
    }
  }

  /** @param {AccountEvent} event */
  function onAccount(event) {
    const key = `${event.host} ${event.program} ${event.pid ?? event.time} ${event.user}`;
    let change = changes.get(key);
    if (!change) {
      const by = whoRan(event);
      const open = [...sessions.values(), ...closedNow]
        .filter((s) => s.host === event.host && s.start <= event.time && event.time <= s.end && (by === null || s.user === by))
        .sort((a, b) => a.seq - b.seq);
      change = {
        host: event.host,
        time: event.time,
        user: event.user,
        created: false,
        uid: null,
        groups: [],
        by,
        sessionIps: [...new Set(open.map((s) => s.ip))],
        finding: null,
      };
      changes.set(key, change);
    }
    if (event.action === 'user-created') {
      change.created = true;
      change.uid = event.uid ?? null;
    } else if (event.group !== undefined && !change.groups.includes(event.group)) {
      change.groups.push(event.group);
    }
    evaluate(change);
  }

  /**
   * The user whose sudo line, within the last minute, ran an account tool on
   * this event's user.
   * @param {AccountEvent} event
   */
  function whoRan(event) {
    for (const s of sudo.reversed()) {
      if (s.host === event.host && event.time - s.time <= SUDO_MATCH_MS && runsAccountToolOn(s.command, event.user)) {
        return s.user;
      }
    }
    return null;
  }

  return {
    name: 'account-change',

    onEvent(event) {
      if (event.time > clock) {
        clock = event.time;
        closedNow = closedNow.filter((s) => s.end >= clock);
      }
      switch (event.type) {
        case 'success': {
          const session = { host: event.host, ip: event.ip, user: event.user, start: event.time, end: Infinity, seq: seq++ };
          const key = event.pid === null ? `unclosable ${session.seq}` : sessionKey(event.host, event.pid, event.user);
          // A reused PID before the old session logged out: the old one can
          // never be closed now, so it stays open (until it is forgotten).
          const previous = sessions.get(key);
          if (previous) sessions.set(`unclosable ${previous.seq}`, previous);
          sessions.set(key, session);
          break;
        }
        case 'logout': {
          if (event.pid === null) break;
          const key = sessionKey(event.host, event.pid, event.user);
          const session = sessions.get(key);
          if (session) {
            session.end = event.time;
            sessions.delete(key);
            closedNow.push(session);
          }
          break;
        }
        case 'sudo':
          sudo.dropBefore(event.time - SUDO_MATCH_MS);
          sudo.push(event);
          break;
        case 'account':
          onAccount(event);
          break;
      }
    },

    onFinding(finding) {
      if (finding.rule !== 'possible-breach' || finding.severity !== 'high') return;
      const list = breaches.touch(finding.ip, () => []);
      if (list.includes(finding)) return;
      list.push(finding);
      list.sort((a, b) => a.time - b.time);
      // A breach that became high after the fact escalates changes made since.
      for (const change of recent) {
        if (change.time >= finding.time && change.sessionIps.includes(finding.ip)) evaluate(change);
      }
    },

    onAdvance(time) {
      if (time < nextSweep) return;
      nextSweep = time + Math.min(windowMs, CHANGE_GROUP_MS);
      sudo.dropBefore(time - SUDO_MATCH_MS);
      changes.sweep((c) => c.time < time - CHANGE_GROUP_MS);
      recent = recent.filter((c) => c.time >= time - windowMs);
      const forgotten = time - limits.memoryMs;
      sessions.sweep((s) => s.start < forgotten);
      breaches.sweep((list) => {
        const kept = list.filter((b) => b.time >= forgotten);
        list.splice(0, list.length, ...kept);
        return list.length === 0;
      });
    },

    size() {
      let entries = 0;
      for (const list of breaches.values()) entries += list.length;
      return {
        keys: sessions.size + changes.size + breaches.size,
        entries: sudo.length + closedNow.length + recent.length + entries,
      };
    },
  };
}

/**
 * @param {string} command
 * @param {string} user
 */
function runsAccountToolOn(command, user) {
  const [program, ...args] = command.trim().split(/\s+/);
  return ACCOUNT_TOOLS.has(program.split('/').pop() ?? '') && args.includes(user);
}
