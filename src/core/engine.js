// The detection engine. Events go in one at a time, in log order; findings
// come out as soon as a rule sees them, and are updated in place when more
// evidence arrives (an attack grows, a later login escalates it). A finished
// file and a live log are the same thing to the engine: a stream that, for a
// file, happens to end.
//
// The engine is synchronous and deterministic: the same events in the same
// order always give the same findings, with no clock, I/O or randomness.
//
// Rules can react to each other's findings (a brute force escalates an earlier
// possible breach; a high-severity breach escalates an account change made
// from that IP). Rule state is bounded (see bounded.js) and evicted as the
// log's own clock moves on.

import { Health } from './bounded.js';
import { resolveOptions } from './options.js';
import { createAccountChange } from './rules/account-change.js';
import { createBruteForce } from './rules/brute-force.js';
import { createPossibleBreach } from './rules/possible-breach.js';
import { createUnusualHour } from './rules/unusual-hour.js';

/** @typedef {import('../types.js').AuthEvent} AuthEvent */
/** @typedef {import('../types.js').Finding} Finding */
/** @typedef {import('../types.js').Options} Options */
/** @typedef {import('../types.js').Limits} Limits */
/** @typedef {import('../types.js').ResolvedOptions} ResolvedOptions */

/**
 * What a rule gets from the engine.
 * @typedef {object} RuleContext
 * @property {ResolvedOptions} options
 * @property {Health} health
 * @property {(finding: Finding) => void} emit  Report a new finding.
 * @property {(finding: Finding) => void} update  Report that a finding changed (same object).
 */

/**
 * A detection rule.
 * @typedef {object} Rule
 * @property {string} name
 * @property {(event: AuthEvent) => void} onEvent  Called for every event, in order.
 * @property {(finding: Finding, isNew: boolean) => void} [onFinding]  Another rule's finding appeared or changed.
 * @property {(time: number) => void} [onAdvance]  The log's clock moved forward to `time`: evict old state.
 * @property {(finding: Finding) => void} [materialize]  Fill in derived fields before the finding is handed out.
 * @property {() => { keys: number, entries: number }} size  State held, for bounded-memory tests.
 */

/** @typedef {(ctx: RuleContext) => Rule} RuleFactory */

/** The rules, in the order they see each event. */
export const RULES = /** @type {RuleFactory[]} */ ([createBruteForce, createPossibleBreach, createUnusualHour, createAccountChange]);

/**
 * @typedef {object} EngineOptions
 * @property {(finding: Finding, isNew: boolean) => void} [onFinding]
 *   Called on `flush()` for each finding that appeared or changed since the
 *   last flush. `isNew` is true the first time a finding is handed out.
 * @property {boolean} [keepFindings]  Keep every finding for `findings()` (default true).
 *   Live mode turns this off and relies on `onFinding`.
 * @property {RuleFactory[]} [rules]
 */

/**
 * @param {Partial<Options> & { limits?: Partial<Limits> }} [options]
 * @param {EngineOptions} [engineOptions]
 */
export function createEngine(options = {}, { onFinding, keepFindings = true, rules: factories = RULES } = {}) {
  const resolved = resolveOptions(options);
  const health = new Health();
  /** @type {Finding[]} */
  const kept = [];
  /** @type {WeakMap<Finding, { rule: Rule, published: boolean }>} */
  const meta = new WeakMap();
  /** @type {Set<Finding>} */
  const dirty = new Set();
  let clock = -Infinity;
  let depth = 0;

  /** @type {Rule[]} */
  const rules = [];
  for (const factory of factories) {
    // The rule this context belongs to; set once the factory returns.
    const index = rules.length;
    /** @type {RuleContext} */
    const ctx = {
      options: resolved,
      health,
      emit(finding) {
        meta.set(finding, { rule: rules[index], published: false });
        if (keepFindings) kept.push(finding);
        changed(finding, true);
      },
      update(finding) {
        changed(finding, false);
      },
    };
    rules.push(factory(ctx));
  }

  /**
   * Marks a finding for the next flush and tells the other rules about it.
   * @param {Finding} finding
   * @param {boolean} isNew
   */
  function changed(finding, isNew) {
    dirty.add(finding);
    if (++depth > 8) throw new Error('rules reacting to each other did not settle');
    const owner = meta.get(finding)?.rule;
    for (const rule of rules) if (rule !== owner) rule.onFinding?.(finding, isNew);
    depth--;
  }

  return {
    options: resolved,
    health,

    /** @param {AuthEvent} event */
    push(event) {
      if (event.time > clock) {
        clock = event.time;
        for (const rule of rules) rule.onAdvance?.(clock);
      }
      for (const rule of rules) rule.onEvent(event);
    },

    /**
     * Moves the clock forward without an event (live mode, when the log is
     * quiet), so old state can be evicted.
     * @param {number} time
     */
    advance(time) {
      if (time > clock) {
        clock = time;
        for (const rule of rules) rule.onAdvance?.(clock);
      }
    },

    /** Completes changed findings and hands them to `onFinding`. */
    flush() {
      for (const finding of dirty) {
        const info = meta.get(finding);
        info?.rule.materialize?.(finding);
        const isNew = info !== undefined && !info.published;
        if (info) info.published = true;
        onFinding?.(finding, isNew);
      }
      dirty.clear();
    },

    /** Every finding so far, in the order they were first reported. */
    findings() {
      this.flush();
      return kept;
    },

    /** State held by each rule. */
    size() {
      return Object.fromEntries(rules.map((rule) => [rule.name, rule.size()]));
    },
  };
}

/** @typedef {ReturnType<typeof createEngine>} Engine */
