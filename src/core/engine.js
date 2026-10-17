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
import { createDistributedBruteForce } from './rules/distributed-brute-force.js';
import { createLogTampering } from './rules/log-tampering.js';
import { createNewSource } from './rules/new-source.js';
import { createPasswordSpray } from './rules/password-spray.js';
import { createPossibleBreach } from './rules/possible-breach.js';
import { createUnusualHour } from './rules/unusual-hour.js';

/** @typedef {import('../types.js').AuthEvent} AuthEvent */
/** @typedef {import('../types.js').Finding} Finding */
/** @typedef {import('../types.js').AnalyzerOptions} AnalyzerOptions */
/** @typedef {import('../types.js').ResolvedOptions} ResolvedOptions */
/** @typedef {import('../types.js').LineInfo} LineInfo */
/** @typedef {import('../types.js').SourceSignal} SourceSignal */

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
 * @property {(info: LineInfo) => void} [onLine]  Every recognized line, for rules about the log itself.
 * @property {(signal: SourceSignal) => void} [onSignal]  Something the shell saw about the input (truncation).
 * @property {(finding: Finding) => void} [materialize]  Fill in derived fields before the finding is handed out.
 * @property {() => { keys: number, entries: number }} size  State held, for bounded-memory tests.
 */

/** @typedef {(ctx: RuleContext) => Rule} RuleFactory */

// Eviction follows the log's clock, so a single forged line from far in the
// future must not be able to age out every rule's state at once. A forward
// jump of more than an hour only moves the eviction clock once three events
// in a row agree with it. Detection itself always uses each event's own time.
const MAX_CLOCK_JUMP_MS = 60 * 60_000;
const JUMP_CONFIRMATIONS = 3;

/** The four rules of v0.1.0, which test/reference/ reimplements in batch form. */
export const ORIGINAL_RULES = /** @type {RuleFactory[]} */ ([createBruteForce, createPossibleBreach, createUnusualHour, createAccountChange]);

/** All rules, in the order they see each event. */
export const RULES = /** @type {RuleFactory[]} */ ([
  ...ORIGINAL_RULES, createPasswordSpray, createDistributedBruteForce, createNewSource, createLogTampering,
]);

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
 * @param {AnalyzerOptions} [options]
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
  let jumpVotes = 0;
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
   * Moves the eviction clock, unless this is an unconfirmed big jump forward.
   * @param {number} time
   */
  function observe(time) {
    const jump = clock !== -Infinity && time > clock + MAX_CLOCK_JUMP_MS;
    if (jump && ++jumpVotes < JUMP_CONFIRMATIONS) return;
    if (!jump && jumpVotes > 0) health.drop('engine: unconfirmed forward time jumps');
    jumpVotes = 0;
    if (time > clock) {
      clock = time;
      for (const rule of rules) rule.onAdvance?.(clock);
    }
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
      observe(event.time);
      for (const rule of rules) rule.onEvent(event);
    },

    /**
     * Reports a recognized line (whether or not it became an event). The
     * streaming path calls this for every line; `analyze(events)` can't, so
     * log-tampering only works on whole logs read through the CLI.
     * @param {LineInfo} info
     */
    line(info) {
      observe(info.time);
      for (const rule of rules) rule.onLine?.(info);
    },

    /** @param {SourceSignal} signal */
    signal(signal) {
      for (const rule of rules) rule.onSignal?.(signal);
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
