// Public API for running the rules over a list of events. The rules
// themselves live in core/rules/ and run on the streaming engine
// (core/engine.js); this module keeps the original `analyze()` entry point.

import { createEngine } from './core/engine.js';
import { toIncidents } from './core/incidents.js';

export { DEFAULTS, DEFAULT_LIMITS, SEVERITIES } from './core/options.js';

/** @typedef {import('./types.js').AuthEvent} AuthEvent */
/** @typedef {import('./types.js').Options} Options */
/** @typedef {import('./types.js').Limits} Limits */
/** @typedef {import('./types.js').Incident} Incident */

/**
 * Runs every rule over `events` and returns incidents (one per IP), most
 * severe first. The events are sorted by time first (stably, so lines with
 * the same timestamp keep their order); the streaming CLI path feeds events
 * in log order instead and never holds them all.
 * @param {AuthEvent[]} events
 * @param {Partial<Options> & { limits?: Partial<Limits> }} [options]
 * @returns {Incident[]}
 */
export function analyze(events, options = {}) {
  const engine = createEngine(options);
  for (const event of [...events].sort((a, b) => a.time - b.time || a.line - b.line)) engine.push(event);
  return toIncidents(engine.findings());
}
