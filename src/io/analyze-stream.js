// Analyzes a byte stream (a file or stdin) line by line. Events go straight
// from the parser into the engine and are never collected, so memory depends
// on the detectors' bounded state and the findings, not on the log's length.

import { createEngine } from '../core/engine.js';
import { toIncidents } from '../core/incidents.js';
import { createParser } from '../core/parse.js';
import { readLines } from './read-lines.js';

/** @typedef {import('../types.js').Options} Options */
/** @typedef {import('../types.js').Limits} Limits */
/** @typedef {import('../report.js').RunHealth} RunHealth */

export const MAX_LINE_LENGTH = 8192;

/**
 * @param {AsyncIterable<Buffer | string>} stream
 * @param {object} [settings]
 * @param {Partial<Options> & { limits?: Partial<Limits> }} [settings.options]
 * @param {number} [settings.year]  Year of the first syslog line.
 * @param {number} [settings.now]  For the year guess; defaults to the current time.
 * @param {number} [settings.maxLineLength]
 */
export async function analyzeStream(stream, { options = {}, year, now = Date.now(), maxLineLength = MAX_LINE_LENGTH } = {}) {
  const { lines, splitter } = readLines(stream, { maxLength: maxLineLength });
  const parser = createParser({ year, now });
  const engine = createEngine(options);
  let lineNo = 0;
  for await (const line of lines) {
    const event = parser.parse(line, ++lineNo);
    if (event) engine.push(event);
  }
  /** @type {RunHealth} */
  const health = { oversizedLines: splitter.oversized, maxLineLength, evicted: { ...engine.health.evicted } };
  return { stats: parser.stats, incidents: toIncidents(engine.findings()), health, options: engine.options };
}
