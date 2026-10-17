// Analyzes a byte stream (a file or stdin) line by line. Events go straight
// from the parser into the engine and are never collected, so memory depends
// on the detectors' bounded state and the findings, not on the log's length.

import { createEngine } from '../core/engine.js';
import { toIncidents } from '../core/incidents.js';
import { createParser } from '../core/parse.js';
import { readLines } from './read-lines.js';

/** @typedef {import('../types.js').AnalyzerOptions} AnalyzerOptions */
/** @typedef {import('../report.js').RunHealth} RunHealth */
/** @typedef {import('../types.js').AuthEvent} AuthEvent */
/** @typedef {import('../types.js').LineInfo} LineInfo */

/**
 * Called for every line, with what it parsed to (for storage).
 * @typedef {(line: { text: string, lineNo: number, event: AuthEvent | null, info: LineInfo | null }) => void} LineTap
 */

export const MAX_LINE_LENGTH = 8192;

/**
 * @param {AsyncIterable<Buffer | string>} stream
 * @param {object} [settings]
 * @param {AnalyzerOptions} [settings.options]
 * @param {number} [settings.year]  Year of the first syslog line.
 * @param {number} [settings.now]  For the year guess; defaults to the current time.
 * @param {number} [settings.maxLineLength]
 * @param {LineTap} [settings.tap]
 */
export async function analyzeStream(stream, { options = {}, year, now = Date.now(), maxLineLength = MAX_LINE_LENGTH, tap } = {}) {
  const { lines, splitter } = readLines(stream, { maxLength: maxLineLength });
  const parser = createParser({ year, now });
  const engine = createEngine(options);
  let lineNo = 0;
  for await (const line of lines) {
    const { event, info } = parser.read(line, ++lineNo);
    if (info) engine.line(info);
    if (event) engine.push(event);
    tap?.({ text: line, lineNo, event, info });
  }
  /** @type {RunHealth} */
  const health = { oversizedLines: splitter.oversized, maxLineLength, evicted: { ...engine.health.evicted } };
  const incidents = toIncidents(engine.findings(), { ipv6Prefix: engine.options.ipv6Prefix });
  return { stats: parser.stats, incidents, health, options: engine.options };
}
