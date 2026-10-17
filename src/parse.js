// Public API for parsing a whole log. The line parser itself is pure and
// lives in core/parse.js; this wrapper iterates the lines and supplies the
// current time for the year guess.

import { createParser } from './core/parse.js';

export { createParser } from './core/parse.js';

/** @typedef {import('./types.js').AuthEvent} AuthEvent */
/** @typedef {import('./types.js').ParseStats} ParseStats */

/**
 * Reads lines from any iterable or async iterable and returns the events in
 * file order plus counters. Line endings may be LF or CRLF. `year` is the year
 * of the first syslog line; without it, the year is chosen so the log doesn't
 * start in the future (`now` defaults to the current time).
 * @param {Iterable<string> | AsyncIterable<string>} lines
 * @param {{ year?: number, now?: number }} [options]
 * @returns {Promise<{ events: AuthEvent[], stats: ParseStats }>}
 */
export async function parseLines(lines, { year, now = Date.now() } = {}) {
  const parser = createParser({ year, now });
  /** @type {AuthEvent[]} */
  const events = [];
  let lineNo = 0;
  for await (const raw of lines) {
    lineNo++;
    const event = parser.parse(raw.endsWith('\r') ? raw.slice(0, -1) : raw, lineNo);
    if (event) events.push(event);
  }
  return { events, stats: parser.stats };
}
