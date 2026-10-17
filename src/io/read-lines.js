// Reads lines from a byte stream (a file or stdin) with a cap on line length.
// See core/lines.js for why this replaces readline.

import { LineSplitter } from '../core/lines.js';

/**
 * @param {AsyncIterable<Buffer | string>} stream
 * @param {{ maxLength?: number }} [options]
 * @returns {{ lines: AsyncGenerator<string>, splitter: LineSplitter }}
 *   `splitter.oversized` counts the lines that were cut off.
 */
export function readLines(stream, { maxLength } = {}) {
  const splitter = new LineSplitter(maxLength);
  async function* lines() {
    for await (const chunk of stream) {
      yield* splitter.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    const last = splitter.end();
    if (last !== null) yield last;
  }
  return { lines: lines(), splitter };
}
