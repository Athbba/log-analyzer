// Makes log-derived text safe to print in a terminal. Usernames, hosts and
// commands come from the log, and a line forged with `logger` can carry
// anything: escape sequences that rewrite the analyst's screen, newlines that
// fake extra report lines, or Unicode bidi overrides that display text in a
// different order than it is stored. All of those are shown as visible escapes.

// C0 controls (including tab and newline), DEL, and C1 controls.
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL = /[\x00-\x1f\x7f-\x9f]/g;
// Bidi embeddings, overrides and isolates; zero-width and other invisible
// format characters; the BOM. Built from code points so that no invisible
// character appears in this source file.
const INVISIBLE = new RegExp(`[${[[0x061c, 0x061c], [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2069], [0xfeff, 0xfeff]]
  .map(([from, to]) => `${String.fromCharCode(from)}-${String.fromCharCode(to)}`)
  .join('')}]`, 'g');

/**
 * @param {string} text
 * @returns {string}
 */
export function safeText(text) {
  return text
    .replace(CONTROL, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
    .replace(INVISIBLE, (c) => `\\u{${c.charCodeAt(0).toString(16)}}`);
}
