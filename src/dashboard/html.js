// HTML built from template literals where every interpolated value is
// escaped unless it is already an Html fragment made the same way. Forgetting
// to escape is not possible: a plain string can't get into the page raw.
//
//   html`<td>${user}</td>`             user is escaped
//   html`<ul>${items.map(...)}</ul>`   arrays of fragments are joined
//
// Escaping also neutralizes the characters a forged log line can use to
// mislead a reader (control characters, bidi overrides), as the terminal
// report does (core/text.js).

import { safeText } from '../core/text.js';

/** A piece of HTML that is safe to include as is. */
export class Html {
  /** @param {string} value */
  constructor(value) {
    this.value = value;
  }

  toString() {
    return this.value;
  }
}

const ENTITIES = /** @type {Record<string, string>} */ ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' });

/**
 * Text as HTML: safe in element content and in quoted attribute values.
 * @param {string} text
 */
export function escapeHtml(text) {
  return safeText(text).replace(/[&<>"'`]/g, (c) => ENTITIES[c]);
}

/** @typedef {Html | string | number | boolean | null | undefined | (Html | string | null | undefined)[]} Value */

/**
 * @param {Value} value
 * @returns {string}
 */
function render(value) {
  if (value instanceof Html) return value.value;
  if (Array.isArray(value)) return value.map(render).join('');
  if (value === null || value === undefined || value === false) return '';
  return escapeHtml(String(value));
}

/**
 * @param {TemplateStringsArray} strings
 * @param {...Value} values
 */
export function html(strings, ...values) {
  let out = strings[0];
  values.forEach((value, i) => {
    out += render(value) + strings[i + 1];
  });
  return new Html(out);
}

/**
 * A URL path with query parameters, every part encoded. Only same-site paths
 * are built this way, so log content can never become a javascript: link.
 * @param {string} path  A fixed path such as "/incidents/3".
 * @param {Record<string, string | number | undefined | string[]>} [query]
 */
export function href(path, query = {}) {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('href() builds same-site paths only');
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    for (const v of [value].flat()) if (v !== undefined && v !== '') params.append(key, String(v));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}
