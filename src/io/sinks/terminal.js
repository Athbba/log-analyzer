// Live-mode sinks for the terminal: a readable line per new or escalated
// incident, or one JSON object per incident event (--json). Every log field is
// escaped for the terminal (core/text.js).

import { styleText } from 'node:util';
import { withAttack } from '../../core/attack.js';
import { safeText } from '../../core/text.js';
import { LABELS, attackLine, describe, stamp } from '../../report.js';

/** @typedef {import('../../core/live-incidents.js').IncidentEvent} IncidentEvent */
/** @typedef {import('../live.js').Sink} Sink */

const COLORS = /** @type {const} */ ({ high: 'red', medium: 'yellow', low: 'cyan' });

/**
 * @param {{ write: (text: string) => void, color?: boolean, minSeverity?: 'high' | 'medium' | 'low' }} options
 * @returns {Sink}
 */
export function createTerminalSink({ write, color = false, minSeverity = 'low' }) {
  const order = ['high', 'medium', 'low'];
  /** @param {Parameters<typeof styleText>[0]} style @param {string} text */
  const paint = (style, text) => (color ? styleText(style, text) : text);
  return {
    name: 'terminal',
    onIncident({ type, incident, finding, firstSeen }) {
      // New and escalated incidents, and new findings joining an open one.
      const shown = type === 'opened' || type === 'escalated' || (type === 'updated' && firstSeen);
      if (!shown || !finding) return;
      if (order.indexOf(incident.severity) > order.indexOf(minSeverity)) return;
      const where = safeText(incident.ip ?? incident.subject ?? 'no single source IP');
      const what = type === 'opened' ? 'new' : type === 'escalated' ? 'now' : 'also';
      const [first, ...more] = describe(finding).map(safeText);
      write(`${paint('dim', stamp(finding.time))}  ${paint(['bold', COLORS[incident.severity]], `${incident.severity.toUpperCase()} (${what})`.padEnd(14))}`
        + `${paint('bold', where)}  ${LABELS[finding.rule]}: ${first}\n`);
      for (const line of more) write(`${' '.repeat(35)}${line}\n`);
      const attack = attackLine(finding);
      if (attack) write(`${' '.repeat(35)}${paint('dim', attack)}\n`);
    },
    onNotice(message) {
      write(`${paint('dim', `note: ${safeText(message)}`)}\n`);
    },
  };
}

/**
 * One JSON object per line, per incident event. Times are wall-clock ISO
 * strings without a zone, as in the batch JSON report.
 * @param {{ write: (text: string) => void }} options
 * @returns {Sink}
 */
export function createJsonLinesSink({ write }) {
  const timeKeys = new Set(['time', 'until', 'last', 'firstFailure']);
  /** @param {string} key @param {unknown} value */
  const replacer = (key, value) => (timeKeys.has(key) && typeof value === 'number' ? new Date(value).toISOString().slice(0, 19) : value);
  return {
    name: 'json',
    onIncident({ type, incident, finding }) {
      const { key, ...shown } = incident;
      void key;
      const labelled = { ...shown, findings: shown.findings.map(withAttack) };
      write(`${JSON.stringify({ event: type, incident: labelled, finding: finding && withAttack(finding) }, replacer)}\n`);
    },
    onNotice(message) {
      write(`${JSON.stringify({ event: 'notice', message })}\n`);
    },
  };
}
