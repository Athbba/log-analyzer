// Labels say which incidents a log must produce: for each source IP, the
// exact findings as "rule:severity". Used by the lab runner and by the
// fixture tests, so a fresh lab run and the committed fixture are judged by
// the same rules.

import { readFileSync } from 'node:fs';
import { analyze } from '../../src/detectors.js';
import { parseLines } from '../../src/parse.js';

/**
 * @typedef {object} LabelledIncident
 * @property {string} scenario  The scenario that produces it.
 * @property {string | null} [ip]  Source IP; null for findings with no single IP.
 * @property {string} [subject]  For incidents with no IP: their subject, e.g. "user dave".
 * @property {string[]} findings  Expected findings as "rule:severity", in any order.
 */

/**
 * @typedef {object} Labels
 * @property {string} description
 * @property {number} [year]  For syslog timestamps, which have no year.
 * @property {boolean} exhaustive  If true, any other incident is a mismatch.
 * @property {LabelledIncident[]} incidents
 */

/**
 * @param {string} path
 * @returns {Labels}
 */
export function loadLabels(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * Compares the analyzer's incidents on `text` with the labels.
 * @param {string} text  The whole log.
 * @param {Labels} labels
 * @returns {Promise<string[]>} One message per mismatch; empty when it all matches.
 */
export async function checkLabels(text, labels) {
  const { events, stats } = await parseLines(text.split('\n'), labels.year === undefined ? {} : { year: labels.year });
  const incidents = analyze(events);
  const problems = [];
  if (stats.unrecognized > 0) problems.push(`${stats.unrecognized} unrecognized lines`);

  /** @param {{ rule: string, severity: string }[]} findings */
  const summary = (findings) => findings.map((f) => `${f.rule}:${f.severity}`).sort().join(', ');
  /** @param {{ ip?: string | null, subject?: string | null }} x */
  const keyOf = (x) => (x.subject ? `subject ${x.subject}` : `ip ${x.ip ?? null}`);
  const seen = new Set();
  for (const label of labels.incidents) {
    const key = keyOf(label);
    const incident = incidents.find((i) => keyOf(i) === key);
    seen.add(key);
    const name = label.subject ?? label.ip;
    const expected = [...label.findings].sort().join(', ');
    if (!incident) {
      problems.push(`${label.scenario}: no incident for ${name}, expected ${expected}`);
    } else if (summary(incident.findings) !== expected) {
      problems.push(`${label.scenario}: ${name} has ${summary(incident.findings)}, expected ${expected}`);
    }
  }
  if (labels.exhaustive) {
    for (const incident of incidents.filter((i) => !seen.has(keyOf(i)))) {
      problems.push(`unexpected incident for ${incident.subject ?? incident.ip}: ${summary(incident.findings)}`);
    }
  }
  return problems;
}
