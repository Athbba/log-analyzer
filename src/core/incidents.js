// Groups findings into incidents, one per source IP, so one attacker's brute
// force, break-in, night-time login and backdoor account read as one story.

import { SEVERITIES } from './options.js';

/** @typedef {import('../types.js').Finding} Finding */
/** @typedef {import('../types.js').Incident} Incident */
/** @typedef {import('../types.js').Severity} Severity */

export const RULE_ORDER = ['brute-force', 'possible-breach', 'unusual-hour', 'account-change'];

/** @param {Severity} severity */
const rank = (severity) => SEVERITIES.indexOf(severity);

/**
 * Within an incident, findings are in time order (ties: rule order, then the
 * order they were found). Incidents are most severe first, then earliest,
 * then by IP, so the order is fully determined.
 * @param {Finding[]} findings  In the order they were found.
 * @returns {Incident[]}
 */
export function toIncidents(findings) {
  /** @type {Map<string | null, Finding[]>} */
  const byIp = new Map();
  for (const finding of findings) {
    const list = byIp.get(finding.ip);
    if (list) list.push(finding);
    else byIp.set(finding.ip, [finding]);
  }
  return [...byIp]
    .map(([ip, list]) => {
      list.sort((a, b) => a.time - b.time || RULE_ORDER.indexOf(a.rule) - RULE_ORDER.indexOf(b.rule));
      const severity = SEVERITIES[Math.min(...list.map((f) => rank(f.severity)))];
      return { ip, severity, time: list[0].time, findings: list };
    })
    .sort((a, b) => rank(a.severity) - rank(b.severity) || a.time - b.time || compareIps(a.ip, b.ip));
}

/**
 * @param {string | null} a
 * @param {string | null} b
 */
function compareIps(a, b) {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return a < b ? -1 : 1;
}
