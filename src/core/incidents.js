// Groups findings into incidents, so one attacker's brute force, break-in,
// night-time login and backdoor account read as one story. Findings group by
// source (an IPv4 address, or an IPv6 /64 by default, since one attacker
// usually holds a whole /64). Findings with no single source group by what
// they are about: a distributed attack on one account, or the log itself.

import { SEVERITIES } from './options.js';
import { sourceOf } from './net.js';

/** @typedef {import('../types.js').Finding} Finding */
/** @typedef {import('../types.js').Incident} Incident */
/** @typedef {import('../types.js').Severity} Severity */

export const RULE_ORDER = [
  'brute-force', 'password-spray', 'distributed-brute-force', 'possible-breach',
  'new-source', 'unusual-hour', 'account-change', 'log-tampering',
];

/** @param {Severity} severity */
const rank = (severity) => SEVERITIES.indexOf(severity);

/**
 * What a finding with no source IP is about, if anything.
 * @param {Finding} f
 * @returns {string | null}
 */
function subjectOf(f) {
  if (f.rule === 'distributed-brute-force') return `user ${f.user}`;
  if (f.rule === 'log-tampering') return 'the log itself';
  return null;
}

/**
 * Within an incident, findings are in time order (ties: rule order, then the
 * order they were found). Incidents are most severe first, then earliest,
 * then by key, so the order is fully determined.
 * @param {Finding[]} findings  In the order they were found.
 * @param {{ ipv6Prefix?: number }} [options]
 * @returns {Incident[]}
 */
export function toIncidents(findings, { ipv6Prefix = 64 } = {}) {
  /** @type {Map<string, { ip: string | null, subject: string | null, findings: Finding[] }>} */
  const groups = new Map();
  for (const finding of findings) {
    const ip = finding.ip === null ? null : sourceOf(finding.ip, ipv6Prefix);
    const subject = ip === null ? subjectOf(finding) : null;
    const key = ip !== null ? `ip ${ip}` : `subject ${subject}`;
    const group = groups.get(key);
    if (group) group.findings.push(finding);
    else groups.set(key, { ip, subject, findings: [finding] });
  }
  return [...groups.values()]
    .map(({ ip, subject, findings: list }) => {
      list.sort((a, b) => a.time - b.time || RULE_ORDER.indexOf(a.rule) - RULE_ORDER.indexOf(b.rule));
      const severity = SEVERITIES[Math.min(...list.map((f) => rank(f.severity)))];
      return { ip, subject, severity, time: list[0].time, findings: list };
    })
    .sort((a, b) => rank(a.severity) - rank(b.severity) || a.time - b.time || compare(a, b));
}

/**
 * IP incidents before subject incidents before the unattributed one.
 * @param {Incident} a
 * @param {Incident} b
 */
function compare(a, b) {
  const keyOf = (/** @type {Incident} */ i) => (i.ip !== null ? `0 ${i.ip}` : i.subject !== null ? `1 ${i.subject}` : '2');
  const [x, y] = [keyOf(a), keyOf(b)];
  return x < y ? -1 : x > y ? 1 : 0;
}
