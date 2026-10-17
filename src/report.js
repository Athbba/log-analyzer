// Renders analysis results as a terminal report or as JSON. Times are the
// server's wall clock (see parse.js), so they are printed without a timezone.

import { styleText } from 'node:util';
import { safeText } from './core/text.js';
import { SEVERITIES } from './detectors.js';

/** @typedef {import('./types.js').Finding} Finding */
/** @typedef {import('./types.js').Incident} Incident */
/** @typedef {import('./types.js').Options} Options */
/** @typedef {import('./types.js').ParseStats} ParseStats */
/** @typedef {import('./types.js').Severity} Severity */
/**
 * Problems with the run itself: lines too long to read, and detector state
 * dropped because a limit was reached (core/bounded.js).
 * @typedef {{ oversizedLines: number, maxLineLength: number, evicted: Record<string, number> }} RunHealth
 */
/** @typedef {{ source: string, stats: ParseStats, options: Options, incidents: Incident[], health?: RunHealth }} Result */

/** @type {Record<Finding['rule'], string>} */
const LABELS = {
  'brute-force': 'brute force',
  'possible-breach': 'possible breach',
  'unusual-hour': 'unusual hour',
  'account-change': 'account change',
};
/** @type {Record<Severity, 'red' | 'yellow' | 'cyan'>} */
const COLORS = { high: 'red', medium: 'yellow', low: 'cyan' };
const INDENT = ' '.repeat(2 + 19 + 2 + 17);

/** @param {number} ms */
const stamp = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
/** @param {number} ms */
const hhmm = (ms) => stamp(ms).slice(11, 16);
/** @param {number} n */
const pad2 = (n) => String(n).padStart(2, '0');
/** @param {number} n */
const num = (n) => n.toLocaleString('en-US');
/** @param {number} n @param {string} word */
const plural = (n, word) => `${num(n)} ${word}${n === 1 ? '' : 's'}`;

/**
 * A duration as "1h 2m 3s", leaving out zero parts.
 * @param {number} ms
 */
export function duration(ms) {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  /** @type {[number, string][]} */
  const parts = [[Math.floor(s / 3600), 'h'], [Math.floor(s / 60) % 60, 'm'], [s % 60, 's']];
  return parts
    .filter(([n]) => n > 0)
    .map(([n, unit]) => `${n}${unit}`)
    .join(' ');
}

/**
 * @param {Incident[]} incidents
 * @returns {Record<Severity, number>}
 */
export function countBySeverity(incidents) {
  return /** @type {Record<Severity, number>} */ (
    Object.fromEntries(SEVERITIES.map((s) => [s, incidents.filter((i) => i.severity === s).length])));
}

/**
 * The terminal report.
 * @param {Result} result
 * @param {{ color?: boolean }} [options]
 */
export function formatText({ source, stats, options, incidents, health }, { color = false } = {}) {
  /** @param {Parameters<typeof styleText>[0]} style @param {string} text */
  const paint = (style, text) => (color ? styleText(style, text) : text);
  const [from, to] = options.night;
  const out = [
    paint('bold', `SSH auth log analysis: ${safeText(source)}`),
    `${plural(stats.lines, 'line')}` +
      (stats.first === null || stats.last === null ? '' : `, ${stamp(stats.first)} to ${stamp(stats.last)}`),
    `${plural(stats.failures, 'failed login')}, ${plural(stats.successes, 'successful login')}`,
  ];
  if (stats.unrecognized > 0) {
    out.push(paint('yellow', `Warning: skipped ${plural(stats.unrecognized, 'line')} not in a recognized syslog format.`));
  }
  if (health && health.oversizedLines > 0) {
    out.push(paint('yellow', `Warning: skipped ${plural(health.oversizedLines, 'line')} longer than ${num(health.maxLineLength)} bytes.`));
  }
  const dropped = health ? Object.entries(health.evicted) : [];
  if (dropped.length > 0) {
    const total = dropped.reduce((sum, [, n]) => sum + n, 0);
    out.push(paint('yellow', `Warning: detector state limits were reached (${num(total)} items dropped); some activity may be missed.`));
    for (const [what, n] of dropped) out.push(paint('yellow', `  ${what}: ${num(n)}`));
  }
  out.push(
    '',
    'Rules:',
    `  brute force      ${options.threshold}+ failed logins from one IP within ${duration(options.windowMs)}`,
    `  possible breach  a login from an IP with failed logins in the previous ${duration(options.lookbackMs)}`,
    `  unusual hour     a login between ${pad2(from)}:00 and ${pad2((to + 23) % 24)}:59`,
    `  account change   a new user, or a user added to ${options.adminGroups.join('/')}; high if made from an IP that broke in`,
  );

  for (const incident of incidents) {
    const source = incident.ip === null ? 'no single source IP' : safeText(incident.ip);
    out.push('', paint(['bold', COLORS[incident.severity]], incident.severity.toUpperCase().padEnd(8)) + paint('bold', source));
    for (const finding of incident.findings) {
      // Every line of a description mixes fixed text with log fields, so the
      // whole line is escaped.
      const [first, ...more] = describe(finding).map(safeText);
      out.push(`  ${paint('dim', stamp(finding.time))}  ${paint(COLORS[finding.severity], LABELS[finding.rule].padEnd(17))}${first}`);
      for (const line of more) out.push(INDENT + line);
    }
  }

  out.push('');
  if (incidents.length === 0) {
    out.push(paint('green', 'No suspicious activity found.'));
  } else {
    const counts = countBySeverity(incidents);
    const breakdown = SEVERITIES.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`).join(', ');
    out.push(paint('bold', `${plural(incidents.length, 'incident')}: ${breakdown}`));
  }
  return out.join('\n') + '\n';
}

/**
 * The text lines describing one finding.
 * @param {Finding} f
 * @returns {string[]}
 */
function describe(f) {
  switch (f.rule) {
    case 'brute-force': {
      const shown = f.users.slice(0, 5).map((u) => `${u.user} (${u.attempts})`).join(', ');
      const rest = f.users.length > 5 ? `, +${f.users.length - 5} more` : '';
      const invalid = f.invalidUsers > 0 ? `, ${num(f.invalidUsers)} nonexistent` : '';
      return [
        `${plural(f.attempts, 'failed login')} over ${duration(f.until - f.time)}`,
        `${plural(f.users.length, 'username')}${invalid}: ${shown}${rest}`,
        f.loggedIn
          ? `then logged in as ${f.loggedIn.user} (${f.loggedIn.method}) at ${stamp(f.loggedIn.time)}`
          : 'never logged in',
      ];
    }
    case 'possible-breach': {
      const gap = duration(f.time - f.firstFailure);
      const lines = [f.attempts === 1
        ? `${f.user} logged in (${f.method}) ${gap} after 1 failed login`
        : `${f.user} logged in (${f.method}) after ${num(f.attempts)} failed logins in the previous ${gap}`];
      if (!f.sameUser) lines.push(`the failures were for other usernames: ${f.users.map((u) => u.user).join(', ')}`);
      return lines;
    }
    case 'unusual-hour':
      return [`${f.user} logged in (${f.method}) at ${hhmm(f.time)}`];
    case 'account-change': {
      const rootUid = f.uid === 0 ? ' with UID 0 (same as root)' : '';
      const lines = [f.created
        ? `new user ${f.user}${rootUid}${f.groups.length ? `, member of ${f.groups.join(', ')}` : ''}`
        : `${f.user} added to ${f.groups.join(', ')}`];
      const ips = f.sessionIps.join(' or ');
      lines.push(f.by
        ? `by ${f.by} via sudo, ${ips ? `in a session from ${ips}` : `but ${f.by} had no SSH session open`}`
        : `no sudo record; ${ips ? `SSH sessions were open from ${ips}` : 'no SSH session was open'}`);
      if (f.afterBreach) {
        lines.push(`${f.ip} broke in as ${f.afterBreach.user} at ${stamp(f.afterBreach.time)} ` +
          `after ${plural(f.afterBreach.attempts, 'failed login')}`);
      }
      return lines;
    }
  }
}

/**
 * The JSON report. Times are printed as wall-clock ISO strings without a zone.
 * @param {Result} result
 */
export function formatJson({ source, stats, options, incidents, health }) {
  const timeKeys = new Set(['time', 'until', 'firstFailure', 'first', 'last']);
  const report = {
    source,
    stats,
    rules: {
      bruteForce: { threshold: options.threshold, windowSeconds: options.windowMs / 1000 },
      possibleBreach: { lookbackSeconds: options.lookbackMs / 1000 },
      unusualHour: { fromHour: options.night[0], toHour: options.night[1] },
      accountChange: { adminGroups: options.adminGroups },
    },
    summary: countBySeverity(incidents),
    ...(health && { health }),
    incidents,
  };
  /** @param {string} key @param {unknown} value */
  const replacer = (key, value) =>
    timeKeys.has(key) && typeof value === 'number' ? new Date(value).toISOString().slice(0, 19) : value;
  return JSON.stringify(report, replacer, 2) + '\n';
}
