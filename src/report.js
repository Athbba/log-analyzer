// Renders analysis results as a terminal report or as JSON. Times are the
// server's wall clock (see parse.js), so they are printed without a timezone.

import { styleText } from 'node:util';
import { techniquesFor, withAttack } from './core/attack.js';
import { safeText } from './core/text.js';
import { SEVERITIES } from './detectors.js';

/** @typedef {import('./types.js').Finding} Finding */
/** @typedef {import('./types.js').Incident} Incident */
/** @typedef {import('./types.js').ResolvedOptions} Options */
/** @typedef {import('./types.js').ParseStats} ParseStats */
/** @typedef {import('./types.js').Severity} Severity */
/**
 * Problems with the run itself: lines too long to read, and detector state
 * dropped because a limit was reached (core/bounded.js).
 * @typedef {{ oversizedLines: number, maxLineLength: number, evicted: Record<string, number> }} RunHealth
 */
/** @typedef {{ source: string, stats: ParseStats, options: Options, incidents: Incident[], health?: RunHealth }} Result */

/** Short names of the rules, as printed. */
/** @type {Record<Finding['rule'], string>} */
export const LABELS = {
  'brute-force': 'brute force',
  'possible-breach': 'possible breach',
  'unusual-hour': 'unusual hour',
  'account-change': 'account change',
  'password-spray': 'password spray',
  'distributed-brute-force': 'distributed',
  'new-source': 'new source',
  'log-tampering': 'log tampering',
};
/** @type {Record<Severity, 'red' | 'yellow' | 'cyan'>} */
const COLORS = { high: 'red', medium: 'yellow', low: 'cyan' };
const INDENT = ' '.repeat(2 + 19 + 2 + 17);

/** A wall-clock time as "2026-09-09 03:39:12". @param {number} ms */
export const stamp = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
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
  const { spray, distributed, newSource, tampering } = options;
  if (spray.enabled) {
    out.push(`  password spray   ${spray.minUsers}+ real accounts from one source within ${duration(spray.windowMs)}, at most ${spray.maxAttemptsPerUser} tries each`);
  }
  if (distributed.enabled) {
    out.push(`  distributed      one account guessed from ${distributed.minSources}+ sources (${distributed.minAttempts}+ failures) within ${duration(distributed.windowMs)}`);
  }
  if (newSource.enabled) {
    out.push(`  new source       a login from a network the user hasn't logged in from before (after ${duration(newSource.learningMs)} of learning)`);
  }
  if (tampering.enabled) {
    out.push(`  log tampering    no lines for ${duration(tampering.maxGapMs)}, time going back ${duration(tampering.maxBackwardsMs)}+, NUL bytes, or truncation`);
  }

  for (const incident of incidents) {
    const source = safeText(incident.ip ?? incident.subject ?? 'no single source IP');
    out.push('', paint(['bold', COLORS[incident.severity]], incident.severity.toUpperCase().padEnd(8)) + paint('bold', source));
    for (const finding of incident.findings) {
      // Every line of a description mixes fixed text with log fields, so the
      // whole line is escaped.
      const [first, ...more] = describe(finding).map(safeText);
      out.push(`  ${paint('dim', stamp(finding.time))}  ${paint(COLORS[finding.severity], LABELS[finding.rule].padEnd(17))}${first}`);
      for (const line of more) out.push(INDENT + line);
      out.push(INDENT + paint('dim', attackLine(finding)));
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
 * A finding's ATT&CK techniques as one line, e.g. "ATT&CK T1110.001 Brute
 * Force: Password Guessing". Fixed text only, no log fields.
 * @param {Finding} finding
 */
export const attackLine = (finding) =>
  `ATT&CK ${techniquesFor(finding).map((t) => `${t.id} ${t.name}`).join(', ')}`;

/**
 * The text lines describing one finding. They contain log fields: escape them
 * for the medium they are shown in.
 * @param {Finding} f
 * @returns {string[]}
 */
export function describe(f) {
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
    case 'password-spray': {
      const shown = f.users.slice(0, 5).map((u) => `${u.user} (${u.attempts})`).join(', ');
      const rest = f.users.length > 5 ? `, +${f.users.length - 5} more` : '';
      return [
        `${plural(f.userCount, 'account')} tried a few times each, ${plural(f.attempts, 'failed login')} over ${duration(f.until - f.time)}`,
        `${shown}${rest}`,
        f.loggedIn
          ? `then logged in as ${f.loggedIn.user} (${f.loggedIn.method}) at ${stamp(f.loggedIn.time)}`
          : 'never logged in as any of them',
      ];
    }
    case 'distributed-brute-force': {
      const shown = f.sources.slice(0, 5).map((s) => `${s.ip} (${s.attempts})`).join(', ');
      const rest = f.sourceCount > 5 ? `, +${f.sourceCount - 5} more` : '';
      return [
        `${f.user}: ${plural(f.attempts, 'failed login')} from ${plural(f.sourceCount, 'source')} over ${duration(f.until - f.time)}`,
        `${shown}${rest}`,
        f.loggedIn
          ? `then ${f.user} logged in from ${f.loggedIn.ip} (${f.loggedIn.method}) at ${stamp(f.loggedIn.time)}`
          : 'no login from any of them',
      ];
    }
    case 'new-source':
      return [
        `${f.user} logged in (${f.method}) from ${f.network}, a network not seen for ${f.user} before`,
        `previously from ${plural(f.knownNetworks, 'other network')}`,
      ];
    case 'log-tampering':
      return [f.detail, f.kind === 'gap' ? `from ${stamp(f.time)} to ${stamp(f.until)}` : `noticed at line ${num(f.line)}`];
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
    incidents: incidents.map((i) => ({ ...i, findings: i.findings.map(withAttack) })),
  };
  /** @param {string} key @param {unknown} value */
  const replacer = (key, value) =>
    timeKeys.has(key) && typeof value === 'number' ? new Date(value).toISOString().slice(0, 19) : value;
  return JSON.stringify(report, replacer, 2) + '\n';
}
