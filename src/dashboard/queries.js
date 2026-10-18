// Read-only queries for the dashboard. Every value from the request is a
// bound parameter, and filter values are checked against fixed lists first.

import { evidence } from '../io/store.js';

/** @typedef {import('node:sqlite').DatabaseSync} DatabaseSync */
/** @typedef {import('../types.js').Finding} Finding */

export const SEVERITIES = ['high', 'medium', 'low'];
export const RULES = [
  'brute-force', 'password-spray', 'distributed-brute-force', 'possible-breach',
  'new-source', 'unusual-hour', 'account-change', 'log-tampering',
];

/**
 * @typedef {object} Filters
 * @property {string[]} severities  Subset of SEVERITIES; empty means all.
 * @property {string | null} rule  One of RULES, or null for any.
 * @property {string} q  Text to find in the source IP, subject or users ('' for none).
 * @property {number | null} [from] Inclusive server-clock range start.
 * @property {number | null} [to] Inclusive server-clock range end.
 */

/** @param {DatabaseSync} db */
export function listRuns(db) {
  return /** @type {{ id: number, source: string, mode: string, started_at: string }[]} */ (
    db.prepare('SELECT id, source, mode, started_at FROM runs ORDER BY id DESC LIMIT 50').all());
}

/**
 * @param {DatabaseSync} db
 * @param {number} id
 */
export function runSummary(db, id) {
  const run = /** @type {any} */ (db.prepare('SELECT id, source, mode, started_at, finished_at, stats FROM runs WHERE id = ?').get(id));
  if (!run) return null;
  const span = /** @type {{ first: number | null, last: number | null, lines: number }} */ (
    db.prepare('SELECT MIN(time) AS first, MAX(time) AS last, COUNT(*) AS lines FROM lines WHERE run = ?').get(id));
  return { ...run, stats: run.stats ? JSON.parse(run.stats) : null, ...span };
}

/**
 * Validated, bound predicates shared by the list and uncapped totals.
 * @param {number} run
 * @param {Filters} filters
 */
function incidentWhere(run, { severities, rule, q, from, to }) {
  const where = ['i.run = ?'];
  /** @type {(string | number)[]} */
  const params = [run];
  const chosen = severities.filter((s) => SEVERITIES.includes(s));
  if (chosen.length > 0) {
    where.push(`i.severity IN (${chosen.map(() => '?').join(', ')})`);
    params.push(...chosen);
  }
  if (rule !== null && RULES.includes(rule)) {
    where.push('EXISTS (SELECT 1 FROM findings r WHERE r.incident = i.id AND r.rule = ?)');
    params.push(rule);
  }
  if (q !== '') {
    const like = `%${q.replace(/[!%_]/g, (c) => `!${c}`)}%`;
    where.push(`(i.ip LIKE ? ESCAPE '!' OR i.subject LIKE ? ESCAPE '!'
      OR EXISTS (SELECT 1 FROM findings u WHERE u.incident = i.id AND u.user LIKE ? ESCAPE '!'))`);
    params.push(like, like, like);
  }
  if (from !== undefined && from !== null) { where.push('i.last >= ?'); params.push(from); }
  if (to !== undefined && to !== null) { where.push('i.time <= ?'); params.push(to); }
  return { where: where.join(' AND '), params };
}

/** @param {DatabaseSync} db @param {number} run @param {Filters} filters */
export function incidentsFor(db, run, filters) {
  const { where, params } = incidentWhere(run, filters);
  return /** @type {{ id: number, ip: string | null, subject: string | null, severity: string, time: number, last: number, closed: number, findings: number, rules: string }[]} */ (
    db.prepare(`SELECT i.id, i.ip, i.subject, i.severity, i.time, i.last, i.closed,
        COUNT(f.id) AS findings, group_concat(DISTINCT f.rule) AS rules
      FROM incidents i JOIN findings f ON f.incident = i.id
      WHERE ${where}
      GROUP BY i.id
      ORDER BY CASE i.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, i.time, i.id
      LIMIT 500`).all(...params));
}

/** Counts the complete matching set, before the 500-row display cap.
 * @param {DatabaseSync} db @param {number} run @param {Filters} filters
 */
export function incidentCounts(db, run, filters) {
  const { where, params } = incidentWhere(run, filters);
  const rows = /** @type {{ severity: string, n: number }[]} */ (db.prepare(
    `SELECT i.severity, COUNT(*) AS n FROM incidents i WHERE ${where} GROUP BY i.severity`).all(...params));
  const counts = { high: 0, medium: 0, low: 0, total: 0 };
  for (const row of rows) {
    if (row.severity === 'high' || row.severity === 'medium' || row.severity === 'low') counts[row.severity] = row.n;
    counts.total += row.n;
  }
  return counts;
}

/**
 * How many incidents a run has, unfiltered and uncapped.
 * @param {DatabaseSync} db
 * @param {number} run
 */
export function countIncidents(db, run) {
  return Number(/** @type {{ n: number }} */ (db.prepare('SELECT COUNT(*) AS n FROM incidents WHERE run = ?').get(run)).n);
}

/**
 * An incident with its findings and, for each, the raw lines behind it.
 * @param {DatabaseSync} db
 * @param {number} id
 * @param {number} [linesPerFinding]
 * @param {number} [maxFindings]  An incident from one file can hold any number of findings.
 */
export function incidentDetail(db, id, linesPerFinding = 60, maxFindings = 200) {
  const incident = /** @type {any} */ (db.prepare('SELECT * FROM incidents WHERE id = ?').get(id));
  if (!incident) return null;
  const rows = /** @type {{ id: number, data: string }[]} */ (
    db.prepare('SELECT id, data FROM findings WHERE incident = ? ORDER BY time, id LIMIT ?').all(id, maxFindings));
  const total = Number(/** @type {{ n: number }} */ (db.prepare('SELECT COUNT(*) AS n FROM findings WHERE incident = ?').get(id)).n);
  const findings = rows.map((row) => {
    /** @type {Finding} */
    const finding = JSON.parse(row.data);
    const lines = evidence(db, incident.run, finding, linesPerFinding + 1);
    return { id: row.id, finding, lines: lines.slice(0, linesPerFinding), more: lines.length > linesPerFinding };
  });
  return { incident, findings, total };
}

/**
 * Failed logins over the run, in `buckets` equal slices of its time span.
 * @param {DatabaseSync} db
 * @param {number} run
 * @param {number} first
 * @param {number} last
 * @param {number} buckets
 */
export function failureTrace(db, run, first, last, buckets) {
  const span = Math.max(1, last - first);
  const counts = new Array(buckets).fill(0);
  const rows = /** @type {{ bucket: number, n: number }[]} */ (db.prepare(
    `SELECT MIN(CAST((time - ?) * ? / ? AS INTEGER), ?) AS bucket, SUM(count) AS n
     FROM events WHERE run = ? AND type = 'failure' GROUP BY bucket`).all(first, buckets, span, buckets - 1, run));
  for (const { bucket, n } of rows) if (bucket >= 0) counts[bucket] = n;
  return counts;
}

