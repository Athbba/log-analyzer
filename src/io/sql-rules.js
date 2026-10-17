// Two rules written again in SQL, over the events table: brute force and
// unusual hour. They exist to cross-check the JavaScript rules from a second,
// independent implementation (tests require identical findings), and to let a
// stored run be re-examined with different settings without re-reading the
// log.
//
// Ordering follows the engine's: by time, then by line, so lines with the same
// timestamp count in the order they were written.

/** @typedef {import('node:sqlite').DatabaseSync} DatabaseSync */
/** @typedef {import('../types.js').BruteForceFinding} BruteForceFinding */
/** @typedef {import('../types.js').UnusualHourFinding} UnusualHourFinding */
/** @typedef {import('../types.js').ResolvedOptions} ResolvedOptions */

/**
 * Brute force: a failure is "hot" if some window of `windowMs` ending at a
 * failure from the same source (and containing only failures logged up to
 * it) adds up to `threshold`. Hot failures no more than a window apart form
 * one attack. The attack is high if the source logs in at or after its start,
 * within `memoryMs`.
 */
const BRUTE_FORCE = `
WITH failure AS (
  SELECT line, time, source, user, invalid_user, count
  FROM events WHERE run = :run AND type = 'failure'
),
window_end AS (
  -- For each failure, the failures in the window that ends at it.
  SELECT a.source, a.time, a.line,
    (SELECT SUM(b.count) FROM failure b
      WHERE b.source = a.source AND b.time >= a.time - :window
        AND (b.time < a.time OR (b.time = a.time AND b.line <= a.line))) AS in_window
  FROM failure a
),
hot AS (
  SELECT DISTINCT f.line, f.time, f.source, f.user, f.invalid_user, f.count
  FROM failure f JOIN window_end w
    ON w.source = f.source AND w.in_window >= :threshold
   AND f.time >= w.time - :window
   AND (f.time < w.time OR (f.time = w.time AND f.line <= w.line))
),
numbered AS (
  SELECT *, SUM(starts) OVER (PARTITION BY source ORDER BY time, line) AS attack
  FROM (
    SELECT *, CASE WHEN time - LAG(time) OVER (PARTITION BY source ORDER BY time, line) <= :window THEN 0 ELSE 1 END AS starts
    FROM hot
  )
),
attack AS (
  SELECT source, attack, MIN(time) AS time, MAX(time) AS until, SUM(count) AS attempts,
    COUNT(DISTINCT CASE WHEN invalid_user THEN user END) AS invalid_users
  FROM numbered GROUP BY source, attack
),
tally AS (
  SELECT source, attack, user, SUM(count) AS attempts FROM numbered GROUP BY source, attack, user
)
SELECT a.source, a.time, a.until, a.attempts, a.invalid_users,
  (SELECT json_group_array(json_object('user', user, 'attempts', attempts))
     FROM (SELECT user, attempts FROM tally t WHERE t.source = a.source AND t.attack = a.attack
           ORDER BY attempts DESC, user)) AS users,
  (SELECT json_object('time', s.time, 'user', s.user, 'method', s.method)
     FROM events s WHERE s.run = :run AND s.type = 'success' AND s.source = a.source
      AND s.time >= a.time AND s.time - a.time <= :memory
     ORDER BY s.time, s.line LIMIT 1) AS logged_in
FROM attack a
ORDER BY a.time, a.source`;

/**
 * @param {DatabaseSync} db
 * @param {number} run
 * @param {ResolvedOptions} options
 * @returns {BruteForceFinding[]}
 */
export function bruteForceSql(db, run, options) {
  const rows = /** @type {any[]} */ (db.prepare(BRUTE_FORCE).all({
    run, window: options.windowMs, threshold: options.threshold, memory: options.limits.memoryMs,
  }));
  return rows.map((r) => {
    const loggedIn = r.logged_in === null ? null : JSON.parse(r.logged_in);
    return {
      rule: 'brute-force',
      ip: r.source,
      time: r.time,
      until: r.until,
      attempts: r.attempts,
      severity: loggedIn ? 'high' : 'medium',
      // Ties are put in the same order as the JavaScript rule's localeCompare.
      users: /** @type {{ user: string, attempts: number }[]} */ (JSON.parse(r.users))
        .sort((x, y) => y.attempts - x.attempts || x.user.localeCompare(y.user)),
      invalidUsers: r.invalid_users,
      loggedIn,
    };
  });
}

/**
 * Unusual hour: a successful login whose hour, on the server's clock, falls in
 * the night window. A window like 22–6 wraps past midnight.
 */
const UNUSUAL_HOUR = `
SELECT ip, time, user, method FROM (
  SELECT ip, time, line, user, method, CAST(strftime('%H', time / 1000, 'unixepoch') AS INTEGER) AS hour
  FROM events WHERE run = :run AND type = 'success'
)
WHERE CASE WHEN :from < :to THEN hour >= :from AND hour < :to ELSE hour >= :from OR hour < :to END
ORDER BY time, line`;

/**
 * @param {DatabaseSync} db
 * @param {number} run
 * @param {ResolvedOptions} options
 * @returns {UnusualHourFinding[]}
 */
export function unusualHourSql(db, run, options) {
  const [from, to] = options.night;
  const rows = /** @type {any[]} */ (db.prepare(UNUSUAL_HOUR).all({ run, from, to }));
  return rows.map((r) => ({ rule: 'unusual-hour', severity: 'low', ip: r.ip, time: r.time, user: r.user, method: r.method }));
}
