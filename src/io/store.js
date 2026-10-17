// SQLite storage for runs, raw lines, events, incidents and findings, using
// Node's built-in node:sqlite (no dependency; docs/adr/0015). The dashboard
// reads it, and the SQL versions of two rules (sql-rules.js) run on it.
//
// Every statement is prepared with parameters. Log content never becomes
// SQL text, so a username like "x'); DROP TABLE runs; --" is just data.
//
// Writes are batched in transactions (one per flush or 5,000 rows), so
// storing a large log costs little more than reading it.

import { DatabaseSync } from 'node:sqlite';
import { withAttack } from '../core/attack.js';
import { sourceOf } from '../core/net.js';

/** @typedef {import('../types.js').AuthEvent} AuthEvent */
/** @typedef {import('../types.js').Finding} Finding */
/** @typedef {import('../types.js').Incident} Incident */
/** @typedef {import('../core/live-incidents.js').LiveIncident} LiveIncident */

export const SCHEMA_VERSION = 1;

const SCHEMA = `
CREATE TABLE runs (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,                 -- the file analyzed, or "stdin"
  mode TEXT NOT NULL CHECK (mode IN ('file', 'follow')),
  started_at TEXT NOT NULL,             -- real time, UTC
  finished_at TEXT,
  options TEXT NOT NULL,                -- effective settings, JSON
  stats TEXT                            -- line counts and health, JSON
);
CREATE TABLE lines (                    -- raw text of the lines behind events, for drill-down
  run INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  line INTEGER NOT NULL,
  time INTEGER,                         -- server wall clock, ms
  text TEXT NOT NULL,
  PRIMARY KEY (run, line)
) WITHOUT ROWID;
CREATE TABLE events (
  run INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  line INTEGER NOT NULL,
  time INTEGER NOT NULL,
  type TEXT NOT NULL,
  host TEXT NOT NULL,
  pid INTEGER,
  ip TEXT,
  source TEXT,                          -- ip, or its IPv6 /64: what attempts are counted against
  user TEXT,
  invalid_user INTEGER,
  method TEXT,
  count INTEGER NOT NULL DEFAULT 1,
  command TEXT,
  action TEXT,
  grp TEXT,
  uid INTEGER,
  PRIMARY KEY (run, line)
) WITHOUT ROWID;
CREATE INDEX events_by_source ON events (run, type, source, time, line);
CREATE INDEX events_by_user ON events (run, type, user, time, line);
CREATE TABLE incidents (
  id INTEGER PRIMARY KEY,
  run INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  key TEXT NOT NULL,                    -- what it groups by: "ip …" or "subject …"
  ip TEXT,
  subject TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
  time INTEGER NOT NULL,
  last INTEGER NOT NULL,
  closed INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX incidents_by_run ON incidents (run, severity, time);
CREATE TABLE findings (
  id INTEGER PRIMARY KEY,
  incident INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  run INTEGER NOT NULL,
  rule TEXT NOT NULL,
  severity TEXT NOT NULL,
  ip TEXT,
  user TEXT,
  time INTEGER NOT NULL,
  until INTEGER,
  data TEXT NOT NULL                    -- the whole finding, JSON
);
CREATE INDEX findings_by_incident ON findings (incident, time);
`;

const BATCH = 5000;

/**
 * @param {string} path  A file, or ":memory:".
 * @param {{ readOnly?: boolean }} [options]
 */
export function openStore(path, { readOnly = false } = {}) {
  const db = new DatabaseSync(path, { readOnly, enableForeignKeyConstraints: true });
  try {
    if (!readOnly) {
      db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;');
      migrate(db);
    } else {
      const version = /** @type {{ user_version: number }} */ (db.prepare('PRAGMA user_version').get()).user_version;
      if (version !== SCHEMA_VERSION) throw new Error(`database schema is version ${version}, expected ${SCHEMA_VERSION}`);
    }
  } catch (err) {
    // Don't leave the file open (and, on Windows, locked) when refusing it.
    db.close();
    throw err;
  }

  const insertLine = readOnly ? null : db.prepare('INSERT INTO lines (run, line, time, text) VALUES (?, ?, ?, ?)');
  const insertEvent = readOnly ? null : db.prepare(`INSERT INTO events
    (run, line, time, type, host, pid, ip, source, user, invalid_user, method, count, command, action, grp, uid)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  let pending = 0;
  /** Row ids of live incidents and findings, by object. */
  /** @type {WeakMap<LiveIncident, number>} */
  const liveIds = new WeakMap();
  /** @type {WeakMap<Finding, number>} */
  const findingIds = new WeakMap();

  const begin = () => {
    if (pending === 0) db.exec('BEGIN');
  };
  const flush = () => {
    if (pending > 0) db.exec('COMMIT');
    pending = 0;
  };

  return {
    db,

    /**
     * @param {{ source: string, mode: 'file' | 'follow', options: object }} run
     * @returns {number}
     */
    beginRun({ source, mode, options }) {
      flush();
      const result = db.prepare('INSERT INTO runs (source, mode, started_at, options) VALUES (?, ?, ?, ?)')
        .run(source, mode, new Date().toISOString(), JSON.stringify(options));
      return Number(result.lastInsertRowid);
    },

    /**
     * Stores an event and the raw line it came from.
     * @param {number} run
     * @param {AuthEvent} event
     * @param {string} text
     * @param {number} ipv6Prefix
     */
    addEvent(run, event, text, ipv6Prefix) {
      begin();
      /** @type {any} */
      const e = event;
      /** @type {string | null} */
      const ip = e.ip ?? null;
      /** @type {NonNullable<typeof insertLine>} */ (insertLine).run(run, event.line, event.time, text);
      /** @type {NonNullable<typeof insertEvent>} */ (insertEvent).run(run, event.line, event.time, event.type, event.host, event.pid,
        ip, ip === null ? null : sourceOf(ip, ipv6Prefix), e.user ?? null, e.invalidUser === undefined ? null : Number(e.invalidUser),
        e.method ?? null, e.count ?? 1, e.command ?? null, e.action ?? null, e.group ?? null, e.uid ?? null);
      if (++pending >= BATCH) flush();
    },

    /**
     * A tap for analyzeStream / startLive that stores every line, and the
     * event it parsed to, so the dashboard can show findings in context.
     * @param {number} run
     * @param {number} ipv6Prefix
     * @returns {import('./analyze-stream.js').LineTap}
     */
    tap(run, ipv6Prefix) {
      return ({ text, lineNo, event, info }) => {
        if (event) this.addEvent(run, event, text, ipv6Prefix);
        else if (text !== '') this.addLine(run, lineNo, info?.time ?? null, text);
      };
    },

    /**
     * Stores a raw line that isn't an event.
     * @param {number} run
     * @param {number} line
     * @param {number | null} time
     * @param {string} text
     */
    addLine(run, line, time, text) {
      begin();
      /** @type {NonNullable<typeof insertLine>} */ (insertLine).run(run, line, time, text);
      if (++pending >= BATCH) flush();
    },

    flush,

    /**
     * Stores a finished report's incidents and findings.
     * @param {number} run
     * @param {Incident[]} incidents
     */
    saveIncidents(run, incidents) {
      flush();
      db.exec('BEGIN');
      try {
        for (const incident of incidents) {
          const key = incident.ip !== null ? `ip ${incident.ip}` : `subject ${incident.subject}`;
          const last = Math.max(...incident.findings.map((f) => ('until' in f ? f.until : f.time)));
          const id = Number(db.prepare('INSERT INTO incidents (run, key, ip, subject, severity, time, last) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .run(run, key, incident.ip, incident.subject, incident.severity, incident.time, last).lastInsertRowid);
          for (const finding of incident.findings) insertFinding(id, run, finding);
        }
        db.exec('COMMIT');
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    },

    /**
     * Records a live incident event: creates or updates the incident row and
     * writes the one finding the event is about. Rows are matched to objects
     * by identity, so nothing else is rewritten.
     * @param {number} run
     * @param {import('../core/live-incidents.js').IncidentEvent} event
     */
    saveLiveEvent(run, { type, incident, finding }) {
      begin();
      let id = liveIds.get(incident);
      if (id === undefined) {
        id = Number(db.prepare('INSERT INTO incidents (run, key, ip, subject, severity, time, last, closed) VALUES (?, ?, ?, ?, ?, ?, ?, 0)')
          .run(run, incident.key, incident.ip, incident.subject, incident.severity, incident.time, incident.last).lastInsertRowid);
        liveIds.set(incident, id);
      } else {
        db.prepare('UPDATE incidents SET severity = ?, time = ?, last = ?, closed = ? WHERE id = ?')
          .run(incident.severity, incident.time, incident.last, Number(type === 'closed'), id);
      }
      if (finding) {
        const row = findingIds.get(finding);
        if (row === undefined) findingIds.set(finding, insertFinding(id, run, finding));
        else updateFinding(row, finding);
      }
      if (++pending >= BATCH) flush();
    },

    /**
     * @param {number} run
     * @param {object} stats
     */
    finishRun(run, stats) {
      flush();
      db.prepare('UPDATE runs SET finished_at = ?, stats = ? WHERE id = ?').run(new Date().toISOString(), JSON.stringify(stats), run);
    },

    close() {
      flush();
      db.close();
    },
  };

  /**
   * @param {number} incident
   * @param {number} run
   * @param {Finding} f
   */
  function insertFinding(incident, run, f) {
    return Number(db.prepare('INSERT INTO findings (incident, run, rule, severity, ip, user, time, until, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(incident, run, f.rule, f.severity, f.ip, 'user' in f ? f.user : null, f.time, 'until' in f ? f.until : null, JSON.stringify(withAttack(f))).lastInsertRowid);
  }

  /**
   * @param {number} id
   * @param {Finding} f
   */
  function updateFinding(id, f) {
    db.prepare('UPDATE findings SET severity = ?, ip = ?, time = ?, until = ?, data = ? WHERE id = ?')
      .run(f.severity, f.ip, f.time, 'until' in f ? f.until : null, JSON.stringify(withAttack(f)), id);
  }
}

/** @param {DatabaseSync} db */
function migrate(db) {
  const version = /** @type {{ user_version: number }} */ (db.prepare('PRAGMA user_version').get()).user_version;
  if (version === SCHEMA_VERSION) return;
  if (version > SCHEMA_VERSION) throw new Error(`database schema is version ${version}, newer than this analyzer (${SCHEMA_VERSION})`);
  db.exec('BEGIN');
  try {
    db.exec(SCHEMA);
    db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

/** @typedef {ReturnType<typeof openStore>} Store */

/**
 * The raw log lines behind a finding, for drill-down: the events its rule
 * looked at, found again by subject and time. At most `limit` lines.
 * @param {DatabaseSync} db
 * @param {number} run
 * @param {Finding} f
 * @param {number} [limit]
 * @returns {{ line: number, time: number | null, text: string }[]}
 */
export function evidence(db, run, f, limit = 200) {
  /** @param {string} where @param {import('node:sqlite').SQLInputValue[]} params */
  const lines = (where, ...params) => /** @type {{ line: number, time: number | null, text: string }[]} */ (db.prepare(
    `SELECT l.line, l.time, l.text FROM events e JOIN lines l ON l.run = e.run AND l.line = e.line
     WHERE e.run = ? AND ${where} ORDER BY l.line LIMIT ?`).all(run, ...params, limit));
  switch (f.rule) {
    case 'brute-force':
    case 'password-spray': {
      const until = f.loggedIn ? Math.max(f.until, f.loggedIn.time) : f.until;
      return lines("e.source = ? AND e.type IN ('failure', 'success') AND e.time BETWEEN ? AND ?", f.ip, f.time, until);
    }
    case 'distributed-brute-force':
      return lines("e.user = ? AND e.type IN ('failure', 'success') AND e.time BETWEEN ? AND ?", f.user, f.time, f.loggedIn ? f.loggedIn.time : f.until);
    case 'possible-breach':
      return lines("e.ip = ? AND e.type IN ('failure', 'success') AND e.time BETWEEN ? AND ?", f.ip, f.firstFailure, f.time);
    case 'new-source':
    case 'unusual-hour':
      return lines("e.type = 'success' AND e.ip = ? AND e.user = ? AND e.time = ?", f.ip, f.user, f.time);
    case 'account-change':
      return lines("((e.type = 'account' AND e.user = ?) OR (e.type = 'sudo' AND e.command LIKE ? ESCAPE '!')) AND e.time BETWEEN ? AND ?",
        f.user, `%${f.user.replace(/[!%_]/g, (c) => `!${c}`)}%`, f.time - 60_000, f.time + 60_000);
    case 'log-tampering':
      return /** @type {{ line: number, time: number | null, text: string }[]} */ (db.prepare(
        'SELECT line, time, text FROM lines WHERE run = ? AND line BETWEEN ? AND ? ORDER BY line LIMIT ?').all(run, f.line - 1, f.line, limit));
  }
}
