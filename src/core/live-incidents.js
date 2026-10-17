// Incidents for live mode. The batch report groups every finding at the end
// (incidents.js); a live log never ends, so here incidents are kept open while
// they are active and closed after `idleMs` of log time without news.
//
// Each change is an event, so sinks can decide what deserves an alert:
//   opened     the first finding for a source (or subject)
//   escalated  the incident's severity rose (a brute force became a break-in)
//   updated    anything else: more attempts, another low finding
//   closed     no new findings for idleMs; its state is forgotten
//
// Both the number of open incidents and the findings kept per incident are
// capped, so memory is bounded however long the follower runs.

import { SEVERITIES } from './options.js';
import { sourceOf } from './net.js';

/** @typedef {import('../types.js').Finding} Finding */
/** @typedef {import('../types.js').Severity} Severity */

/**
 * @typedef {object} LiveIncident
 * @property {string} id  Stable for the incident's life, e.g. "ip 198.51.100.7 #1".
 * @property {string} key  What it groups by, e.g. "ip 198.51.100.7".
 * @property {string | null} ip
 * @property {string | null} subject
 * @property {Severity} severity
 * @property {number} time  Its first finding.
 * @property {number} last  Its latest activity.
 * @property {Finding[]} findings  In arrival order, up to the cap.
 * @property {number} droppedFindings  Findings beyond the cap.
 */

/**
 * `firstSeen` is true when the finding itself is new (not an update to one
 * the incident already had), so a terminal can show a new kind of finding in
 * an open incident without an alert being sent for it.
 * @typedef {{ type: 'opened' | 'escalated' | 'updated' | 'closed', incident: LiveIncident, finding: Finding | null, firstSeen?: boolean }} IncidentEvent
 */

/** @param {Severity} s */
const rank = (s) => SEVERITIES.indexOf(s);

/** @param {Finding} f */
function subjectOf(f) {
  if (f.rule === 'distributed-brute-force') return `user ${f.user}`;
  if (f.rule === 'log-tampering') return 'the log itself';
  return null;
}

/** @param {Finding} f */
const latestOf = (f) => Math.max(f.time, 'until' in f ? f.until : f.time, 'loggedIn' in f && f.loggedIn ? f.loggedIn.time : f.time);

/**
 * @param {object} [options]
 * @param {number} [options.ipv6Prefix]
 * @param {number} [options.idleMs]  Close an incident after this long without findings.
 * @param {number} [options.maxOpen]  Open incidents kept; the least recently active closes first.
 * @param {number} [options.maxFindingsPerIncident]
 */
export function createIncidentTracker({ ipv6Prefix = 64, idleMs = 24 * 60 * 60_000, maxOpen = 10_000, maxFindingsPerIncident = 500 } = {}) {
  /** Open incidents by key, least recently active first. */
  /** @type {Map<string, LiveIncident>} */
  const open = new Map();
  /** Which incident each finding was filed under. */
  /** @type {WeakMap<Finding, LiveIncident>} */
  const filed = new WeakMap();
  /** @type {Map<string, number>} */
  const opened = new Map();

  /** @param {Finding} f */
  function keyOf(f) {
    const ip = f.ip === null ? null : sourceOf(f.ip, ipv6Prefix);
    const subject = ip === null ? subjectOf(f) : null;
    return { key: ip !== null ? `ip ${ip}` : `subject ${subject}`, ip, subject };
  }

  /** @param {LiveIncident} incident */
  const severityOf = (incident) => SEVERITIES[Math.min(...incident.findings.map((f) => rank(f.severity)))];

  return {
    /**
     * A finding appeared or changed. Findings stay in the incident they first
     * joined while it is open, even if their IP is later revised.
     * @param {Finding} finding
     * @param {boolean} [isNew]  Whether the engine reports it for the first time.
     * @returns {IncidentEvent[]}
     */
    onFinding(finding, isNew = false) {
      /** @type {IncidentEvent[]} */
      const events = [];
      const { key, ip, subject } = keyOf(finding);
      let incident = filed.get(finding);
      if (incident && open.get(incident.key) !== incident) incident = undefined;
      if (!incident) {
        incident = open.get(key);
        if (!incident) {
          const n = (opened.get(key) ?? 0) + 1;
          opened.set(key, n);
          incident = { id: `${key} #${n}`, key, ip, subject, severity: finding.severity, time: finding.time, last: latestOf(finding), findings: [], droppedFindings: 0 };
          if (open.size >= maxOpen) {
            const [oldestKey, oldest] = /** @type {[string, LiveIncident]} */ (open.entries().next().value);
            open.delete(oldestKey);
            events.push({ type: 'closed', incident: oldest, finding: null });
          }
          open.set(key, incident);
          incident.findings.push(finding);
          filed.set(finding, incident);
          events.push({ type: 'opened', incident, finding, firstSeen: true });
          return events;
        }
        if (incident.findings.length < maxFindingsPerIncident) incident.findings.push(finding);
        else incident.droppedFindings++;
        filed.set(finding, incident);
      }
      // Most recently active last, for the open-incident cap.
      open.delete(incident.key);
      open.set(incident.key, incident);
      incident.last = Math.max(incident.last, latestOf(finding));
      incident.time = Math.min(incident.time, finding.time);
      const before = incident.severity;
      incident.severity = severityOf(incident);
      events.push({ type: rank(incident.severity) < rank(before) ? 'escalated' : 'updated', incident, finding, firstSeen: isNew });
      return events;
    },

    /**
     * Closes incidents that have been quiet for idleMs of log time.
     * @param {number} time
     * @returns {IncidentEvent[]}
     */
    advance(time) {
      /** @type {IncidentEvent[]} */
      const events = [];
      for (const [key, incident] of open) {
        if (incident.last >= time - idleMs) continue;
        open.delete(key);
        events.push({ type: 'closed', incident, finding: null });
      }
      return events;
    },

    /** Closes every open incident (at shutdown). @returns {IncidentEvent[]} */
    closeAll() {
      const events = [...open.values()].map((incident) => ({ type: /** @type {const} */ ('closed'), incident, finding: null }));
      open.clear();
      return events;
    },

    /** Open incidents, least recently active first. */
    open: () => [...open.values()],
    size: () => open.size,
  };
}
