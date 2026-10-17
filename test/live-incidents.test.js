// Live incidents: one "opened" per attack, one "escalated" per rise in
// severity, "updated" for everything else, and incidents closed when quiet.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createEngine } from '../src/core/engine.js';
import { createIncidentTracker } from '../src/core/live-incidents.js';

/** @typedef {import('../src/types.js').AuthEvent} AuthEvent */

const T0 = Date.UTC(2026, 8, 7, 12);
const MIN = 60_000;
/** @returns {AuthEvent} */
const fail = (ip, minute, user = 'deploy') =>
  ({ type: 'failure', time: T0 + minute * MIN, host: 'web01', pid: 1, line: 0, ip, user, invalidUser: false, method: 'password', count: 1 });
/** @returns {AuthEvent} */
const ok = (ip, minute, user = 'deploy') =>
  ({ type: 'success', time: T0 + minute * MIN, host: 'web01', pid: 2, line: 0, ip, user, method: 'password', count: 1 });

/**
 * Feeds events through an engine into a tracker, flushing after each one as
 * live mode does, and returns the incident events as "type severity key".
 * @param {AuthEvent[]} events
 * @param {{ idleMs?: number }} [options]
 */
function live(events, options = {}) {
  /** @type {string[]} */
  const out = [];
  const tracker = createIncidentTracker(options);
  /** @param {import('../src/core/live-incidents.js').IncidentEvent[]} list */
  const record = (list) => out.push(...list.map((e) => `${e.type} ${e.incident.severity} ${e.incident.ip ?? e.incident.subject}`));
  const engine = createEngine({}, { keepFindings: false, onFinding: (f) => record(tracker.onFinding(f)) });
  for (const e of events) {
    engine.push(e);
    engine.flush();
    record(tracker.advance(e.time));
  }
  record(tracker.closeAll());
  return out;
}

const attack = (ip, from) => [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6].map((m) => fail(ip, from + m));

test('an attack opens one incident; more of the same only updates it', () => {
  assert.deepEqual(live(attack('198.51.100.7', 0)), [
    'opened medium 198.51.100.7',
    'updated medium 198.51.100.7',
    'updated medium 198.51.100.7',
    'closed medium 198.51.100.7',
  ]);
});

test('a break-in escalates the open incident once', () => {
  const events = live([...attack('198.51.100.7', 0), ok('198.51.100.7', 2)]);
  assert.deepEqual(events.filter((e) => !e.startsWith('updated')), [
    'opened medium 198.51.100.7',
    'escalated high 198.51.100.7',
    'closed high 198.51.100.7',
  ]);
});

test('separate attackers get separate incidents', () => {
  const opened = live([...attack('198.51.100.7', 0), ...attack('203.0.113.9', 1)]).filter((e) => e.startsWith('opened'));
  assert.deepEqual(opened, ['opened medium 198.51.100.7', 'opened medium 203.0.113.9']);
});

test('an incident closes after the quiet period, and a later attack opens a new one', () => {
  const events = live([...attack('198.51.100.7', 0), fail('192.0.2.1', 30), ...attack('198.51.100.7', 40)], { idleMs: 20 * MIN });
  assert.deepEqual(events.filter((e) => !e.startsWith('updated')), [
    'opened medium 198.51.100.7',
    'closed medium 198.51.100.7',
    'opened medium 198.51.100.7',
    'closed medium 198.51.100.7',
  ]);
});

test('open incidents and their findings are capped', () => {
  const tracker = createIncidentTracker({ maxOpen: 3, maxFindingsPerIncident: 2 });
  for (let i = 0; i < 10; i++) {
    tracker.onFinding({ rule: 'unusual-hour', severity: 'low', ip: `192.0.2.${i}`, time: T0 + i, user: 'u', method: 'password' });
  }
  for (let i = 0; i < 5; i++) {
    tracker.onFinding({ rule: 'unusual-hour', severity: 'low', ip: '192.0.2.9', time: T0 + 100 + i, user: 'u', method: 'password' });
  }
  assert.equal(tracker.size(), 3);
  const nine = tracker.open().find((i) => i.ip === '192.0.2.9');
  assert.equal(nine?.findings.length, 2);
  assert.equal(nine?.droppedFindings, 4);
});

test('a new kind of finding in an open incident is marked firstSeen, an update to one is not', () => {
  const tracker = createIncidentTracker();
  /** @type {any} */
  const brute = { rule: 'brute-force', severity: 'medium', ip: '198.51.100.88', time: T0, until: T0, attempts: 5, users: [], invalidUsers: 0, loggedIn: null };
  /** @type {any} */
  const spray = { rule: 'password-spray', severity: 'medium', ip: '198.51.100.88', time: T0, until: T0, attempts: 6, userCount: 6, users: [], loggedIn: null };
  tracker.onFinding(brute, true);
  assert.deepEqual(tracker.onFinding(spray, true).map((e) => [e.type, e.firstSeen]), [['updated', true]]);
  assert.deepEqual(tracker.onFinding(brute, false).map((e) => [e.type, e.firstSeen]), [['updated', false]]);
});
