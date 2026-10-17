// The streaming engine must find exactly what the original batch rules found.
// fast-check generates random event streams, in time order, dense enough that
// rules interact (attacks, logins, sessions, sudo lines and account changes on
// a handful of IPs and users), and compares the two implementations. When it
// finds a difference it shrinks the stream to a minimal one.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import fc from 'fast-check';
import { ORIGINAL_RULES, createEngine } from '../src/core/engine.js';
import { toIncidents } from '../src/core/incidents.js';
import { analyze as reference } from './reference/batch-detectors.js';

/** @typedef {import('../src/types.js').AuthEvent} AuthEvent */
/** @typedef {import('../src/types.js').Incident} Incident */

/**
 * The engine running only the four rules the reference implements, on events
 * sorted the way the reference sorts them.
 * @param {AuthEvent[]} events
 */
function analyze(events) {
  const engine = createEngine({}, { rules: ORIGINAL_RULES });
  for (const event of [...events].sort((a, b) => a.time - b.time || a.line - b.line)) engine.push(event);
  return toIncidents(engine.findings());
}

const START = Date.UTC(2026, 8, 7, 0, 30);
const IPS = ['198.51.100.1', '198.51.100.2', '203.0.113.3', '10.0.0.4'];
const USERS = ['root', 'deploy', 'alice', 'erin'];
const MINUTE = 60_000;

const ip = fc.constantFrom(...IPS);
const user = fc.constantFrom(...USERS);
const host = fc.constantFrom('web01', 'web01', 'web01', 'web02');
const pid = fc.integer({ min: 1, max: 5 });

const action = fc.oneof(
  { weight: 8, arbitrary: fc.record({ kind: fc.constant('failure'), ip, user, host, invalid: fc.boolean(), count: fc.oneof(fc.constant(1), fc.integer({ min: 1, max: 6 })) }) },
  { weight: 3, arbitrary: fc.record({ kind: fc.constant('success'), ip, user, host, pid }) },
  { weight: 2, arbitrary: fc.record({ kind: fc.constant('logout'), user, host, pid }) },
  { weight: 2, arbitrary: fc.record({ kind: fc.constant('sudo'), user, host, target: user, tool: fc.constantFrom('/usr/sbin/useradd', '/usr/sbin/usermod -aG sudo', '/usr/bin/id') }) },
  { weight: 2, arbitrary: fc.record({ kind: fc.constant('account'), user, host, program: fc.constantFrom('useradd', 'usermod'), created: fc.boolean(), uid: fc.constantFrom(0, 1200, 1201), groups: fc.subarray(['sudo', 'docker', 'wheel']) }) },
);

/**
 * @param {readonly number[]} steps  Milliseconds to advance before each action.
 */
const streams = (steps) => fc.array(fc.tuple(fc.constantFrom(...steps), action), { minLength: 20, maxLength: 160 }).map(toEvents);

/**
 * Turns generated actions into events in time order. One account action is one
 * tool run: its lines share a timestamp and a fresh PID, as real ones do.
 * @param {[number, any][]} actions
 * @returns {AuthEvent[]}
 */
function toEvents(actions) {
  /** @type {AuthEvent[]} */
  const events = [];
  let time = START;
  let toolPid = 1000;
  for (const [step, a] of actions) {
    time += step;
    const base = { time, host: a.host, line: 0 };
    switch (a.kind) {
      case 'failure':
        events.push({ ...base, type: 'failure', pid: 50, ip: a.ip, user: a.user, invalidUser: a.invalid, method: 'password', count: a.count });
        break;
      case 'success':
        events.push({ ...base, type: 'success', pid: a.pid, ip: a.ip, user: a.user, method: 'password', count: 1 });
        break;
      case 'logout':
        events.push({ ...base, type: 'logout', pid: a.pid, user: a.user });
        break;
      case 'sudo':
        events.push({ ...base, type: 'sudo', pid: null, user: a.user, command: `${a.tool} ${a.target}` });
        break;
      case 'account': {
        const p = toolPid++;
        if (a.created) events.push({ ...base, type: 'account', pid: p, program: a.program, action: 'user-created', user: a.user, uid: a.uid });
        for (const group of a.groups) events.push({ ...base, type: 'account', pid: p, program: a.program, action: 'group-added', user: a.user, group });
        break;
      }
    }
  }
  return events.map((e, i) => ({ ...e, line: i + 1 }));
}

/**
 * Order-independent form of a result: incidents by IP, findings by content.
 * The engine orders ties deterministically (by IP); the batch version left
 * them in an incidental order, so order is compared separately below.
 * @param {Omit<Incident, 'subject'>[]} incidents
 */
function normalize(incidents) {
  return incidents
    .map(({ ip, severity, time, findings }) => ({ ip, severity, time, findings: findings.map((f) => JSON.stringify(f)).sort() }))
    .sort((a, b) => String(a.ip).localeCompare(String(b.ip)));
}

/** @param {Incident[]} incidents */
const isOrdered = (incidents) => incidents.every((inc, k) =>
  k === 0 || ['high', 'medium', 'low'].indexOf(incidents[k - 1].severity) <= ['high', 'medium', 'low'].indexOf(inc.severity));

const RUNS = Number(process.env.EQUIVALENCE_RUNS ?? 1000);

test('engine and batch rules agree on random streams (no two actions at the same time)', () => {
  const steps = [1_000, 5_000, 30_000, MINUTE, 4 * MINUTE, 9 * MINUTE, 11 * MINUTE, 29 * MINUTE, 31 * MINUTE, 3 * 60 * MINUTE];
  fc.assert(fc.property(streams(steps), (events) => {
    const engine = analyze(events);
    assert.deepEqual(normalize(engine), normalize(reference(events)));
    assert.ok(isOrdered(engine));
  }), { numRuns: RUNS });
});

test('engine and batch rules agree with same-second ties, for the rules without session attribution', () => {
  // With ties, the batch version could attribute an account change to an SSH
  // session whose login is logged *after* the change in the same second. The
  // engine only uses what the log has said so far, so account changes are
  // left out of this comparison; the test above covers them.
  const steps = [0, 0, 1_000, 5_000, MINUTE, 4 * MINUTE, 9 * MINUTE, 10 * MINUTE, 11 * MINUTE, 30 * MINUTE, 31 * MINUTE];
  /** @param {Omit<Incident, 'subject'>[]} incidents */
  const withoutAccounts = (incidents) => normalize(incidents.map((i) => ({ ...i, findings: i.findings.filter((f) => f.rule !== 'account-change') }))
    .filter((i) => i.findings.length > 0)
    .map((i) => ({ ...i, severity: i.findings.some((f) => f.severity === 'high') ? 'high' : i.findings.some((f) => f.severity === 'medium') ? 'medium' : 'low', time: Math.min(...i.findings.map((f) => f.time)) })));
  fc.assert(fc.property(streams(steps), (events) => {
    assert.deepEqual(withoutAccounts(analyze(events)), withoutAccounts(reference(events)));
  }), { numRuns: RUNS });
});
