import assert from 'node:assert/strict';
import { test } from 'node:test';
import { incidentPage, timeline } from '../src/dashboard/views.js';

test('incident evidence is escaped even inside highlights and has separate copy targets', () => {
  const run = { id: 1, source: 'auth.log', mode: 'file', started_at: '', first: 0, last: 1000, lines: 5 };
  const incident = { id: 1, ip: '192.0.2.1', subject: null, severity: 'medium', time: 0, last: 1000, closed: 1 };
  const finding = /** @type {any} */ ({ rule: 'brute-force', severity: 'medium', ip: '192.0.2.1', time: 0, attempts: 5, until: 1000, invalidUsers: 1, users: [{ user: '<script>', count: 5 }], loggedIn: null, lines: [1] });
  const page = incidentPage({ run, incident, findings: [{ id: 7, finding, lines: [{ line: 1, text: 'Sep  7 10:00:00 web sshd[1]: Failed password for <script>alert(1)</script> from 192.0.2.1 port 1 ssh2' }], more: false }], total: 1 });
  assert.match(page, /class="log-failure">Failed password<\/span>/);
  assert.match(page, /data-copy="evidence-7"/);
  assert.match(page, /class="log-raw"/);
  assert.match(page, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(page, /<script>alert|onerror=/);
});

test('timeline separates severity lanes from keyboard-accessible range controls', () => {
  const chart = timeline({ run: 1, first: 0, last: 1000, trace: [1, 3], incidents: [], marks: new Map() });
  assert.match(chart.value, /Activity &amp; incident timeline/);
  assert.match(chart.value, /class="brush-track"/);
  assert.match(chart.value, /aria-label="Window start"/);
  assert.match(chart.value, /aria-label="Window end"/);
  assert.match(chart.value, /form="filters-form"/);
});
