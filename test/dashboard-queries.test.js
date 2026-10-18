import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { openStore } from '../src/io/store.js';
import { incidentCounts, incidentsFor } from '../src/dashboard/queries.js';
import { parseRangeTime } from '../src/dashboard/server.js';

const filters = { severities: [], rule: null, q: '' };

test('time boundaries select overlapping incidents inclusively and totals ignore display limits', async () => {
  const store = openStore(':memory:');
  try {
    const run = store.beginRun({ source: 'synthetic.log', mode: 'file', options: {} });
    const lines = [10, 11].flatMap((hour, n) => Array.from({ length: 5 }, (_, i) =>
      `Sep  7 ${hour}:00:0${i} host sshd[1]: Failed password for root from 192.0.2.${n + 1} port 1 ssh2`));
    const { incidents } = await analyzeStream(Readable.from([lines.join('\n') + '\n']), { year: 2026, tap: store.tap(run, 64) });
    store.saveIncidents(run, incidents);
    const first = Date.UTC(2026, 8, 7, 10);
    assert.equal(incidentsFor(store.db, run, { ...filters, from: first, to: first })[0].ip, '192.0.2.1');
    assert.equal(incidentsFor(store.db, run, { ...filters, from: first + 5_000, to: first + 3_600_000 - 1 }).length, 0);
    assert.equal(incidentCounts(store.db, run, { ...filters, q: '192.0.2.2' }).total, 1);
    const copies = Array.from({ length: 520 }, (_, i) => ({ ...incidents[0], ip: `10.0.${i >> 8}.${i & 255}` }));
    const largeRun = store.beginRun({ source: 'large.log', mode: 'file', options: {} });
    store.saveIncidents(largeRun, copies);
    assert.equal(incidentsFor(store.db, largeRun, filters).length, 500);
    assert.equal(incidentCounts(store.db, largeRun, filters).total, 520);
    assert.equal(incidentCounts(store.db, largeRun, { ...filters, from: first + 5000 }).total, 0);
  } finally { store.close(); }
});

test('time input accepts exact server-clock dates and rejects normalization or unsafe values', () => {
  assert.equal(parseRangeTime(null), null);
  assert.equal(parseRangeTime(''), null);
  assert.equal(parseRangeTime('2026-09-07T10:00'), Date.UTC(2026, 8, 7, 10));
  assert.equal(parseRangeTime('2026-09-07T10:00:00.123'), Date.UTC(2026, 8, 7, 10, 0, 0, 123));
  assert.equal(parseRangeTime('2026-09-07T10:00:00.1'), Date.UTC(2026, 8, 7, 10, 0, 0, 100));
  assert.equal(parseRangeTime('2026-09-07T10:00:00.12'), Date.UTC(2026, 8, 7, 10, 0, 0, 120));
  assert.equal(parseRangeTime('0'), 0);
  for (const invalid of ['2026-02-30T12:00', '2026-09-07T24:00', '-1', '9999999999999999', '<script>', 'NaN']) {
    assert.throws(() => parseRangeTime(invalid), /invalid time range/, invalid);
  }
});
