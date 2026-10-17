// The SQL versions of brute force and unusual hour must find exactly what the
// JavaScript rules find: on the sample, the lab recording, the labelled
// corpus, and random event streams (with same-second ties and IPv6 sources).
//
// That holds for logs in time order. On a log whose times go backwards (lines
// spliced in, which the log-tampering rule reports), the streaming engine
// follows the order the lines were written while SQL orders by time, and they
// can differ; ADR-0015 records why that is accepted.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import fc from 'fast-check';
import { createEngine } from '../src/core/engine.js';
import { resolveOptions } from '../src/core/options.js';
import { createBruteForce } from '../src/core/rules/brute-force.js';
import { createUnusualHour } from '../src/core/rules/unusual-hour.js';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { bruteForceSql, unusualHourSql } from '../src/io/sql-rules.js';
import { openStore } from '../src/io/store.js';
import { generateCorpus } from '../scripts/lib/corpus.js';

/** @typedef {import('../src/types.js').AuthEvent} AuthEvent */
/** @typedef {import('../src/types.js').Finding} Finding */
/** @typedef {import('../src/types.js').AnalyzerOptions} AnalyzerOptions */

/** @param {Finding[]} list */
const sorted = (list) => list.map((f) => JSON.stringify(f)).sort();

/**
 * Runs the JavaScript rules and the SQL rules over the same log text.
 * @param {string} text
 * @param {AnalyzerOptions} [options]
 */
async function both(text, options = {}) {
  const store = openStore(':memory:');
  try {
    const run = store.beginRun({ source: 'test', mode: 'file', options: {} });
    const { incidents } = await analyzeStream(Readable.from([text]), { options, year: 2026, tap: store.tap(run, resolveOptions(options).ipv6Prefix) });
    store.flush();
    const js = incidents.flatMap((i) => i.findings);
    const resolved = resolveOptions(options);
    // Logs the tampering rule reports as going back in time (spliced lines).
    // Small clock steps and DST are still compared.
    const spliced = js.some((f) => f.rule === 'log-tampering' && f.kind === 'backwards');
    return {
      inOrder: !spliced,
      js: { brute: js.filter((f) => f.rule === 'brute-force'), night: js.filter((f) => f.rule === 'unusual-hour') },
      sql: { brute: bruteForceSql(store.db, run, resolved), night: unusualHourSql(store.db, run, resolved) },
    };
  } finally {
    store.close();
  }
}

test('SQL and JavaScript agree on the sample log, with default and other settings', async () => {
  const text = readFileSync(new URL('../samples/auth.log', import.meta.url), 'utf8');
  for (const options of [{}, { threshold: 3, windowMs: 3_600_000 }, { night: /** @type {[number, number]} */ ([22, 6]) }]) {
    const { js, sql } = await both(text, options);
    assert.ok(js.brute.length > 0 && js.night.length > 0, 'there is something to compare');
    assert.deepEqual(sorted(sql.brute), sorted(js.brute), JSON.stringify(options));
    assert.deepEqual(sorted(sql.night), sorted(js.night), JSON.stringify(options));
  }
});

test('SQL and JavaScript agree on the Docker-lab recording and the labelled corpus', async () => {
  const lab = readFileSync(new URL('./fixtures/lab/auth.log', import.meta.url), 'utf8');
  const texts = [lab, ...generateCorpus(40).map((d) => `${d.lines.join('\n')}\n`)];
  let compared = 0;
  let skipped = 0;
  for (const text of texts) {
    const { js, sql, inOrder } = await both(text);
    if (!inOrder) {
      skipped++;
      continue;
    }
    assert.deepEqual(sorted(sql.brute), sorted(js.brute));
    assert.deepEqual(sorted(sql.night), sorted(js.night));
    compared += js.brute.length + js.night.length;
  }
  console.log(`compared ${compared} findings on ${texts.length - skipped} logs (${skipped} with spliced lines skipped)`);
  assert.ok(compared >= 30, `${compared} findings compared`);
  assert.ok(skipped <= 12, `${skipped} of ${texts.length} logs were out of time order`);
});

test('SQL and JavaScript agree on random event streams, ties and IPv6 included', () => {
  const START = Date.UTC(2026, 8, 7, 0, 30);
  const ip = fc.constantFrom('198.51.100.1', '198.51.100.2', '2001:db8:1:2::5', '2001:db8:1:2::9', '2001:db8:9::1');
  const action = fc.oneof(
    { weight: 6, arbitrary: fc.record({ type: fc.constant('failure'), ip, user: fc.constantFrom('root', 'deploy', 'x'), invalid: fc.boolean(), count: fc.integer({ min: 1, max: 4 }) }) },
    { weight: 2, arbitrary: fc.record({ type: fc.constant('success'), ip, user: fc.constantFrom('deploy', 'alice') }) },
  );
  const step = fc.constantFrom(0, 0, 1000, 30_000, 120_000, 290_000, 600_000, 610_000, 3 * 3_600_000);
  const options = resolveOptions({ threshold: 4 });
  fc.assert(fc.property(fc.array(fc.tuple(step, action), { minLength: 5, maxLength: 120 }), (actions) => {
    /** @type {AuthEvent[]} */
    const events = [];
    let time = START;
    actions.forEach(([dt, a], i) => {
      time += dt;
      const base = { time, host: 'web01', pid: 1, line: i + 1, ip: a.ip, user: a.user, method: 'password' };
      events.push(a.type === 'failure'
        ? { ...base, type: 'failure', invalidUser: a.invalid, count: a.count }
        : { ...base, type: 'success', count: 1 });
    });
    const engine = createEngine(options, { rules: [createBruteForce, createUnusualHour] });
    for (const e of events) engine.push(e);
    const js = engine.findings();
    const store = openStore(':memory:');
    try {
      const run = store.beginRun({ source: 'random', mode: 'file', options: {} });
      for (const e of events) store.addEvent(run, e, 'synthetic', options.ipv6Prefix);
      store.flush();
      assert.deepEqual(sorted(bruteForceSql(store.db, run, options)), sorted(js.filter((f) => f.rule === 'brute-force')));
      assert.deepEqual(sorted(unusualHourSql(store.db, run, options)), sorted(js.filter((f) => f.rule === 'unusual-hour')));
    } finally {
      store.close();
    }
  }), { numRuns: 300 });
});
