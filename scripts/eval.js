#!/usr/bin/env node
// Measures detection quality on labelled data and writes docs/evaluation.md.
//
//   node scripts/eval.js            regenerate docs/evaluation.md
//   node scripts/eval.js --check    fail if the committed file is out of date (CI)
//
// Datasets: the seeded synthetic corpus (scripts/lib/corpus.js) and the
// recorded Docker-lab log (test/fixtures/lab/, with "truth" in labels.json).
// A finding is a true positive if it matches a malicious item that its rule is
// meant or allowed to catch: same subject (IP, /64, user, or the log) and a
// span overlapping the item's (from 10 minutes before it to an hour after). Recall is
// measured on each item's primary rule. Everything else a rule reports is a
// false positive, traced to the benign lookalike it matches when there is one.

import { readFileSync, writeFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { generateCorpus } from './lib/corpus.js';
import { loadLabels } from './lib/labels.js';

/** @typedef {import('./lib/corpus.js').Dataset} Dataset */
/** @typedef {import('./lib/corpus.js').Truth} Truth */
/** @typedef {import('../src/types.js').Finding} Finding */
/** @typedef {import('../src/types.js').AnalyzerOptions} AnalyzerOptions */

const OUT = fileURLToPath(new URL('../docs/evaluation.md', import.meta.url));
const LAB_LOG = fileURLToPath(new URL('../test/fixtures/lab/auth.log', import.meta.url));
const LAB_LABELS = fileURLToPath(new URL('../test/fixtures/lab/labels.json', import.meta.url));
const CORPUS_SIZE = 40;
const RULES = ['brute-force', 'password-spray', 'distributed-brute-force', 'new-source', 'log-tampering'];
const MIN = 60_000;

/** @type {{ name: string, options: AnalyzerOptions, note: string }[]} */
const CONFIGS = [
  { name: 'defaults', options: {}, note: 'out of the box' },
  { name: 'internal networks trusted', options: { trustedNetworks: ['10.0.0.0/8'] }, note: '`trustedNetworks: ["10.0.0.0/8"]`' },
];

/**
 * The subjects a finding can be about, in the form truth keys use.
 * @param {Finding} f
 */
function keysOf(f) {
  const keys = [];
  if (f.ip !== null) keys.push(f.ip);
  if ('user' in f && typeof f.user === 'string') {
    keys.push(`user ${f.user}`);
    if (f.ip !== null) keys.push(`${f.user} ${f.ip}`);
  }
  if (f.rule === 'log-tampering') keys.push('log');
  return keys;
}

/**
 * Same subject, and the finding's span overlaps the item's (from 10 minutes
 * before it to an hour after).
 * @param {Finding} f
 * @param {{ key: string, from: number, to: number }} item
 */
function matches(f, item) {
  // A backwards jump's `until` is earlier than its `time`.
  const other = 'until' in f ? f.until : f.time;
  const [start, end] = [Math.min(f.time, other), Math.max(f.time, other)];
  return keysOf(f).includes(item.key) && end >= item.from - 10 * MIN && start <= item.to + 60 * MIN;
}

/** The lab's truth, from labels.json, as a dataset. */
function labDataset() {
  const labels = /** @type {any} */ (loadLabels(LAB_LABELS));
  /** @type {Dataset} */
  const dataset = {
    name: 'docker-lab',
    format: 'rfc3339',
    year: 2026,
    lines: readFileSync(LAB_LOG, 'utf8').split('\n'),
    truth: (labels.truth ?? []).map((/** @type {any} */ t) => ({ ...t, from: Date.parse(`${t.from}Z`), to: Date.parse(`${t.to}Z`), params: t.params ?? {} })),
    benign: (labels.benign ?? []).map((/** @type {any} */ b) => ({ ...b, from: Date.parse(`${b.from}Z`), to: Date.parse(`${b.to}Z`) })),
  };
  return dataset;
}

/**
 * @param {Dataset} dataset
 * @param {AnalyzerOptions} options
 */
async function findingsOf(dataset, options) {
  const text = `${dataset.lines.join('\n')}\n`;
  const { incidents } = await analyzeStream(Readable.from([text]), { options, year: dataset.year, now: Date.UTC(2026, 11, 31) });
  return incidents.flatMap((i) => i.findings);
}

/**
 * @param {Dataset[]} datasets
 * @param {AnalyzerOptions} options
 */
async function evaluate(datasets, options) {
  /** @type {Record<string, { tp: number, fp: number, detected: number, items: number }>} */
  const perRule = Object.fromEntries(RULES.map((r) => [r, { tp: 0, fp: 0, detected: 0, items: 0 }]));
  /** @type {Map<string, number>} */
  const falsePositives = new Map();
  /** @type {{ truth: Truth, caught: boolean }[]} */
  const outcomes = [];
  for (const dataset of datasets) {
    const findings = await findingsOf(dataset, options);
    for (const f of findings) {
      if (!(f.rule in perRule)) continue;
      if (dataset.truth.some((t) => (t.primary === f.rule || t.accept.includes(f.rule)) && matches(f, t))) {
        perRule[f.rule].tp++;
      } else {
        perRule[f.rule].fp++;
        const cause = dataset.benign.find((b) => matches(f, b))?.kind ?? 'other';
        const label = `${f.rule} on ${cause}`;
        falsePositives.set(label, (falsePositives.get(label) ?? 0) + 1);
      }
    }
    for (const t of dataset.truth) {
      const caught = findings.some((f) => f.rule === t.primary && matches(f, t));
      perRule[t.primary].items++;
      if (caught) perRule[t.primary].detected++;
      outcomes.push({ truth: t, caught });
    }
  }
  return { perRule, falsePositives, outcomes };
}

/** @param {number} a @param {number} b */
const pct = (a, b) => (b === 0 ? 'n/a' : `${Math.round((100 * a) / b)}%`);

/**
 * Recall for one kind of attack, bucketed by one of its size parameters.
 * @param {{ truth: Truth, caught: boolean }[]} outcomes
 * @param {string} primary
 * @param {string} param
 * @param {[number, number][]} buckets
 */
function sensitivity(outcomes, primary, param, buckets) {
  const rows = buckets.map(([lo, hi]) => {
    const inBucket = outcomes.filter((o) => o.truth.primary === primary && o.truth.params[param] >= lo && o.truth.params[param] <= hi);
    const caught = inBucket.filter((o) => o.caught).length;
    return `| ${lo === hi ? lo : `${lo}–${hi}`} | ${inBucket.length} | ${caught} | ${pct(caught, inBucket.length)} |`;
  });
  return rows.join('\n');
}

async function main() {
  const corpus = generateCorpus(CORPUS_SIZE);
  const lab = labDataset();
  const corpusItems = corpus.reduce((n, d) => n + d.truth.length, 0);
  const corpusLines = corpus.reduce((n, d) => n + d.lines.length, 0);
  const out = [
    '# Detection evaluation',
    '',
    '<!-- Generated by `npm run eval` (scripts/eval.js). Do not edit by hand; CI checks it is up to date. -->',
    '',
    'Precision and recall of the rules that have labelled attacks to find, measured on two kinds of data:',
    '',
    `- **Synthetic corpus:** ${CORPUS_SIZE} seeded datasets of three days each (${corpusLines.toLocaleString('en-US')} lines, ${corpusItems} labelled attacks; half classic syslog, half RFC 3339 across the end of DST). Attack sizes are random and **deliberately straddle the default thresholds**, so recall below 100% is expected and shows where the thresholds sit. Each dataset also contains benign lookalikes: office NAT typos, roaming users, a misconfigured internal service, travelling users, maintenance downtime, NTP clock steps, and DST. See [scripts/lib/corpus.js](../scripts/lib/corpus.js).`,
    `- **Docker lab:** the recorded run in [test/fixtures/lab/](../test/fixtures/lab/), written by real OpenSSH 10, sudo and rsyslog (${lab.truth.length} labelled attacks).`,
    '',
    'A finding counts as a true positive if it matches a malicious item its rule is meant or allowed to catch: the same subject (IP or IPv6 /64, user, or the log), and a span overlapping the time of the item, from 10 minutes before it to an hour after. Recall counts each item once, under the rule meant to catch it. Every other finding of these rules is a false positive. Possible breach, unusual hour and account change are context rules with no separate ground truth here; their behaviour is covered by the sample log, the lab, and the tests.',
    '',
    '**Read these numbers for what they are.** The synthetic data was written alongside the rules, by the same author, so it can only test the cases that were thought of. Real traffic will be messier. The value of the corpus is in the trade-offs it makes visible: which attacks fall below the thresholds, and which benign patterns trip the rules.',
  ];

  for (const config of CONFIGS) {
    out.push('', `## Results: ${config.name}`, '', `Settings: ${config.note}.`, '');
    for (const [label, datasets] of /** @type {[string, Dataset[]][]} */ ([['Synthetic corpus', corpus], ['Docker lab', [lab]]])) {
      const { perRule, falsePositives } = await evaluate(datasets, config.options);
      out.push(`### ${label}`, '', '| Rule | Attacks | Detected | Recall | Findings | False positives | Precision |', '|---|---|---|---|---|---|---|');
      for (const rule of RULES) {
        const r = perRule[rule];
        if (r.items === 0 && r.tp + r.fp === 0) continue;
        out.push(`| ${rule} | ${r.items} | ${r.detected} | ${pct(r.detected, r.items)} | ${r.tp + r.fp} | ${r.fp} | ${pct(r.tp, r.tp + r.fp)} |`);
      }
      if (falsePositives.size > 0) {
        out.push('', 'False positives by cause:', '');
        for (const [cause, n] of [...falsePositives].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))) out.push(`- ${cause}: ${n}`);
      }
      out.push('');
    }
  }

  const { outcomes } = await evaluate(corpus, {});
  out.push(
    '## Where the thresholds sit (synthetic corpus, defaults)',
    '',
    '**Password spraying**, by real accounts tried (default `minUsers` 6):',
    '', '| Accounts | Attacks | Detected | Recall |', '|---|---|---|---|',
    sensitivity(outcomes, 'password-spray', 'accounts', [[3, 5], [6, 9], [10, 14]]),
    '',
    '**Distributed brute force**, by sources (default `minSources` 4, `minAttempts` 8):',
    '', '| Sources | Attacks | Detected | Recall |', '|---|---|---|---|',
    sensitivity(outcomes, 'distributed-brute-force', 'sources', [[2, 3], [4, 5], [6, 9]]),
    '',
    'and by total attempts:',
    '', '| Attempts | Attacks | Detected | Recall |', '|---|---|---|---|',
    sensitivity(outcomes, 'distributed-brute-force', 'attempts', [[2, 7], [8, 14], [15, 27]]),
    '',
    '**Brute force**, by attempts (default `threshold` 5 within 10 minutes; guesses here are 5–40 s apart):',
    '', '| Attempts | Attacks | Detected | Recall |', '|---|---|---|---|',
    sensitivity(outcomes, 'brute-force', 'attempts', [[3, 4], [5, 9], [10, 40]]),
    '',
    '**Log tampering**, wiped lines by the size of the hole (default `maxGap` 2h):',
    '', '| Minutes wiped | Attacks | Detected | Recall |', '|---|---|---|---|',
    sensitivity(outcomes, 'log-tampering', 'gapMinutes', [[60, 89], [90, 179], [180, 360]]),
    '',
    'Spliced lines are found whenever they jump back more than `maxBackwards` (5 minutes); every splice in the corpus jumps back 3–10 hours.',
    '',
  );

  const text = `${out.join('\n')}\n`;
  if (process.argv.includes('--check')) {
    const committed = readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n');
    if (committed !== text) {
      console.error('docs/evaluation.md is out of date: run `npm run eval` and commit the result.');
      process.exitCode = 1;
    } else {
      console.error('docs/evaluation.md is up to date');
    }
  } else {
    writeFileSync(OUT, text);
    console.error(`wrote ${OUT}`);
  }
}

await main();
