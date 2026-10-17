#!/usr/bin/env node
// Runs the Docker lab (lab/compose.yaml): starts the SSH server, plays each
// scenario from its own client container, copies out the server's auth.log,
// checks it against the labels, and tears everything down.
//
// Usage:
//   node scripts/lab.js run [--out <file>] [--keep]   run the scenarios, collect and verify the log
//                                                     (default lab/out/auth.log; `npm run lab:fixture`
//                                                     writes the committed fixture instead)
//   node scripts/lab.js verify <log> [--labels <file>] check a collected log against its labels
//
// Every command is run with an argument array, never through a shell.

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { checkLabels, loadLabels } from './lib/labels.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const COMPOSE = ['compose', '-f', resolve(ROOT, 'lab/compose.yaml')];
const DEFAULT_OUT = resolve(ROOT, 'lab/out/auth.log');
const CLIENT_IMAGE = 'log-analyzer-lab/client:local';
// lib.sh exits with this status when the target is not on the lab network.
const GUARD_REFUSED = 64;
const DEFAULT_LABELS = resolve(ROOT, 'test/fixtures/lab/labels.json');

/** The scenarios, in the order they run: which client plays which script. */
export const SCENARIOS = [
  { id: 'admin-work', service: 'office', script: '/scenarios/admin-work.sh' },
  { id: 'guessing', service: 'attacker-guess', script: '/scenarios/guessing.sh' },
  { id: 'break-in', service: 'attacker-breakin', script: '/scenarios/break-in.sh' },
];

/**
 * A POSIX TZ string that makes the lab's clock read about 10:00 right now, so
 * the scenarios never fall in the unusual-hour window whatever time CI runs.
 * POSIX offsets are west-positive: "LAB-3" is three hours ahead of UTC.
 * @param {Date} now
 */
export function morningTz(now) {
  let east = 10 - now.getUTCHours();
  if (east > 14) east -= 24;
  if (east < -12) east += 24;
  return east === 0 ? 'LAB0' : `LAB${east > 0 ? '-' : '+'}${Math.abs(east)}`;
}

/**
 * @param {string[]} args
 * @param {{ env?: NodeJS.ProcessEnv, allowFailure?: boolean }} [options]
 */
function docker(args, { env, allowFailure = false } = {}) {
  console.error(`$ docker ${args.join(' ')}`);
  const result = spawnSync('docker', args, { stdio: 'inherit', env: { ...process.env, ...env } });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) throw new Error(`docker ${args[1] ?? args[0]} exited with status ${result.status}`);
  return result.status;
}

/**
 * Proves the scenarios' safety check works before running any of them: with
 * no network, `lab-target` can't resolve to the lab subnet, so a scenario
 * must refuse to start.
 */
function checkGuard() {
  const status = docker(['run', '--rm', '--network', 'none', CLIENT_IMAGE, '/scenarios/guessing.sh'], { allowFailure: true });
  if (status !== GUARD_REFUSED) throw new Error(`scenario guard did not refuse an off-lab target (exit ${status})`);
  console.error('scenario guard refuses off-lab targets: ok');
}

/**
 * Proves the lab network has no way out: a client on it must have no default
 * route (`internal: true` gives the network no gateway). It only reads the
 * routing table; nothing is sent.
 * @param {NodeJS.ProcessEnv} env
 */
function checkNoRouteOut(env) {
  const noDefaultRoute = `awk 'NR > 1 && $2 == "00000000" { found = 1 } END { exit found }' /proc/net/route`;
  const status = docker([...COMPOSE, 'run', '--rm', '--no-TTY', 'office', '-c', noDefaultRoute], { env, allowFailure: true });
  if (status !== 0) throw new Error('the lab network has a default route; refusing to run the scenarios');
  console.error('lab network has no route out: ok');
}

/** @param {{ out: string, keep: boolean }} options */
function run({ out, keep }) {
  const env = { LAB_TZ: morningTz(new Date()) };
  try {
    docker([...COMPOSE, '--profile', 'clients', 'build'], { env });
    checkGuard();
    docker([...COMPOSE, 'up', '--detach', '--wait', 'target'], { env });
    checkNoRouteOut(env);
    for (const { id, service, script } of SCENARIOS) {
      console.error(`\n== scenario ${id} (${service})`);
      docker([...COMPOSE, 'run', '--rm', '--no-TTY', service, script], { env });
    }
    // Give rsyslog a moment to write the last lines.
    spawnSync(process.execPath, ['-e', 'setTimeout(() => {}, 1500)']);
    mkdirSync(dirname(out), { recursive: true });
    docker([...COMPOSE, 'cp', 'target:/var/log/auth.log', out], { env });
  } finally {
    if (!keep) docker([...COMPOSE, '--profile', 'clients', 'down', '--volumes', '--remove-orphans'], { env, allowFailure: true });
  }
  console.error(`\nWrote ${out}`);
}

/**
 * @param {string} log
 * @param {string} labels
 */
async function verify(log, labels) {
  const problems = await checkLabels(readFileSync(log, 'utf8'), loadLabels(labels));
  if (problems.length > 0) {
    console.error(`${log} does not match ${labels}:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
    return false;
  }
  console.error(`${log} matches every label in ${labels}`);
  return true;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: { out: { type: 'string' }, labels: { type: 'string' }, keep: { type: 'boolean' } },
  });
  const [command, file] = positionals;
  const labels = values.labels ?? DEFAULT_LABELS;
  if (command === 'run') {
    const out = resolve(values.out ?? DEFAULT_OUT);
    run({ out, keep: values.keep ?? false });
    process.exitCode = (await verify(out, labels)) ? 0 : 1;
  } else if (command === 'verify' && file) {
    process.exitCode = (await verify(file, labels)) ? 0 : 1;
  } else {
    console.error('usage: node scripts/lab.js run [--out <file>] [--keep] | verify <log> [--labels <file>]');
    process.exitCode = 2;
  }
}
