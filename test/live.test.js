// Live mode end to end: following a file, incident events, truncation, the
// CLI with signals and Discord (against a local mock webhook), and a soak run
// that checks state stays bounded.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, mkdtempSync, rmSync, truncateSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { startLive } from '../src/io/live.js';

/** @typedef {import('../src/core/live-incidents.js').IncidentEvent} IncidentEvent */

const BIN = fileURLToPath(new URL('../bin/analyze.js', import.meta.url));
const SAMPLE = fileURLToPath(new URL('../samples/auth.log', import.meta.url));

/** RFC 3339 lines a few seconds apart, starting at 13:00 (no unusual hour). */
let second = 0;
const stamp = () => `2026-10-17T13:${String(Math.floor(second / 60)).padStart(2, '0')}:${String(second++ % 60).padStart(2, '0')}.000000+00:00`;
const failure = (ip, user = 'deploy') => `${stamp()} web01 sshd-session[900]: Failed password for ${user} from ${ip} port 4000 ssh2\n`;
const login = (ip, user = 'deploy') => `${stamp()} web01 sshd-session[901]: Accepted password for ${user} from ${ip} port 4001 ssh2\n`;

/** @param {import('node:test').TestContext} t */
function tempDir(t) {
  const dir = mkdtempSync(join(tmpdir(), 'live-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** A sink that records events as "type severity where". */
function recorder() {
  /** @type {string[]} */
  const events = [];
  /** @type {string[]} */
  const notices = [];
  return {
    events,
    notices,
    sink: {
      name: 'recorder',
      /** @param {IncidentEvent} e */
      onIncident: (e) => { if (e.type !== 'updated') events.push(`${e.type} ${e.incident.severity} ${e.incident.ip ?? e.incident.subject}`); },
      /** @param {string} m */
      onNotice: (m) => notices.push(m),
    },
  };
}

test('live: an attack opens an incident, the break-in escalates it, shutdown closes it', async (t) => {
  const file = join(tempDir(t), 'auth.log');
  writeFileSync(file, '');
  const { events, sink } = recorder();
  const live = startLive({ path: file, sinks: [sink], pollMs: 20 });
  await sleep(60);
  for (let i = 0; i < 6; i++) appendFileSync(file, failure('198.51.100.23'));
  await sleep(150);
  assert.deepEqual(events, ['opened medium 198.51.100.23'], 'reported before the attack is over');
  appendFileSync(file, login('198.51.100.23'));
  await sleep(150);
  const result = await live.stop();
  assert.deepEqual(events, ['opened medium 198.51.100.23', 'escalated high 198.51.100.23', 'closed high 198.51.100.23']);
  assert.equal(result.lines, 7);
});

test('live: a log emptied in place, with no rotated copy, is reported as tampering', async (t) => {
  const file = join(tempDir(t), 'auth.log');
  writeFileSync(file, '');
  const { events, notices, sink } = recorder();
  const live = startLive({ path: file, sinks: [sink], pollMs: 20 });
  await sleep(60);
  appendFileSync(file, login('10.0.1.23', 'alice'));
  await sleep(100);
  truncateSync(file, 0);
  await sleep(100);
  await live.stop();
  assert.ok(events.includes('opened high the log itself'), events.join('; '));
  assert.ok(notices.some((n) => n.includes('shrank')), notices.join('; '));
});

/**
 * A mock Discord webhook that records the alert titles it receives.
 * @param {import('node:test').TestContext} t
 */
async function mockWebhook(t) {
  /** @type {string[]} */
  const titles = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      titles.push(JSON.parse(body).embeds[0].title);
      res.writeHead(204).end();
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const { port } = /** @type {import('node:net').AddressInfo} */ (server.address());
  return { url: `http://127.0.0.1:${port}/api/webhooks/1/token`, titles };
}

test('CLI: --discord sends one alert per incident at medium or above, with the URL from .env', async (t) => {
  const hook = await mockWebhook(t);
  const dir = tempDir(t);
  writeFileSync(join(dir, '.env'), `DISCORD_WEBHOOK_URL=${hook.url}\n`);
  const env = { ...process.env };
  delete env.DISCORD_WEBHOOK_URL;
  const run = await new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, SAMPLE, '--year', '2026', '--discord'], { cwd: dir, env });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('exit', (status) => resolve({ status, stderr }));
  });
  assert.equal(run.status, 1, 'still exits 1 for a high-severity finding');
  assert.match(run.stderr, /Discord: \{"sent":3,"dropped":0,"failed":0,"undelivered":0\}/);
  assert.deepEqual(hook.titles.sort(), [
    'New HIGH incident: 198.51.100.23',
    'New MEDIUM incident: 10.0.1.81',
    'New MEDIUM incident: 203.0.113.45',
  ]);
});

test('CLI: --discord without a webhook URL, or with a non-Discord one, exits 2', (t) => {
  const dir = tempDir(t);
  const env = { ...process.env };
  delete env.DISCORD_WEBHOOK_URL;
  const missing = spawnSync(process.execPath, [BIN, SAMPLE, '--discord'], { cwd: dir, env, encoding: 'utf8' });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /needs DISCORD_WEBHOOK_URL/);
  const wrong = spawnSync(process.execPath, [BIN, SAMPLE, '--discord'], {
    cwd: dir, env: { ...env, DISCORD_WEBHOOK_URL: 'https://attacker.example/api/webhooks/1/SECRET' }, encoding: 'utf8',
  });
  assert.equal(wrong.status, 2);
  assert.doesNotMatch(wrong.stderr, /SECRET|attacker/, 'the URL is never echoed');
});

test('CLI: --follow --json streams incident events and stops cleanly on SIGTERM', { skip: process.platform === 'win32' && 'Windows has no catchable SIGTERM' }, async (t) => {
  const hook = await mockWebhook(t);
  const dir = tempDir(t);
  const file = join(dir, 'auth.log');
  writeFileSync(file, '');
  writeFileSync(join(dir, 'log-analyzer.config.json'), JSON.stringify({ live: { poll: '1s' } }));
  const child = spawn(process.execPath, [BIN, '--follow', '--json', '--discord', file], {
    cwd: dir, env: { ...process.env, DISCORD_WEBHOOK_URL: hook.url },
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  const exited = new Promise((resolve) => child.on('exit', (status) => resolve(status)));
  await sleep(1500);
  for (let i = 0; i < 6; i++) appendFileSync(file, failure('203.0.113.9', 'root'));
  for (let waited = 0; !stdout.includes('"opened"') && waited < 10_000; waited += 100) await sleep(100);
  child.kill('SIGTERM');
  assert.equal(await exited, 0, stderr);
  const events = stdout.trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(events.map((e) => `${e.event} ${e.incident?.severity}`), ['opened medium', 'closed medium']);
  assert.equal(events[0].incident.ip, '203.0.113.9');
  assert.match(stderr, /SIGTERM: stopping/);
  assert.match(stderr, /stopped after 6 lines; Discord: \{"sent":1/);
  assert.deepEqual(hook.titles, ['New MEDIUM incident: 203.0.113.9']);
});

test('soak: a long hostile stream keeps live state bounded', async (t) => {
  const file = join(tempDir(t), 'auth.log');
  writeFileSync(file, '');
  const live = startLive({ path: file, sinks: [], pollMs: 5, options: { limits: { maxKeys: 2000 } } });
  await sleep(30);
  // 100,000 failures from 50,000 addresses, written in bursts, plus logins.
  for (let burst = 0; burst < 50; burst++) {
    let text = '';
    for (let i = 0; i < 2000; i++) {
      const n = burst * 1000 + (i % 1000);
      text += i % 50 === 0 ? login(`10.9.${n % 250}.${n % 200}`, `user${n % 30}`) : failure(`10.${n >> 16}.${(n >> 8) & 255}.${n & 255}`, 'root');
    }
    appendFileSync(file, text);
    await sleep(5);
  }
  await sleep(300);
  const sizes = live.engine.size();
  const result = await live.stop();
  assert.equal(result.lines, 100_000);
  for (const [rule, { keys }] of Object.entries(sizes)) assert.ok(keys <= 3 * 2000, `${rule} holds ${keys} keys`);
  assert.ok(live.tracker.size() === 0, 'every incident closed at shutdown');
});
