// The Discord sink against a local mock webhook: what gets sent, how hostile
// log content is neutralized, and how it copes with 429s, 5xx, 4xx, slow and
// hanging servers, without ever blocking the caller.

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { alertPayload, checkWebhookUrl, createDiscordSink, escapeMarkdown } from '../src/io/sinks/discord.js';

/** @typedef {import('../src/core/live-incidents.js').IncidentEvent} IncidentEvent */
/** @typedef {import('../src/types.js').Finding} Finding */

/**
 * A mock webhook. Each request takes the next scripted reply ({ status, body,
 * delayMs, hang }); once the script runs out, it answers 204.
 * @param {import('node:test').TestContext} t  The server closes when this test ends.
 * @param {{ status?: number, body?: object, delayMs?: number, hang?: boolean }[]} [script]
 */
async function mockWebhook(t, script = []) {
  /** @type {{ at: number, body: any }[]} */
  const requests = [];
  const server = createServer((req, res) => {
    let data = '';
    req.on('data', (c) => { data += c; });
    req.on('end', () => {
      requests.push({ at: Date.now(), body: JSON.parse(data) });
      const reply = script.shift() ?? { status: 204 };
      if (reply.hang) return;
      setTimeout(() => {
        res.writeHead(reply.status ?? 204, { 'content-type': 'application/json' });
        res.end(reply.body ? JSON.stringify(reply.body) : '');
      }, reply.delayMs ?? 0);
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)));
  const { port } = /** @type {import('node:net').AddressInfo} */ (server.address());
  t.after(() => { server.closeAllConnections(); server.close(); });
  return {
    url: `http://127.0.0.1:${port}/api/webhooks/1/test-token`,
    requests,
    close: () => { server.closeAllConnections(); return new Promise((resolve) => server.close(() => resolve(undefined))); },
  };
}

/**
 * @param {string} type
 * @param {'high' | 'medium' | 'low'} severity
 * @param {Partial<Finding>} [finding]
 * @param {string} [id]
 * @returns {IncidentEvent}
 */
function event(type, severity, finding = {}, id = 'ip 198.51.100.23 #1') {
  /** @type {any} */
  const f = { rule: 'brute-force', severity, ip: '198.51.100.23', time: Date.UTC(2026, 8, 9, 3, 21), until: Date.UTC(2026, 8, 9, 3, 37), attempts: 14, users: [{ user: 'deploy', attempts: 14 }], invalidUsers: 0, loggedIn: null, ...finding };
  return /** @type {IncidentEvent} */ ({ type, finding: f, incident: { id, key: id.split(' #')[0], ip: f.ip, subject: null, severity, time: f.time, last: f.until, findings: [f], droppedFindings: 0 } });
}

const fast = { backoffMs: 5, burst: 100, perMinute: 60_000 };

test('one alert when an incident opens, one when it escalates, none for updates or low severity', async (t) => {
  const hook = await mockWebhook(t);
  const sink = createDiscordSink({ url: hook.url, ...fast });
  sink.onIncident(event('opened', 'low', {}, 'ip 192.0.2.1 #1'));
  sink.onIncident(event('opened', 'medium'));
  sink.onIncident(event('updated', 'medium'));
  sink.onIncident(event('updated', 'medium'));
  sink.onIncident(event('escalated', 'high'));
  sink.onIncident(event('escalated', 'high'));
  const result = await sink.close(2000);
  await hook.close();
  assert.deepEqual(result, { sent: 2, dropped: 0, failed: 0, undelivered: 0 });
  assert.deepEqual(hook.requests.map((r) => r.body.embeds[0].title), [
    'New MEDIUM incident: 198.51.100.23',
    'Escalated to HIGH incident: 198.51.100.23',
  ]);
  assert.deepEqual(hook.requests[0].body.allowed_mentions, { parse: [] });
});

test('hostile log content cannot ping, link, format, or break out of the code block', () => {
  const evil = '@everyone ``` [click](https://evil.example) **bold** <@123> ' + String.fromCharCode(27) + '[2J';
  const payload = alertPayload(event('opened', 'high', { users: [{ user: evil, attempts: 5 }] }));
  const description = payload.embeds[0].description;
  assert.ok(description.startsWith('```\n') && description.endsWith('\n```'));
  assert.equal(description.split('```').length, 3, 'only the two fences remain');
  assert.ok(!description.includes(String.fromCharCode(27)), 'no raw escape character');
  assert.deepEqual(payload.allowed_mentions, { parse: [] });

  const titled = alertPayload(event('opened', 'high', { ip: '[x](https://evil)@everyone' }));
  assert.equal(titled.embeds[0].title, 'New HIGH incident: \\[x\\]\\(https\\://evil\\)\\@everyone');
  assert.equal(escapeMarkdown('a_b*c'), 'a\\_b\\*c');
});

test('a 429 pauses sending for retry_after, then the same alert goes through', async (t) => {
  const hook = await mockWebhook(t, [{ status: 429, body: { retry_after: 0.2 } }]);
  const sink = createDiscordSink({ url: hook.url, ...fast });
  sink.onIncident(event('opened', 'high'));
  const result = await sink.close(3000);
  await hook.close();
  assert.equal(result.sent, 1);
  assert.equal(hook.requests.length, 2);
  assert.ok(hook.requests[1].at - hook.requests[0].at >= 190, `waited ${hook.requests[1].at - hook.requests[0].at} ms`);
});

test('5xx is retried with backoff; other 4xx is not retried', async (t) => {
  const flaky = await mockWebhook(t, [{ status: 500 }, { status: 502 }]);
  const retried = createDiscordSink({ url: flaky.url, ...fast });
  retried.onIncident(event('opened', 'high'));
  assert.equal((await retried.close(3000)).sent, 1);
  await flaky.close();
  assert.equal(flaky.requests.length, 3);

  /** @type {string[]} */
  const logged = [];
  const broken = await mockWebhook(t, [{ status: 400 }]);
  const rejected = createDiscordSink({ url: broken.url, ...fast, log: (m) => logged.push(m) });
  rejected.onIncident(event('opened', 'high'));
  assert.deepEqual(await rejected.close(3000), { sent: 0, dropped: 0, failed: 1, undelivered: 0 });
  await broken.close();
  assert.equal(broken.requests.length, 1);
  assert.deepEqual(logged, ['discord: alert not delivered (HTTP 400)']);
  assert.ok(!logged.join('').includes('test-token'), 'the webhook URL is never logged');
});

test('a slow webhook never blocks the caller, and the rate limit spaces alerts out', async (t) => {
  const hook = await mockWebhook(t, [{ delayMs: 300 }]);
  const sink = createDiscordSink({ url: hook.url, backoffMs: 5, burst: 2, perMinute: 600 });
  const started = performance.now();
  for (let i = 0; i < 4; i++) sink.onIncident(event('opened', 'high', {}, `ip 192.0.2.${i} #1`));
  assert.ok(performance.now() - started < 50, 'queuing four alerts took no time');
  const result = await sink.close(5000);
  await hook.close();
  assert.equal(result.sent, 4);
  // Two at once, then one every 100 ms (600 per minute).
  const gaps = hook.requests.slice(1).map((r, i) => r.at - hook.requests[i].at);
  assert.ok(gaps[2] >= 80, `gaps ${gaps.join(', ')}`);
});

test('a full queue drops the least severe alerts, and close() gives up at its deadline', async (t) => {
  const hook = await mockWebhook(t, [{ hang: true }]);
  const sink = createDiscordSink({ url: hook.url, ...fast, maxQueue: 3, timeoutMs: 60_000 });
  sink.onIncident(event('opened', 'high', {}, 'ip a #1'));
  sink.onIncident(event('opened', 'medium', {}, 'ip b #1'));
  sink.onIncident(event('opened', 'medium', {}, 'ip c #1'));
  sink.onIncident(event('opened', 'high', {}, 'ip d #1'));
  const started = Date.now();
  const result = await sink.close(300);
  await hook.close();
  assert.ok(Date.now() - started < 1500, 'close() returned near its deadline');
  assert.equal(result.dropped, 1, 'a medium alert made room for the high one');
  assert.equal(result.sent, 0);
});

test('only Discord webhooks over HTTPS, or loopback, are accepted', () => {
  assert.doesNotThrow(() => checkWebhookUrl('https://discord.com/api/webhooks/123/abc'));
  assert.doesNotThrow(() => checkWebhookUrl('http://127.0.0.1:8080/hook'));
  for (const bad of ['http://discord.com/api/webhooks/1/SECRET', 'https://evil.example/api/webhooks/1/SECRET', 'https://discord.com/SECRET', 'not a url SECRET']) {
    assert.throws(() => checkWebhookUrl(bad), (err) => err instanceof Error && !err.message.includes('SECRET'), bad);
  }
});

test('alert lines are separated by real line breaks, while a newline inside a log field stays escaped', () => {
  const plain = alertPayload(event('opened', 'high')).embeds[0].description;
  assert.ok(!plain.includes(String.raw`\x0a`), 'no escaped newline between the lines of one finding');
  assert.ok(plain.split('\n').length >= 4, 'fence, finding lines and fence on their own lines');

  const forged = alertPayload(event('opened', 'high', { users: [{ user: 'root\nFAKE LINE', attempts: 5 }] })).embeds[0].description;
  assert.ok(forged.includes(String.raw`root\x0aFAKE LINE`), 'a forged newline in a username is shown, not obeyed');
});
