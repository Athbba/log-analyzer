// The dashboard: what it serves, to whom, and what it does with hostile log
// content. Pages are fetched over real HTTP from a server on 127.0.0.1.

import assert from 'node:assert/strict';
import { request } from 'node:http';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDashboard, SECURITY_HEADERS } from '../src/dashboard/server.js';
import { escapeHtml, href, html } from '../src/dashboard/html.js';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { openStore } from '../src/io/store.js';

const ESC = String.fromCharCode(0x1b);
const RLO = String.fromCharCode(0x202e);

/** Usernames, hosts and commands an attacker can put in auth.log. */
const HOSTILE = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(2)>',
  "'><svg onload=alert(3)>",
  // eslint-disable-next-line no-script-url -- hostile input under test
  'javascript:alert(4)',
  '</title><script>alert(5)</script>',
  '{{7*7}}${7*7}',
  `bidi${RLO}evil`,
  `esc${ESC}[2Jx`,
];

/**
 * A database with one run built from lines carrying hostile content in every
 * field an attacker controls, and a dashboard serving it on a free port.
 * @param {import('node:test').TestContext} t
 */
async function hostileDashboard(t) {
  const dir = mkdtempSync(join(tmpdir(), 'dash-'));
  const file = join(dir, 'runs.db');
  const store = openStore(file);
  const run = store.beginRun({ source: 'evil<script>.log', mode: 'file', options: {} });
  const lines = [];
  HOSTILE.forEach((name, n) => {
    for (let s = 0; s < 5; s++) lines.push(`Sep  7 10:${String(n).padStart(2, '0')}:${String(s * 5).padStart(2, '0')} web01 sshd[1]: Failed password for invalid user ${name} from 192.0.2.${n + 1} port 1 ssh2`);
  });
  // A forged line with a hostile "IP": sshd wouldn't write it, but logger can.
  for (let s = 0; s < 5; s++) lines.push(`Sep  7 11:00:0${s} web01 sshd[2]: Failed password for root from "onmouseover="alert(6) port 1 ssh2`);
  lines.push(`Sep  7 11:30:00 web01 sudo:   root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -G sudo ${HOSTILE[1]}`);
  lines.push(`Sep  7 11:30:00 web01 useradd[9]: new user: name=${HOSTILE[1]}, UID=1200, GID=1200, home=/home/x, shell=/bin/bash`);
  const { incidents } = await analyzeStream(Readable.from([`${lines.join('\n')}\n`]), { year: 2026, tap: store.tap(run, 64) });
  store.saveIncidents(run, incidents);
  store.finishRun(run, {});
  store.close();
  const dashboard = createDashboard({ dbPath: file, port: 0 });
  const url = await dashboard.listen();
  t.after(async () => {
    await dashboard.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return { url: new URL(url), incidents };
}

/**
 * @param {URL} base
 * @param {string} path
 * @param {{ method?: string, host?: string }} [options]
 * @returns {Promise<{ status: number, headers: import('node:http').IncomingHttpHeaders, body: string }>}
 */
function get(base, path, { method = 'GET', host } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: base.hostname, port: base.port, path, method, headers: host ? { host } : {} }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

/**
 * Checks a page carries no markup from the log: every tag in it is one of
 * ours, every attribute value is ours or escaped, and nothing executes.
 * @param {string} body
 */
function assertInert(body) {
  assert.doesNotMatch(body, /<script/i, 'no script element');
  assert.doesNotMatch(body, /<img|<svg onload|<iframe|<object|<embed/i, 'no injected element');
  // Every "<" from the log is escaped, so each literal <...> is one of our tags;
  // the attributes inside them are what could run code.
  for (const tag of body.match(/<[^>]*>/g) ?? []) {
    assert.doesNotMatch(tag, /\son[a-z]+\s*=/i, `no event handler attribute in ${tag}`);
    assert.doesNotMatch(tag, /javascript:/i, `no javascript: URL in ${tag}`);
  }
  for (const tag of body.matchAll(/<([a-z][a-z0-9-]*)\b/gi)) {
    assert.ok(['html', 'head', 'meta', 'title', 'link', 'body', 'header', 'a', 'span', 'main', 'section', 'div', 'h1', 'h2', 'p', 'form', 'label',
      'select', 'option', 'button', 'figure', 'svg', 'rect', 'line', 'text', 'circle', 'figcaption', 'input', 'fieldset', 'legend', 'ol', 'li',
      'time', 'details', 'summary', 'pre'].includes(tag[1].toLowerCase()), `unexpected <${tag[1]}>`);
  }
  assert.ok(!body.includes(ESC) && !body.includes(RLO), 'no raw escape or bidi character');
}

test('pages built from hostile log content render it as text, everywhere', async (t) => {
  const { url, incidents } = await hostileDashboard(t);
  const overview = await get(url, '/');
  assert.equal(overview.status, 200);
  assertInert(overview.body);
  assert.ok(overview.body.includes('evil&lt;script&gt;.log'), 'the file name is shown, escaped');

  // Every incident page, including the one for the forged "IP" and the account change.
  const ids = [...overview.body.matchAll(/href="\/incidents\/(\d+)\?run=1"/g)].map((m) => m[1]);
  assert.equal(new Set(ids).size, incidents.length, 'every incident is linked');
  let pages = '';
  for (const id of new Set(ids)) {
    const page = await get(url, `/incidents/${id}?run=1`);
    assert.equal(page.status, 200);
    assertInert(page.body);
    pages += page.body;
  }
  assert.ok(pages.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'usernames are shown, escaped');
  assert.ok(pages.includes('&quot;&gt;&lt;img src=x onerror=alert(2)&gt;'), 'in descriptions and in the raw log lines');
  assert.ok(pages.includes('\\u{202e}'), 'a bidi override is shown as an escape');
  // Searching for hostile text is a parameter, not SQL or markup.
  const search = await get(url, `/?run=1&q=${encodeURIComponent("' OR 1=1 --<script>")}`);
  assert.equal(search.status, 200);
  assertInert(search.body);
  assert.match(search.body, /No incidents match these filters/);
});

test('every response carries the security headers, including errors', async (t) => {
  const { url } = await hostileDashboard(t);
  for (const path of ['/', '/incidents/1?run=1', '/static/dashboard.css', '/nope', '/incidents/999?run=1']) {
    const res = await get(url, path);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      if (name === 'cache-control' && path.startsWith('/static/')) continue;
      assert.equal(res.headers[name], value, `${name} on ${path}`);
    }
  }
  assert.match(SECURITY_HEADERS['content-security-policy'], /script-src 'none'/);
  assert.match(SECURITY_HEADERS['content-security-policy'], /frame-ancestors 'none'/);
  assert.doesNotMatch(SECURITY_HEADERS['content-security-policy'], /unsafe/);
});

test('only GET and HEAD, only its own Host, only known paths', async (t) => {
  const { url } = await hostileDashboard(t);
  const post = await get(url, '/', { method: 'POST' });
  assert.equal(post.status, 405);
  assert.equal(post.headers.allow, 'GET, HEAD');
  assert.equal((await get(url, '/', { method: 'DELETE' })).status, 405);

  // DNS rebinding: a page on evil.example resolving its name to 127.0.0.1.
  const rebound = await get(url, '/', { host: `evil.example:${url.port}` });
  assert.equal(rebound.status, 421);
  assert.doesNotMatch(rebound.body, /incident/i);
  assert.equal((await get(url, '/', { host: `localhost:${url.port}` })).status, 200);
  assert.equal((await get(url, '/', { host: '127.0.0.1:1' })).status, 421, 'another port is another origin');

  assert.equal((await get(url, '/static/../package.json')).status, 404);
  assert.equal((await get(url, '/static/dashboard.css/../../../src/io/store.js')).status, 404);
  assert.equal((await get(url, '/incidents/1abc')).status, 404);
  assert.equal((await get(url, '/?run=999')).status, 404);
  assert.equal((await get(url, '/', { method: 'HEAD' })).body, '');
});

test('the dashboard refuses to listen anywhere but loopback', () => {
  assert.throws(() => createDashboard({ dbPath: ':memory:', host: '0.0.0.0' }), /only listens on loopback/);
  assert.throws(() => createDashboard({ dbPath: ':memory:', host: '192.168.1.10' }), /only listens on loopback/);
});

test('the template escapes by default and builds same-site links only', () => {
  assert.equal(html`<p title="${'"x"'}">${'<b>'}</p>`.value, '<p title="&quot;x&quot;">&lt;b&gt;</p>');
  assert.equal(html`<ul>${['<a>', html`<li>ok</li>`]}</ul>`.value, '<ul>&lt;a&gt;<li>ok</li></ul>');
  assert.equal(escapeHtml(`a\`b'c&`), 'a&#96;b&#39;c&amp;');
  assert.equal(href('/incidents/3', { run: 1, q: 'a&b c' }), '/incidents/3?run=1&q=a%26b+c');
  // eslint-disable-next-line no-script-url -- the link builder must refuse it
  assert.throws(() => href('javascript:alert(1)'));
  assert.throws(() => href('//evil.example/'));
});
