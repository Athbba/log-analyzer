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
import { incidentPage } from '../src/dashboard/views.js';
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
 * @param {{ method?: string, host?: string, headers?: Record<string, string> }} [options]
 * @returns {Promise<{ status: number, headers: import('node:http').IncomingHttpHeaders, body: string }>}
 */
function get(base, path, { method = 'GET', host, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: base.hostname, port: base.port, path, method, headers: host ? { ...headers, host } : headers }, (res) => {
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
  const untrustedScripts = body.replace('<script type="module" src="/static/dashboard.js"></script>', '');
  assert.doesNotMatch(untrustedScripts, /<script/i, 'only the fixed local script is allowed');
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
      'time', 'details', 'summary', 'pre', 'script', 'output', 'nav', 'h3', 'code', 'g', 'dl', 'dt', 'dd'].includes(tag[1].toLowerCase()), `unexpected <${tag[1]}>`);
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
  assert.match(SECURITY_HEADERS['content-security-policy'], /script-src 'self'/);
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

test('requests from other sites are refused, so a web page can neither probe nor load it', async (t) => {
  const { url } = await hostileDashboard(t);
  for (const site of ['cross-site', 'same-site']) {
    const res = await get(url, '/?q=192.0.2', { headers: { 'sec-fetch-site': site } });
    assert.equal(res.status, 403, site);
    assert.doesNotMatch(res.body, /incident/i);
    assert.equal(res.headers['content-security-policy'], SECURITY_HEADERS['content-security-policy']);
  }
  // Typing the URL, following a link on the dashboard itself, or curl.
  for (const site of ['none', 'same-origin']) assert.equal((await get(url, '/', { headers: { 'sec-fetch-site': site } })).status, 200, site);
  assert.equal((await get(url, '/')).status, 200, 'no Sec-Fetch-Site header');
});

test('large runs stay bounded: findings per incident page are capped, totals counted in full', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'dash-'));
  const file = join(dir, 'runs.db');
  const store = openStore(file);
  const run = store.beginRun({ source: 'big.log', mode: 'file', options: {} });
  const lines = [];
  const stamp = (/** @type {number} */ ms) => {
    const d = new Date(Date.UTC(2026, 0, 1) + ms);
    return `${d.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' })} ${String(d.getUTCDate()).padStart(2, ' ')} ${d.toISOString().slice(11, 19)}`;
  };
  // One IP, a burst of 6 guesses every 30 minutes: 250 brute-force findings in one incident.
  for (let b = 0; b < 250; b++) {
    for (let g = 0; g < 6; g++) lines.push(`${stamp(b * 30 * 60_000 + g * 1000)} web01 sshd[1]: Failed password for root from 198.51.100.7 port 1 ssh2`);
  }
  // 520 other IPs, one burst each: more incidents than the list shows.
  for (let n = 0; n < 520; n++) {
    for (let g = 0; g < 6; g++) lines.push(`${stamp(n * 60_000 + g * 1000)} web01 sshd[1]: Failed password for root from 10.${n >> 8}.${n & 255}.9 port 1 ssh2`);
  }
  lines.sort();
  const { incidents } = await analyzeStream(Readable.from([`${lines.join('\n')}\n`]), { year: 2026, tap: store.tap(run, 5000) });
  store.saveIncidents(run, incidents);
  store.finishRun(run, {});
  store.close();
  const dashboard = createDashboard({ dbPath: file, port: 0 });
  const url = new URL(await dashboard.listen());
  t.after(async () => {
    await dashboard.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const overview = await get(url, '/');
  assert.equal(overview.status, 200);
  assert.equal((overview.body.match(/<li><a href="\/incidents\//g) ?? []).length, 500, 'the list is capped');
  const heading = /<h2 id="incidents-heading">([^<]*)/.exec(overview.body)?.[1];
  assert.ok(incidents.length > 500);
  assert.equal(heading?.trim(), `500 incidents of ${incidents.length}`, 'the total is the real count, not the capped list');

  const big = /<li><a href="\/incidents\/(\d+)[^"]*">\s*<span[^>]*>[^<]*<\/span>\s*<span class="where">198\.51\.100\.7</.exec(overview.body);
  assert.ok(big, 'the busy IP is listed');
  const page = await get(url, `/incidents/${big[1]}`);
  assert.equal(page.status, 200);
  assert.equal((page.body.match(/<li class="finding"/g) ?? []).length, 200, 'findings on one page are capped');
  assert.match(page.body, /first 200 of 250 findings/);
});

test('the dashboard refuses to listen anywhere but loopback', () => {
  assert.throws(() => createDashboard({ dbPath: ':memory:', host: '0.0.0.0' }), /only listens on loopback/);
  assert.throws(() => createDashboard({ dbPath: ':memory:', host: '192.168.1.10' }), /only listens on loopback/);
});

test('range filtering rejects invalid bounds and preserves filters through incident navigation', async (t) => {
  const { url } = await hostileDashboard(t);
  for (const query of ['from=bad', 'from=9999999999999999', 'from=2&to=1', 'from=2026-02-30T00:00', 'to=-1']) {
    assert.equal((await get(url, `/?${query}`)).status, 400, query);
  }
  const from = Date.UTC(2026, 8, 7, 10, 0);
  const to = from + 25_000;
  const path = `/?run=1&severity=medium&rule=brute-force&q=192.0.2.1&from=${from}&to=${to}`;
  const res = await get(url, path);
  assert.equal(res.status, 200);
  assert.match(res.body, /class="where">192\.0\.2\.1</);
  assert.doesNotMatch(res.body, /class="where">192\.0\.2\.2</);
  const link = /href="(\/incidents\/\d+\?[^"]+)"/.exec(res.body)?.[1];
  assert.ok(link);
  const decoded = link.replaceAll('&amp;', '&');
  const next = new URL(decoded, url);
  assert.equal(next.searchParams.get('from'), String(from));
  assert.equal(next.searchParams.get('q'), '192.0.2.1');
  const detail = await get(url, decoded);
  assert.equal(detail.status, 200);
  assert.match(detail.body, /href="\/\?run=1&amp;severity=medium&amp;rule=brute-force&amp;q=192\.0\.2\.1&amp;from=/);
  assert.match((await get(url, `/?from=${to + 86400000}`)).body, /No incidents match these filters/);
  assert.equal((await get(url, '/?from=2026-09-07T10%3A00&to=2026-09-07T10%3A01')).status, 200);
});

test('local script and fonts have fixed routes, secure headers and HEAD support', async (t) => {
  const { url } = await hostileDashboard(t);
  for (const [path, type] of [['/static/dashboard.js', 'text/javascript'], ['/static/fonts/ibm-plex-sans-regular.woff2', 'font/woff2']]) {
    const res = await get(url, path);
    assert.equal(res.status, 200, path);
    assert.ok(String(res.headers['content-type']).startsWith(type));
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal((await get(url, path, { method: 'HEAD' })).body, '');
    assert.equal((await get(url, path, { host: 'evil.example' })).status, 421);
    assert.equal((await get(url, path, { headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
  }
  assert.equal((await get(url, '/static/fonts/not-a-font.woff2')).status, 404);
  assert.doesNotMatch(SECURITY_HEADERS['content-security-policy'], /unsafe-inline|unsafe-eval/);
});

test('evidence highlighting keeps hostile content inert and provides plain-text copy targets', async (t) => {
  const { url } = await hostileDashboard(t);
  const page = await get(url, '/incidents/1?run=1');
  assertInert(page.body);
  assert.match(page.body, /data-copy=/);
  assert.match(page.body, /class="log-raw"/);
  assert.match(page.body, /class="log-failure">Failed password<\/span>/);
  assert.match(page.body, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
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

test('the dashboard shows each finding\'s techniques, linked to attack.mitre.org', () => {
  const run = /** @type {any} */ ({ id: 1, source: 'auth.log' });
  const incident = { id: 1, ip: '192.0.2.1', subject: null, severity: 'medium', time: 0, last: 0, closed: 1 };
  const finding = /** @type {any} */ ({ rule: 'log-tampering', severity: 'medium', ip: null, time: 0, kind: 'gap', until: 0, line: 1, detail: 'no lines' });
  const page = incidentPage({ run, incident, findings: [{ id: 7, finding, lines: [], more: false }], total: 1 });
  assert.match(page, /href="https:\/\/attack\.mitre\.org\/techniques\/T1685\/006\/" rel="noreferrer"><span class="attack-id">T1685\.006<\/span>/);
  assert.match(page, /Disable or Modify Tools: Clear Linux or Mac System Logs/);
});

