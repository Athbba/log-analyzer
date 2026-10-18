// Browser smoke tests for CI. Uses Chrome's DevTools protocol without adding
// an application dependency. Run: node scripts/dashboard-ui-check.js
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createReadStream, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { analyzeStream } from '../src/io/analyze-stream.js';
import { openStore } from '../src/io/store.js';
import { createDashboard } from '../src/dashboard/server.js';

class DevTools {
  /** @param {WebSocket} socket */
  constructor(socket) {
    this.socket = socket;
    this.id = 0;
    /** @type {string|undefined} */
    this.session = undefined;
    /** @type {Map<number,{resolve:(value:any)=>void,reject:(reason:Error)=>void}>} */
    this.pending = new Map();
    /** @type {string[]} */
    this.errors = [];
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data));
      if (message.method === 'Runtime.exceptionThrown') this.errors.push(JSON.stringify(message.params));
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(JSON.stringify(message.error)));
      else pending.resolve(message.result);
    });
  }
  /** @param {string} method @param {object} [params] @returns {Promise<any>} */
  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++this.id;
      const timeout = setTimeout(() => { this.pending.delete(id); reject(new Error(`DevTools timeout: ${method}`)); }, 10000);
      this.pending.set(id, {
        resolve: (value) => { clearTimeout(timeout); resolve(value); },
        reject: (reason) => { clearTimeout(timeout); reject(reason); },
      });
      this.socket.send(JSON.stringify({ id, method, params, sessionId: this.session }));
    });
  }
  /** @param {string} expression */
  async evaluate(expression) {
    const result = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  /** @param {string} url */
  async navigate(url) {
    await this.send('Page.navigate', { url });
    for (let i = 0; i < 100; i++) {
      if (await this.evaluate(`location.href === ${JSON.stringify(url)} && document.readyState === 'complete'`)) return;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Navigation timeout: ${url}`);
  }
}

const dir = mkdtempSync(join(tmpdir(), 'ssh-dashboard-ui-'));
const dbPath = join(dir, 'runs.db');
const store = openStore(dbPath);
const run = store.beginRun({ source: 'samples/auth.log', mode: 'file', options: {} });
const result = await analyzeStream(createReadStream(new URL('../samples/auth.log', import.meta.url)), { year: 2026, tap: store.tap(run, 64) });
store.saveIncidents(run, result.incidents);
store.finishRun(run, {});
store.close();
const dashboard = createDashboard({ dbPath, port: 0 });
const url = await dashboard.listen();
const chrome = spawn(process.env.CHROME_BIN ?? 'google-chrome', ['--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--remote-debugging-port=0', `--user-data-dir=${join(dir, 'chrome')}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
/** @type {WebSocket|undefined} */
let socket;
try {
  const endpoint = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Chrome did not start')), 15000);
    let stderr = '';
    chrome.once('error', (error) => { clearTimeout(timeout); reject(error); });
    chrome.stderr.on('data', (chunk) => {
      stderr += String(chunk);
      const match = /DevTools listening on (ws:\/\/\S+)/.exec(stderr);
      if (match) { clearTimeout(timeout); resolve(match[1]); }
    });
  });
  socket = new WebSocket(String(endpoint));
  await new Promise((resolve, reject) => { socket?.addEventListener('open', resolve, { once: true }); socket?.addEventListener('error', reject, { once: true }); });
  const browser = new DevTools(socket);
  const target = await browser.send('Target.createTarget', { url: 'about:blank' });
  await browser.send('Browser.grantPermissions', { origin: new URL(url).origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
  const attached = await browser.send('Target.attachToTarget', { targetId: target.targetId, flatten: true });
  browser.session = attached.sessionId;
  await browser.send('Page.enable');
  await browser.send('Runtime.enable');
  await browser.send('Page.addScriptToEvaluateOnNewDocument', { source: 'window.__csp = []; document.addEventListener("securitypolicyviolation", e => window.__csp.push(e.violatedDirective));' });
  await browser.send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  await browser.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'dark' }] });
  await browser.navigate(url);
  assert.equal(await browser.evaluate('document.documentElement.classList.contains("js")'), true);
  assert.equal(await browser.evaluate('document.querySelector(".brush").getBoundingClientRect().top >= document.querySelector(".timeline svg").getBoundingClientRect().bottom'), true, 'brush is below all timeline lanes and labels');
  await browser.evaluate('document.fonts.ready');
  assert.equal(await browser.evaluate('document.fonts.check(\'12px "IBM Plex Sans"\') && document.fonts.check(\'12px "JetBrains Mono"\')'), true);

  const first = await browser.evaluate('Number(document.querySelector(".range-start").value)');
  const rect = await browser.evaluate('(() => { const r = document.querySelector(".range-start").getBoundingClientRect(); return { x: r.left + 6, y: r.top + 12, end: r.left + r.width / 4 }; })()');
  await browser.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: rect.x, y: rect.y });
  await browser.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: rect.x, y: rect.y, button: 'left', buttons: 1, clickCount: 1 });
  await browser.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: rect.end, y: rect.y, button: 'left', buttons: 1 });
  await browser.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: rect.end, y: rect.y, button: 'left', buttons: 0, clickCount: 1 });
  assert.ok(await browser.evaluate('Number(document.querySelector(".range-start").value)') > first, 'pointer dragging changes the selected start');
  await browser.evaluate('document.querySelector(".range-start").focus()');
  const beforeKey = await browser.evaluate('Number(document.querySelector(".range-start").value)');
  await browser.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'ArrowRight', code: 'ArrowRight', windowsVirtualKeyCode: 39 });
  await browser.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'ArrowRight', code: 'ArrowRight', windowsVirtualKeyCode: 39 });
  assert.ok(await browser.evaluate('Number(document.querySelector(".range-start").value)') > beforeKey, 'keyboard changes selected start');

  assert.equal(await browser.evaluate('(() => { const a=document.querySelector("#from"), b=document.querySelector("#to"), f=a.form; a.value="2026-09-08T00:00"; b.value="2026-09-07T00:00"; f.dispatchEvent(new Event("submit", {cancelable:true})); if(b.validity.valid) return false; a.value="2026-09-06T00:00"; a.dispatchEvent(new Event("input", {bubbles:true})); return f.checkValidity(); })()'), true, 'correcting start clears reversed-range error');
  await browser.navigate(url + '?run=1&q=198.51.100.23&from=2026-09-07T00%3A00%3A00.1');
  assert.equal(await browser.evaluate('document.querySelector("h1").textContent'), 'samples/auth.log');
  const detail = await browser.evaluate('document.querySelector(".incident-list a").href');
  assert.ok(detail.includes('q=198.51.100.23'));
  await browser.navigate(detail);
  await browser.evaluate('document.querySelector("details").open=true');
  const expected = await browser.evaluate('Array.from(document.querySelectorAll(".log .log-raw"), e => e.textContent).join("\\n")');
  await browser.evaluate('document.querySelector(".copy-button").click()');
  let copied = '';
  for (let i=0; i<20 && !copied; i++) { copied = await browser.evaluate('navigator.clipboard.readText()'); if (!copied) await new Promise(resolve=>setTimeout(resolve,50)); }
  assert.ok(copied.includes(expected.split('\n')[0]), 'clipboard contains evidence without gutter');
  const back = await browser.evaluate('document.querySelector(".back a").href');
  assert.ok(back.includes('q=198.51.100.23') && back.includes('from='));

  mkdirSync('reports/dashboard-ui', { recursive: true });
  for (const [name, width, theme] of [['detail-dark',1440,'dark'], ['detail-mobile',390,'dark'], ['detail-light',1440,'light']]) {
    await browser.send('Emulation.setDeviceMetricsOverride', { width, height: 1000, deviceScaleFactor: 1, mobile: width < 600 });
    await browser.send('Emulation.setEmulatedMedia', { features: [{ name:'prefers-color-scheme', value:theme }] });
    assert.equal(await browser.evaluate('document.documentElement.scrollWidth <= innerWidth'), true, `${name} has no page overflow`);
    const shot = await browser.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
    writeFileSync(`reports/dashboard-ui/${name}.png`, Buffer.from(shot.data, 'base64'));
  }
  await browser.navigate(back);
  assert.equal(await browser.evaluate('document.querySelector("#q").value'), '198.51.100.23');
  assert.deepEqual(await browser.evaluate('window.__csp'), [], 'no CSP violations');
  assert.deepEqual(browser.errors, [], 'no browser exceptions');
  console.log('Dashboard browser checks passed: fonts, separate tracks, pointer/keyboard range, validation recovery, filters, routing, clipboard, mobile/light/dark.');
} finally {
  socket?.close();
  chrome.kill();
  await Promise.race([once(chrome, 'exit'), new Promise(resolve => setTimeout(resolve, 3000))]);
  await dashboard.close();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
