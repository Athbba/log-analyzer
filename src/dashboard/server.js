// The dashboard server: local, read-only, and strict about what it serves.
//
// - Binds to a loopback address only (127.0.0.1 or ::1), never 0.0.0.0.
// - Answers only requests whose Host header names that address and port, so a
//   web page can't use DNS rebinding to read the dashboard from the browser.
// - GET and HEAD only; everything else is 405.
// - Opens the database read-only.
// - Sends no JavaScript. The Content-Security-Policy forbids scripts, inline
//   styles, frames, plugins, forms to other origins, and loading anything
//   from elsewhere.
// - Refuses requests the browser marks as coming from another site.
// - Every log field is escaped (html.js); errors never echo request data.

import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { openStore } from '../io/store.js';
import { countIncidents, failureTrace, incidentDetail, incidentsFor, listRuns, RULES, runSummary, SEVERITIES } from './queries.js';
import { errorPage, incidentPage, overviewPage } from './views.js';

/** @typedef {import('node:http').IncomingMessage} IncomingMessage */
/** @typedef {import('node:http').ServerResponse} ServerResponse */

const CSS = readFileSync(new URL('./dashboard.css', import.meta.url), 'utf8');

export const SECURITY_HEADERS = {
  'content-security-policy': [
    "default-src 'none'", "style-src 'self'", "img-src 'self'", "script-src 'none'", "connect-src 'none'",
    "font-src 'none'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'",
  ].join('; '),
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
  'cache-control': 'no-store',
};

const LOOPBACK = new Set(['127.0.0.1', '::1']);

/**
 * @param {object} options
 * @param {string} options.dbPath
 * @param {string} [options.host]  127.0.0.1 (default) or ::1.
 * @param {number} [options.port]  0 picks a free port.
 */
export function createDashboard({ dbPath, host = '127.0.0.1', port = 4797 }) {
  if (!LOOPBACK.has(host)) throw new Error(`the dashboard only listens on loopback (127.0.0.1 or ::1), not ${host}`);
  const store = openStore(dbPath, { readOnly: true });
  const { db } = store;

  /** The Host header values this server answers to, once it is listening. */
  const allowedHosts = () => {
    const address = server.address();
    const p = typeof address === 'object' && address ? address.port : port;
    return new Set([`127.0.0.1:${p}`, `localhost:${p}`, `[::1]:${p}`]);
  };

  /**
   * @param {ServerResponse} res
   * @param {number} status
   * @param {string} type
   * @param {string} body
   * @param {boolean} head
   * @param {Record<string, string>} [extra]
   */
  const send = (res, status, type, body, head, extra = {}) => {
    res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': type, 'content-length': Buffer.byteLength(body), ...extra });
    res.end(head ? undefined : body);
  };

  /**
   * @param {IncomingMessage} req
   * @param {ServerResponse} res
   */
  function handle(req, res) {
    const head = req.method === 'HEAD';
    if (req.method !== 'GET' && !head) {
      return send(res, 405, 'text/plain; charset=utf-8', 'Only GET and HEAD are allowed.\n', false, { allow: 'GET, HEAD' });
    }
    if (!allowedHosts().has(req.headers.host ?? '')) {
      return send(res, 421, 'text/plain; charset=utf-8', 'This dashboard only answers on its own loopback address.\n', head);
    }
    // A page on another site can still make the browser send requests here
    // (images, no-cors fetches) and time them; browsers mark those.
    const site = req.headers['sec-fetch-site'];
    if (site === 'cross-site' || site === 'same-site') {
      return send(res, 403, 'text/plain; charset=utf-8', 'This dashboard only answers to itself, not to other sites.\n', head);
    }
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === '/static/dashboard.css') {
      return send(res, 200, 'text/css; charset=utf-8', CSS, head, { 'cache-control': 'no-cache' });
    }

    const page = (/** @type {number} */ status, /** @type {string} */ body) => send(res, status, 'text/html; charset=utf-8', body, head);
    const runs = listRuns(db);
    if (runs.length === 0) return page(404, errorPage(404, 'This database has no runs yet. Store one with: node bin/analyze.js <log> --db <file>'));
    const runParam = url.searchParams.get('run');
    const runId = runParam !== null && /^\d{1,9}$/.test(runParam) ? Number(runParam) : runs[0].id;
    const run = runSummary(db, runId);
    if (!run) return page(404, errorPage(404, 'There is no run with that number.'));

    if (url.pathname === '/') {
      const filters = {
        severities: url.searchParams.getAll('severity').filter((s) => SEVERITIES.includes(s)),
        rule: RULES.includes(url.searchParams.get('rule') ?? '') ? url.searchParams.get('rule') : null,
        q: (url.searchParams.get('q') ?? '').trim().slice(0, 100),
      };
      const incidents = incidentsFor(db, run.id, filters);
      const total = countIncidents(db, run.id);
      const hasSpan = run.first !== null && run.last !== null;
      const trace = hasSpan ? failureTrace(db, run.id, run.first, run.last, 160) : [];
      /** @type {Map<number, number[]>} */
      const marks = new Map();
      for (const { incident, time } of /** @type {{ incident: number, time: number }[]} */ (
        db.prepare('SELECT incident, time FROM findings WHERE run = ? ORDER BY time LIMIT 20000').all(run.id))) {
        const list = marks.get(incident);
        if (list) list.push(time);
        else marks.set(incident, [time]);
      }
      return page(200, overviewPage({ run, runs, incidents, total, trace, marks, filters }));
    }

    const match = /^\/incidents\/(\d{1,9})$/.exec(url.pathname);
    if (match) {
      const detail = incidentDetail(db, Number(match[1]));
      if (!detail || detail.incident.run !== run.id) return page(404, errorPage(404, 'There is no incident with that number in this run.'));
      return page(200, incidentPage({ run, ...detail }));
    }
    return page(404, errorPage(404, 'There is no such page.'));
  }

  const server = createServer((req, res) => {
    try {
      handle(req, res);
    } catch (err) {
      console.error(`dashboard: ${err instanceof Error ? err.message : String(err)}`);
      if (!res.headersSent) send(res, 500, 'text/plain; charset=utf-8', 'Something went wrong reading the database.\n', false);
      else res.destroy();
    }
  });

  return {
    server,
    /** @returns {Promise<string>} The dashboard's URL. */
    listen: () => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        const address = /** @type {import('node:net').AddressInfo} */ (server.address());
        resolve(`http://${host === '::1' ? '[::1]' : host}:${address.port}/`);
      });
    }),
    close: () => new Promise((resolve) => {
      server.closeAllConnections();
      server.close(() => {
        store.close();
        resolve(undefined);
      });
    }),
  };
}
