// Discord alerts through a webhook. One alert when an incident opens at or
// above `minSeverity`, and one more each time it escalates: one attack is one
// alert, however many lines it writes. Alerts go through a bounded queue and a
// token bucket, and are sent in the background, so a slow or failing webhook
// can never slow detection down.
//
// Every alert is built from log fields, which an attacker controls (a username
// can be "@everyone", markdown, a link, or a fake code fence). So:
// - details go in a code block, where Discord renders no markdown, links or
//   mentions, and any ``` inside them is broken up;
// - allowed_mentions is empty, so nothing can ping anyone even if it got out;
// - the title is markdown-escaped, and every field is cut to Discord's limits.
//
// The webhook URL is a secret: it is never printed, logged or put in errors.

import { safeText } from '../../core/text.js';
import { LABELS, describe, stamp } from '../../report.js';

/** @typedef {import('../../core/live-incidents.js').IncidentEvent} IncidentEvent */
/** @typedef {import('../../core/live-incidents.js').LiveIncident} LiveIncident */
/** @typedef {import('../../types.js').Severity} Severity */

const SEVERITY_RANK = /** @type {Record<Severity, number>} */ ({ high: 0, medium: 1, low: 2 });
const COLORS = /** @type {Record<Severity, number>} */ ({ high: 0xd32f2f, medium: 0xf9a825, low: 0x0288d1 });
const DISCORD_HOSTS = new Set(['discord.com', 'discordapp.com', 'canary.discord.com', 'ptb.discord.com']);
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const NL = String.fromCharCode(10);
const FENCE = '```';
/** Most findings listed in one alert; the rest are counted. */
const LISTED = 10;

/**
 * Checks the webhook URL: a Discord webhook over HTTPS, or a loopback address
 * (for a local relay or a test server). Errors never include the URL.
 * @param {string} url
 */
export function checkWebhookUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('DISCORD_WEBHOOK_URL is not a valid URL');
  }
  if (LOOPBACK.has(parsed.hostname) && (parsed.protocol === 'http:' || parsed.protocol === 'https:')) return parsed;
  if (parsed.protocol !== 'https:' || !DISCORD_HOSTS.has(parsed.hostname) || !parsed.pathname.startsWith('/api/webhooks/')) {
    throw new Error('DISCORD_WEBHOOK_URL must be a https://discord.com/api/webhooks/… URL');
  }
  return parsed;
}

/**
 * Escapes Discord markdown in text shown outside a code block.
 * @param {string} text
 */
export function escapeMarkdown(text) {
  return safeText(text).replace(/[\x5c*_~`|>#[\]()<:@-]/g, (c) => `\x5c${c}`);
}

/**
 * Text safe inside a code block: no control characters, and no ``` that could
 * close the block early.
 * @param {string} text
 */
const inCodeBlock = (text) => safeText(text).split(FENCE).join("'''");

/**
 * @param {string} text
 * @param {number} max
 */
const cut = (text, max) => (text.length <= max ? text : `${text.slice(0, max - 1)}…`);

/**
 * The webhook payload for an incident event.
 * @param {IncidentEvent} event
 */
export function alertPayload(event) {
  const { incident } = event;
  const where = incident.ip ?? incident.subject ?? 'no single source IP';
  const verb = event.type === 'escalated' ? 'Escalated to' : 'New';
  const lines = [];
  for (const f of incident.findings.slice(-LISTED)) {
    const [first, ...more] = describe(f);
    lines.push(`${stamp(f.time)}  ${LABELS[f.rule].padEnd(15)}${first}`);
    for (const line of more) lines.push(`${' '.repeat(36)}${line}`);
  }
  const hidden = incident.findings.length - Math.min(incident.findings.length, LISTED) + incident.droppedFindings;
  if (hidden > 0) lines.push(`… and ${hidden} earlier finding${hidden === 1 ? '' : 's'}`);
  const body = cut(inCodeBlock(lines.join(NL)), 3900);
  return {
    username: 'log-analyzer',
    allowed_mentions: { parse: [] },
    embeds: [{
      title: cut(`${verb} ${incident.severity.toUpperCase()} incident: ${escapeMarkdown(where)}`, 256),
      description: `${FENCE}${NL}${body}${NL}${FENCE}`,
      color: COLORS[incident.severity],
      footer: { text: cut(`incident ${safeText(incident.id)} · times are the server's clock`, 2048) },
    }],
  };
}

/**
 * @typedef {object} DiscordOptions
 * @property {string} url
 * @property {Severity} [minSeverity]  Alert on incidents at least this severe (default medium).
 * @property {number} [burst]  Alerts that may go out at once.
 * @property {number} [perMinute]  Sustained alert rate. Discord allows about 30 per minute per webhook.
 * @property {number} [maxQueue]  Alerts waiting to be sent; when full, the least severe oldest one is dropped.
 * @property {number} [maxAttempts]  For network errors and 5xx responses.
 * @property {number} [backoffMs]  First retry delay; doubles each time, with jitter.
 * @property {number} [timeoutMs]  Per request.
 * @property {typeof fetch} [fetch]
 * @property {(message: string) => void} [log]
 */

/**
 * @param {DiscordOptions} options
 */
export function createDiscordSink({
  url, minSeverity = 'medium', burst = 5, perMinute = 20, maxQueue = 100, maxAttempts = 5,
  backoffMs = 1000, timeoutMs = 10_000, fetch: send = globalThis.fetch, log = (m) => console.error(m),
}) {
  const target = checkWebhookUrl(url).href;
  /** @typedef {{ payload: object, severity: Severity, attempts: number }} Alert */
  /** @type {Alert[]} */
  const queue = [];
  /** The most severe level each incident has been alerted at. */
  /** @type {Map<string, Severity>} */
  const alerted = new Map();
  const stats = { sent: 0, dropped: 0, failed: 0 };
  let tokens = burst;
  let refilled = Date.now();
  let pausedUntil = 0;
  let closing = false;
  let closeBy = Infinity;
  /** @type {Promise<void> | null} */
  let pumping = null;
  /** @type {AbortController | null} */
  let inFlight = null;

  // Unref'd, so a sink waiting out a rate limit never keeps the process alive.
  const sleep = (/** @type {number} */ ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)).unref());

  /** @param {Alert} alert */
  function enqueue(alert) {
    if (queue.length >= maxQueue) {
      // Drop the least severe, oldest alert (which may be this one).
      let worst = -1;
      for (let i = 0; i < queue.length; i++) {
        if (worst === -1 || SEVERITY_RANK[queue[i].severity] > SEVERITY_RANK[queue[worst].severity]) worst = i;
      }
      if (SEVERITY_RANK[alert.severity] >= SEVERITY_RANK[queue[worst].severity]) {
        stats.dropped++;
        return;
      }
      queue.splice(worst, 1);
      stats.dropped++;
    }
    queue.push(alert);
    pumping ??= pump().finally(() => { pumping = null; });
  }

  /** Waits for a send token. */
  async function takeToken() {
    for (;;) {
      const now = Date.now();
      tokens = Math.min(burst, tokens + ((now - refilled) / 60_000) * perMinute);
      refilled = now;
      if (now < pausedUntil) await sleep(pausedUntil - now);
      else if (tokens >= 1) {
        tokens--;
        return;
      } else await sleep(((1 - tokens) / perMinute) * 60_000);
    }
  }

  async function pump() {
    while (queue.length > 0) {
      await takeToken();
      const alert = queue[0];
      const result = await post(alert.payload);
      if (result.ok) {
        queue.shift();
        stats.sent++;
      } else if (result.retryAfterMs !== undefined) {
        // Rate limited: everything waits, and this alert is tried again.
        pausedUntil = Date.now() + Math.min(result.retryAfterMs, 60_000);
      } else if (result.retry && ++alert.attempts < maxAttempts) {
        await sleep(backoffMs * 2 ** (alert.attempts - 1) * (0.75 + Math.random() / 2));
      } else {
        queue.shift();
        stats.failed++;
        log(`discord: alert not delivered (${result.reason})`);
      }
      if (closing && queue.length > 0 && Date.now() >= closeBy) break;
    }
  }

  /**
   * @param {object} payload
   * @returns {Promise<{ ok: true } | { ok: false, retry: boolean, reason: string, retryAfterMs?: number }>}
   */
  async function post(payload) {
    inFlight = new AbortController();
    const timer = setTimeout(() => inFlight?.abort(), timeoutMs);
    try {
      const response = await send(target, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: inFlight.signal,
        redirect: 'error',
      });
      if (response.ok) return { ok: true };
      if (response.status === 429) {
        const body = /** @type {{ retry_after?: unknown }} */ (await response.json().catch(() => ({})));
        const seconds = Number(body.retry_after ?? response.headers.get('retry-after') ?? 1);
        return { ok: false, retry: true, reason: 'rate limited', retryAfterMs: (Number.isFinite(seconds) ? seconds : 1) * 1000 };
      }
      return { ok: false, retry: response.status >= 500, reason: `HTTP ${response.status}` };
    } catch (err) {
      const aborted = err instanceof Error && err.name === 'AbortError';
      return { ok: false, retry: true, reason: aborted ? 'timed out' : 'network error' };
    } finally {
      clearTimeout(timer);
      inFlight = null;
    }
  }

  return {
    name: 'discord',
    stats,

    /**
     * Queues an alert for new and escalated incidents. Returns at once.
     * @param {IncidentEvent} event
     */
    onIncident(event) {
      if (closing || (event.type !== 'opened' && event.type !== 'escalated')) return;
      const { incident } = event;
      if (SEVERITY_RANK[incident.severity] > SEVERITY_RANK[minSeverity]) return;
      const before = alerted.get(incident.id);
      if (before !== undefined && SEVERITY_RANK[incident.severity] >= SEVERITY_RANK[before]) return;
      alerted.delete(incident.id);
      alerted.set(incident.id, incident.severity);
      if (alerted.size > 10_000) alerted.delete(/** @type {string} */ (alerted.keys().next().value));
      // The payload is built now: the incident keeps changing after this.
      enqueue({ payload: alertPayload(event), severity: incident.severity, attempts: 0 });
    },

    /**
     * Stops taking alerts and tries to deliver the queue within `deadlineMs`.
     * @param {number} [deadlineMs]
     */
    async close(deadlineMs = 5000) {
      closing = true;
      closeBy = Date.now() + deadlineMs;
      if (pumping) {
        const deadline = sleep(deadlineMs).then(() => inFlight?.abort());
        await Promise.race([pumping, deadline]);
      }
      const undelivered = queue.length;
      queue.length = 0;
      return { ...stats, undelivered };
    },
  };
}
