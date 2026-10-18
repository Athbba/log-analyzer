// Server-rendered pages. Log values always pass through the escaping template.
import { techniquesFor, techniqueUrl } from '../core/attack.js';
import { safeText } from '../core/text.js';
import { LABELS, describe, stamp } from '../report.js';
import { Html, href, html } from './html.js';
import { EVIDENCE_COUNT_CAP, RULES, SEVERITIES } from './queries.js';

/** @typedef {import('./queries.js').Filters} Filters */
/** @typedef {import('../types.js').Finding} Finding */
/** @typedef {{id:number, source:string, mode:string, started_at:string, first:number|null, last:number|null, lines:number}} RunSummary */
/** @typedef {{id:number, ip:string|null, subject:string|null, severity:string, time:number, last:number, findings:number, rules:string}} IncidentRow */
/** @typedef {{high:number, medium:number, low:number, total:number}} Counts */
const EMPTY_FILTERS = { severities: [], rule: null, q: '', from: null, to: null };
/** @param {number} n */
const num = (n) => n.toLocaleString('en-US');
/** @param {number} n @param {string} word */
const plural = (n, word) => `${num(n)} ${word}${n === 1 ? '' : 's'}`;
/** @param {string} s */
const capital = (s) => s.charAt(0).toUpperCase() + s.slice(1);
/** @param {number|null|undefined} value */
const localInput = (value) => value === null || value === undefined ? '' : new Date(value).toISOString().slice(0, 23);
/** @param {number} first @param {number} last */
const span = (first, last) => `${stamp(first)} – ${stamp(last)}`;
/** @param {number} run @param {Filters} [filters] */
export function filterQuery(run, filters = EMPTY_FILTERS) {
  return { run, severity: filters.severities, rule: filters.rule ?? undefined, q: filters.q, from: filters.from ?? undefined, to: filters.to ?? undefined };
}
/** @param {string} severity */
const badge = (severity) => html`<span class="sev sev-${severity}">${severity === 'medium' ? 'MED' : severity.toUpperCase()}</span>`;

/** @param {{title:string, body:Html}} page */
export function layout({ title, body }) {
  return html`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="color-scheme" content="dark light">
<title>${title}</title><link rel="stylesheet" href="/static/dashboard.css">
<script type="module" src="/static/dashboard.js"></script>
</head><body>
<a class="skip" href="#main">Skip to content</a>
<header class="masthead"><div class="masthead-inner"><a class="home" href="/">SSH Log Analyzer</a><span class="local"><span class="status-dot"></span>LOCAL · READ-ONLY</span></div></header>
${body}<div id="chart-tooltip" class="chart-tooltip" role="tooltip" hidden></div>
<div id="copy-status" class="sr-only" role="status" aria-live="polite"></div>
</body></html>`.value;
}

/** @param {{run:number, first:number, last:number, trace:number[], incidents:IncidentRow[], marks:Map<number,number[]>, filters?:Filters}} data */
export function timeline({ run, first, last, trace, incidents, marks, filters = EMPTY_FILTERS }) {
  const width = 1000, left = 64, right = 984, chartWidth = right - left;
  const range = Math.max(1, last - first);
  /** @param {number} t */
  const x = (t) => left + Math.min(1, Math.max(0, (t - first) / range)) * chartWidth;
  const peak = Math.max(1, ...trace);
  const barWidth = chartWidth / Math.max(1, trace.length);
  const bars = trace.map((n, i) => {
    if (!n) return null;
    const h = Math.max(1, n / peak * 56);
    return html`<rect class="trace" x="${(left + i * barWidth).toFixed(1)}" y="${(64 - h).toFixed(1)}" width="${Math.max(1, barWidth - 1).toFixed(1)}" height="${h.toFixed(1)}"/>`;
  });
  const shown = incidents.slice(0, 40);
  const lanes = [];
  let y = 88;
  for (const severity of SEVERITIES) {
    const group = shown.filter((i) => i.severity === severity).sort((a, b) => a.time - b.time);
    /** @type {number[]} */
    const ends = [];
    lanes.push(html`<text class="lane-label" x="8" y="${y + 9}">${severity === 'medium' ? 'MED' : severity.toUpperCase()}</text>`);
    for (const incident of group) {
      const x1 = Math.min(right - 8, x(incident.time));
      const x2 = Math.max(x1 + 8, x(incident.last));
      let lane = ends.findIndex((end) => end + 8 < x1);
      if (lane === -1) lane = ends.length;
      ends[lane] = x2;
      const cy = y + lane * 16;
      const rules = incident.rules.split(',').map((r) => LABELS[/** @type {Finding['rule']} */ (r)] ?? r).join(', ');
      const label = `${capital(severity)}: ${incident.ip ?? incident.subject ?? 'Multiple sources'} · ${rules} · ${span(incident.time, incident.last)}`;
      const dots = (marks.get(incident.id) ?? []).slice(0, 200).map((t) => html`<circle class="mark" cx="${Math.min(right - 3, x(t)).toFixed(1)}" cy="${cy + 6}" r="2"/>`);
      lanes.push(html`<a class="timeline-incident" href="${href(`/incidents/${incident.id}`, filterQuery(run, filters))}" aria-label="${label}" data-tooltip="${label}"><title>${label}</title><rect class="bar sev-${severity}" x="${x1.toFixed(1)}" y="${cy}" width="${(x2 - x1).toFixed(1)}" height="12" rx="2"/>${dots}</a>`);
    }
    y += Math.max(1, ends.length) * 16 + 16;
  }
  const ticks = Array.from({ length: 5 }, (_, i) => {
    const time = first + (last - first) * i / 4;
    const px = left + chartWidth * i / 4;
    return html`<line class="tick" x1="${px}" x2="${px}" y1="8" y2="${y}"/><text class="tick-label" text-anchor="${i === 0 ? 'start' : i === 4 ? 'end' : 'middle'}" x="${px}" y="${y + 20}">${stamp(time).slice(5, 16)}</text>`;
  });
  const start = Math.max(first, Math.min(last, filters.from ?? first));
  const end = Math.max(start, Math.min(last, filters.to ?? last));
  return html`<figure class="timeline" aria-labelledby="activity-heading">
<div class="panel-head"><h2 id="activity-heading">Activity &amp; incident timeline</h2><figcaption><span class="key key-trace">Failed logins</span><span class="key key-high">High</span><span class="key key-medium">Medium</span><span class="key key-low">Low</span></figcaption></div>
<div class="chart-scroll"><div class="timeline-canvas">
<svg viewBox="0 0 ${width} ${y + 36}" aria-labelledby="timeline-title" role="group"><title id="timeline-title">Failed logins and linked incidents, grouped by severity. Times use the server clock.</title>${ticks}${bars}<line class="baseline" x1="${left}" x2="${right}" y1="68" y2="68"/>${lanes}</svg>
<div class="brush" data-first="${first}" data-last="${last}"><div class="brush-track"><span class="brush-selection"></span><input class="range-start" type="range" min="${first}" max="${last === first ? last + 1 : last}" value="${start}" step="1" aria-label="Window start" form="filters-form"><input class="range-end" type="range" min="${first}" max="${last === first ? last + 1 : last}" value="${end}" step="1" aria-label="Window end" form="filters-form"></div></div>
</div></div>
<div class="range-footer"><span>Server clock · <output id="range-readout">${span(start, end)}</output></span><div class="range-actions"><a href="${href('/', filterQuery(run, { ...filters, from: null, to: null }))}">Full window</a><button form="filters-form" type="submit">Apply window</button></div></div>
${incidents.length > shown.length ? html`<p class="chart-note">Showing ${num(shown.length)} priority incidents on the chart. All displayed matches are listed below.</p>` : ''}
</figure>`;
}

/**
 * An incident row's rules: the first two as chips in the fixed rule order, then
 * how many more, so every row keeps one height. All of them are in the text a
 * screen reader reads and in the hover title.
 * @param {string} list  Comma-separated rule names from the query.
 */
function ruleCell(list) {
  const rules = list.split(',').sort((a, b) => RULES.indexOf(a) - RULES.indexOf(b)).map((r) => LABELS[/** @type {Finding['rule']} */ (r)] ?? r);
  const rest = rules.slice(2);
  return html`<span class="rules" title="${capital(rules.join(', '))}">${rules.slice(0, 2).map((r) => html`<span class="rule-chip">${capital(r)}</span>`)}${rest.length ? html`<span class="rule-more" aria-hidden="true">+${rest.length} more</span><span class="sr-only">, ${rest.join(', ')}</span>` : ''}</span>`;
}

/** @param {{run:RunSummary, runs:{id:number,source:string,started_at:string}[], incidents:IncidentRow[], total:number, trace:number[], marks:Map<number,number[]>, filters:Filters, counts?:Counts, facets?:Counts}} data */
export function overviewPage({ run, runs, incidents, total, trace, marks, filters, counts, facets }) {
  const filtered = filters.severities.length > 0 || filters.rule !== null || filters.q !== '' || (filters.from !== null && filters.from !== undefined) || (filters.to !== null && filters.to !== undefined);
  const hasSpan = run.first !== null && run.last !== null;
  const totals = counts ?? { high: 0, medium: 0, low: 0, total: incidents.length };
  const options = facets ?? totals;
  const picker = runs.length > 1 ? html`<form class="run-picker" method="get" action="/"><label for="run">Analysis run</label><select id="run" name="run">${runs.map((r) => html`<option value="${r.id}"${r.id === run.id ? new Html(' selected') : ''}>#${r.id} ${r.source} (${r.started_at.slice(0, 16).replace('T', ' ')} UTC)</option>`)}</select><button type="submit">Open</button></form>` : '';
  const list = incidents.length === 0 ? html`<div class="empty"><h3>${filtered ? 'No incidents match these filters.' : 'No incidents in this run.'}</h3><p>${filtered ? html`Adjust the window or <a href="${href('/', { run: run.id })}">reset all filters</a>.` : 'No configured detection rules flagged this sample. This does not establish that the source is safe.'}</p></div>` : html`<div class="table-scroll"><div class="incident-table"><div class="table-head" aria-hidden="true"><span>Severity</span><span>Source IP</span><span>Triggered rules</span><span>Findings</span><span>Time window</span></div><ol class="incident-list">${incidents.map((i) => html`<li><a href="${href(`/incidents/${i.id}`, filterQuery(run.id, filters))}">
${badge(i.severity)}<span class="where">${i.ip ?? i.subject ?? 'Multiple sources'}</span>${ruleCell(i.rules)}<span class="count"><span class="sr-only">Findings: </span>${num(i.findings)}</span><span class="when">${stamp(i.time)}<span class="range-end-time">${stamp(i.last)}</span></span></a></li>`)}</ol></div></div>`;
  const body = html`<main id="main">
<section class="summary"><div><p class="eyebrow">Analysis workspace</p><h1>${run.source}</h1></div>${picker}</section>
<div class="telemetry"><span><span class="meta-key">Lines</span><span>${num(run.lines)}</span></span><span><span class="meta-key">Window</span><span>${hasSpan ? span(/** @type {number} */ (run.first), /** @type {number} */ (run.last)) : 'Unavailable'}</span></span><span><span class="meta-key">Source</span><span>${run.mode === 'follow' ? 'FOLLOW' : 'FILE'}</span></span><span><span class="meta-key">Clock</span><span>SERVER LOCAL</span></span></div>
<div class="metrics"><span><span class="meta-key">Matching incidents</span><span class="metric-value">${num(totals.total)}</span></span>${SEVERITIES.map((s) => html`<span>${badge(s)}<span class="metric-value">${num(totals[/** @type {'high'|'medium'|'low'} */ (s)])}</span></span>`)}<span class="metric-scope">Current filters · ${num(total)} in run</span></div>
${hasSpan ? timeline({ run: run.id, first: /** @type {number} */ (run.first), last: /** @type {number} */ (run.last), trace, incidents, marks, filters }) : ''}
<div class="workspace"><form id="filters-form" class="filters" method="get" action="/">
<div class="panel-head"><h2>Filters</h2></div><div class="filter-body"><input type="hidden" name="run" value="${run.id}"><fieldset><legend>Severity</legend>${SEVERITIES.map((s) => html`<label class="check"><input type="checkbox" name="severity" value="${s}"${filters.severities.includes(s) ? new Html(' checked') : ''}><span class="filter-square sev-text-${s}"></span><span>${capital(s)}</span><span class="facet-count">${num(options[/** @type {'high'|'medium'|'low'} */ (s)])}</span></label>`)}</fieldset>
<label for="rule">Rule</label><select id="rule" name="rule"><option value="">Any rule</option>${RULES.map((r) => html`<option value="${r}"${filters.rule === r ? new Html(' selected') : ''}>${capital(LABELS[/** @type {Finding['rule']} */ (r)])}</option>`)}</select>
<label for="q">IP or user</label><input id="q" name="q" type="search" maxlength="100" value="${filters.q}" autocomplete="off" spellcheck="false" placeholder="Search IP or username">
<label for="from">Window start</label><input id="from" name="from" type="datetime-local" step="0.001" value="${localInput(filters.from)}"><label for="to">Window end</label><input id="to" name="to" type="datetime-local" step="0.001" value="${localInput(filters.to)}"><p class="field-note">Server-local time. Counts include matching incidents before the display limit.</p>
<div class="actions"><button type="submit">Filter</button>${filtered ? html`<a href="${href('/', { run: run.id })}">Reset</a>` : ''}</div></div></form>
<section class="incidents" aria-labelledby="incidents-heading"><div class="panel-head"><h2 id="incidents-heading">${filtered || incidents.length < total ? `${plural(incidents.length, 'incident')} of ${num(total)}` : plural(incidents.length, 'incident')}</h2><span class="result-scope">${num(totals.total)} matching${totals.total > incidents.length ? ' · display limited to 500' : ''}</span></div>${list}</section></div></main>`;
  return layout({ title: `${run.source}: incidents`, body });
}

/** @param {Finding} finding */
function attackHtml(finding) {
  return html`<span class="attack">${techniquesFor(finding).map((t) => html`<a class="attack-chip" href="${techniqueUrl(t.id)}" rel="noreferrer"><span class="attack-id">${t.id}</span><span> · ${t.name}</span></a>`)}</span>`;
}

/** Splits only safe text into fixed classes; never interprets log markup.
 * @param {string} text
 */
export function highlightLog(text) {
  const parts = safeText(text).split(/(Failed password|Accepted password|Accepted publickey|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b\d{4}-\d{2}-\d{2}T[\d:.+Z-]+|\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b|\bsshd(?:-session|-auth)?\[\d+\]|\b(?:for(?: invalid user)?|from)\s+\S+)/g);
  return html`${parts.map((part, i) => {
    if (i % 2 === 0) return html`${part}`;
    const style = part === 'Failed password' ? 'log-failure' : part.startsWith('Accepted ') ? 'log-success' : /^(?:\d{1,3}\.){3}\d{1,3}$/.test(part) || part.startsWith('from ') ? 'log-address' : /^(?:invalid user|for) /.test(part) ? 'log-user' : 'log-time';
    return html`<span class="${style}">${part}</span>`;
  })}`;
}

/**
 * The incident at a glance, from every finding (incidentSummary), with its
 * scope stated when the page lists only some of them.
 * @param {{rules:string[], users:string[], userCount:number, techniques:{id:string,name:string}[]}} summary
 * @param {number} shown @param {number} total
 */
function caseFacts({ rules, users, userCount, techniques }, shown, total) {
  const ruleNames = rules.map((r) => LABELS[/** @type {Finding['rule']} */ (r)] ?? r);
  return html`<section class="case-facts" aria-label="Incident summary">${shown < total ? html`<p class="facts-scope">Across all ${plural(total, 'finding')}, including those not listed below.</p>` : ''}<dl>
<div><dt>Rules</dt>
<dd>${capital(ruleNames.join(', '))}</dd></div>
<div><dt>Users</dt>
<dd>${users.length ? `${users.join(', ')}${userCount > users.length ? `, +${num(userCount - users.length)} more` : ''}` : 'None named'}</dd></div>
<div><dt>ATT&amp;CK</dt>
<dd>${techniques.length ? techniques.map((t, n) => html`${n > 0 ? ', ' : ''}<a href="${techniqueUrl(t.id)}" rel="noreferrer">${t.id}</a> ${t.name}`) : 'None mapped'}</dd></div>
</dl></section>`;
}

/**
 * What an evidence block holds: how many lines, of how many, and which.
 * @param {{line:number}[]} lines @param {number} count @param {boolean} more
 */
function evidenceLabel(lines, count, more) {
  const last = lines[lines.length - 1].line;
  const range = lines.length === 1 ? `line ${num(last)}` : `lines ${num(lines[0].line)}–${num(last)}`;
  if (!more) return `${plural(lines.length, 'log line')}, ${range}`;
  return `First ${num(lines.length)} of ${num(count)}${count >= EVIDENCE_COUNT_CAP ? '+' : ''} log lines, ${range}`;
}

/** @param {{run:RunSummary, incident:{id:number,ip:string|null,subject:string|null,severity:string,time:number,last:number,closed:number}, findings:{id:number,finding:Finding,lines:{line:number,text:string}[],more:boolean,count?:number}[],total:number,filters?:Filters,summary?:Parameters<typeof caseFacts>[0]}} data */
export function incidentPage({ run, incident, findings, total, filters = EMPTY_FILTERS, summary }) {
  const opened = findings.findIndex((f) => f.lines.length > 0);
  const where = incident.ip ?? incident.subject ?? 'Multiple sources';
  const body = html`<main id="main" class="incident"><nav class="back" aria-label="Breadcrumb"><a href="${href('/', filterQuery(run.id, filters))}">Incidents · ${run.source}</a></nav>
<header class="incident-head"><div><p class="eyebrow">Incident ${num(incident.id)}</p><h1>${where}</h1></div><div class="incident-state">${badge(incident.severity)}<span class="state-label">${incident.closed ? 'CLOSED' : 'OPEN'}</span></div>
<div class="detail-meta"><span>${span(incident.time, incident.last)}</span><span>${findings.length < total ? `first ${num(findings.length)} of ${plural(total, 'finding')}` : plural(findings.length, 'finding')}</span><span>SERVER LOCAL</span></div></header>
${summary ? caseFacts(summary, findings.length, total) : ''}
<div class="findings-title"><h2>Findings &amp; evidence</h2><span>Chronological order</span></div>
<ol class="findings">${findings.map(({ id, finding, lines, more, count }, n) => {
    const [first, ...rest] = describe(finding);
    return html`<li class="finding" id="finding-${id}"><div class="finding-head"><time>${stamp(finding.time)}</time><span class="rule">${capital(LABELS[finding.rule])}</span>${badge(finding.severity)}${attackHtml(finding)}</div>
<p class="what">${first}</p>${rest.map((line) => html`<p class="detail">${line}</p>`)}
${lines.length ? html`<div class="evidence"><details${n === opened ? new Html(' open') : ''}><summary><span>${evidenceLabel(lines, count ?? lines.length, more)}</span><span class="disclosure-label">Raw evidence</span></summary><pre class="log" id="evidence-${id}" tabindex="0" aria-label="Log evidence for ${LABELS[finding.rule]}">${lines.map((l) => html`<span class="log-line"><span class="ln" aria-hidden="true">${l.line}</span><code class="log-raw">${highlightLog(l.text)}</code></span>`)}</pre></details><button type="button" class="copy-button" data-copy="evidence-${id}" aria-label="Copy raw log lines for finding ${id}" hidden>Copy raw</button></div>` : html`<p class="detail">No stored log lines for this finding.</p>`}</li>`;
  })}</ol></main>`;
  return layout({ title: `${capital(incident.severity)} incident: ${where}`, body });
}

/** @param {number} status @param {string} message */
export function errorPage(status, message) {
  return layout({ title: `${status}`, body: html`<main id="main"><section class="summary"><div><h1>${status}</h1><p>${message}</p><p><a href="/">Back to incidents</a></p></div></section></main>` });
}
