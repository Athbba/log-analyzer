// The dashboard's pages, as pure functions from query results to HTML. Every
// value goes through the escaping `html` template (html.js), links are built
// with `href` (same-site paths only), and there is no JavaScript at all: the
// filters are a GET form and the timeline is server-drawn SVG. The one kind of
// outside link, to a technique on attack.mitre.org, is built from the fixed
// table in core/attack.js, never from log content.

import { techniquesFor, techniqueUrl } from '../core/attack.js';
import { LABELS, describe, stamp } from '../report.js';
import { Html, href, html } from './html.js';
import { RULES, SEVERITIES } from './queries.js';

/** @typedef {import('./queries.js').Filters} Filters */
/** @typedef {import('../types.js').Finding} Finding */

/** @param {number} n */
const num = (n) => n.toLocaleString('en-US');
/** @param {number} n @param {string} word */
const plural = (n, word) => `${num(n)} ${word}${n === 1 ? '' : 's'}`;
/** @param {string} s */
const capital = (s) => s.charAt(0).toUpperCase() + s.slice(1);
/** @param {number} ms */
const day = (ms) => new Date(ms).toLocaleDateString('en-US', { timeZone: 'UTC', month: 'short', day: 'numeric' });
/** @param {number} ms */
const clock = (ms) => stamp(ms).slice(11, 16);

/**
 * A time span, shortened when both ends are on the same day.
 * @param {number} from
 * @param {number} to
 */
function span(from, to) {
  if (to - from < 60_000) return `${day(from)} ${clock(from)}`;
  return stamp(from).slice(0, 10) === stamp(to).slice(0, 10)
    ? `${day(from)} ${clock(from)}–${clock(to)}`
    : `${day(from)} ${clock(from)} – ${day(to)} ${clock(to)}`;
}

/**
 * @param {{ title: string, body: Html }} page
 */
export function layout({ title, body }) {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${title}</title>
<link rel="stylesheet" href="/static/dashboard.css">
</head>
<body>
<header class="masthead"><a class="home" href="/">SSH log analyzer</a><span class="local">local, read-only</span></header>
${body}
</body>
</html>
`.value;
}

/**
 * @typedef {object} RunSummary
 * @property {number} id
 * @property {string} source
 * @property {string} mode
 * @property {string} started_at
 * @property {number | null} first
 * @property {number | null} last
 * @property {number} lines
 */

/**
 * @typedef {object} IncidentRow
 * @property {number} id
 * @property {string | null} ip
 * @property {string | null} subject
 * @property {string} severity
 * @property {number} time
 * @property {number} last
 * @property {number} findings
 * @property {string} rules
 */

/**
 * The strip chart: failed logins over the run as a faint trace, and each
 * incident as a bar from its first to its last finding, linking to it.
 * @param {{ run: number, first: number, last: number, trace: number[], incidents: IncidentRow[], marks: Map<number, number[]> }} data
 */
export function timeline({ run, first, last, trace, incidents, marks }) {
  const width = 900;
  const traceHeight = 40;
  const lane = 17;
  const shown = incidents.slice(0, 40);
  const top = traceHeight + 26;
  const height = top + Math.max(1, shown.length) * lane + 8;
  const range = Math.max(1, last - first);
  /** @param {number} t */
  const x = (t) => ((t - first) / range) * width;
  const peak = Math.max(1, ...trace);
  const barWidth = width / trace.length;

  const bars = trace.map((n, i) => {
    if (n === 0) return null;
    const h = Math.max(1, (n / peak) * traceHeight);
    return html`<rect class="trace" x="${(i * barWidth).toFixed(1)}" y="${(traceHeight - h).toFixed(1)}" width="${Math.max(1, barWidth - 1).toFixed(1)}" height="${h.toFixed(1)}"/>`;
  });

  // Midnight ticks on the server's clock.
  const ticks = [];
  const firstDay = Date.UTC(new Date(first).getUTCFullYear(), new Date(first).getUTCMonth(), new Date(first).getUTCDate());
  const stride = Math.max(1, Math.ceil(range / 86_400_000 / 12));
  for (let t = firstDay + 86_400_000; t <= last; t += stride * 86_400_000) {
    ticks.push(html`<line class="tick" x1="${x(t).toFixed(1)}" x2="${x(t).toFixed(1)}" y1="0" y2="${height}"/><text class="tick-label" x="${(x(t) + 4).toFixed(1)}" y="${traceHeight + 16}">${day(t)}</text>`);
  }

  const lanes = shown.map((incident, i) => {
    const y = top + i * lane;
    const x1 = x(incident.time);
    const w = Math.max(8, x(incident.last) - x1);
    const where = incident.ip ?? incident.subject ?? 'no single source IP';
    const dots = (marks.get(incident.id) ?? []).slice(0, 200)
      .map((t) => html`<circle class="mark" cx="${x(t).toFixed(1)}" cy="${y + 6}" r="2.2"/>`);
    const rules = incident.rules.split(',').map((r) => LABELS[/** @type {Finding['rule']} */ (r)] ?? r).join(', ');
    return html`<a href="${href(`/incidents/${incident.id}`, { run })}"><title>${capital(incident.severity)}: ${where}, ${rules} (${span(incident.time, incident.last)})</title><rect class="bar sev-${incident.severity}" x="${x1.toFixed(1)}" y="${y}" width="${w.toFixed(1)}" height="12" rx="2"/>${dots}</a>`;
  });

  const more = incidents.length > shown.length ? html`<p class="note">The ${num(incidents.length - shown.length)} least severe incidents aren't drawn; they are in the list below.</p>` : '';
  return html`<figure class="timeline">
<svg viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="timeline-title">
<title id="timeline-title">Failed logins over time, and each incident from its first to its last finding</title>
${bars}${ticks}
<line class="baseline" x1="0" x2="${width}" y1="${traceHeight}" y2="${traceHeight}"/>
${lanes}
</svg>
<figcaption><span class="key-trace">failed logins</span> <span class="key sev-high">high</span> <span class="key sev-medium">medium</span> <span class="key sev-low">low</span></figcaption>
${more}
</figure>`;
}

/**
 * The overview: run summary, timeline, filters, and the list of incidents.
 * @param {object} data
 * @param {RunSummary} data.run
 * @param {{ id: number, source: string, started_at: string }[]} data.runs
 * @param {IncidentRow[]} data.incidents
 * @param {number} data.total  Incidents in the run before filtering.
 * @param {number[]} data.trace
 * @param {Map<number, number[]>} data.marks
 * @param {Filters} data.filters
 */
export function overviewPage({ run, runs, incidents, total, trace, marks, filters }) {
  const filtered = filters.severities.length > 0 || filters.rule !== null || filters.q !== '';
  const hasSpan = run.first !== null && run.last !== null;
  const counts = SEVERITIES.map((s) => [s, incidents.filter((i) => i.severity === s).length]).filter(([, n]) => n);

  const picker = runs.length > 1 ? html`<form class="run-picker" method="get" action="/">
<label for="run">Run</label>
<select id="run" name="run">${runs.map((r) => html`<option value="${r.id}"${r.id === run.id ? new Html(' selected') : ''}>#${r.id} ${r.source} (${r.started_at.slice(0, 16).replace('T', ' ')} UTC)</option>`)}</select>
<button type="submit">Open</button>
</form>` : '';

  const list = incidents.length === 0
    ? html`<p class="empty">${filtered ? html`No incidents match these filters. <a href="${href('/', { run: run.id })}">Show all ${plural(total, 'incident')}</a>.` : 'No incidents in this run.'}</p>`
    : html`<ol class="incident-list">${incidents.map((i) => html`<li><a href="${href(`/incidents/${i.id}`, { run: run.id })}">
<span class="sev sev-${i.severity}">${capital(i.severity)}</span>
<span class="where">${i.ip ?? i.subject ?? 'no single source IP'}</span>
<span class="count">${plural(i.findings, 'finding')}</span>
<span class="rules">${capital(i.rules.split(',').map((r) => LABELS[/** @type {Finding['rule']} */ (r)] ?? r).join(', '))}</span>
<span class="when">${span(i.time, i.last)}</span>
</a></li>`)}</ol>`;

  const body = html`<main>
<section class="summary">
<div><h1>${run.source}</h1>
<p>${plural(run.lines, 'line')}${hasSpan ? ` from ${stamp(/** @type {number} */ (run.first)).slice(0, 16)} to ${stamp(/** @type {number} */ (run.last)).slice(0, 16)}` : ''}, ${run.mode === 'follow' ? 'followed live' : 'read as a file'}. Times are the server's own clock.</p></div>
${picker}
</section>
${hasSpan && total > 0 ? timeline({ run: run.id, first: /** @type {number} */ (run.first), last: /** @type {number} */ (run.last), trace, incidents, marks }) : ''}
<div class="workspace">
<form class="filters" method="get" action="/">
<input type="hidden" name="run" value="${run.id}">
<fieldset><legend>Severity</legend>
${SEVERITIES.map((s) => html`<label class="check"><input type="checkbox" name="severity" value="${s}"${filters.severities.includes(s) ? new Html(' checked') : ''}> ${capital(s)}</label>`)}
</fieldset>
<label for="rule">Rule</label>
<select id="rule" name="rule"><option value="">Any rule</option>${RULES.map((r) => html`<option value="${r}"${filters.rule === r ? new Html(' selected') : ''}>${capital(LABELS[/** @type {Finding['rule']} */ (r)])}</option>`)}</select>
<label for="q">IP or user</label>
<input id="q" name="q" type="search" maxlength="100" value="${filters.q}" autocomplete="off" spellcheck="false">
<div class="actions"><button type="submit">Filter</button>${filtered ? html` <a href="${href('/', { run: run.id })}">Clear</a>` : ''}</div>
</form>
<section class="incidents" aria-labelledby="incidents-heading">
<h2 id="incidents-heading">${filtered || incidents.length < total ? `${plural(incidents.length, 'incident')} of ${num(total)}` : plural(incidents.length, 'incident')}${counts.length ? html` <span class="breakdown">${counts.map(([s, n]) => `${n} ${s}`).join(', ')}</span>` : ''}</h2>
${list}
</section>
</div>
</main>`;
  return layout({ title: `${run.source}: incidents`, body });
}

/**
 * A finding's ATT&CK techniques, each linked to its page on attack.mitre.org.
 * The URLs come from the fixed table in core/attack.js, never from the log.
 * @param {Finding} finding
 */
function attackHtml(finding) {
  const techniques = techniquesFor(finding);
  if (techniques.length === 0) return '';
  return html`<p class="attack">ATT&amp;CK ${techniques.map((t, n) => html`${n > 0 ? ', ' : ''}<a href="${techniqueUrl(t.id)}" rel="noreferrer">${t.id}</a> ${t.name}`)}</p>`;
}

/**
 * One incident: its findings, each with the raw log lines behind it.
 * @param {object} data
 * @param {RunSummary} data.run
 * @param {{ id: number, ip: string | null, subject: string | null, severity: string, time: number, last: number, closed: number }} data.incident
 * @param {{ id: number, finding: Finding, lines: { line: number, text: string }[], more: boolean }[]} data.findings
 * @param {number} data.total  Findings in the incident; more than are shown when capped.
 */
export function incidentPage({ run, incident, findings, total }) {
  const where = incident.ip ?? incident.subject ?? 'no single source IP';
  const body = html`<main class="incident">
<p class="back"><a href="${href('/', { run: run.id })}">All incidents in ${run.source}</a></p>
<header class="incident-head">
<span class="sev sev-${incident.severity}">${capital(incident.severity)}</span>
<h1>${where}</h1>
<p>${span(incident.time, incident.last)}, ${findings.length < total ? `first ${num(findings.length)} of ${plural(total, 'finding')}` : plural(findings.length, 'finding')}${incident.closed ? '' : ', still open'}</p>
</header>
<ol class="findings">${findings.map(({ id, finding, lines, more }) => {
    const [first, ...rest] = describe(finding);
    return html`<li class="finding" id="finding-${id}">
<div class="finding-head"><time>${stamp(finding.time)}</time><span class="rule sev-text-${finding.severity}">${capital(LABELS[finding.rule])}</span><span class="sev-word">${finding.severity}</span></div>
<p class="what">${first}</p>${rest.map((line) => html`<p class="detail">${line}</p>`)}
${attackHtml(finding)}
${lines.length > 0 ? html`<details>
<summary>${more ? `First ${plural(lines.length, 'log line')}` : plural(lines.length, 'log line')}</summary>
<pre class="log">${lines.map((l) => html`<span class="ln">${l.line}</span>${l.text}\n`)}</pre>
</details>` : html`<p class="detail">No stored log lines for this finding.</p>`}
</li>`;
  })}</ol>
</main>`;
  return layout({ title: `${capital(incident.severity)} incident: ${where}`, body });
}

/**
 * @param {number} status
 * @param {string} message
 */
export function errorPage(status, message) {
  return layout({ title: `${status}`, body: html`<main><section class="summary"><div><h1>${status}</h1><p>${message}</p><p><a href="/">Back to the incidents</a></p></div></section></main>` });
}
