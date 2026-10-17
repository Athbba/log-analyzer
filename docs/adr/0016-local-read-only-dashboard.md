# ADR-0016: A local, read-only, server-rendered dashboard

- Status: accepted
- Date: 2026-10-17

## Context

M5 adds a web view of the incidents stored by `--db` (ADR-0015): a timeline,
filters, and drill-down to the raw lines. Everything it shows comes from log
lines, and every log line is hostile (ADR-0008): a username can be
`<script>`, an attribute breakout or a bidi override. A web server on a
workstation is also reachable by any page the browser opens, through DNS
rebinding or cross-site requests. ADR-0003 rules out a web framework or a
front-end build.

## Decision

- **`node:http`, no dependencies, server-rendered HTML.** Pages are built by
  a tagged template (`src/dashboard/html.js`) that escapes every
  interpolated value unless it is an `Html` fragment made the same way, so a
  raw string can't reach the page. Escaping also neutralizes control
  characters and bidi overrides, like the terminal report.
- **No JavaScript at all.** Filters are a GET form; the timeline is inline
  SVG built on the server. The Content-Security-Policy is `default-src
  'none'` with only `style-src 'self'`, `img-src 'self'` and
  `form-action 'self'`; `script-src`, `connect-src`, frames and plugins are
  all `'none'`. No inline styles either, so the CSP needs no `unsafe-inline`.
- **Loopback only.** The server refuses to listen on anything but
  `127.0.0.1` or `::1`. It answers only requests whose `Host` header is its
  own loopback address and port (421 otherwise), which defeats DNS
  rebinding. It also refuses (403) requests the browser marks
  `Sec-Fetch-Site: cross-site` or `same-site`, so a page on another site
  can't load it in an image or a no-cors fetch to time its answers or keep
  it busy. Typed URLs, its own links and curl are still served.
- **Read-only.** GET and HEAD only (405 otherwise); the database is opened
  read-only, so even a bug in a query can't change it.
- **No JSON API.** Machine-readable output already exists (`--json`, and
  the SQLite file itself); an API would be one more surface to secure.
- **Parameterized SQL, bounded results.** Filter values are bound
  parameters; `LIKE` wildcards in the search are escaped; severities and
  rules are checked against fixed lists; numbers in paths and queries are
  limited to nine digits. The incident list shows at most 500 (with the
  real total), an incident page at most 200 findings (with the real count),
  and each finding at most 60 raw lines: one IP guessing in bursts for
  weeks can make a single incident with thousands of findings.
- **Errors never echo request data**, and every response, errors included,
  carries the security headers.

## Consequences

- Run it with `npm run dashboard -- --db runs.db`; nothing to build.
- Filtering reloads the page. With one user on one machine, that is fine.
- The time filter in SPEC is the timeline itself (each run's span); finer
  time filtering is left for later.
- The dashboard is for this machine only. Viewing it from elsewhere means an
  SSH tunnel to the same port number (`ssh -L 4797:127.0.0.1:4797 host`),
  since the Host check requires the dashboard's own port.
- Tests render hostile usernames into every page and assert they come out
  as text, and check headers, methods, Host and cross-site rejection,
  unknown paths, and the caps on a run with over 500 incidents.
