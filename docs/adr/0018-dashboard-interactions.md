# ADR-0018: Local dashboard interactions and carbon visual system

- Status: accepted
- Date: 2026-10-18
- Supersedes: ADR-0016's no-JavaScript and no-font-loading decisions only.

## Context

The requested redesign adds a draggable time brush, keyboard range controls,
rich incident tooltips, and evidence copying. Those interactions need a small
browser script. The dashboard still handles attacker-controlled log text.

## Decision

- Serve a single fixed ES module and three bundled WOFF2 fonts on exact static
  routes. Fonts are IBM Plex Sans (regular/semibold) and JetBrains Mono
  (regular), distributed with their SIL Open Font Licenses.
- CSP allows scripts and fonts from self only. No inline scripts, inline event
  handlers, eval, external assets, network fetches, or write endpoints.
- Retain loopback binding, Host and Fetch Metadata checks, database read-only
  mode, GET/HEAD-only handling, parameterized queries, and output caps.
- Time-window GET parameters accept epoch milliseconds or exact server-clock
  datetime-local values. Invalid, normalized, unsafe, or reversed values return
  400. Windows match incident interval overlap, including both boundaries.
- Range handles update date fields locally; Apply window submits the existing
  filters. Without scripts, native date fields, forms, links, and details work.
- Links to incident details and back retain filter context. Counts aggregate
  the complete filtered set; the incident list stays capped at 500.
- Highlight only escaped log fragments through the existing template helper.
  Clipboard text comes from rendered evidence spans, excluding gutter numbers.
  Existing visible escaping of control and bidi characters is preserved.
- Use a carbon theme plus an equivalent high-contrast light theme. Functional
  muted text and low-severity blue are brightened from the suggested colors
  where needed for normal-text AA contrast. Structural hairlines are decorative.

## Consequences

The script is progressive enhancement, not a framework. The dashboard still
works offline and adds no runtime package dependencies. Clipboard permissions
can be denied; in that case evidence opens and receives focus, with an accessible
instruction to select and copy manually. Brush bounds are based on the complete
run; markers and incident rows follow the current filters. Histogram context is
the full run. The chart shows at most 40 priority incidents and up to 200 evidence
marks per incident, with collision-packed lanes per severity.
