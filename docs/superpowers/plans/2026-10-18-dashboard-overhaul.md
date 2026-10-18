# Security dashboard overhaul implementation plan

> Execute inline using superpowers:executing-plans. The user's detailed UI brief in this conversation is the specification.

**Goal:** Deliver an accessible carbon dashboard with a non-overlapping timeline brush, filter-preserving investigation links, and safe evidence copying.

**Architecture:** Retain Node HTTP, SQLite read-only queries, server-rendered escaped HTML, bounded results, and local assets. Add one external same-origin ES module as progressive enhancement; permit only same-origin scripts and fonts in CSP.

**Tech stack:** Plain JavaScript, CSS, SVG, local IBM Plex Sans and JetBrains Mono WOFF2 assets.

## Constraints and decisions
- User authorizes browser interactions, superseding ADR-0016's no-script decision. No runtime framework or dependency.
- Use later palette values from the brief. Raise muted line-number contrast to meet AA; fine borders remain decorative.
- Filtering is GET-based and works without JavaScript. Epoch-millisecond range parameters match the server-clock timestamps already stored.
- Brush applies on explicit form submission, preserves other filters, and supports native keyboard sliders.
- Clipboard copies only visible stored evidence, without line-number gutters; control and bidi characters remain safely escaped as visible text.
- Unknown static paths, external Host headers, cross-site requests, and write methods remain rejected.

## Tasks
- [ ] Add failing HTTP tests for range validation/filtering, scope-correct counts, preserved navigation, trusted local assets, and highlighted hostile evidence.
- [ ] Implement query predicates and counts, fixed asset routes, time inputs, and filter-preserving links. Run dashboard tests.
- [ ] Implement safe evidence highlighting and a small client module for tooltip, brush, and clipboard interactions. Verify keyboard and failure states.
- [ ] Apply the full layout, carbon theme, local fonts, responsive list, severity tags, controls, and code containers.
- [ ] Run regression checks and browser review at desktop/mobile sizes; verify brush, copy, filters, routing, hostile input, and local asset loading.
- [ ] Update architecture/usage docs and collect deliverable changes on a feature branch.

## Review focus
- Invalid/reversed/out-of-run time ranges must never expand results silently.
- More than 500 matching incidents must produce accurate totals without unbounded responses.
- Hostile log fragments must stay escaped even when split into highlighted spans.
- Native forms, details, links, and keyboard controls must work with script blocked.
- Brush/filter context must survive overview-detail-back navigation; tooltip must stay within viewport.

## Execution ledger
- Source snapshot: c2730bb0b867b1eec02b3336476349aa322f0a9e. Git shell DNS unavailable; reconstructed through GitHub connector.
- npm installation blocked by registry DNS. Full npm run check cannot run until dependencies are available; run dependency-free Node coverage and report limits.
