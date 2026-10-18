# Dashboard gap review after the carbon redesign

Status: review, not yet a plan. Reviewed at `main` `22779be` on 2026-10-18.
Branch `feat/dashboard-redesign`.

The redesign on `main` (ADR-0018) added a time brush, scope-correct counts, a
time-window filter, filter-preserving links, highlighted evidence, copy, local
fonts and a light theme. It replaces the earlier presentation plan for this
branch. This review lists what the dashboard still lacks for incident
investigation, measured against CLAUDE.md's dashboard rules.

## How it was reviewed

- Demo data: `samples/auth.log` stored with `--db` (one run, 6 incidents).
- `npm run dashboard` from `main`, browsed in the app's browser at about 545 px
  (dark) and at 375 × 812 (light), overview and two incident pages.
- Text contrast measured in the light theme on badges, meta keys, table
  head, chart ticks, rule chips and the eyebrow label: all 6.1:1 or more. The
  dark theme was not measured.
- Code read: `views.js`, `dashboard.js`, `dashboard.css`, `queries.js`,
  `server.js`, ADR-0018, and the overhaul plan.
- Not covered here: no-JavaScript behaviour, Windows High Contrast, and
  screen-reader output. CI's `dashboard-ui` job covers the scripted
  interactions; nothing here re-ran it.

## Already done on main (dropped from the old plan)

- Severity counts aggregate the whole filtered set, not the 500-row list.
- Time-window filter with validated bounds (PLAN.md still lists it as
  deferred; this branch marks it done).
- Evidence highlighting of the failure, success, address, user and time fields.
- Links from an incident back to the overview keep the filters.

## What is still missing

Ordered by how much each one slows an investigation.

### 1. The incident page has no case summary

The header shows the source, the time span, the finding count, and open or
closed. The rules, the usernames involved, and the ATT&CK techniques appear
only finding by finding, so an analyst has to read every finding to answer
"which accounts were touched?". Past the 200-finding cap
(`queries.js:115`), they can't be answered from the page at all.

*Needs:* a bounded aggregate over **all** findings of the incident (distinct
rules, distinct users with a count and a cap, distinct techniques, duration),
shown as a `dl` in the header, with scope wording when capped. A behaviour
change, so tests first.

### 2. Evidence starts hidden and its extent is unclear

Every finding's `<details>` is closed (`views.js:152`), so the incident page
opens without a single log line. The summary says "15 log lines" or "First 60
log lines", but not which line numbers they cover or how many lines exist in
total.

*Needs:* open the first finding's evidence by default; show the line-number
range in the summary, and the real total when capped (counting is bounded by
the existing `evidence` limit plus one).

### 3. Timeline bars are identified only by hover or focus

Lanes are labelled by severity group only. An incident's source appears only
in the tooltip, so on touch screens (no hover) a bar can't be identified
before you tap it, and tapping navigates away.

*Needs:* a source label for each bar in the chart (truncated server-side,
escaped), or a numbered key that matches the incident rows. The tooltip stays
as enhancement.

### 4. Narrow screens: the list scrolls sideways and starts two screens down

At 375 px:
- The incident list keeps its desktop table width (768 px) inside a scrolling
  container, so the rules column is cut off and the time column is
  off-screen.
- The filter form, with two `datetime-local` fields, comes before the list, so
  the first incident is about two screens down. The run metadata block takes
  most of the first screen.
- The timeline and brush scroll sideways inside their panel.

*Needs:* a stacked row layout under 600 px (severity, source, then rules and
time on a second line); filters folded into a `<details>` summary that shows
the active filters (works without JavaScript); compact metadata on one or two
lines. The timeline may keep contained scrolling, but its labels must still
fit.

### 5. Rows with many rules become chip piles

The high incident has five rule chips, which wrap into three lines and set
the row height. Rows end up different heights and hard to scan.

*Needs:* the first two rules, then "+N more", with the full list in the
row's accessible name and on the incident page.

### 6. Small uppercase monospace labels

Meta keys, table headings, badges, chart ticks and state labels are 10–11 px
uppercase monospace ("MATCHING INCIDENTS", "MED", "SERVER LOCAL", "CLOSED").
They pass contrast, but they are small for the main labels of a working tool,
and "MED" is read out as a word by screen readers.

*Needs:* 12 px minimum for labels; sentence case for labels and state; spell
out "Medium" (or add an accessible name). Keep monospace for IPs, times and
log lines, where it helps alignment.

### 7. Scope wording is vague in places

The counts are now right, but the wording is loose: the strip says "Current
filters · 6 in run", and the list heading shows "6 incidents" next to "6
matching".

*Needs:* one sentence that states the scope: "6 of 6 incidents in this run",
"2 of 6 match the filters", or "showing the first 500 of 1,204 that match".

## Later work (not in this branch)

Sorting, pagination past the caps, exports (CSV/JSON of the filtered list), a
per-source page (every incident for one IP or user), comparing runs, a manual
theme switch, and any detection or schema change.

## Suggested order

Items 1 and 2 first (the incident page is where investigation happens; item 1
needs a tested query). Then 4 and 5 together (both change the row layout),
then 3, then 6 and 7 as one copy-and-type pass. Each needs a before/after
browser check at desktop and 375 px in both themes.
