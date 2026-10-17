# ADR-0015: SQLite storage with node:sqlite, and two rules in SQL

- Status: accepted
- Date: 2026-10-17

## Context

The dashboard (M5) needs incidents, findings and the raw lines behind them,
kept across runs. A second, independent implementation of some rules is also
valuable: if SQL and JavaScript agree on every input, both are more likely to
be right. ADR-0003 rules out runtime dependencies such as `better-sqlite3`.

## Decision

- **Use Node's built-in `node:sqlite`** (SQLite 3.51 on Node 22, 3.53 on Node
  24). Node 22 still marks it experimental and prints a warning, so the store
  is imported only when `--db` is given; the minimum Node becomes 22.13, the
  first 22.x where it needs no flag.
- **Schema** (versioned with `PRAGMA user_version`, version 1): `runs`,
  `lines` (every line of a run, so a finding can be shown in context),
  `events` (with a `source` column holding the IPv6 /64 the rules count by),
  `incidents`, `findings` (the whole finding as JSON, plus indexed columns).
  An older analyzer refuses a newer database rather than misreading it.
- **Parameterized SQL only.** Log content is always a bound parameter; a test
  stores `x'); DROP TABLE runs; --` and reads it back intact.
- **Batched writes**: one transaction per 5,000 rows or per flush, WAL mode.
- **Drill-down** is a query per rule (`evidence()`): the events of the
  finding's subject and time span, joined to their raw lines.
- **Two rules in SQL**: brute force (window sums, hot failures, attacks split by
  gaps, the first login within `memoryMs`) and unusual hour. Tests require
  identical findings to the JavaScript rules on the sample (three settings),
  the lab recording, 29 corpus logs, and 300 random streams with same-second
  ties and IPv6. Four bugs planted in the SQL were all caught.
- **Where they may differ, by design:** on a log whose times go backwards
  (lines spliced in), the streaming engine follows file order and SQL orders by
  time. Such logs are what the log-tampering rule reports, and they are left
  out of the comparison rather than forced to agree.

## Consequences

- `--db runs.db` works for a one-off analysis and for `--follow`, where each
  incident event updates its rows.
- Storing every line roughly doubles the work per line; it is opt-in.
- No retention policy yet: the database grows with every run.
