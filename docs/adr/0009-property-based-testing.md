# ADR-0009: fast-check for property-based tests

- Status: accepted
- Date: 2026-10-17

## Context

Rewriting the rules as a streaming engine risks subtle differences that
example tests won't find: windows that straddle an eviction, escalations that
arrive late, ties at the same timestamp. A random generator would find them,
but a raw counterexample of 150 events is unreadable.

## Decision

Add **fast-check** (dev dependency only) for property-based tests. Its
shrinking reduces a failing stream to a minimal one, and its seeded runs make
failures reproducible. A hand-written random loop was considered; it would
need its own shrinking to be useful, which is most of what fast-check is.

Used first for engine-vs-reference equivalence (M2a), then for parser
properties (M7). `EQUIVALENCE_RUNS` raises the number of cases for a long
local run.

## Consequences

- One more dev dependency, with no transitive dependencies of its own
  (`pure-rand` only).
- Generators are only as good as their coverage, so the equivalence test's
  generator was measured (every finding kind appears in 15–89% of streams)
  and checked with planted bugs.
