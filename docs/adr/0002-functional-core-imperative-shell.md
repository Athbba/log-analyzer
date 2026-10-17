# ADR-0002: Functional core, imperative shell

- Status: accepted
- Date: 2026-10-17

## Context

The same detection logic must run over a finished file, a live log that
rotates, and (for tests) arrays of strings. It must be deterministic so that
tests, the SQL reimplementations and the evaluation numbers can be compared
exactly. The current parser already reads the wall clock (`new Date()`) to
guess the year, which makes its output depend on when it runs.

## Decision

- **Core** (parsing, time resolution, detectors, incident grouping, ATT&CK
  mapping, config validation): pure functions and deterministic state
  machines. No I/O, no `Date.now()`, no randomness, no dependencies. Anything
  time-dependent, such as "now" for the year guess, is passed in.
- **Shell** (CLI, line reader, file follower, sinks, SQLite, HTTP, Discord,
  signals): does all I/O and feeds the core.
- The core is synchronous. The shell decides when to call it, so slow I/O
  (a Discord webhook) can never stall detection.

## Consequences

- Core tests need no files, network or timers, and run in milliseconds.
- Batch and live modes share every detector; only the shell differs.
- The shell is thinner but harder to unit-test; it gets integration tests
  with real files, child processes and local mock servers.
