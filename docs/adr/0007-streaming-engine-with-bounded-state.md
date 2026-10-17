# ADR-0007: A streaming engine with bounded state

- Status: accepted
- Date: 2026-10-17

## Context

The original rules took the whole event list at once: they sorted it, kept
every event, every session and every sudo line, and two of them used the
future (a brute force is high "if that IP *later* logs in"; a possible breach
is high if a brute force that only becomes visible *after* the login covers
it). Live mode needs the same rules on an endless stream with flat memory.

## Decision

- **One engine** (`src/core/engine.js`) for files and live logs. Events are
  pushed one at a time in log order. Each rule is an object with
  `onEvent`, `onFinding` (react to another rule's finding), `onAdvance`
  (evict as the log's clock moves), `materialize` (fill presentation fields
  once per flush instead of per event) and `size`.
- **Findings are incremental.** A rule emits a finding when it first sees it
  and updates the same object when evidence arrives. Where the batch rules
  looked ahead, the streaming rules escalate later instead:
  - a brute force is emitted as medium and becomes high when the IP logs in;
  - a low possible breach is kept for one window and escalated if a brute
    force covering it appears (proved sufficient: after one window no new or
    growing brute force can cover it);
  - an account change is re-evaluated when a breach from one of its session
    IPs becomes high after the fact.
- **Bounded state.** Everything that grows with input is a `BoundedMap` (LRU
  with a cap) or a `TimeWindow` (time-ordered queue with a cap), swept as the
  log clock passes. Defaults: 100,000 keys per rule, 5,000 failures per IP,
  1,000 usernames per attack, and attacker IPs, breaches and sessions with no
  logout are remembered for 7 days (`limits.memoryMs`). Every drop caused by a
  cap is counted and printed as a warning; expiry by age is not a drop.
- **Caps resist flooding.** When a map is full, the oldest entry that isn't
  protected goes first (at most 64 are scanned). A rule protects the state
  that matters, such as an IP with an attack or more than one recent failure,
  so a flood of one-off addresses can't push out a real attacker's partial
  attack. Forced evictions of protected entries are counted separately.
- **The eviction clock resists forged timestamps.** A forward jump of more
  than an hour moves the clock that drives eviction only after three events
  in a row agree with it, so one forged far-future line can't age out every
  rule's state. Detection always uses each event's own time, and abandoned
  jumps are counted in health.
- **Same results as before** on in-order input, with three deliberate,
  documented differences:
  1. memory is 7 days, not "the whole file";
  2. the engine is causal: in a tie (same second), it uses only lines
     already read, so a login logged after an account change in the same
     second no longer counts as a session open at the change;
  3. ties between incidents are ordered by IP, so the order is total.
- **Proof:** the v0.1.0 batch rules are frozen in `test/reference/` as an
  oracle. A fast-check property test compares the engine with them on
  thousands of random streams that exercise every finding kind, and seven
  planted bugs in the new escalation paths were checked against it (six
  caught; the seventh exposed a gap the generator can't reach, now covered by
  a targeted test).

## Consequences

- `analyze(events)` still works (it sorts, then streams). The CLI streams
  straight from the file, never holding the events: on a 1M-line benchmark
  the live heap stays near 40 MB, against 359 MB and growing for the old way.
- A file with lines out of order (several sources merged) is processed in
  file order, not sorted, which can split or miss a window that straddles the
  disorder.
- New rules must follow the same discipline: bounded containers, an
  `onAdvance` sweep, and tests of their `size()`.
