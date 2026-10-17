# Specification

This document says what the analyzer is for, what it deliberately is not, and
how each milestone is judged finished. [PLAN.md](PLAN.md) breaks the work into
tasks; [docs/adr/](docs/adr/) records the decisions behind it.

## Purpose

Read Linux SSH authentication logs (`auth.log`), either a finished file or a
log that is still being written, and report attacks in a form a SOC analyst can
act on: grouped by attacker, explained in plain words, labelled with MITRE
ATT&CK techniques, and stored so they can be browsed later.

## Review of the starting point (v0.1.0)

### What is good

- **Clear pipeline.** `parse.js` turns lines into events, `detectors.js` turns
  events into findings and incidents, `report.js` renders them. The detectors
  never touch I/O.
- **Real domain knowledge.** The parser counts `message repeated N times`
  lines, skips the duplicate PAM and `Invalid user` lines, takes the *last*
  `from … port` so a username cannot spoof the address, and knows the
  `sshd-session`/`sshd-auth` names used by OpenSSH 9.8+.
- **Tests that pin behaviour at the boundaries** (4 vs 5 failures, a window
  exactly 10 minutes wide, 00:59 vs 01:00), plus an end-to-end answer key from
  a seeded generator, plus a record of planted-bug testing.
- **No runtime dependencies**, and an honest README.

### Risks for the planned work

| Area | Risk | Evidence |
|---|---|---|
| Memory in a long-running process | `parseLines` keeps every event; `analyze` copies and sorts them all, keeps a `hot` array per IP, every SSH session ever opened, and every sudo line. Memory grows with the log, without limit. | `src/parse.js:50`, `src/detectors.js:26,47,141-142` |
| Retrospective rules | Brute force is "high if that IP *later* logs in", with no time limit; a breach is high if a brute force that only becomes visible *after* the login covers it. Both need the future, so they cannot run unchanged on a live stream. | `src/detectors.js:74,100` |
| One huge line | `readline` buffers until it sees a newline, so a single line with no newline (corruption, or an attacker with write access) is held in memory whole. There is no line-length limit. | `bin/analyze.js:94-97` |
| Regexes on attacker input | Fuzzing 3,000 adversarial lines up to 1.5 KB found a worst case of 0.5 ms, and 48 KB spoofed usernames parse in under 1 ms, so the current patterns do not backtrack catastrophically. Nothing stops a future pattern from doing so, and nothing tests for it. | probe run during review |
| Terminal output | Usernames, hosts and commands are printed raw. A log line forged with `logger` (any local user can do this) can carry terminal escape sequences or Unicode bidi overrides into the analyst's terminal. | `src/report.js:60-61` |
| sudo parsing | `PWD=` is user-controlled and comes before `COMMAND=`. A directory named `x ; COMMAND=/usr/bin/id` makes the lazy match pick the fake command, which downgrades attribution of an account change to the "any open session" fallback. | `src/parse.js:33` |
| Year inference | Syslog has no year. The guess uses the wall clock of the analyzing machine (impure), and only handles the year changing forwards: a late line from Dec 31 arriving after Jan 1 is placed a year in the future. | `src/parse.js:121-133` |
| Timezones and DST | Times are the server's wall clock. When DST ends an hour repeats, so events go backwards; when it starts an hour is missing, which a "time gap" tamper rule would mistake for deleted lines. | design |
| Log rotation | Nothing follows a file yet. Live mode must survive `create` rotation (rename then new file), `copytruncate` (same file shrinks to zero), partial last lines, and the file briefly not existing. | design |
| Forged lines | `auth.log` does not authenticate the program name: `logger -t sshd …` writes a line that looks like sshd's. Detections are only as trustworthy as the syslog pipeline. | design |

## Goals

1. Detect SSH attacks accurately in finished files and live logs, using **one
   detector implementation** for both.
2. Keep memory **bounded** on unbounded input: every piece of detector state
   has an eviction rule and a hard cap, and hitting a cap is reported, never
   silent.
3. Treat every log line as **hostile**: linear-time parsing, a line-length
   cap, escaped output in every sink, no `eval`, no shell, parameterised SQL.
4. **Measure** detection quality (precision and recall on labelled data) and
   speed, and publish only measured numbers.
5. Stay **dependency-free at runtime**. Development tools may be added when an
   ADR justifies them.
6. Keep the existing CLI flags, exit codes and JSON fields working. New output
   is additive.

## Non-goals

- Replacing fail2ban, auditd, or a SIEM. The analyzer reports; it never blocks
  an IP or changes the system.
- Parsing every syslog program. Only sshd, sudo and the shadow-utils account
  tools are interpreted.
- Authenticating log sources. Forged local lines are a documented limitation.
- Multi-host correlation, a hosted service, or user accounts on the
  dashboard. The dashboard is local, single-user and read-only.
- A TypeScript rewrite. Types come from JSDoc checked by `tsc --checkJs`.
- Converting timestamps between timezones. All times stay on the server's own
  clock, as the unusual-hour rule needs.

## Target architecture

**Functional core, imperative shell.** ([ADR-0002](docs/adr/0002-functional-core-imperative-shell.md))

```text
            shell (I/O)                         core (pure, no I/O, no dependencies)
  file / stdin / follow ──► line reader ──► parseLine ──► engine ──► findings ──► incidents
  (rotation, truncation,    (length cap,     (time         (detectors with
   shutdown)                 CRLF)            resolver)      bounded state)
                                                                   │
            sinks: terminal · JSON · SQLite · Discord · dashboard ◄┘
```

- **Detector interface.** Each rule is an object with `onEvent(event, ctx)`,
  optional `onFinding(finding, ctx)` (rules may react to each other's findings,
  for example a brute force escalating an earlier possible breach),
  `onAdvance(time, ctx)` for eviction, and `size()` for bounded-state tests.
  The engine is synchronous and deterministic: the same events in the same
  order always give the same findings.
- **Findings are incremental.** A finding is emitted when first detected and
  updated when new evidence arrives (an attack grows, a later login escalates
  it). A file is just a stream that ends.
- **Sinks** implement `{ onFinding?, onIncident?, close() }`. The terminal and
  JSON reports, SQLite and Discord are all sinks.
- **Config.** One JSON file (`log-analyzer.config.json`, or `--config`) over
  built-in defaults; CLI flags override it; secrets come only from the
  environment or `.env`.

## Compatibility contract

- Flags `--json --threshold --window --lookback --night --admin-groups --year
  -h` keep their meaning and defaults.
- Exit status: `0` nothing high-severity, `1` high-severity found, `2` bad
  arguments or unreadable input. Live mode: `0` on a clean shutdown by signal,
  `2` on a fatal error.
- Existing JSON fields keep their names, types and meaning. New fields may be
  added.
- The sample log keeps producing the five incidents in the README.

## Acceptance criteria

### M0: Foundation

- `npm run lint`, `npm run typecheck` (`tsc --checkJs`, strict) and `npm test`
  pass locally and in GitHub Actions on Node 22 and 24, on every pull request.
- Workflow uses least-privilege `permissions`, actions pinned to commit SHAs.
- `main` is protected: changes only through pull requests, required checks
  must pass, branch up to date, applies to admins, no force pushes.
- SPEC.md, PLAN.md, CLAUDE.md and the first ADRs exist.

### M1: Docker lab

- `docker compose` lab with an OpenSSH + rsyslog target and an attacker
  container, on an internal network with no route out. The attacker script
  refuses any target other than the lab container.
- Scenarios: password guessing, break-in followed by a backdoor sudo user,
  normal admin work (keys, sudo, a mistyped password, a legitimate new user).
- The resulting `auth.log` files are committed as fixtures with a labels file,
  and tests assert the analyzer's findings on them.
- CI builds the lab, runs every scenario, and runs the analyzer on the fresh
  log, asserting the labelled findings.

### M2: Detection engineering

- **M2a, engine.** All four existing rules run on the streaming engine with
  bounded state; the 35 existing tests pass unchanged; a property test shows
  the engine and the original batch implementation agree on random event
  streams; a test feeds a long hostile stream (hundreds of thousands of IPs)
  and asserts state stays under its caps. Output escaping, line-length cap and
  the new year resolver land here.
- **M2b, new rules.** Password spraying, distributed brute force (many IPs,
  one user), first login from a new source, and log tampering (time gaps,
  time going backwards, truncation, NUL bytes). Each has: positive tests,
  lookalike tests that must not alert, documented false positives, tuning
  options in the config file, and measured precision and recall on the
  labelled synthetic and lab datasets, published in `docs/evaluation.md`.

### M3: Live mode

- `--follow` reads new lines as they are written; survives `create` rotation,
  `copytruncate`, partial lines and a missing file; stops cleanly on SIGINT and
  SIGTERM (flushing sinks with a deadline); memory stays flat in a soak test.
- Discord sink: one alert per incident, plus one per escalation; rate-limited;
  retries with backoff on 429/5xx honouring `retry_after`; a bounded queue so a
  slow webhook never blocks detection; mentions disabled and markdown escaped.
  Tests use a local mock webhook. The real URL is read from `.env`.

### M4: Storage

- `node:sqlite` store of events (with raw line and position), findings and
  incidents; schema versioned; all SQL parameterised.
- At least two rules reimplemented in SQL, with tests showing identical
  results to the JavaScript rules on the sample, the lab fixtures and random
  streams.

### M5: Dashboard

- Local read-only web UI: incident timeline, drill-down to the raw log lines,
  filters by severity, rule, IP and time.
- Binds 127.0.0.1 only; rejects other `Host` headers; strict CSP with no
  inline script or style; GET/HEAD only; database opened read-only.
- Tests render malicious usernames (`<script>`, attribute breakouts, bidi
  overrides) and assert they come out inert.

### M6: MITRE ATT&CK

- Every finding carries technique IDs and names in the CLI, JSON, SQLite and
  dashboard. `docs/detections.md` explains each rule: what it looks for, the
  log lines involved, tuning, false positives and the ATT&CK mapping.

### M7: Advanced quality

- Semgrep (with project rules for this codebase's hazards) and CodeQL run in
  CI. Property-based parser tests (fast-check). Mutation testing (Stryker)
  with a recorded score and a break threshold. A speed and memory benchmark
  runs in CI; the README quotes only its measured numbers.
