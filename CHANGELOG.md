# Changelog

All notable changes, by milestone. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Each milestone links to its pull
request; [SPEC.md](SPEC.md) has the acceptance criteria and
[docs/adr/](docs/adr/) the decisions behind them.

## [1.0.1] - 2026-10-17

### Fixed

- `--window` and `--lookback` crashed with a ReferenceError on any valid
  value (for example `--window 1h`); they now work as documented. A test
  covers valid values, not only invalid ones.

### Changed

- Internal refactoring with no change in output: one error helper for both
  command-line tools, one JSON time replacer, one SQLite transaction helper,
  a shorter terminal report function, and less duplication in the CLI.

## [1.0.0] - 2026-10-17

The first release: milestones M0 to M6 on top of v0.1.0. CLI flags, exit
codes and JSON fields from v0.1.0 still work; everything new is additive.

### M6: MITRE ATT&CK ([#10](https://github.com/Athbba/log-analyzer/pull/10))

- Every finding is labelled with the ATT&CK techniques it is evidence of
  (Enterprise v20, IDs checked against attack.mitre.org): in the terminal
  report, as an `attack` array in `--json`, live JSON lines and SQLite, and
  as links on the dashboard ([ADR-0017](docs/adr/0017-attack-labels.md)).
- `docs/detections.md` gains a mapping table and a technique for every rule.

### M5: Dashboard ([#9](https://github.com/Athbba/log-analyzer/pull/9))

- `npm run dashboard`: a local, read-only web view of a `--db` file with an
  SVG timeline, filters by severity, rule and IP or username, and drill-down
  from each finding to its raw log lines.
- Loopback only, Host check against DNS rebinding, cross-site requests
  refused, GET/HEAD only, database opened read-only, no JavaScript under a
  strict CSP ([ADR-0016](docs/adr/0016-local-read-only-dashboard.md)).

### M4: Storage ([#8](https://github.com/Athbba/log-analyzer/pull/8))

- `--db <file>`: a versioned `node:sqlite` store of runs, raw lines, events,
  incidents and findings, in batch and live mode, with parameterised SQL
  ([ADR-0015](docs/adr/0015-sqlite-storage.md)).
- Brute force and unusual hour reimplemented in SQL, tested to give identical
  findings to the JavaScript rules.

### M3: Live mode ([#7](https://github.com/Athbba/log-analyzer/pull/7))

- `--follow`: watches a log through `create` and `copytruncate` rotation,
  partial lines and a missing file; stops cleanly on SIGINT/SIGTERM
  ([ADR-0013](docs/adr/0013-following-a-log.md)).
- `--discord`: one alert per incident and per escalation, rate-limited,
  retried with backoff, bounded queue, mentions disabled
  ([ADR-0014](docs/adr/0014-discord-alerting.md)).

### M2b: New detections ([#6](https://github.com/Athbba/log-analyzer/pull/6))

- Password spraying, distributed brute force, first login from a new
  source, and log tampering (gaps, time going backwards, NUL bytes,
  truncation) ([ADR-0011](docs/adr/0011-new-detections.md)).
- Config file with strict validation (`--config`, `--print-config`)
  ([ADR-0010](docs/adr/0010-config-file.md)); IPv6 counted per /64.
- `npm run eval`: precision and recall on a labelled synthetic corpus and
  the lab recording, published in [docs/evaluation.md](docs/evaluation.md)
  and checked by CI ([ADR-0012](docs/adr/0012-evaluation-methodology.md)).

### M2a: Streaming engine ([#4](https://github.com/Athbba/log-analyzer/pull/4))

- All rules run on a streaming engine with bounded state: every kind of
  state has an eviction rule and a hard cap, and hitting one is reported
  ([ADR-0007](docs/adr/0007-streaming-engine-with-bounded-state.md)).
  Memory stays flat on a million-line log instead of growing with it.
- Hostile-input hardening: a line-length cap, escaped terminal output
  (control characters and bidi overrides), and a pure year resolver
  ([ADR-0008](docs/adr/0008-hostile-input.md)).
- A property test checks the engine against the original rules on random
  event streams ([ADR-0009](docs/adr/0009-property-based-testing.md)).

### M1: Docker lab ([#3](https://github.com/Athbba/log-analyzer/pull/3))

- A Docker lab with a real OpenSSH and rsyslog target and an attacker
  container on an internal network, with scenarios for password guessing, a
  break-in with a backdoor account, and normal admin work
  ([ADR-0006](docs/adr/0006-docker-lab.md)).
- The recorded `auth.log` is a labelled test fixture, and CI replays the
  scenarios and checks a fresh log on every pull request.

### M0: Foundation ([#1](https://github.com/Athbba/log-analyzer/pull/1))

- ESLint, `tsc --checkJs` in strict mode on JSDoc types, and GitHub Actions
  on Node 22 and 24 with SHA-pinned actions and least-privilege permissions.
- `main` protected: pull requests only, required checks, no force pushes
  ([ADR-0005](docs/adr/0005-ci-and-branch-protection.md)).
- SPEC.md, PLAN.md, CLAUDE.md and the first ADRs.

## [0.1.0] - 2026-09-18

- Command-line analyzer for SSH `auth.log`: brute force, possible breach,
  unusual hour and account change, with terminal and JSON reports and a
  synthetic sample log with an answer key.

[1.0.1]: https://github.com/Athbba/log-analyzer/releases/tag/v1.0.1
[1.0.0]: https://github.com/Athbba/log-analyzer/releases/tag/v1.0.0
