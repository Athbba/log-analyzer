# CLAUDE.md

SSH auth-log analyzer. Plain Node.js (22+), ES modules, no runtime
dependencies. Read SPEC.md for goals and PLAN.md for the current milestone.

## Commands

```sh
npm test             # unit, end-to-end and fixture tests (node:test)
npm run lint         # ESLint
npm run typecheck    # tsc --checkJs on JSDoc types, strict
npm run check        # all three, as CI runs them
npm run bench        # speed and memory benchmark            (lands in M7)
npm run lab          # Docker lab: play the scenarios, collect and check auth.log
npm run lab:fixture  # same, but refresh test/fixtures/lab/auth.log
```

## Rules

- **No real logs or secrets in the repo.** Logs here are synthetic or come
  from the Docker lab. Real logs hold usernames and IPs; `.gitignore` keeps
  `*.log` out. Secrets live only in `.env` (ignored). Never read `.env`.
- **Attacks only inside the local Docker lab.** Scenario scripts target the
  lab's `target` container on its internal network and nothing else.
- **Every log line is hostile.** No `eval`, `new Function`, or shell commands
  built from log content; regexes must be linear-time; escape log fields in
  every output (terminal, HTML, Discord, SQL parameters).
- **Functional core, imperative shell.** Parsing and detection are pure and
  deterministic: no I/O, no clock, no randomness, no dependencies. All I/O
  (files, network, database, signals) lives in the CLI and the sinks.
- **Tests first.** Write the failing test, then the code. Show real output.
- **Bounded state.** Any detector state that grows with input needs an
  eviction rule and a cap, and a test proving both.
- **Decisions** that a future maintainer would ask "why?" about get a short
  ADR in `docs/adr/`.
- Conventional commits; one branch and PR per milestone; never push to `main`.
