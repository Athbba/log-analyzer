# CLAUDE.md

SSH auth-log analyzer. Plain Node.js (22+), ES modules, no runtime
dependencies. Read SPEC.md for goals and PLAN.md for the current milestone.

## Commands

```sh
npm test             # unit, end-to-end and fixture tests (node:test)
npm run lint         # ESLint
npm run typecheck    # tsc --checkJs on JSDoc types, strict
npm run check        # all three, as CI runs them
node bin/analyze.js --follow <log> [--discord]   # live mode (webhook URL in .env, never read it)
npm run dashboard -- --db <file>   # local read-only dashboard on 127.0.0.1:4797
npm run bench        # speed and memory benchmark (--lines N, --collect, --json)
npm run eval         # precision/recall on labelled data -> docs/evaluation.md (--check in CI)
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
- **Keep command output short.** Use quiet flags and show only failing
  tests, not full logs.
- **Bounded state.** Any detector state that grows with input needs an
  eviction rule and a cap, and a test proving both.
- **Decisions** that a future maintainer would ask "why?" about get a short
  ADR in `docs/adr/`.
- Conventional commits; one branch and PR per milestone; never push to `main`.
- **Small commits, small PRs.** One logical change per commit, with a
  conventional commit message.
- **Rebase and merge only.** Never squash-merge; every commit lands on
  `main` on its own. Keep rebase merging enabled in the repo settings.
  Never rewrite anything already on `main`.
- **Save usage.** Let CI run the Docker lab (`lab-e2e`) instead of running
  it locally. For dashboard changes, use a focused browser review before and
  after implementation, covering desktop, mobile, and both color themes.
  Reuse the running server and avoid repeated checks unless changes justify
  them.
- **Leave `AGENTS.md` out of commits.**

## Dashboard development

- Preserve the existing server-rendered HTML and CSS architecture, offline
  operation, and zero runtime dependencies.
- Browser JavaScript is progressive enhancement only
  ([ADR-0018](docs/adr/0018-dashboard-interactions.md)): one fixed
  same-origin module, `src/dashboard/dashboard.js`, served on an exact static
  route. Every page, filter, link and disclosure must still work with scripts
  blocked. No inline scripts or event handlers, `eval`, `innerHTML` or other
  HTML injection, network calls, or write endpoints; the script sets text with
  `textContent` only.
- Preserve the Content-Security-Policy (`script-src` and `font-src` `'self'`
  only, everything else as strict as today), loopback binding, Host and Fetch
  Metadata checks, GET/HEAD only, read-only database access, parameterized
  SQL, validated time-window parameters (bad input is a 400, never a silently
  wider result), and bounded results.
- Render all log-derived content through the existing escaping helpers,
  including highlighted log fragments and `data-` attributes the script
  reads. Treat log content as untrusted data.
- For substantial visual changes, use the frontend-design skill when
  installed. Use relevant Superpowers skills for planning, debugging, and
  verification when installed. If a skill is unavailable, report that and
  continue using the repository's instructions.
- Design for incident investigation: clear severity, source, time, findings,
  and supporting evidence.
- Keep light and dark themes, visible keyboard focus, readable contrast,
  semantic HTML, and responsive layouts.
- Use consistent CSS variables for colors, typography, spacing, borders, and
  component states. Keep fonts and assets local: the bundled WOFF2 files in
  `src/dashboard/fonts/` (with their OFL licence files) or system fonts.
- Summary numbers must state their scope and remain accurate when results
  are filtered, paginated, or capped.
- For behavior changes, follow the existing tests-first rule. Verify visual
  changes in the running dashboard; do not add tests that merely assert
  decorative CSS values. Interactions (brush, tooltip, copy) are checked in
  headless Chrome by `scripts/dashboard-ui-check.js`, which CI runs as the
  `dashboard-ui` job; extend it for new interactions and let CI run it.
- Report the checks actually run and any remaining limitations.
