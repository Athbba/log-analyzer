# Plan

Small tasks, in order. Each says how it is verified. One branch and pull
request per milestone (or per part, when a milestone is split). A task is done
when its check passes in CI, not just locally.

Status: `[x]` done, `[ ]` to do.

## M0: Foundation (`chore/m0-foundation`)

- [x] SPEC.md, PLAN.md, CLAUDE.md, ADR-0001 to ADR-0005. *Check: files exist and are linked from the README.*
- [x] ESLint (flat config, `@eslint/js` recommended + a few strict rules). *Check: `npm run lint` exits 0; a planted `eval()` makes it fail.*
- [x] JSDoc types for parse, detectors, report, CLI; `tsc --checkJs --strict`. *Check: `npm run typecheck` exits 0; a planted type error makes it fail.*
- [x] GitHub Actions: lint, typecheck, test on Node 22 and 24; SHA-pinned actions; `permissions: contents: read`. *Check: green run on the PR.*
- [x] Dependabot for npm and Actions. *Check: config validates (GitHub shows no error on the PR).*
- [ ] Protect `main`: PRs only, required checks, up to date, admins included, no force push. *Check: `gh api …/branches/main/protection` shows the settings; a direct `git push origin main` is rejected.*

## M1: Docker lab (`feat/m1-docker-lab`)

- [ ] Target image: Debian + OpenSSH + rsyslog, lab users and keys generated at build time. *Check: `docker compose up target` then `ssh` with the lab key works.*
- [ ] Attacker image + scenario runner that only targets `target`. *Check: running it with another host name exits non-zero without connecting.*
- [ ] Scenarios: guessing, break-in + backdoor, admin work. *Check: the target's `auth.log` contains the expected sshd/sudo/useradd lines.*
- [ ] `npm run lab` collects the log into `test/fixtures/lab/`, with `labels.json`. *Check: rerun produces a log with the same labelled findings.*
- [ ] Fixture tests assert the labelled findings. *Check: `npm test` passes; removing one labelled line makes it fail.*
- [ ] CI job `lab-e2e`: build, run, analyze the fresh log. *Check: green run, log uploaded as an artifact.*

## M2a: Streaming engine (`refactor/m2a-streaming-engine`)

- [ ] Copy the current rules to `test/reference/` as an oracle. *Check: it passes the existing tests.*
- [ ] Bounded primitives: time-windowed deque, LRU map with TTL and cap. *Check: unit tests for eviction order and caps.*
- [ ] Engine + four rules as detectors, `analyze()` kept as a façade. *Check: the 35 original tests pass unchanged.*
- [ ] Property test: engine vs reference on random ordered event streams. *Check: 1,000+ cases agree; a planted bug in either is caught.*
- [ ] Bounded-state test: 500k failures from 200k IPs keep every detector under its caps. *Check: test asserts `size()` and eviction counters.*
- [ ] Safe line reader (length cap, CRLF, no unbounded buffering). *Check: a 50 MB line with no newline uses < 20 MB extra memory.*
- [ ] Time resolver (closest-to-previous year). *Check: Dec/Jan in both directions, late lines, explicit `--year`.*
- [ ] Escape control characters and bidi overrides in terminal output. *Check: test with `\x1b[2J` and U+202E usernames.*
- [ ] Streaming CLI path (no event array). *Check: CLI tests unchanged; RSS on a 1M-line file stays flat.*

## M2b: New detections (`feat/m2b-detections`)

- [ ] Config file loader with validation; tuning options for every rule. *Check: unit tests for defaults, overrides, rejections.*
- [ ] Password spraying. *Check: positive + lookalike tests (office NAT, scanner noise).*
- [ ] Distributed brute force. *Check: positive + lookalike tests (internet root noise, misconfigured service).*
- [ ] First login from a new source. *Check: positive + lookalike tests (learning period, same /24 or /64, roaming).*
- [ ] Log tampering: gaps, backwards time, truncation, NUL bytes. *Check: positive + lookalike tests (quiet night, NTP step, DST).*
- [ ] Generator scenarios + labels; lab scenarios for spraying and distributed attacks. *Check: labels files list every scenario.*
- [ ] `npm run eval`: precision/recall per rule per dataset → `docs/evaluation.md`. *Check: CI regenerates it and fails if it differs from the committed file.*

## M3: Live mode (`feat/m3-live-mode`)

- [ ] File follower: polling, inode change, truncation, partial lines, missing file. *Check: tests for each rotation style on real files.*
- [ ] Live pipeline + signals + flush deadline. *Check: child-process test sends SIGTERM and checks exit 0 and flushed output.*
- [ ] Discord sink: dedup, rate limit, retry/backoff, bounded queue, safe content. *Check: tests against a local mock webhook, including 429 and 500.*
- [ ] Soak test: memory stays flat over a long live run. *Check: RSS growth below a set bound.*
- [ ] `.env` loading for `DISCORD_WEBHOOK_URL`; `.env.example`. *Check: test with a temp env file.*

## M4: Storage (`feat/m4-sqlite`)

- [ ] Schema + migrations, store sink. *Check: round-trip tests.*
- [ ] SQL brute force + SQL unusual hour (+ possible breach if feasible). *Check: equivalence tests on sample, lab, random streams.*

## M5: Dashboard (`feat/m5-dashboard`)

- [ ] Server: 127.0.0.1, Host check, CSP, read-only DB, JSON API. *Check: HTTP tests for headers, methods, Host rejection.*
- [ ] UI: timeline, incident drill-down, raw lines, filters. *Check: rendered HTML tests; manual check in the browser.*
- [ ] Hostile-data tests. *Check: malicious usernames render as text.*

## M6: ATT&CK (`feat/m6-attack`)

- [ ] Technique mapping in core; shown in all outputs. *Check: tests per rule; JSON schema includes `attack`.*
- [ ] `docs/detections.md`. *Check: every rule has a section; links valid.*

## M7: Advanced quality (`feat/m7-quality`)

- [ ] Semgrep with custom rules; CodeQL. *Check: CI jobs green; a planted `eval` is flagged.*
- [ ] fast-check property tests for the parser. *Check: invariants hold for 10k+ cases.*
- [ ] Stryker mutation testing with a break threshold. *Check: score recorded in docs.*
- [ ] Benchmark (speed + memory) in CI. *Check: numbers in README match the CI output.*
