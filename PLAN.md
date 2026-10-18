# Plan

Small tasks, in order. Each says how it is verified. One branch and pull
request per milestone (or per part, when a milestone is split). A task is done
when its check passes in CI, not just locally.

Status: `[x]` done, `[ ]` to do.

Working rules (also in CLAUDE.md): small commits with conventional messages;
small pull requests; merge with "rebase and merge", never squash, and never
rewrite `main`; CI runs the Docker lab, not the local machine; the browser is
for one final visual check only; `AGENTS.md` stays out of commits.

## M0: Foundation (`chore/m0-foundation`)

- [x] SPEC.md, PLAN.md, CLAUDE.md, ADR-0001 to ADR-0005. *Check: files exist and are linked from the README.*
- [x] ESLint (flat config, `@eslint/js` recommended + a few strict rules). *Check: `npm run lint` exits 0; a planted `eval()` makes it fail.*
- [x] JSDoc types for parse, detectors, report, CLI; `tsc --checkJs --strict`. *Check: `npm run typecheck` exits 0; a planted type error makes it fail.*
- [x] GitHub Actions: lint, typecheck, test on Node 22 and 24; SHA-pinned actions; `permissions: contents: read`. *Check: green run on the PR.*
- [x] Dependabot for npm and Actions. *Check: config validates (GitHub shows no error on the PR).*
- [x] Protect `main`: PRs only, required checks, up to date, admins included, no force push. *Check: `gh api …/branches/main/protection` reads back all four required checks, strict, admins enforced, no force push or deletion; PR #1 merged through it. (A direct push was not attempted, since if protection were off it would land on `main`.)*

## M1: Docker lab (`feat/m1-docker-lab`)

- [x] Target image: Debian + OpenSSH + rsyslog, lab users and keys generated at build time. *Check: `docker compose up target` then `ssh` with the lab key works.*
- [x] Attacker image + scenario runner that only targets `target`. *Check: running it with another host name exits non-zero without connecting.*
- [x] Scenarios: guessing, break-in + backdoor, admin work. *Check: the target's `auth.log` contains the expected sshd/sudo/useradd lines.*
- [x] `npm run lab` collects the log into `test/fixtures/lab/`, with `labels.json`. *Check: rerun produces a log with the same labelled findings.*
- [x] Fixture tests assert the labelled findings. *Check: `npm test` passes; removing one labelled line makes it fail.*
- [x] CI job `lab-e2e`: build, run, analyze the fresh log. *Check: green run, log uploaded as an artifact.*

## M2a: Streaming engine (`refactor/m2a-streaming-engine`)

- [x] Copy the current rules to `test/reference/` as an oracle. *Check: it passes the existing tests.*
- [x] Bounded primitives: time-windowed deque, LRU map with TTL and cap. *Check: unit tests for eviction order and caps.*
- [x] Engine + four rules as detectors, `analyze()` kept as a façade. *Check: the 35 original tests pass unchanged.*
- [x] Property test: engine vs reference on random ordered event streams. *Check: 1,000+ cases agree on each run; 7 planted bugs in the new paths: 6 caught by it, the 7th (a same-second case the generator can't reach) by a targeted test.*
- [x] Bounded-state test: 500k failures from 200k IPs keep every detector under its caps. *Check: test pushes 200k failures from 100k IPs plus one 2,000-username attack and asserts `size()` and the eviction counters.*
- [x] Safe line reader (length cap, CRLF, no unbounded buffering). *Check: a 50 MB line with no newline never buffers more than 8 KiB (asserted on the splitter's buffer).*
- [x] Time resolver (closest-to-previous year). *Check: Dec/Jan in both directions, late lines, explicit `--year`.*
- [x] Escape control characters and bidi overrides in terminal output. *Check: test with `\x1b[2J` and U+202E usernames.*
- [x] Streaming CLI path (no event array). *Check: CLI tests unchanged; `npm run bench`: live heap 41/43/42/40 MB across 1M lines vs 93→359 MB the old way.*

## M2b: New detections (`feat/m2b-detections`)

- [x] Config file loader with strict validation; tuning options for every rule. *Check: round trip of the defaults; typos and wrong types rejected; CLI flags override the file; bad file exits 2.*
- [x] Password spraying. *Check: positive tests plus lookalikes: scanner noise, office-NAT typos, a dictionary attack.*
- [x] Distributed brute force. *Check: positive tests plus lookalikes: roaming user, nonexistent accounts, IPv6 rotation in one /64, trusted networks.*
- [x] First login from a new source. *Check: learning period, first-ever login, same /24, shared office network, trusted networks that still build the baseline.*
- [x] Log tampering: gaps, backwards time, truncation signal, NUL bytes. *Check: NTP steps and DST (with and without offsets) don't alert.*
- [x] IPv6 counted per /64 in every attempt-counting rule. *Check: rotation within a /64 is one brute force.*
- [x] Shared-IP false positive from M1 fixed. *Check: lab labels now expect one low possible breach on the office IP.*
- [x] 11 planted bugs in the new rules. *Check: all 11 caught.*
- [x] Labelled synthetic corpus (40 seeded datasets) and lab scenarios for spraying and distributed attacks, with truth labels. *Check: lab run matches labels; corpus is deterministic (CI regenerates it).*
- [x] `npm run eval`: precision/recall per rule → `docs/evaluation.md`. *Check: CI job `eval` fails if the committed file differs.*
- [x] docs/detections.md: every rule's lines, tuning and false positives. *Check: counts match docs/evaluation.md.*

## M3: Live mode (`feat/m3-live-mode`)

- [x] File follower: polling, inode change, copytruncate vs truncation, partial lines, missing file. *Check: tests for each on real files, on Windows and on Linux (Docker and CI).*
- [x] Live incident tracker: opened / escalated / updated / closed, idle close, caps. *Check: one opened per attack, one escalated per rise; caps tested.*
- [x] Live pipeline + `--follow` + signals + flush deadline. *Check: child-process test sends SIGTERM, exit 0, last events flushed (Linux).*
- [x] Discord sink: dedup, rate limit, retry/backoff, bounded queue, safe content, secret URL. *Check: 7 tests against a local mock webhook, incl. 429, 5xx, 4xx, slow and hanging servers.*
- [x] Soak test: 100,000 hostile lines through a live run keep state under its caps. *Check: `engine.size()` asserted.*
- [x] `.env` loading for `DISCORD_WEBHOOK_URL`; `.env.example`. *Check: CLI test with a temp `.env` and the mock webhook.*

## M4: Storage (`feat/m4-sqlite`)

- [x] Schema v1 (runs, lines, events, incidents, findings), versioned; store for batch and live mode via `--db`. *Check: CLI round trip against the JSON report; live incidents updated and closed; newer schema refused; read-only enforced; hostile strings stored as data.*
- [x] Drill-down: from a finding to its raw lines. *Check: attacker B's brute force returns its 14 guesses and the login.*
- [x] SQL brute force + SQL unusual hour. *Check: identical findings to JavaScript on the sample (3 settings), the lab, 29 corpus logs, 300 random streams with ties and IPv6; 4 planted SQL bugs all caught.*

## M5: Dashboard (`feat/m5-dashboard`)

- [x] Server: 127.0.0.1 or ::1 only, Host check, CSP with no script, GET/HEAD only, read-only DB. No JSON API: `--json` and the SQLite file cover that ([ADR-0016](docs/adr/0016-local-read-only-dashboard.md)). *Check: HTTP tests for headers on every response, 405 for other methods, 421 for other Hosts, 404 for unknown paths, refusal to bind non-loopback.*
- [x] UI: SVG timeline, incident drill-down to raw lines, filters by severity, rule and IP/username; `npm run dashboard`. *Check: rendered HTML tests; one visual check in the browser (screenshots in `docs/images/`).*
- [x] Hostile-data tests. *Check: `<script>`, attribute breakouts and bidi overrides in usernames render as inert text on every page.*

## M6: ATT&CK (`feat/m6-attack`)

- [x] Technique mapping in core; shown in all outputs. IDs checked against attack.mitre.org (ATT&CK v20, which moved T1070.002 to T1685.006) ([ADR-0017](docs/adr/0017-attack-labels.md)). *Check: tests per rule and per kind of account change; `attack` on every finding in the terminal report, `--json`, live JSON lines, SQLite and the dashboard.*
- [x] `docs/detections.md`: ATT&CK mapping table and a technique line per rule. *Check: test asserts every rule is in the table, every technique is linked, and local links resolve.*

## M7: Advanced quality (`feat/m7-quality`)

- [ ] Semgrep with custom rules; CodeQL. *Check: CI jobs green; a planted `eval` is flagged.*
- [ ] fast-check property tests for the parser. *Check: invariants hold for 10k+ cases.*
- [ ] Stryker mutation testing with a break threshold. *Check: score recorded in docs.*
- [ ] Benchmark (speed + memory) in CI. *Check: numbers in README match the CI output.*

## Dashboard follow-up (`feat/dashboard-redesign`)

What the carbon redesign (ADR-0018) still lacked after a browser and code review.

- [x] Incident case summary: rules, users and techniques over every finding, not the first 200. *Check: test on an incident with 250 findings; browser review.*
- [x] Evidence: first finding open, line-number range and real total in the summary. *Check: rendered HTML test for the range and the capped total.*
- [x] Narrow screens and rule chips: stacked rows under 600 px, filters folded, compact metadata, first two rules then "+N more". *Check: no clipped columns at 375 px in both themes; works without JavaScript.*
- [ ] Timeline bars identifiable without hover. *Check: each bar has a visible source label or matching key at desktop and 375 px.*
- [ ] Labels and scope copy: 12 px minimum, sentence case, "Medium" spelled out, one scope sentence for the counts. *Check: browser review; existing count tests still pass.*

## Deferred

- [ ] Dashboard sorting, pagination past the caps, exports, a per-source page, run comparison, a manual theme switch. *Check: each its own tested change.*
- [x] Dashboard time filter (SPEC M5: "filters by … time"). Landed with the carbon redesign: a brush and validated from/to fields ([ADR-0018](docs/adr/0018-dashboard-interactions.md)). *Check: a from/to filter on the incident list, with tests for bounds and bad input.*
