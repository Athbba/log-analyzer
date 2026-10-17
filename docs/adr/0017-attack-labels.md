# ADR-0017: ATT&CK labels worked out from each finding, at the outputs

- Status: accepted
- Date: 2026-10-17

## Context

M6 labels every finding with the MITRE ATT&CK techniques it is evidence of,
in the terminal, the JSON output, SQLite and the dashboard. The labels could
be set by each rule when it emits a finding, or worked out from the finding
wherever it is shown or stored. ATT&CK also changes: v20 moved "Clear Linux or
Mac System Logs" from T1070.002 to T1685.006, and renamed the Defense Evasion
tactic of Valid Accounts to Stealth.

## Decision

- **One pure table and function in the core** (`src/core/attack.js`):
  `techniquesFor(finding)` maps a rule, and for account changes what changed
  (a new account, admin rights, or both), to a fixed list of technique IDs and
  names. No I/O, no log content in the output.
- **Applied at the outputs, not stored in rule state.** The JSON report, the
  live JSON lines and the SQLite store write a copy of each finding with an
  `attack` array of `{ id, name }`; the terminal prints an `ATT&CK …` line; the
  dashboard works the labels out from the stored finding when it renders. So
  the rules, their bounded state and the engine-equivalence tests are
  untouched, and runs stored before M6 are labelled the same way.
- **IDs pinned to ATT&CK v20**, each checked against attack.mitre.org on
  2026-10-17. Sub-techniques are used where one fits (password guessing vs
  spraying, local accounts) because they say more than the parent.
- **The only outside links on the dashboard** go to attack.mitre.org, built
  from the fixed table, never from log content, with `rel="noreferrer"` (the
  server also sends `Referrer-Policy: no-referrer`).

## Consequences

- `attack` is a new JSON field, so the compatibility contract holds.
- The `attack` stored in SQLite reflects the mapping at the time of the run,
  while the dashboard shows the current mapping. When ATT&CK renumbers a
  technique, update the table (and `docs/detections.md`); stored JSON keeps
  the old ID, which `json_extract` queries should allow for.
- A new rule needs an entry in the table; the type of `techniquesFor`'s
  table and a test that every rule has a technique enforce it.
