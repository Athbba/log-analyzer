# ADR-0012: Measuring precision and recall

- Status: accepted
- Date: 2026-10-17

## Context

"It catches the attack in the sample" says little: the sample was written to be
caught. To tune thresholds and to quote numbers honestly, the project needs
labelled data with attacks of varied size, benign lookalikes, and a matching
rule that can't be gamed by the detector.

## Decision

- **A seeded synthetic corpus** (`scripts/lib/corpus.js`): 40 datasets of three
  days, half classic syslog and half RFC 3339 across the end of DST. Attack
  sizes are randomized and **deliberately straddle the thresholds**. Each
  dataset includes benign lookalikes (office NAT typos, roaming and travelling
  users, a misconfigured service, maintenance downtime, NTP steps).
- **Ground truth is about maliciousness**, not about what a rule should fire on.
  Each malicious item names its primary rule (for recall) and the other rules
  that are also right to fire on it (for precision); a brute force on a fast
  spray is not a false positive. Lookalikes are labelled too, so every false
  positive can be traced to a cause.
- **Matching** is by subject (IP or /64, user, or the log) and by a span that
  overlaps the item's, with 10 minutes of slack before and an hour after.
- **The Docker lab fixture** is the second dataset; its truth is derived from
  the attacker IPs' lines in the raw log, not from the analyzer.
- **Results are generated, not written**: `npm run eval` writes
  docs/evaluation.md, and CI fails if the committed file is stale, so the
  numbers in the docs are always the numbers the code produces.
- Two configurations are reported: defaults, and internal networks trusted.

## Consequences

- The evaluation found three real bugs before they shipped: DST steps across
  minutes apart misread as tampering, trusted logins not building the
  new-source baseline, and the office-NAT flood of new-source alerts.
- The corpus is written by the same person as the rules, so it can only contain
  the cases that were thought of. The docs say so next to the numbers.
- Changing a rule or the generator changes the numbers; the diff of
  docs/evaluation.md shows by how much, in the same pull request.
