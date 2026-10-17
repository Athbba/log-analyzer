# ADR-0011: Design of the M2b detections

- Status: accepted
- Date: 2026-10-17

## Context

Brute force and possible breach catch loud attacks from one address. Attackers
avoid them by going slow, spreading guesses over many accounts, spreading them
over many addresses, using valid credentials, or editing the log afterwards.
Each new rule must catch one of these without drowning the analyst in the
benign patterns that look similar.

## Decisions

- **IPv6 is counted per /64** in every rule that counts attempts, and incidents
  group by it. An IPv6 attacker usually holds a /64 and could otherwise use a
  new address per guess. Configurable (`ipv6Prefix: 128` restores exact
  addresses). IPv4 stays exact: a /24 often holds unrelated hosts.
- **Password spray counts only existing accounts** by default, because scanners
  cycle nonexistent names, and takes back a failure when the same user logs in
  from the same source right after (a typo). Default 6 accounts in an hour, at
  most 2 tries each.
- **Distributed brute force** is per account: 4 sources and 8 attempts in an
  hour. It ignores nonexistent accounts, and offers `ignoreUsers` for the
  constant background guessing of `root`.
- **New source** compares /24 or /64 networks, learns for 24 hours, never
  reports a first-ever login, treats a network that 2 other users use as the
  organisation's own, and is low (keys) or medium (passwords), never high: its
  false positives (travel, new ISPs) are inherent.
- **Log tampering** needs every line, not just authentication events, so the
  engine gained a `line()` input (and `signal()`, for truncation seen by the
  live-mode follower). With RFC 3339 offsets it measures real time, so DST is
  invisible; without them a one-hour step back is allowed.
- **Shared-IP fix for possible breach**: a key login after other users'
  failures from the same IP is held back (found by the Docker lab), and is
  reported high if a brute force later covers it.
- **Defaults were checked against the labelled corpus** (ADR-0012), which is
  where the shared-network allowance came from: before it, new source raised 72
  false positives on office NAT logins in the corpus; after it, 19.

## Consequences

- Each rule's false positives are documented with counts in
  docs/detections.md, from docs/evaluation.md.
- The sample log gains three new-source findings: attacker B's login as deploy
  (a true positive) and two benign lookalikes at low severity (carol from home,
  dave on call over the VPN).
