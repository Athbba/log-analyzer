# ADR-0006: A Docker lab for real log fixtures

- Status: accepted
- Date: 2026-10-17

## Context

The synthetic sample is written by our own generator, so it can only contain
log formats we already know about. Real systems change formats (OpenSSH 9.8
moved logging to `sshd-session`; sudo 1.9 omits `TTY=` without a terminal;
Debian 12+ rsyslog writes RFC 3339 timestamps). We need logs written by the
real software, and we cannot use real servers' logs (they hold real users'
data) or attack hosts we don't own.

## Decision

- A Compose lab: one Debian 13 target running OpenSSH 10 and rsyslog, and one
  client image used by several services with fixed IPs (an office
  workstation and two attackers). Base images are pinned by digest.
- The lab network is `internal: true`, scenario scripts verify the target
  resolves into the lab subnet before doing anything, and the orchestrator
  tests that guard before each run.
- Scenarios are plain bash with `ssh` and `sshpass`, one connection per
  password guess. `scripts/lab.js` orchestrates with argument arrays (no
  shell), sets the lab timezone so the clock reads ~10:00, and copies the log
  out.
- Expected results are a labels file (`rule:severity` per source IP, plus
  notes). The committed fixture and every fresh CI run are judged by the
  same `checkLabels` function.
- CI runs the whole lab on every pull request (`lab-e2e`).

## Consequences

- The lab found a real false positive on its first run (a shared office IP
  makes a colleague's login look like a possible breach) and confirmed the
  parser handles OpenSSH 10 and sudo 1.9 formats.
- CI time grows by a couple of minutes for the image builds.
- The fixture is one recorded run; `npm run lab:fixture` refreshes it, and
  the diff shows what changed.
- No systemd/logind in the lab; the synthetic sample still covers those.
