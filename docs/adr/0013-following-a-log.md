# ADR-0013: Following a live log by polling

- Status: accepted
- Date: 2026-10-17

## Context

Live mode must read auth.log as it is written, for weeks, through logrotate in
both its modes (rename and `create`, or `copytruncate`), through the file
briefly not existing, and through an attacker emptying it. It must run on Linux
(where it matters) and be testable on any developer machine.

## Decision

- **Poll with `stat()`** every second (configurable), rather than use
  `fs.watch`, which behaves differently per platform, can miss events, and does
  not work on network filesystems. A second of latency is fine for alerting.
- **Identity by inode.** Inodes are compared as bigints (`stat` with
  `bigint: true`), exact on every OS. A new inode at the path means rotation by
  rename: the old file is read to its end first (processes may still write to
  it), then the new one is read from its start.
- **Shrinking means rotation or tampering.** If the file is shorter than what
  was already read and a sibling `auth.log.1` or `auth.log-…` was modified in
  the last minute, it is a copytruncate rotation. Otherwise it is reported as
  `truncated`, which the log-tampering rule raises as high.
- **Partial lines** are held until their newline arrives. A bug found while
  writing the follower's tests (the line splitter kept a view into a buffer the
  follower reused) is fixed in the splitter, which now copies what it keeps.
- **Start at the end** like `tail -f`; `--from-start` reads the backlog first.
  Reads are sliced (8 MB per poll), so a huge backlog can't starve shutdown.
- **Flush when caught up.** The follower yields an `idle` item after each poll
  that reached the end of the file; live mode flushes findings to the incident
  tracker then, and every 1,000 lines during a backlog.
- **Clean shutdown** on SIGINT/SIGTERM: stop polling, read what is left, close
  every incident, give sinks up to 5 s to deliver, exit 0. A second signal exits
  at once (130).
- No offset is persisted between runs: a restart starts at the end again.

## Consequences

- The follower is tested on real files on Windows and on Linux (in CI, and in a
  Docker container before pushing), including SIGTERM, which Windows can't
  deliver to a handler.
- Lines written in the moment between a copytruncate's copy and its truncation
  can be missed. That is logrotate's own documented race.
