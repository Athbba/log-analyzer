# ADR-0008: Treating every log line as hostile

- Status: accepted
- Date: 2026-10-17

## Context

Usernames, and with `logger` whole lines, are written by attackers. Any local
user can forge a line that looks like sshd's. The analyzer must not be made
to run out of memory, hang, rewrite the analyst's terminal, or misplace events
in time by such input.

## Decision

- **Line length cap, 8 KiB.** Node's readline holds a line until it sees a
  newline, so one huge line could exhaust memory. `LineSplitter` (pure, in
  `src/core/lines.js`) splits bytes itself and skips lines over the cap,
  counting them; it never buffers more than the cap. sshd caps usernames at
  100 characters in its log format, so no genuine sshd line comes near it.
- **Linear-time regexes, with a test.** Every pattern is anchored and avoids
  nested or overlapping quantifiers. A test parses 7–8 KB adversarial lines
  (repeated spoofed `from … port`, colon tails, bracket floods) under a time
  budget. Semgrep rules land in M7.
- **Escape on output.** The terminal report passes every description line
  and IP through `safeText`, which turns C0/C1 control characters (escape
  sequences, newlines) and invisible or bidi-override characters into visible
  escapes like `\x1b` and `\u{202e}`. Later sinks escape for their own medium
  (HTML, Discord markdown, SQL parameters).
- **Year inference is pure and symmetric.** Syslog timestamps have no year.
  The first line takes `--year`, or the latest year that doesn't put it in
  the future relative to an injected `now` (one day of skew allowed). Each
  later line takes the year that puts it closest to the previous line. This
  replaces "increment when the month goes backwards", which put a late Dec 31
  line arriving after Jan 1 a whole year in the future.
- **Documented, not fixed:**
  - forged lines: `auth.log` can't tell sshd from `logger -t sshd`;
  - sudo's `PWD=` is user-controlled and precedes `COMMAND=`, so a directory
    named `x ; COMMAND=…` can fake the command. The effect is limited to
    weaker attribution of an account change (the rule falls back to any
    open session). sudo's JSON log format would remove the ambiguity.

## Consequences

- An oversized line produces a warning and an empty line slot, so line
  numbers (needed for drill-down to raw lines) stay correct.
- The core purity rules are enforced by ESLint: no Node I/O modules, no
  `Date.now()` or `new Date()` without arguments, no `Math.random`, no
  `process` in `src/core/`.
