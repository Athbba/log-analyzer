# Detections

What each rule looks for, which log lines it reads, how to tune it, and when
it is wrong. Settings are shown as they appear in the config file
(`log-analyzer.config.json`; run `node bin/analyze.js --print-config` for the
full list with current values). Measured precision and recall are in
[evaluation.md](evaluation.md).

Every finding is labelled with the [MITRE ATT&CK](https://attack.mitre.org/)
techniques it is evidence of (Enterprise, ATT&CK v20): in the terminal report
(`ATT&CK T1110.001 Brute Force: Password Guessing`), as an `attack` array of
`{ id, name }` on each finding in the JSON output and in the SQLite `data`
column, and as links on the dashboard's incident page. The labels are worked
out from the finding itself ([ADR-0017](adr/0017-attack-labels.md)).

| Rule | Finds | Severity |
|---|---|---|
| [Brute force](#brute-force) | many failed logins from one source in a short time | medium; high if that source logs in |
| [Password spray](#password-spray) | many real accounts tried a few times each from one source | medium; high on a login as one of them |
| [Distributed brute force](#distributed-brute-force) | one account guessed from many sources | medium; high on a login from one of them |
| [Possible breach](#possible-breach) | a login from a source that just failed | low; high after 5+ failures or a brute force |
| [New source](#new-source) | a login from a network the user never used | low for keys, medium for passwords |
| [Unusual hour](#unusual-hour) | a login in the night window | low |
| [Account change](#account-change) | a new user, or a user given admin rights | low, medium, or high if made from a breached session |
| [Log tampering](#log-tampering) | lines removed from or spliced into the log, truncation | low (gaps, NULs), medium (time going back), high (truncation) |

| Rule (`rule` in JSON) | ATT&CK techniques |
|---|---|
| `brute-force` | T1110.001 |
| `password-spray` | T1110.003 |
| `distributed-brute-force` | T1110.001 |
| `possible-breach` | T1110.001, T1078.003 |
| `new-source` | T1078.003, T1021.004 |
| `unusual-hour` | T1078.003 |
| `account-change` | T1136.001 for a new account, T1098.007 for admin rights (both when a new account gets them) |
| `log-tampering` | T1685.006 |

**Sources.** Rules that count attempts count them per *source*: an IPv4
address, or an IPv6 /64 (`bruteForce.ipv6Prefix`; 128 means exact addresses).
An IPv6 attacker usually controls a whole /64 and could otherwise use a fresh
address for every guess. Incidents group findings by the same source.

**Trusted networks.** `trustedNetworks` lists CIDRs (for example
`["10.0.0.0/8"]`) that the spray, distributed and new-source rules never
report. Brute force and possible breach still apply to them: an internal
machine hammering passwords is worth knowing about.

## Brute force

**Looks for** `threshold` (5) or more failed logins from one source within
`window` (10 minutes), fail2ban's defaults. Every failure inside such a window
is part of the attack; failures less than a window apart join the same
finding, so one attack is one finding.

**Reads** sshd's `Failed <method> for [invalid user] <name> from <ip> port <n>`
lines, counting rsyslog's `message repeated N times: [ … ]` as N. The PAM
`authentication failure` and `Invalid user` lines describe the same attempts
and are not counted, which would double the total.

**Tuning:** `bruteForce.threshold`, `bruteForce.window`, `bruteForce.ipv6Prefix`;
also `--threshold` and `--window` on the command line.

**False positives:** several people behind one NAT address mistyping within ten
minutes (2 in the synthetic corpus). A misconfigured client retrying a wrong
password.

**Misses:** attacks slower than the threshold allows (3–4 guesses per 10
minutes); the password-spray and distributed rules cover the slow variants.

**ATT&CK:** [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/). Many guesses at one account from one source.

## Password spray

**Looks for** one source failing against at least `minUsers` (6) **existing**
accounts within `window` (1 hour), each tried no more than
`maxAttemptsPerUser` (2) times. This is the attack brute force misses: no
single account (and, done slowly, no ten-minute window) gets many guesses.

**Why only existing accounts:** internet scanners cycle through names like
`admin`, `oracle` and `ubuntu`, which sshd logs as `invalid user`. A spray aimed
at your server uses accounts that exist. `countInvalidUsers: true` counts both.

**Typo handling:** a failure followed by a successful login as the same user
from the same source, before a spray is detected, is a typo and is taken back
out. This is what keeps an office NAT, where several people mistype their
password in one morning, from looking like a spray. After a spray is detected,
such a login is the spray succeeding, and makes the finding high.

**Tuning:** `passwordSpray.minUsers`, `.window`, `.maxAttemptsPerUser`,
`.countInvalidUsers`, `.enabled`.

**False positives:** none in the corpus. Conceivable: a script testing one
password against many service accounts.

**Misses:** sprays of 3–5 accounts (0 of 14 caught in the corpus); lowering
`minUsers` catches them at the risk of the office-NAT pattern.

**ATT&CK:** [T1110.003 Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/). One or two guesses each at many accounts, to stay under lockouts.

## Distributed brute force

**Looks for** failed logins for one existing account from at least
`minSources` (4) sources within `window` (1 hour), totalling at least
`minAttempts` (8). Botnets do this to stay under per-source defences such as
fail2ban. The finding has no single source IP; its incident is "user <name>".

**Tuning:** `distributedBruteForce.minSources`, `.minAttempts`, `.window`,
`.countInvalidUsers`, `.ignoreUsers`, `.enabled`, and `trustedNetworks`.

**False positives:**

- **A misconfigured internal service**: several CI runners or monitoring hosts
  with an expired credential failing for the same account (11 of the 11 false
  positives in the corpus). Trusting internal networks removes them.
- **root on an internet-facing server** is guessed by unrelated scanners all
  the time. That is a real distributed attack, but a constant one; with
  `PermitRootLogin no`, add `root` to `ignoreUsers`.

**Misses:** attacks from 2–3 sources, or with fewer than 8 attempts in all.

**ATT&CK:** [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/): the same guessing, spread over many sources. ATT&CK has no separate technique for where the guesses come from.

## Possible breach

**Looks for** a successful login from a source that failed within `lookback`
(30 minutes) before it. High when those failures reach the brute-force
threshold or a brute force from that source covers the login; low for the odd
mistyped password. If a brute force becomes visible only after the login (four
failures, the login, a fifth failure), the finding is escalated then.

**Shared IPs:** a **key** login after a few failures for *other* usernames from
the same IP is not reported (`possibleBreach.ignoreKeyLoginsAfterOthersFailures`,
on by default). That is a colleague behind the same office NAT; a key can't be
the payoff of guessing someone else's password. The Docker lab found this false
positive. If a brute force from the IP covers the login after all, it is
reported, at high.

**Tuning:** `possibleBreach.lookback` (`--lookback`).

**False positives:** typos, by design reported at low: they are context.

**ATT&CK:** [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) for the failures, and [T1078.003 Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/) for the login that follows: guessing that ends in a working account.

## New source

**Looks for** a successful login from a network the user has never logged in
from: the /24 (IPv4) or /64 (IPv6) around the address, so a home connection
that changes address within its ISP block isn't new each time. Stolen
credentials are usually used from the attacker's own infrastructure, so this
catches logins that look normal in every other way: no failures, daytime, the
right password.

**Baseline:** the first `learning` (24 hours) of the log only build it. A
user's first-ever login is never reported; new accounts are the account-change
rule's job. A network that `sharedNetworkUsers` (2) other users already log in
from is known for everyone: that is an office NAT or a VPN exit, not an
attacker. Logins from trusted networks build the baseline but are never
reported. Networks are forgotten after `remember` (90 days) without a login.

**Severity:** medium for password logins, low for key logins (a key can't be
guessed, so a key login from somewhere new is more often travel).

**Tuning:** `newSource.learning`, `.prefixV4`, `.prefixV6`, `.remember`,
`.sharedNetworkUsers`, `.enabled`, and `trustedNetworks`.

**False positives:** inherent. A user travelling, a new ISP, a new VPN exit, or
the first few people through a new office NAT all look exactly like stolen
credentials from the log alone. In the corpus: 20 from travel and 19 from the
office NAT, against 24 real stolen-credential logins, all caught. This is why
the rule is low or medium and never high on its own; it adds weight to an
incident rather than being one.

**ATT&CK:** [T1078.003 Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/), an account used from somewhere it never was, and [T1021.004 Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/), the way in.

## Unusual hour

**Looks for** a successful SSH login during `night` (01:00–04:59), by the
server's own clock. Times are never converted between timezones: "3 AM" is 3
AM where the server is. The end hour is excluded so a 05:30 backup job isn't
flagged; windows can wrap midnight (`22-6`).

**Tuning:** `unusualHour.night` (`--night`).

**False positives:** on-call admins and night jobs, by design at low: context.

**ATT&CK:** [T1078.003 Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/). An unusual time is weak evidence of an account in the wrong hands.

## Account change

**Looks for** a new user, or a user added to an admin group (`sudo`, `wheel`,
`admin`), from the lines `useradd`, `usermod` and `gpasswd` write. The tools
don't log who ran them or from where, so the rule works it out: the `sudo`
line that ran the tool names the user, and that user's SSH sessions open at the
time give the IP. High when one of those IPs had broken in (a high possible
breach); medium for admin rights or UID 0; low for a plain new user.

**Tuning:** `accountChange.adminGroups` (`--admin-groups`).

**Limits:** a change made from a root shell has no sudo line, so every open
session is a candidate. sudo's `PWD=` is user-controlled and precedes
`COMMAND=`, so a directory named `x ; COMMAND=…` can disguise the command; the
effect is the same weaker attribution. sudo's JSON log format would remove the
ambiguity.

**ATT&CK:** [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) when the account is new, [T1098.007 Account Manipulation: Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/) when it gets admin rights (`adminGroups`), both for a backdoor account created straight into `sudo`.

## Log tampering

**Looks for** traces that lines were removed from or added to the log:

- **gap** (low): no lines for more than `maxGap` (2 hours). On a normal Debian or
  Ubuntu host cron writes to auth.log at least hourly, so hours of silence mean
  the logger was down, the machine was off, or lines were deleted.
- **backwards** (medium): a line more than `maxBackwards` (5 minutes) earlier
  than the line before it, as when old lines are spliced in. Small steps back
  (NTP, several writers) are normal.
- **nul-bytes** (low): lines containing NUL characters, left by truncating or
  zero-filling a file that is still being written. The NULs are stripped and
  the rest of the line is still read.
- **truncated** (high, live mode only): the file got shorter without being
  rotated.

**DST:** with RFC 3339 timestamps the offsets turn each line into a real
instant, so gaps and steps are measured in real time and the end of DST is
invisible. Classic syslog timestamps have no offset, so a one-hour step back is
allowed (`allowDstJumps`).

**Needs the whole log**, so it runs when the CLI reads a file or stdin, but not
through the `analyze(events)` API, which only sees authentication events.

**Tuning:** `logTampering.maxGap`, `.maxBackwards`, `.allowDstJumps`, `.enabled`.

**False positives:** maintenance downtime and reboots (8 in the corpus, against
26 real tamperings). **Misses:** wiping less than `maxGap` of lines leaves no
gap long enough (1 of 26 missed).

**ATT&CK:** [T1685.006 Disable or Modify Tools: Clear Linux or Mac System Logs](https://attack.mitre.org/techniques/T1685/006/). ATT&CK v20 moved this from T1070.002 (Indicator Removal) to the new Defense Impairment tactic; older tools may still show the old ID.

## What no rule can see

- **Forged lines.** auth.log doesn't authenticate the program name, so any
  local user can write a line that looks like sshd's with `logger -t sshd`. The
  analyzer is only as trustworthy as the system logger.
- **Successful logins with stolen keys from a known network**, with no failures,
  at normal hours: they look exactly like the real user.
