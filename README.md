# SSH Log Analyzer

A command-line tool that reads a Linux SSH `auth.log` and reports four kinds of suspicious activity:

1. **Brute force**: many failed logins from one IP in a short time.
2. **Possible breach**: a successful login from an IP that was failing just before.
3. **Unusual hour**: a successful login in the middle of the night.
4. **Account change**: a new user, or a user given admin rights, flagged high when it comes from an IP that broke in.

Findings are grouped by source IP, so one attacker's activity reads as one incident: brute force, then break-in, then the backdoor account.

It is plain Node.js with no dependencies and nothing to install.

## Running it

Requires Node.js 22 or later.

```sh
node bin/analyze.js samples/auth.log            # terminal report
node bin/analyze.js samples/auth.log --json     # machine-readable output
sudo cat /var/log/auth.log | node bin/analyze.js -   # read from stdin
npm test                                        # run the tests
npm run generate-sample                         # rebuild samples/auth.log
```

```text
Options:
  --json              Print the results as JSON
  --threshold <n>     Failed logins from one IP that count as brute force (default 5)
  --window <time>     ...within this window, e.g. 90s, 10m, 1h (default 10m)
  --lookback <time>   How far before a login to look for failures (default 30m)
  --night <from-to>   Unusual login hours on a 24h clock, end excluded (default 1-5)
  --admin-groups <g>  Comma-separated groups that grant admin rights (default sudo,wheel,admin)
  --year <yyyy>       Year of the first line; syslog timestamps have none (default: guessed)
  -h, --help          Show this help
```

The exit status is 0 if nothing high-severity was found, 1 if something was, and 2 for bad arguments or an unreadable file, so the tool can gate a cron job or CI step.

## Example: one attacker, start to finish

`samples/auth.log` is four days of synthetic activity on a small web server, with attacks hidden among normal traffic. This is how the analyzer reports attacker B:

```text
HIGH    198.51.100.23
  2026-09-09 03:21:40  brute force      14 failed logins over 16m 1s
                                        2 usernames: deploy (12), root (2)
                                        then logged in as deploy (password) at 2026-09-09 03:39:12
  2026-09-09 03:39:12  possible breach  deploy logged in (password) after 14 failed logins in the previous 17m 32s
  2026-09-09 03:39:12  unusual hour     deploy logged in (password) at 03:39
  2026-09-09 03:40:56  account change   new user sysupdate, member of sudo
                                        by deploy via sudo, in a session from 198.51.100.23
                                        198.51.100.23 broke in as deploy at 2026-09-09 03:39:12 after 14 failed logins
```

In words: B guessed the `deploy` account's password over about 17 minutes, logged in at 3:39 AM, and less than two minutes later created a new sudo user called `sysupdate` as a backdoor. All four rules fire, and they appear together under one IP.

<details>
<summary>Full report for the sample log</summary>

```text
SSH auth log analysis: samples/auth.log
1,316 lines, 2026-09-07 00:17:01 to 2026-09-10 23:17:02
116 failed logins, 44 successful logins

Rules:
  brute force      5+ failed logins from one IP within 10m
  possible breach  a login from an IP with failed logins in the previous 30m
  unusual hour     a login between 01:00 and 04:59
  account change   a new user, or a user added to sudo/wheel/admin; high if made from an IP that broke in

HIGH    198.51.100.23
  2026-09-09 03:21:40  brute force      14 failed logins over 16m 1s
                                        2 usernames: deploy (12), root (2)
                                        then logged in as deploy (password) at 2026-09-09 03:39:12
  2026-09-09 03:39:12  possible breach  deploy logged in (password) after 14 failed logins in the previous 17m 32s
  2026-09-09 03:39:12  unusual hour     deploy logged in (password) at 03:39
  2026-09-09 03:40:56  account change   new user sysupdate, member of sudo
                                        by deploy via sudo, in a session from 198.51.100.23
                                        198.51.100.23 broke in as deploy at 2026-09-09 03:39:12 after 14 failed logins

MEDIUM  203.0.113.45
  2026-09-08 02:14:10  brute force      36 failed logins over 2m 58s
                                        16 usernames, 15 nonexistent: root (18), admin (4), administrator (1), ftpuser (1), git (1), +11 more
                                        never logged in

MEDIUM  10.0.1.81
  2026-09-10 11:22:17  account change   new user erin
                                        by dave via sudo, in a session from 10.0.1.81
  2026-09-10 11:23:53  account change   erin added to sudo
                                        by dave via sudo, in a session from 10.0.1.81

LOW     10.0.1.57
  2026-09-07 09:01:50  possible breach  bob logged in (password) 6s after 1 failed login
  2026-09-09 09:03:04  possible breach  bob logged in (password) 5s after 1 failed login
  2026-09-10 09:19:38  possible breach  bob logged in (password) 6s after 1 failed login

LOW     10.8.0.22
  2026-09-10 01:52:13  unusual hour     dave logged in (publickey) at 01:52

5 incidents: 1 high, 2 medium, 2 low
```

</details>

## The four detections

| Rule | Fires when | Default | Severity |
|---|---|---|---|
| Brute force | failed logins from one IP within a sliding window | 5 in 10 minutes | medium; high if that IP later logs in |
| Possible breach | a successful login, and the same IP failed in the time before it | 30-minute lookback | low for 1–4 failures; high for 5+ or during a brute force |
| Unusual hour | a successful SSH login during the night window | 01:00–04:59 | low |
| Account change | a new user, or a user added to an admin group | groups `sudo`, `wheel`, `admin` | low for a plain user; medium for admin rights or UID 0; high if made from an IP that broke in |

### Brute force

Five or more failed logins from one IP within ten minutes, which are also fail2ban's defaults. Overlapping windows merge into one finding per attack, which lists the usernames tried and how many of them don't exist on the server.

The hard part is counting correctly. sshd records one failed attempt on several lines: a PAM "authentication failure" line, an "Invalid user" line, and a "Failed password" line. Only the `Failed …` line is counted; counting all of them would roughly double the total. The system logger also collapses repeated identical lines into `message repeated 5 times: [ … ]`, and that one line counts as five failures. In the sample, 16 of attacker A's 36 failures appear only inside such lines.

The rule uses a sliding window rather than a total for the whole file. With a total, a user who mistypes their password five times over a month would look like an attacker.

### Possible breach

For every successful login, the rule counts failed logins from the same IP in the previous 30 minutes. The severity split is what makes this rule useful. One failure a few seconds before a login is almost always a typo, as with bob in the sample, so it is low. Five or more, or a login during a brute force from that IP, is how a successful password-guessing attack looks, so it is high.

### Unusual hour

Successful SSH logins from 01:00 to 04:59, by the server's own clock. Times are never converted between timezones: "3 AM" means 3 AM where the server is. Cron jobs and other non-SSH sessions at night are ignored. The rule is low severity on its own, because it is context: it adds weight to a breach, and without one it is often just the on-call admin. The end hour is excluded so that the sample's nightly 05:30 backup job isn't flagged every day. Windows that cross midnight work too, for example `--night 22-6`.

### Account change

This rule watches the lines written by the standard account tools: `useradd` (a new user, plus any groups given with `-G`), `usermod -aG` and `gpasswd -a`. `adduser` is covered through the `useradd` and `gpasswd` calls it makes. It reports:

- **a new user**: low;
- **a user added to an admin group** (`sudo`, `wheel`, `admin`), **or a new user with UID 0**, which is a second root account: medium;
- **either of the above made from an IP that had already broken in**: high.

Being added to any other group, such as `docker`, is ignored. You can change the list of admin groups with `--admin-groups`.

## How the account-change rule finds the source IP

`useradd` and `usermod` don't record who ran them or from where. The log just says:

```text
useradd[5474]: new user: name=sysupdate, UID=1101, GID=1101, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/1
useradd[5474]: add 'sysupdate' to group 'sudo'
```

To tell whether the change followed a break-in, the rule has to work out the source IP itself. It takes four steps.

1. **Group the lines.** `useradd -G sudo` writes the new user and the group on separate lines from the same process. Lines with the same process ID and target user are merged into one change.

2. **Find who ran it.** The rule looks back for the most recent `sudo` line that:
   - is at most one minute earlier (`adduser` asks questions, so it allows time for typing),
   - runs one of `useradd`, `adduser`, `usermod` or `gpasswd`, and
   - names the same target user in its arguments.

   sudo logs the user who invoked it, so that gives the person:
   ```text
   sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash -G sudo sysupdate
   ```

3. **Rebuild the SSH sessions.** Every `Accepted …` line opens a session with a user, an IP and a start time. The line that ends it, `session closed for user deploy`, has no IP. But the same sshd process writes both lines, so they are matched by process ID. A session with no closing line counts as open until the end of the log.
   ```text
   sshd[5465]: Accepted password for deploy from 198.51.100.23 port 33951 ssh2
   sshd[5465]: pam_unix(sshd:session): session closed for user deploy
   ```

4. **Put them together.** The rule takes that person's sessions that were open when the change happened and collects their IPs. If any of those IPs had a high-severity possible breach before the change, the change is high and joins that IP's incident.

For attacker B: `deploy` logs in from 198.51.100.23 at 03:39 after 14 failed guesses. At 03:40 `deploy` runs `sudo useradd -G sudo sysupdate`. `deploy`'s only open session at that moment is the one from 198.51.100.23; the CI system's earlier `deploy` sessions had already closed. So the change is high severity, and it is reported under B's IP.

Only the sudo user's sessions are considered. That way, if an admin makes a legitimate change while an attacker happens to be logged in, the admin's action isn't blamed on the attacker's session. The sample includes this kind of legitimate change: dave onboards a new hire from the office and is reported as medium, not high.

**Limits:**
- If the change is made from a root shell (`sudo -i`, then `useradd`), there is no matching sudo line. The rule falls back to every open SSH session. It still escalates if a breached session is open, but the attribution is looser.
- If one user has sessions open from two IPs at once, the log doesn't say which terminal ran the command. Both IPs are reported, and the change is high if either IP broke in.
- Only a high-severity breach escalates a change. A login right after a single mistyped password doesn't.

## Log formats

- Classic syslog timestamps (`Sep  7 03:39:12`). These have no year: pass `--year`, or the tool uses the current year (last year if the log starts in a later month than now). Moving from December to January inside a log starts the next year.
- RFC 3339 timestamps (`2026-09-07T03:39:12.123456+00:00`), used by newer Debian and Ubuntu. The offset is ignored so times stay on the server clock.
- `sshd`, and the `sshd-session` and `sshd-auth` processes used by OpenSSH 9.8 and later.
- IPv6 addresses, Windows (CRLF) line endings, and input from stdin.
- **Spoofed usernames.** Usernames come from the attacker and can contain text like `from 10.0.0.1 port 22`. The parser always takes the *last* `from … port …` on the line, which sshd itself writes.
- Lines in no recognized format are counted and reported, not treated as errors.

Speed: a 1-million-line (about 110 MB) log takes about 3.5 seconds on my laptop. The file is read as a stream, and only the parsed events are kept in memory.

## Testing

### Sample data with a known answer key

[`scripts/generate-sample-log.js`](scripts/generate-sample-log.js) writes `samples/auth.log`. It uses a fixed random seed, so every run produces the same file and the expected results are always known. The normal background includes:
- five users logging in with keys or passwords and running sudo,
- cron jobs and CI deploys,
- 60 internet scanners, each making at most two password guesses.

External addresses come from the IP ranges reserved for documentation (RFC 5737), so no real host appears. Hidden inside are:

| | Scenario | Expected |
|---|---|---|
| A | Dictionary attack: 36 guesses at root and common account names; never gets in | brute force (medium) |
| B | Targeted guessing of `deploy`, logs in at 03:39, creates the sudo user `sysupdate` | all four rules (high) |
| C | On-call admin logs in over the VPN at 01:52 | unusual hour (low) |
| D | 4 failed guesses | nothing: one below the threshold |
| E | Nightly backup job logs in at 05:30 | nothing: just outside the night window |
| F | bob mistypes his password once, then logs in (3 times) | possible breach (low) |
| G | Admin creates a new hire's account, gives her sudo, adds bob to `docker` | account change (low and medium); `docker` ignored |

C through G are deliberate lookalikes. They check that the analyzer is right about what it *doesn't* flag, not only about what it does.

### Test suites

35 tests using Node's built-in `node:test`. Run them with `npm test`.

- `test/parse.test.js`: each line type, `message repeated` counting, spoofed usernames, IPv6, RFC 3339, the December-to-January year change, unreadable lines.
- `test/detectors.test.js`: each rule's thresholds and boundaries (4 vs 5 failures, a window exactly 10 minutes wide, 00:59 vs 01:00 vs 05:00), plus each way an account change can or can't be linked to a break-in.
- `test/sample.test.js`: an end-to-end check that the sample log produces exactly the incidents in the table above, plus the command line (exit codes, `--json`, stdin, bad arguments).

### Planted-bug testing

Tests that have never failed haven't proved they can catch anything. So after each feature, I planted small bugs in the code on purpose, one at a time, and checked that at least one test failed. Examples:

- raising the brute-force threshold from 5 to 6;
- making the window edge exclusive;
- ignoring the count in `message repeated` lines;
- letting a break-in that happens *after* an account change escalate it;
- ignoring logouts, so sessions never close;
- ignoring which user ran sudo.

Of 11 planted bugs, two survived at first. Both were real gaps in the tests:

- **The spoofed-username test passed for the wrong reason.** The parser matches usernames greedily so that the last `from … port …` on the line wins. Switching to a lazy match should have broken the test, but it didn't: the test's fake username was rejected by the end-of-line anchor anyway. The test now uses a username containing `ssh2: …`, which a lazy match really does misread.
- **No test covered a break-in after the change.** Nothing checked that a break-in occurring *after* an account change leaves the change un-escalated. A test was added.

One lesson from the process: a planted bug that doesn't actually apply gives the same "0 tests failed" as a real gap. The script therefore checks that the source file really changed before trusting the result. That check caught one planted bug that hadn't applied.

## Development

```sh
npm ci              # install the development tools (there are no runtime dependencies)
npm run check       # lint, type check and tests, exactly as CI runs them
```

- **Lint:** ESLint with the recommended rules plus `no-eval`, `no-implied-eval` and `no-new-func`.
- **Types:** JSDoc annotations checked by `tsc --checkJs` in strict mode. There is no build step; the `.js` files run as they are.
- **CI:** every pull request runs lint, type check, and tests on Node 22 and 24. `main` only accepts pull requests whose checks pass.

The plan and the reasoning behind it live in [SPEC.md](SPEC.md) (goals, non-goals, acceptance criteria), [PLAN.md](PLAN.md) (tasks and how each is verified) and [docs/adr/](docs/adr/) (architecture decision records).

## Project layout

```text
bin/analyze.js                  command line: options, reading the file or stdin, exit codes
src/parse.js                    log lines to events (logins, logouts, sudo commands, account changes)
src/detectors.js                the four rules and the grouping into incidents
src/report.js                   terminal and JSON output
src/types.js                    shared JSDoc types (events, findings, options)
scripts/generate-sample-log.js  synthetic auth.log with a known answer key
samples/auth.log                the generated sample
test/                           parser, detector and end-to-end tests
docs/adr/                       architecture decision records
```

## About this project

I built this to learn the fundamentals of SOC log analysis:
- how sshd, PAM, sudo and the account tools each write to the auth log;
- why raw line counts mislead;
- how to connect events across different processes when no single line tells the whole story;
- how to set thresholds so that real attacks stand out from everyday noise like typos and on-call logins.

Development is AI-assisted: I set the direction, the requirements and the standards, and review the results; much of the code is written with Claude Code, an AI coding assistant, working under that direction.

It is a learning project, not a production security tool. It has only been tested against the synthetic logs described above, not real-world traffic. It analyzes a file after the fact rather than watching live. Its account attribution is a best guess, as described in the limits above. On a real system, this job belongs to tools like fail2ban, auditd and a SIEM. This project is about understanding what those tools are doing underneath.

## License

MIT. See [LICENSE](LICENSE).
