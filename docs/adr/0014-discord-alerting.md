# ADR-0014: Discord alerts that can't flood, block, or be weaponized

- Status: accepted
- Date: 2026-10-17

## Context

Alerts go to a Discord channel through a webhook. A brute force writes hundreds
of lines a minute; a naive "alert per finding" would flood the channel and hit
Discord's rate limits. Webhooks fail and slow down. And every alert is built
from attacker-controlled text: a username can be `@everyone`, a markdown link,
or a fake code fence.

## Decision

- **Alert on incidents, not findings.** One alert when an incident opens at or
  above `minSeverity` (default medium), one more each time it escalates (a brute
  force that becomes a break-in). Updates never alert. One attack, one alert.
- **Never block detection.** `onIncident` builds the payload and queues it,
  returning immediately; a background loop sends. The queue is bounded (100);
  when full, the least severe, oldest alert is dropped and counted.
- **Rate limit** with a token bucket (burst 5, 20 per minute by default; Discord
  allows about 30 per minute per webhook). A 429 pauses the whole sink for
  `retry_after` (capped at a minute) and retries the same alert. 5xx and network
  errors retry with exponential backoff and jitter, up to 5 attempts. Other 4xx
  are not retried.
- **Neutralize content.** Details go in a code block, where Discord renders no
  markdown, links or mentions, and any ``` inside them is broken up.
  `allowed_mentions` is empty, so nothing can ping anyone even if text escaped.
  The title is markdown-escaped, control characters are escaped, and every field
  is cut to Discord's limits.
- **The webhook URL is a secret.** It is read from `DISCORD_WEBHOOK_URL`, in the
  environment or a `.env` file (git-ignored; `.env.example` shows the shape),
  loaded with Node's own `process.loadEnvFile`. It must be a
  `https://discord.com/api/webhooks/…` URL, or loopback for a local relay. It
  is never printed, logged or put in an error message.
- **Shutdown** gives the queue up to 5 seconds, then reports what was sent,
  dropped, failed and left undelivered.
- Also usable without `--follow`: a one-off analysis with `--discord` sends one
  alert per incident in the report, which suits a cron job.

## Consequences

- Tests run against a local mock webhook: 429 with `retry_after`, 500s, 400, a
  slow server, a hanging server, a full queue, and hostile content.
- Alerts carry the incident as it was when it opened or escalated. Later
  findings appear in the next escalation, or in the terminal and JSON output.
