# ADR-0010: One JSON config file, validated strictly

- Status: accepted
- Date: 2026-10-17

## Context

The four new rules bring about twenty tuning settings, and live mode will add
outputs. They don't all fit on the command line, and a security tool whose
settings are silently ignored when misspelled is dangerous: `"treshold": 50`
would leave the default in place and the operator believing otherwise.

## Decision

- One file, **JSON** (no YAML or TOML parser: no runtime dependencies, ADR-0003),
  default `./log-analyzer.config.json` if it exists, or `--config <file>`.
- Grouped by rule (`bruteForce`, `passwordSpray`, …) plus `trustedNetworks` and
  `limits`. Every key is optional; defaults live in `src/core/options.js`.
- **Strict validation** (`src/core/config.js`, pure): unknown keys and wrong
  types are errors and the CLI exits 2, listing every problem at once. Keys
  starting with `$` are ignored, for `$schema` or `$comment`.
- **Durations always carry a unit** (`"90s"`, `"10m"`, `"1h"`, `"7d"`), so
  seconds and milliseconds can't be confused.
- Precedence: defaults < config file < command-line flags. Existing flags keep
  their meaning (the compatibility contract in SPEC.md).
- `--print-config` prints the effective settings in the file's format;
  `log-analyzer.config.example.json` is generated that way, and a test checks the
  round trip.
- Secrets (the Discord webhook, in M3) never go in this file; they come from the
  environment or `.env`.

## Consequences

- About 200 lines of hand-written validation instead of a schema library.
- Adding a setting means adding it to the spec table, the defaults and
  `toConfig`; the round-trip test fails if one is forgotten.
