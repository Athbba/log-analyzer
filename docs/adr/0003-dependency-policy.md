# ADR-0003: Dependency policy

- Status: accepted
- Date: 2026-10-17

## Context

This is a security tool that reads hostile input and may run as a privileged
user (to read `/var/log/auth.log`). Every runtime dependency is code that runs
with those privileges and a supply-chain path into the analyst's machine.
Node 22+ ships what the tool needs: streams, `parseArgs`, `node:test`,
`node:sqlite`, `node:http`, `fetch`.

## Decision

- **Runtime dependencies: none.** `dependencies` in `package.json` stays
  empty. A runtime dependency needs an ADR that explains why the standard
  library cannot do the job.
- **Development dependencies** (linters, type checker, test tools) are allowed
  when an ADR justifies each one. They never ship and never run on the
  analyzed host.
- `package-lock.json` is committed and CI installs with `npm ci`.
- `.npmrc` sets `ignore-scripts=true`, so no dependency's install script runs.
  (None of the chosen tools need one.)
- New versions are adopted only after they have been published for at least
  two weeks, to let compromised releases be caught by the ecosystem first.
  Dependabot proposes updates; CI must pass before they merge.

## Consequences

- Some conveniences are written by hand (argument parsing exists in Node;
  config validation and a small `.env` reader are ~100 lines).
- `npm audit` on the production tree is trivially clean; the development tree
  is scanned by Dependabot.
