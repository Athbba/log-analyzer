# ADR-0005: CI on every pull request, protected `main`

- Status: accepted
- Date: 2026-10-17

## Context

The repository is public and is the main portfolio project. Changes are made
by one developer working with an AI assistant, so the safety net has to be
mechanical: nothing reaches `main` unless the checks pass.

## Decision

- GitHub Actions runs on every pull request and on pushes to `main`:
  `lint`, `typecheck`, and `test` on Node 22 and 24. Later milestones add
  their own jobs (lab, static analysis, mutation testing, benchmark).
- Workflows use `permissions: contents: read` by default and grant more only
  per job. Third-party actions are pinned to a full commit SHA with the
  version in a comment; Dependabot keeps the pins current. `checkout` runs
  with `persist-credentials: false`.
- `main` is protected: pull requests only, required status checks, branch must
  be up to date, rules apply to administrators, no force pushes or deletion.
- **No required approving review.** GitHub does not let an author approve
  their own pull request, so with a single developer a required review would
  block every merge or force the rules to be bypassed. Required checks are
  the gate instead. Add a review requirement when a second maintainer joins.
- Pull requests are squash-merged, one per milestone, with conventional
  commit titles.

## Consequences

- A red check blocks the merge, including for the repository owner.
- New required jobs must be added to the protection rule when they land.
