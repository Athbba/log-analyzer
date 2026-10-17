# ADR-0001: Record architecture decisions

- Status: accepted
- Date: 2026-10-17

## Context

The project is moving from a one-shot script to a codebase with live mode,
storage, a dashboard and several detection rules. Choices made now (why no
runtime dependencies, why a rule is tuned a certain way) will be questioned
later, by reviewers and by future me.

## Decision

Record each significant decision as a short Architecture Decision Record in
`docs/adr/`, numbered in order, using the Nygard format: context, decision,
consequences. Superseded ADRs are kept and marked, not deleted.

## Consequences

- A decision is reviewable in the pull request that introduces it.
- ADRs stay short; detail belongs in code comments, SPEC.md or docs.
