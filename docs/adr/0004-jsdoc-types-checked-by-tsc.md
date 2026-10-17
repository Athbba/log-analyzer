# ADR-0004: JSDoc types checked by `tsc --checkJs`, ESLint for lint

- Status: accepted
- Date: 2026-10-17

## Context

Type checking catches a class of bugs (a misspelled field on a finding, a
`null` IP passed where a string is required) that tests miss. A TypeScript
rewrite would add a build step and change every file for no runtime benefit.

## Decision

- Types are written as JSDoc in the `.js` sources and checked with
  `tsc --noEmit` using `checkJs` and `strict`. Shared shapes (events,
  findings, options) are `@typedef`s in `src/types.js`.
- **TypeScript 6.0.x**, not 7.0. TypeScript 7 is the new native compiler; its
  JavaScript/JSDoc checking was reimplemented and is the least mature part.
  6.0 is the last release of the long-proven checker. Revisit when 7.x has
  been stable for a few months.
- **`@types/node` 22.x**, matching the oldest supported Node, so the checker
  rejects APIs that Node 22 lacks.
- **ESLint** with the flat config and `@eslint/js` recommended rules, plus
  rules that matter for hostile input: `no-eval`, `no-implied-eval`,
  `no-new-func`, `no-control-regex` (off where control characters are the
  point, with a comment). Node and browser globals are listed in the config
  rather than pulling in the `globals` package.
- Dev dependencies added: `typescript`, `@types/node`, `eslint`, `@eslint/js`.

## Consequences

- No build step: `node bin/analyze.js` still runs the sources directly.
- JSDoc is more verbose than TypeScript syntax; typedefs keep it manageable.
- `npm run check` runs lint, typecheck and tests, the same as CI.
