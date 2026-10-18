// ESLint flat config. The recommended rules, plus rules that matter for a tool
// that reads hostile input. Globals are listed here rather than pulled from
// the `globals` package (docs/adr/0004).

import js from '@eslint/js';

const NODE_GLOBALS = Object.fromEntries([
  'AbortController', 'AbortSignal', 'Buffer', 'TextDecoder', 'TextEncoder', 'URL', 'URLSearchParams',
  'clearImmediate', 'clearInterval', 'clearTimeout', 'console', 'fetch', 'performance', 'process',
  'queueMicrotask', 'setImmediate', 'setInterval', 'setTimeout', 'structuredClone', 'WebSocket',
].map((name) => [name, 'readonly']));

export default [
  { ignores: ['node_modules/', 'coverage/', 'reports/', '.stryker-tmp/'] },
  js.configs.recommended,
  {
    files: ['src/dashboard/dashboard.js'],
    languageOptions: { globals: Object.fromEntries(['document', 'window', 'navigator', 'HTMLElement', 'HTMLInputElement', 'HTMLButtonElement', 'PointerEvent'].map((name) => [name, 'readonly'])) },
  },
  {
    languageOptions: { ecmaVersion: 2024, sourceType: 'module', globals: NODE_GLOBALS },
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    rules: {
      // Never execute strings: log content must not be able to become code.
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      // Correctness and clarity.
      eqeqeq: ['error', 'always'],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-shadow-restricted-names': 'error',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none', ignoreRestSiblings: true }],
      'no-throw-literal': 'error',
      'prefer-promise-reject-errors': 'error',
      'no-return-assign': ['error', 'except-parens'],
    },
  },
  {
    // The functional core is pure and deterministic (docs/adr/0002): no I/O,
    // no clock, no randomness. Time comes in with the events.
    files: ['src/core/**/*.js'],
    rules: {
      'no-restricted-imports': ['error', {
        patterns: [{ group: ['node:*', 'fs', 'fs/*', 'path', 'http', 'https', 'net', 'os', 'child_process'], message: 'src/core does no I/O; do it in the shell (src/io, bin).' }],
      }],
      'no-restricted-globals': ['error', ...['process', 'fetch', 'console', 'performance', 'setTimeout', 'setInterval', 'setImmediate', 'queueMicrotask']
        .map((name) => ({ name, message: 'src/core is pure; pass what it needs in.' }))],
      'no-restricted-syntax': ['error',
        { selector: "NewExpression[callee.name='Date'][arguments.length=0]", message: 'src/core has no clock; pass the time in.' },
        { selector: "CallExpression[callee.object.name='Date'][callee.property.name='now']", message: 'src/core has no clock; pass the time in.' },
        { selector: "CallExpression[callee.object.name='Math'][callee.property.name='random']", message: 'src/core is deterministic.' },
      ],
    },
  },
];

