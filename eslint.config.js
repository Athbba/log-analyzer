// ESLint flat config. The recommended rules, plus rules that matter for a tool
// that reads hostile input. Globals are listed here rather than pulled from
// the `globals` package (docs/adr/0004).

import js from '@eslint/js';

const NODE_GLOBALS = Object.fromEntries([
  'AbortController', 'AbortSignal', 'Buffer', 'TextDecoder', 'TextEncoder', 'URL', 'URLSearchParams',
  'clearImmediate', 'clearInterval', 'clearTimeout', 'console', 'fetch', 'performance', 'process',
  'queueMicrotask', 'setImmediate', 'setInterval', 'setTimeout', 'structuredClone',
].map((name) => [name, 'readonly']));

export default [
  { ignores: ['node_modules/', 'coverage/', 'reports/', '.stryker-tmp/'] },
  js.configs.recommended,
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
];
