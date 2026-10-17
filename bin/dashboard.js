#!/usr/bin/env node
// Starts the local, read-only dashboard over a database written by
// `node bin/analyze.js <log> --db <file>`.
//
// Usage: node bin/dashboard.js --db <file> [--port <n>] [--ipv6]

import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { createDashboard } from '../src/dashboard/server.js';
import { errorMessage, fail } from '../src/io/cli.js';

const USAGE = `Usage: node bin/dashboard.js --db <file> [--port <n>] [--ipv6]

Serves the incidents stored in <file> at http://127.0.0.1:<port>/ (default 4797),
read-only and to this machine only. --ipv6 listens on [::1] instead.`;

let values;
try {
  ({ values } = parseArgs({ options: { db: { type: 'string' }, port: { type: 'string' }, ipv6: { type: 'boolean' }, help: { type: 'boolean', short: 'h' } } }));
} catch (err) {
  fail(errorMessage(err), USAGE);
}
if (values.help) {
  console.log(USAGE);
  process.exit(0);
}
if (!values.db) fail('give the database with --db', USAGE);
if (!existsSync(values.db)) fail(`${values.db} doesn't exist; create it with: node bin/analyze.js <log> --db ${values.db}`);
const port = values.port === undefined ? 4797 : Number(values.port);
if (!Number.isInteger(port) || port < 0 || port > 65535) fail('--port must be a number from 0 to 65535');

let dashboard;
try {
  dashboard = createDashboard({ dbPath: values.db, port, host: values.ipv6 ? '::1' : '127.0.0.1' });
} catch (err) {
  fail(`can't open ${values.db}: ${errorMessage(err)}`);
}
const url = await dashboard.listen();
console.log(`Dashboard at ${url} (Ctrl+C to stop)`);
for (const signal of /** @type {const} */ (['SIGINT', 'SIGTERM'])) {
  process.on(signal, () => void dashboard.close().then(() => process.exit(0)));
}
