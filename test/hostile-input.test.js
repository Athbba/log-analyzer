// Every log line is hostile: these tests feed the analyzer input designed to
// exhaust memory, hang the regexes, rewrite the terminal, or confuse the
// year guess.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { LineSplitter } from '../src/core/lines.js';
import { createParser } from '../src/core/parse.js';
import { safeText } from '../src/core/text.js';
import { createSyslogClock } from '../src/core/time.js';

const BIN = fileURLToPath(new URL('../bin/analyze.js', import.meta.url));
const cli = (args, input) => spawnSync(process.execPath, [BIN, ...args], { input, encoding: 'utf8', maxBuffer: 64 << 20 });
const ESC = String.fromCharCode(0x1b);
const RLO = String.fromCharCode(0x202e); // right-to-left override

// --- Line splitting ---

test('lines split across chunks, including inside a multi-byte character, come out whole', () => {
  const text = 'Sep  7 10:00:00 web01 sshd[1]: Failed password for jürgen from 192.0.2.1 port 1 ssh2\r\nsecond\n';
  const bytes = Buffer.from(text);
  const umlaut = bytes.indexOf(0xc3); // first byte of "ü"
  const splitter = new LineSplitter();
  const lines = [...splitter.push(bytes.subarray(0, umlaut + 1)), ...splitter.push(bytes.subarray(umlaut + 1))];
  assert.deepEqual(lines, [text.split('\r\n')[0], 'second']);
  assert.equal(splitter.end(), null);
});

test('a line longer than the limit is skipped as one empty line, and counted', () => {
  const splitter = new LineSplitter(100);
  const lines = [
    ...splitter.push(Buffer.from(`ok\n${'x'.repeat(60)}`)),
    ...splitter.push(Buffer.from(`${'x'.repeat(60)}\nafter\nlast`)),
  ];
  assert.deepEqual([...lines, splitter.end()], ['ok', '', 'after', 'last']);
  assert.equal(splitter.oversized, 1);
});

test('a 50 MB line with no newline never holds more than the line limit in memory', () => {
  const splitter = new LineSplitter(8192);
  const chunk = Buffer.alloc(64 * 1024, 0x41);
  let most = 0;
  for (let i = 0; i < 800; i++) {
    assert.deepEqual(splitter.push(chunk), []);
    most = Math.max(most, splitter.buffered);
  }
  assert.ok(most <= 8192, `buffered ${most} bytes`);
  assert.equal(splitter.end(), '');
  assert.equal(splitter.oversized, 1);
});

test('the CLI reports oversized lines and still analyzes the rest', () => {
  const huge = `Sep  7 10:00:00 web01 sshd[1]: Failed password for ${'a'.repeat(5 << 20)} from 192.0.2.1 port 1 ssh2`;
  const ok = 'Sep  7 10:00:05 web01 sshd[2]: Accepted publickey for alice from 10.0.1.23 port 5 ssh2';
  const { status, stdout } = cli(['-', '--year', '2026'], `${huge}\n${ok}\n`);
  assert.equal(status, 0);
  assert.match(stdout, /Warning: skipped 1 line longer than 8,192 bytes\./);
  assert.match(stdout, /0 failed logins, 1 successful login/);
});

// --- Regexes ---

test('adversarial lines parse in linear time', () => {
  const parser = createParser({ year: 2026, now: 0 });
  const prefix = 'Sep  8 02:14:30 web01 sshd[1]: ';
  const bodies = [
    `Failed password for invalid user ${'a from 1.2.3.4 port 22 '.repeat(330)}`,
    `Failed password for x from 1.2.3.4 port 22 ssh2:${' from 1.1.1.1 port 1:'.repeat(380)}`,
    `Failed password for ${'x from 1.2.3.4 port 1x'.repeat(340)}`,
    `Accepted password for ${'a from 1.2.3.4 port 22 :'.repeat(330)}z`,
    `message repeated 9 times: [ Failed password for ${' ['.repeat(4000)}`,
  ];
  const sudo = `Sep  8 02:14:30 web01 sudo:   bob : PWD=${' ; COMMAND= ; PWD='.repeat(400)}`;
  for (const line of [...bodies.map((b) => prefix + b), sudo]) {
    assert.ok(line.length <= 8192 && line.length > 7000, `test line is ${line.length} chars`);
    const start = performance.now();
    for (let i = 0; i < 20; i++) parser.parse(line, 1);
    const ms = (performance.now() - start) / 20;
    assert.ok(ms < 5, `${ms.toFixed(2)} ms for: ${line.slice(31, 80)}…`);
  }
});

// --- Output ---

test('control characters and bidi overrides in log fields are shown as escapes', () => {
  assert.equal(safeText(`root${ESC}[2Jx`), 'root\\x1b[2Jx');
  assert.equal(safeText('a\nHIGH  fake line'), 'a\\x0aHIGH  fake line');
  assert.equal(safeText(`user${RLO}txt.exe`), 'user\\u{202e}txt.exe');
  assert.equal(safeText('plain ascii, ünïcode, 日本'), 'plain ascii, ünïcode, 日本');
});

test('the terminal report never prints a raw escape character from the log', () => {
  const evil = `x${ESC}]0;pwned${String.fromCharCode(7)}${RLO}`;
  const lines = ['00', '10', '20', '30', '40'].map((s) =>
    `Sep  7 10:00:${s} web01 sshd[1]: Failed password for invalid user ${evil} from 192.0.2.1 port 1 ssh2`);
  const { stdout } = cli(['-', '--year', '2026'], lines.join('\n'));
  assert.match(stdout, /1 username, 1 nonexistent: x\\x1b\]0;pwned\\x07\\u\{202e\} \(5\)/);
  assert.equal(stdout.includes(ESC), false);
  assert.equal(stdout.includes(RLO), false);
});

// --- Year inference ---

test('syslog years: explicit, guessed from now, and New Year in both directions', () => {
  const at = (clock, mon, day, h = 12) => new Date(clock(mon, day, h, 0, 0)).toISOString().slice(0, 10);
  const now = Date.UTC(2026, 9, 17, 12);

  const explicit = createSyslogClock({ year: 2025, now });
  assert.deepEqual([at(explicit, 11, 31), at(explicit, 0, 1), at(explicit, 11, 31, 23), at(explicit, 0, 1)],
    ['2025-12-31', '2026-01-01', '2025-12-31', '2026-01-01'], 'a late Dec 31 line after Jan 1 stays in the old year');

  assert.equal(at(createSyslogClock({ now }), 9, 17), '2026-10-17', 'today is this year');
  assert.equal(at(createSyslogClock({ now }), 9, 18), '2026-10-18', 'tomorrow is allowed: clock skew');
  assert.equal(at(createSyslogClock({ now }), 9, 25), '2025-10-25', 'next week would be in the future');
  assert.equal(at(createSyslogClock({ now }), 11, 1), '2025-12-01');

  const live = createSyslogClock({ now: Date.UTC(2027, 0, 1, 0, 5) });
  assert.deepEqual([at(live, 11, 31, 23), at(live, 0, 1, 0), at(live, 11, 31, 23)],
    ['2026-12-31', '2027-01-01', '2026-12-31'], 'live at New Year, with a late line from the old year');
});
