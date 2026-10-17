// The file follower, on real files: new lines, partial lines, rotation by
// rename, copytruncate, truncation (tampering), and a file that disappears.

import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync, renameSync, rmSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { createFollower } from '../src/io/follow.js';

/** @typedef {import('../src/io/follow.js').FollowItem} FollowItem */

/**
 * Follows `file` while `script` changes it, and returns what the follower saw.
 * @param {string} file
 * @param {(step: () => Promise<void>) => Promise<void>} script  Call step() after each change.
 * @param {{ fromStart?: boolean }} [options]
 */
async function watch(file, script, options = {}) {
  const follower = createFollower(file, { pollMs: 20, ...options });
  /** @type {string[]} */
  const seen = [];
  const reading = (async () => {
    for await (const item of follower.items()) {
      if (item.type === 'idle') continue;
      seen.push(item.type === 'line' ? item.text : item.type === 'truncated' ? `<truncated ${item.fromBytes}->${item.toBytes}>` : `<${item.type}>`);
    }
  })();
  await sleep(60);
  await script(() => sleep(80));
  await sleep(80);
  await follower.stop();
  await reading;
  return seen;
}

/** @param {(dir: string) => Promise<void>} body */
async function inTempDir(body) {
  const dir = mkdtempSync(join(tmpdir(), 'follow-'));
  try {
    await body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('follow: starts at the end by default, then reads new lines, holding partial ones', () => inTempDir(async (dir) => {
  const file = join(dir, 'auth.log');
  writeFileSync(file, 'old line\n');
  const seen = await watch(file, async (step) => {
    appendFileSync(file, 'one\ntw');
    await step();
    appendFileSync(file, 'o\r\nthree\n');
    await step();
  });
  assert.deepEqual(seen, ['one', 'two', 'three']);
}));

test('follow: --from-start reads what is already there first', () => inTempDir(async (dir) => {
  const file = join(dir, 'auth.log');
  writeFileSync(file, 'old line\n');
  const seen = await watch(file, async (step) => {
    appendFileSync(file, 'new\n');
    await step();
  }, { fromStart: true });
  assert.deepEqual(seen, ['old line', 'new']);
}));

test('follow: rotation by rename (logrotate "create") finishes the old file, then reads the new one', () => inTempDir(async (dir) => {
  const file = join(dir, 'auth.log');
  writeFileSync(file, '');
  const seen = await watch(file, async (step) => {
    appendFileSync(file, 'before\n');
    await step();
    renameSync(file, `${file}.1`);
    appendFileSync(`${file}.1`, 'late write to the old file\n');
    writeFileSync(file, 'after\n');
    await step();
    appendFileSync(file, 'more\n');
    await step();
  });
  assert.deepEqual(seen, ['before', 'late write to the old file', '<rotated>', 'after', 'more']);
}));

test('follow: copytruncate (copied to .1, then emptied) is a rotation, not tampering', () => inTempDir(async (dir) => {
  const file = join(dir, 'auth.log');
  writeFileSync(file, '');
  const seen = await watch(file, async (step) => {
    appendFileSync(file, 'before\n');
    await step();
    writeFileSync(`${file}.1`, 'before\n');
    truncateSync(file, 0);
    appendFileSync(file, 'after\n');
    await step();
  });
  assert.deepEqual(seen, ['before', '<rotated>', 'after']);
}));

test('follow: a file that shrinks with no rotated copy is reported as truncated', () => inTempDir(async (dir) => {
  const file = join(dir, 'auth.log');
  writeFileSync(file, '');
  const seen = await watch(file, async (step) => {
    appendFileSync(file, 'line one\nline two\n');
    await step();
    truncateSync(file, 9);
    await step();
    appendFileSync(file, 'next\n');
    await step();
  });
  assert.deepEqual(seen, ['line one', 'line two', '<truncated 18->9>', 'next']);
}));

test('follow: a file that disappears and comes back is picked up again', () => inTempDir(async (dir) => {
  const file = join(dir, 'auth.log');
  writeFileSync(file, '');
  const seen = await watch(file, async (step) => {
    appendFileSync(file, 'a\n');
    await step();
    rmSync(file);
    await step();
    writeFileSync(file, 'b\n');
    await step();
  });
  assert.deepEqual(seen, ['a', '<missing>', '<rotated>', 'b']);
}));

test('follow: stop() ends the iteration promptly even while waiting', () => inTempDir(async (dir) => {
  const file = join(dir, 'auth.log');
  writeFileSync(file, '');
  const follower = createFollower(file, { pollMs: 10_000 });
  const done = (async () => { for await (const _ of follower.items()) void _; })();
  await sleep(50);
  const started = Date.now();
  await follower.stop();
  await done;
  assert.ok(Date.now() - started < 1000);
}));
