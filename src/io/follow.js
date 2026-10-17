// Follows a log file as it is written, like `tail -F`, and survives what
// logrotate and attackers do to it:
//
// - new lines, including a last line still being written (held until its
//   newline arrives);
// - rotation by rename ("create" mode): the old file is read to its end, then
//   the new one is opened and read from the start;
// - copytruncate: the file is copied to auth.log.1 and emptied in place. A file
//   that shrinks while a freshly written sibling (auth.log.1, auth.log-2026…)
//   exists is a rotation;
// - truncation without such a sibling is reported as "truncated", which the
//   log-tampering rule treats as high: nothing legitimate empties auth.log;
// - the file disappearing for a while, and coming back.
//
// It polls with stat() rather than using fs.watch, which behaves differently
// on every platform and misses events on network filesystems. Inodes are
// compared as bigints so they are exact on every OS.

import { readdir, open, stat } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { LineSplitter } from '../core/lines.js';

/**
 * Lines and events, in order. 'idle' comes after each poll that has caught up
 * with the file, so a consumer knows when to flush.
 * @typedef {{ type: 'line', text: string }
 *   | { type: 'rotated' }
 *   | { type: 'missing' }
 *   | { type: 'idle' }
 *   | { type: 'truncated', fromBytes: number, toBytes: number }} FollowItem
 */

/**
 * @param {string} path
 * @param {object} [options]
 * @param {number} [options.pollMs]  How often to check the file.
 * @param {boolean} [options.fromStart]  Read what is already in the file first (default: start at its end).
 * @param {number} [options.maxLineLength]  Passed to LineSplitter.
 * @param {number} [options.chunkSize]  Bytes per read.
 * @param {number} [options.maxReadPerPoll]  Bytes read before yielding to the next poll, so a huge backlog
 *   is processed in slices and stop() stays responsive.
 * @param {number} [options.rotationWindowMs]  How recent a rotated sibling must be for a shrink to count as rotation.
 */
export function createFollower(path, {
  pollMs = 250, fromStart = false, maxLineLength, chunkSize = 64 * 1024, maxReadPerPoll = 8 << 20, rotationWindowMs = 60_000,
} = {}) {
  let stopped = false;
  /** @type {(() => void) | null} */
  let wake = null;
  /** @type {Promise<void> | null} */
  let running = null;
  const splitter = new LineSplitter(maxLineLength);

  /** Waits for the next poll, or until stop(). */
  const pause = () => new Promise((resolve) => {
    const timer = setTimeout(() => { wake = null; resolve(undefined); }, pollMs);
    wake = () => { clearTimeout(timer); wake = null; resolve(undefined); };
  });

  /** @returns {Promise<import('node:fs').BigIntStats | null>} */
  async function statOrNull() {
    try {
      return await stat(path, { bigint: true });
    } catch (err) {
      const code = /** @type {NodeJS.ErrnoException} */ (err).code;
      // EPERM: on Windows a file being deleted can't be opened or stat'ed.
      if (code === 'ENOENT' || code === 'EPERM') return null;
      throw err;
    }
  }

  /** Whether logrotate just made a copy of the file next to it. */
  async function freshlyRotated() {
    const dir = dirname(path);
    const name = basename(path);
    const since = Date.now() - rotationWindowMs;
    let entries;
    try {
      entries = await readdir(dir);
    } catch {
      return false;
    }
    for (const entry of entries) {
      if (entry === name || !(entry.startsWith(`${name}.`) || entry.startsWith(`${name}-`))) continue;
      const s = await stat(join(dir, entry)).catch(() => null);
      if (s && s.mtimeMs >= since) return true;
    }
    return false;
  }

  /** @returns {AsyncGenerator<FollowItem>} */
  async function* items() {
    /** @type {import('node:fs/promises').FileHandle | null} */
    let handle = null;
    let inode = -1n;
    let offset = 0;
    let opened = false;
    let missing = false;
    const buffer = Buffer.alloc(chunkSize);

    /**
     * Reads what has been appended since the last read.
     * @returns {AsyncGenerator<FollowItem>}
     */
    async function* drain() {
      if (!handle) return;
      let read = 0;
      while (read < maxReadPerPoll) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
        read += bytesRead;
        for (const text of splitter.push(buffer.subarray(0, bytesRead))) yield /** @type {FollowItem} */ ({ type: 'line', text });
      }
    }

    async function closeHandle() {
      await handle?.close();
      handle = null;
    }

    try {
      while (!stopped) {
        const info = await statOrNull();
        if (handle && info && info.ino !== inode) {
          // Renamed away and replaced: finish the old file first.
          yield* drain();
          const last = splitter.end();
          if (last !== null) yield { type: 'line', text: last };
          await closeHandle();
        }
        if (!handle) {
          if (info) {
            handle = await open(path, 'r');
            inode = info.ino;
            offset = !opened && !fromStart ? Number(info.size) : 0;
            if (opened) yield { type: 'rotated' };
            opened = true;
            missing = false;
          } else if (!missing && opened) {
            missing = true;
            yield { type: 'missing' };
          }
        } else if (!info) {
          // Gone (deleted, or renamed with nothing in its place yet). Keep
          // reading the open file: processes may still be writing to it.
          yield* drain();
          if (!missing) {
            missing = true;
            yield { type: 'missing' };
          }
        } else if (Number(info.size) < offset) {
          const fromBytes = offset;
          splitter.end();
          if (await freshlyRotated()) {
            yield { type: 'rotated' };
            offset = 0;
          } else {
            yield { type: 'truncated', fromBytes, toBytes: Number(info.size) };
            offset = Number(info.size);
          }
        }
        yield* drain();
        yield { type: 'idle' };
        if (!stopped) await pause();
      }
      yield* drain();
      const last = splitter.end();
      if (last !== null) yield { type: 'line', text: last };
    } finally {
      await closeHandle();
    }
  }

  return {
    /**
     * Lines and events, until stop(). Can be iterated once.
     * @returns {AsyncGenerator<FollowItem>}
     */
    items() {
      /** @type {() => void} */
      let finish = () => {};
      running = new Promise((resolve) => { finish = () => resolve(undefined); });
      const inner = items();
      return (async function* () {
        try {
          yield* inner;
        } finally {
          finish();
        }
      })();
    },
    /** Lines cut off for being too long, so far. */
    get oversized() {
      return splitter.oversized;
    },
    /** Stops after a last read; resolves once the iteration has ended. */
    async stop() {
      stopped = true;
      wake?.();
      await running;
    },
  };
}
