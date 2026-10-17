// Live mode: follow a log as it is written and report incidents as they
// happen. The same parser and engine as for a file; what differs is that
// findings are flushed whenever the follower has caught up, incidents are kept
// open while active and closed when quiet (core/live-incidents.js), and sinks
// (terminal, JSON lines, Discord) receive incident events instead of a report.
//
// Nothing here waits for a sink: sinks queue their own work, so a slow webhook
// can't delay the next line.

import { createEngine } from '../core/engine.js';
import { createIncidentTracker } from '../core/live-incidents.js';
import { createParser } from '../core/parse.js';
import { errorMessage } from './cli.js';
import { createFollower } from './follow.js';

/** @typedef {import('../types.js').AnalyzerOptions} AnalyzerOptions */
/** @typedef {import('../core/live-incidents.js').IncidentEvent} IncidentEvent */

/**
 * @typedef {object} Sink
 * @property {string} name
 * @property {(event: IncidentEvent) => void} [onIncident]  Must return quickly.
 * @property {(message: string) => void} [onNotice]  Things about the input: rotation, a missing file.
 * @property {(deadlineMs?: number) => Promise<unknown>} [close]
 */

/**
 * @param {object} settings
 * @param {string} settings.path
 * @param {Sink[]} settings.sinks
 * @param {AnalyzerOptions} [settings.options]
 * @param {number} [settings.year]
 * @param {boolean} [settings.fromStart]
 * @param {number} [settings.pollMs]
 * @param {number} [settings.idleMs]  Close incidents after this long without findings (log time).
 * @param {number} [settings.closeDeadlineMs]  How long sinks get to finish at shutdown.
 * @param {import('./analyze-stream.js').LineTap} [settings.tap]  Called for every line (for storage).
 */
export function startLive({ path, sinks, options = {}, year, fromStart = false, pollMs = 250, idleMs, closeDeadlineMs = 5000, tap }) {
  const follower = createFollower(path, { pollMs, fromStart });
  const parser = createParser({ year, now: Date.now() });
  /** @param {IncidentEvent[]} events */
  const dispatch = (events) => {
    for (const event of events) {
      for (const sink of sinks) {
        try {
          sink.onIncident?.(event);
        } catch (err) {
          console.error(`${sink.name}: ${errorMessage(err)}`);
        }
      }
    }
  };
  /** @param {string} message */
  const notice = (message) => { for (const sink of sinks) sink.onNotice?.(message); };
  const engine = createEngine(options, { keepFindings: false, onFinding: (f, isNew) => dispatch(tracker.onFinding(f, isNew)) });
  const tracker = createIncidentTracker({ ipv6Prefix: engine.options.ipv6Prefix, ...(idleMs !== undefined && { idleMs }) });
  let lineNo = 0;
  let lastTime = 0;
  let sinceFlush = 0;

  const flush = () => {
    engine.flush();
    dispatch(tracker.advance(lastTime));
    sinceFlush = 0;
  };

  const done = (async () => {
    for await (const item of follower.items()) {
      switch (item.type) {
        case 'line': {
          const { event, info } = parser.read(item.text, ++lineNo);
          if (info) {
            lastTime = info.time;
            engine.line(info);
          }
          if (event) engine.push(event);
          tap?.({ text: item.text, lineNo, event, info });
          if (++sinceFlush >= 1000) flush();
          break;
        }
        case 'idle':
          flush();
          break;
        case 'rotated':
          notice(`${path} was rotated; following the new file`);
          break;
        case 'missing':
          notice(`${path} is missing; waiting for it to come back`);
          break;
        case 'truncated':
          notice(`${path} shrank from ${item.fromBytes} to ${item.toBytes} bytes without being rotated`);
          engine.signal({ type: 'truncated', time: lastTime, line: lineNo, fromBytes: item.fromBytes, toBytes: item.toBytes });
          break;
      }
    }
    flush();
    dispatch(tracker.closeAll());
    const reports = await Promise.all(sinks.map((s) => s.close?.(closeDeadlineMs)));
    return { lines: lineNo, stats: parser.stats, health: { ...engine.health.evicted }, sinks: reports, size: engine.size() };
  })();

  return {
    /** Resolves when the follower has stopped and the sinks have closed. */
    done,
    /** Stops following; `done` resolves after a last read and the sinks' close. */
    async stop() {
      await follower.stop();
      return done;
    },
    engine,
    tracker,
  };
}
