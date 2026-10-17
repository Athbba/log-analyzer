// Log tampering: signs that lines were removed from the log or inserted into
// it. An attacker who gets root often edits auth.log to remove their logins
// (or truncates it), and both leave traces in the log's own timeline:
//
// - gap: no lines at all for longer than `maxGapMs`. On a normal Debian or
//   Ubuntu host cron writes to auth.log at least hourly, so hours of silence
//   mean the logger was down, the machine was off, or lines were deleted.
// - backwards: a line more than `maxBackwardsMs` earlier than the one before
//   it, as when lines are spliced in from elsewhere. Small steps back (clock
//   sync, lines from several processes) are normal. When DST ends the clock
//   goes back an hour. With RFC 3339 timestamps the offsets turn every line
//   into a real instant, so gaps and steps are measured in real time and DST
//   never shows. With classic syslog timestamps there is no offset, so a
//   one-hour step back is let through when `allowDstJumps` is on.
// - nul-bytes: lines containing NUL characters, which appear when a file is
//   truncated or zero-filled while a process still writes to it.
// - truncated: in live mode, the file got shorter without being rotated.
//
// Each finding is evidence, not proof: a reboot leaves a gap too.

/** @typedef {import('../../types.js').LogTamperingFinding} LogTamperingFinding */
/** @typedef {import('../../types.js').LineInfo} LineInfo */
/** @typedef {import('../engine.js').RuleContext} RuleContext */
/** @typedef {import('../engine.js').Rule} Rule */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/** @param {number} ms */
function span(ms) {
  const minutes = Math.round(ms / MINUTE);
  if (minutes < 60) return `${minutes}m`;
  const h = Math.floor(minutes / 60);
  return minutes % 60 === 0 ? `${h}h` : `${h}h ${minutes % 60}m`;
}

/**
 * @param {RuleContext} ctx
 * @returns {Rule}
 */
export function createLogTampering(ctx) {
  const { maxGapMs, maxBackwardsMs, allowDstJumps } = ctx.options.tampering;
  /** @type {LineInfo | null} */
  let previous = null;
  /** Latest wall-clock time, and latest real instant (for lines with offsets). */
  let latest = -Infinity;
  let latestInstant = -Infinity;
  /** The finding for the current run of lines with NUL bytes, if any. */
  /** @type {LogTamperingFinding | null} */
  let nulRun = null;
  let nulLines = 0;
  /** @param {number} n */
  const nulDetail = (n) => `${n} ${n === 1 ? 'line' : 'lines'} with NUL bytes, as left by truncating a file that is still being written`;

  /**
   * @param {Omit<LogTamperingFinding, 'rule' | 'ip'>} fields
   */
  const report = (fields) => {
    /** @type {LogTamperingFinding} */
    const finding = { rule: 'log-tampering', ip: null, ...fields };
    ctx.emit(finding);
    return finding;
  };

  return {
    name: 'log-tampering',
    onEvent() {},

    onLine(info) {
      if (!ctx.options.tampering.enabled) return;
      if (info.hasNul) {
        nulLines++;
        if (nulRun) {
          nulRun.until = info.time;
          nulRun.detail = nulDetail(nulLines);
          ctx.update(nulRun);
        } else {
          nulRun = report({ kind: 'nul-bytes', severity: 'low', time: info.time, until: info.time, line: info.line, detail: nulDetail(nulLines) });
        }
      } else {
        nulRun = null;
        nulLines = 0;
      }

      const instant = instantOf(info);
      if (previous) {
        const prevInstant = instantOf(previous);
        const real = instant !== null && prevInstant !== null && latestInstant > -Infinity;
        const silence = real ? /** @type {number} */ (instant) - latestInstant : info.time - latest;
        if (silence > maxGapMs) {
          report({
            kind: 'gap', severity: 'low', time: latest, until: info.time, line: info.line,
            detail: `no log lines for ${span(silence)}`,
          });
        }
        const back = real ? /** @type {number} */ (prevInstant) - /** @type {number} */ (instant) : previous.time - info.time;
        if (back > maxBackwardsMs && (real || !isDst(back))) {
          report({
            kind: 'backwards', severity: 'medium', time: previous.time, until: info.time, line: info.line,
            detail: `timestamps went back ${span(back)} at line ${info.line}`,
          });
        }
      }
      previous = info;
      latest = Math.max(latest, info.time);
      if (instant !== null) latestInstant = Math.max(latestInstant, instant);
    },

    onSignal(signal) {
      if (!ctx.options.tampering.enabled || signal.type !== 'truncated') return;
      report({
        kind: 'truncated', severity: 'high', time: signal.time, until: signal.time, line: signal.line,
        detail: `the log file shrank from ${signal.fromBytes} to ${signal.toBytes} bytes without being rotated`,
      });
    },

    size: () => ({ keys: 0, entries: previous ? 1 : 0 }),
  };

  /**
   * The real instant of a line, when its timestamp has an offset.
   * @param {LineInfo} info
   */
  function instantOf(info) {
    return info.offsetMinutes === null ? null : info.time - info.offsetMinutes * MINUTE;
  }

  /**
   * Whether a wall-clock step back (no offsets to go by) may be the end of DST.
   * @param {number} back
   */
  function isDst(back) {
    return allowDstJumps && Math.abs(back - HOUR) <= maxBackwardsMs;
  }
}
