// Classic syslog timestamps ("Sep  7 03:39:12") have no year, so it has to be
// inferred. The first line gets the given year, or else the latest year that
// doesn't put it in the future. Every later line gets whichever year puts it
// closest to the line before it. That handles New Year in both directions: a
// log going from Dec 31 to Jan 1 moves to the next year, and a late Dec 31
// line arriving after Jan 1 stays in the old year instead of jumping a year
// ahead. It fails only across a gap of more than six months with no lines.
//
// Times are the server's wall clock as UTC milliseconds (see parse.js).

const DAY = 24 * 60 * 60_000;

/**
 * @param {{ year?: number, now: number }} options
 *   `year` is the year of the first line, if known. `now` (ms) bounds the
 *   guess when it isn't: a log can't start in the future, give or take a day
 *   of clock skew.
 * @returns {(month: number, day: number, h: number, m: number, s: number) => number}
 */
export function createSyslogClock({ year, now }) {
  /** @type {number | null} */
  let previous = null;
  return (month, day, h, m, s) => {
    /** @param {number} y */
    const at = (y) => Date.UTC(y, month, day, h, m, s);
    let time;
    if (previous === null) {
      if (year !== undefined) {
        time = at(year);
      } else {
        const thisYear = new Date(now).getUTCFullYear();
        time = at(thisYear) <= now + DAY ? at(thisYear) : at(thisYear - 1);
      }
    } else {
      const y = new Date(previous).getUTCFullYear();
      const prev = /** @type {number} */ (previous);
      time = [at(y - 1), at(y), at(y + 1)].reduce((best, t) => (Math.abs(t - prev) < Math.abs(best - prev) ? t : best));
    }
    previous = time;
    return time;
  };
}
