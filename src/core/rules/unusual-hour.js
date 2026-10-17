// Unusual hour: a successful SSH login during the night window. Hours come
// straight from the log, i.e. the server's clock. A window like [22, 6] wraps
// past midnight. No state.

/** @typedef {import('../engine.js').RuleContext} RuleContext */
/** @typedef {import('../engine.js').Rule} Rule */

/**
 * @param {RuleContext} ctx
 * @returns {Rule}
 */
export function createUnusualHour(ctx) {
  const [from, to] = ctx.options.night;
  /** @param {number} h */
  const atNight = (h) => (from < to ? h >= from && h < to : h >= from || h < to);

  return {
    name: 'unusual-hour',
    onEvent(event) {
      if (event.type !== 'success' || !atNight(new Date(event.time).getUTCHours())) return;
      ctx.emit({
        rule: 'unusual-hour',
        severity: 'low',
        ip: event.ip,
        time: event.time,
        user: event.user,
        method: event.method,
      });
    },
    size: () => ({ keys: 0, entries: 0 }),
  };
}
