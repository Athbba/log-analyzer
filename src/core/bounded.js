// Bounded containers for detector state. Every piece of state that grows with
// the input lives in one of these, so memory has a hard ceiling however long
// the log is or however many addresses an attacker uses. Hitting a ceiling is
// never silent: it is counted in `Health`, and the report says so.

/**
 * Counters of state that was dropped because a limit was reached. A non-zero
 * count means a detection may have been missed.
 */
export class Health {
  /** @type {Record<string, number>} */
  evicted = {};

  /** @param {string} what */
  drop(what) {
    this.evicted[what] = (this.evicted[what] ?? 0) + 1;
  }

  get total() {
    return Object.values(this.evicted).reduce((sum, n) => sum + n, 0);
  }
}

/**
 * A Map with a size cap and least-recently-used eviction. `touch` marks a key
 * as used (Map iteration order is insertion order, so re-inserting moves it to
 * the end); when the map is over its cap, the least recently used entry goes.
 * @template K, V
 */
export class BoundedMap {
  /** @type {Map<K, V>} */
  #map = new Map();

  /**
   * @param {string} name  What the entries are, for the health counters.
   * @param {number} maxSize
   * @param {Health} health
   */
  constructor(name, maxSize, health) {
    this.name = name;
    this.maxSize = maxSize;
    this.health = health;
  }

  /** @param {K} key */
  get(key) {
    return this.#map.get(key);
  }

  /** @param {K} key */
  has(key) {
    return this.#map.has(key);
  }

  /**
   * Returns the entry for `key`, creating it if needed, and marks it as used.
   * @param {K} key
   * @param {() => V} create
   * @returns {V}
   */
  touch(key, create) {
    let value = this.#map.get(key);
    if (value === undefined) {
      value = create();
    } else {
      this.#map.delete(key);
    }
    this.#map.set(key, value);
    if (this.#map.size > this.maxSize) {
      const oldest = this.#map.keys().next().value;
      this.#map.delete(/** @type {K} */ (oldest));
      this.health.drop(this.name);
    }
    return value;
  }

  /**
   * Sets `key` to `value` as its most recently used entry, replacing any old one.
   * @param {K} key
   * @param {V} value
   */
  set(key, value) {
    this.#map.delete(key);
    this.touch(key, () => value);
  }

  /** @param {K} key */
  delete(key) {
    return this.#map.delete(key);
  }

  /**
   * Deletes every entry for which `isDead` is true. O(size), so callers run it
   * at most once per time window, not per event.
   * @param {(value: V, key: K) => boolean} isDead
   */
  sweep(isDead) {
    for (const [key, value] of this.#map) if (isDead(value, key)) this.#map.delete(key);
  }

  get size() {
    return this.#map.size;
  }

  values() {
    return this.#map.values();
  }
}

/**
 * A queue of timed items, oldest first, with a cap on its length. Items must be
 * pushed in time order. Used for "what happened in the last N minutes".
 * @template {{ time: number }} T
 */
export class TimeWindow {
  /** @type {T[]} */
  #items = [];
  #head = 0;

  /**
   * @param {string} name  What the items are, for the health counters.
   * @param {number} maxLength
   * @param {Health} health
   */
  constructor(name, maxLength, health) {
    this.name = name;
    this.maxLength = maxLength;
    this.health = health;
  }

  /**
   * Appends an item. If that goes over the cap, the oldest item is dropped,
   * counted in the health counters, and passed to `onEvict`.
   * @param {T} item
   * @param {(item: T) => void} [onEvict]
   */
  push(item, onEvict) {
    this.#items.push(item);
    if (this.length > this.maxLength) {
      const dropped = /** @type {T} */ (this.shift());
      this.health.drop(this.name);
      onEvict?.(dropped);
    }
  }

  /**
   * The newest `n` items, oldest of them first.
   * @param {number} n
   */
  *tail(n) {
    for (let i = Math.max(this.#head, this.#items.length - n); i < this.#items.length; i++) yield this.#items[i];
  }

  /** Newest first. */
  *reversed() {
    for (let i = this.#items.length - 1; i >= this.#head; i--) yield this.#items[i];
  }

  /** Removes and returns the oldest item. */
  shift() {
    if (this.#head >= this.#items.length) return undefined;
    const item = this.#items[this.#head++];
    // Compact once the dead prefix is half the array, so shifting stays O(1)
    // amortized and the array doesn't keep references to evicted items.
    if (this.#head > 32 && this.#head * 2 > this.#items.length) {
      this.#items = this.#items.slice(this.#head);
      this.#head = 0;
    }
    return item;
  }

  /** The oldest item, or undefined. */
  first() {
    return this.#head < this.#items.length ? this.#items[this.#head] : undefined;
  }

  /** The newest item, or undefined. */
  last() {
    return this.#head < this.#items.length ? this.#items[this.#items.length - 1] : undefined;
  }

  /**
   * Removes items older than `time`, calling `onEvict` for each.
   * @param {number} time
   * @param {(item: T) => void} [onEvict]
   */
  dropBefore(time, onEvict) {
    let item;
    while ((item = this.first()) !== undefined && item.time < time) {
      this.shift();
      onEvict?.(item);
    }
  }

  get length() {
    return this.#items.length - this.#head;
  }

  *[Symbol.iterator]() {
    for (let i = this.#head; i < this.#items.length; i++) yield this.#items[i];
  }
}
