// Splits a byte stream into lines without ever holding more than one line's
// worth of bytes. Node's readline buffers until it finds a newline, so a single
// line with none (a corrupt file, or an attacker with write access) is held in
// memory whole. Here a line longer than `maxLength` bytes is cut off: its first
// `maxLength` bytes are kept to count, the rest is skipped until the next
// newline, and the line is reported as oversized.
//
// Splitting on the byte 0x0A is safe in UTF-8, which never uses it inside a
// multi-byte character. A trailing CR (Windows line endings) is removed.

/**
 * Lines in the order they were completed. An oversized line comes out as ''
 * so line numbers stay right; the parser skips empty lines.
 */
export class LineSplitter {
  /** @type {Buffer[]} */
  #parts = [];
  #partLength = 0;
  #skipping = false;
  oversized = 0;

  /** @param {number} [maxLength] Longest line kept, in bytes. sshd's own lines are under 1 KB. */
  constructor(maxLength = 8192) {
    this.maxLength = maxLength;
  }

  /**
   * @param {Buffer} chunk
   * @returns {string[]} The lines this chunk completed.
   */
  push(chunk) {
    /** @type {string[]} */
    const lines = [];
    let start = 0;
    let newline;
    while ((newline = chunk.indexOf(0x0a, start)) !== -1) {
      this.#take(chunk.subarray(start, newline));
      lines.push(this.#finish());
      start = newline + 1;
    }
    // The unfinished tail is kept until the next chunk, so it is copied: the
    // caller may reuse its buffer for the next read.
    this.#take(chunk.subarray(start), true);
    return lines;
  }

  /** Bytes held for the line in progress; never more than `maxLength`. */
  get buffered() {
    return this.#partLength;
  }

  /** @returns {string | null} The last line, if the input didn't end with a newline. */
  end() {
    if (this.#partLength === 0 && !this.#skipping) return null;
    return this.#finish();
  }

  /**
   * @param {Buffer} bytes
   * @param {boolean} [keep]  Whether the bytes outlive this push and must be copied.
   */
  #take(bytes, keep = false) {
    if (this.#skipping || bytes.length === 0) return;
    const room = this.maxLength - this.#partLength;
    if (bytes.length > room) {
      this.#skipping = true;
      this.#parts = [];
      this.#partLength = 0;
      return;
    }
    this.#parts.push(keep ? Buffer.from(bytes) : bytes);
    this.#partLength += bytes.length;
  }

  #finish() {
    if (this.#skipping) {
      this.#skipping = false;
      this.oversized++;
      return '';
    }
    const text = Buffer.concat(this.#parts, this.#partLength).toString('utf8');
    this.#parts = [];
    this.#partLength = 0;
    return text.endsWith('\r') ? text.slice(0, -1) : text;
  }
}
