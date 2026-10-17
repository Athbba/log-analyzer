// IP addresses, networks, and the "source" a rule counts attempts against.
//
// An IPv6 attacker usually controls a whole /64, so they can use a fresh
// address for every guess and stay under any per-address threshold. Rules
// that count attempts therefore key IPv6 by its /64 prefix (configurable;
// 128 keeps exact addresses). IPv4 is always exact.

/**
 * Parses an IPv4 or IPv6 address into its bytes, or null if it is neither.
 * IPv4-mapped IPv6 (::ffff:192.0.2.1) is treated as the IPv4 address.
 * @param {string} text
 * @returns {{ version: 4 | 6, bytes: number[] } | null}
 */
export function parseIp(text) {
  const v4 = parseIpv4(text);
  if (v4) return { version: 4, bytes: v4 };
  const v6 = parseIpv6(text);
  if (!v6) return null;
  const mapped = v6.slice(0, 10).every((b) => b === 0) && v6[10] === 0xff && v6[11] === 0xff;
  return mapped ? { version: 4, bytes: v6.slice(12) } : { version: 6, bytes: v6 };
}

/** @param {string} text */
function parseIpv4(text) {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const bytes = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  return bytes.every((b) => b >= 0 && b <= 255) ? bytes : null;
}

/** @param {string} text */
function parseIpv6(text) {
  if (!/^[0-9a-fA-F:.]{2,45}$/.test(text)) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  /** @param {string} half */
  const groups = (half) => {
    if (half === '') return [];
    const parts = half.split(':');
    /** @type {number[]} */
    const out = [];
    for (const [i, part] of parts.entries()) {
      if (i === parts.length - 1 && part.includes('.')) {
        const v4 = parseIpv4(part);
        if (!v4) return null;
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else if (/^[0-9a-fA-F]{1,4}$/.test(part)) {
        out.push(parseInt(part, 16));
      } else {
        return null;
      }
    }
    return out;
  };
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  if (!head || !tail) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const all = [...head, ...new Array(missing).fill(0), ...tail];
  return all.flatMap((g) => [g >> 8, g & 0xff]);
}

/**
 * A network such as "10.0.0.0/8" or "2001:db8::/32".
 * @typedef {{ version: 4 | 6, bytes: number[], bits: number }} Network
 */

/**
 * @param {string} cidr
 * @returns {Network | null}
 */
export function parseCidr(cidr) {
  const [address, bitsText, ...rest] = cidr.split('/');
  const ip = parseIp(address);
  if (!ip || rest.length > 0) return null;
  const max = ip.version === 4 ? 32 : 128;
  const bits = bitsText === undefined ? max : /^\d{1,3}$/.test(bitsText) ? Number(bitsText) : NaN;
  if (!(bits >= 0 && bits <= max)) return null;
  return { version: ip.version, bytes: ip.bytes, bits };
}

/**
 * @param {number[]} a
 * @param {number[]} b
 * @param {number} bits  How many leading bits must match.
 */
function samePrefix(a, b, bits) {
  for (let i = 0; i < bits; i += 8) {
    const take = Math.min(8, bits - i);
    const mask = (0xff << (8 - take)) & 0xff;
    if ((a[i / 8] & mask) !== (b[i / 8] & mask)) return false;
  }
  return true;
}

/**
 * Builds a matcher for a list of networks. Unparseable addresses never match.
 * @param {Network[]} networks
 * @returns {(ip: string) => boolean}
 */
export function networkMatcher(networks) {
  if (networks.length === 0) return () => false;
  return (text) => {
    const ip = parseIp(text);
    return ip !== null && networks.some((n) => n.version === ip.version && samePrefix(n.bytes, ip.bytes, n.bits));
  };
}

/**
 * The prefix of an address as a network string, e.g. "10.0.1.0/24".
 * @param {string} text
 * @param {number} bitsV4
 * @param {number} bitsV6
 * @returns {string}  The input unchanged if it isn't an IP address.
 */
export function prefixOf(text, bitsV4, bitsV6) {
  const ip = parseIp(text);
  if (!ip) return text;
  const bits = ip.version === 4 ? bitsV4 : bitsV6;
  const max = ip.version === 4 ? 32 : 128;
  if (bits >= max) return text;
  const bytes = ip.bytes.map((b, i) => {
    const keep = Math.max(0, Math.min(8, bits - i * 8));
    return b & ((0xff << (8 - keep)) & 0xff);
  });
  return `${formatIp(ip.version, bytes)}/${bits}`;
}

/**
 * The key a rule counts attempts against: the address for IPv4, and its /64
 * (or `bitsV6`) for IPv6.
 * @param {string} ip
 * @param {number} bitsV6
 */
export function sourceOf(ip, bitsV6) {
  // Hot path (every failure, in several rules): plain IPv4 is its own source.
  if (!ip.includes(':')) return ip;
  return prefixOf(ip, 32, bitsV6);
}

/**
 * @param {4 | 6} version
 * @param {number[]} bytes
 */
function formatIp(version, bytes) {
  if (version === 4) return bytes.join('.');
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // Compress the longest run of zero groups (RFC 5952).
  let best = { at: -1, length: 0 };
  for (let i = 0; i < 8;) {
    if (groups[i] !== '0') { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > best.length && j - i > 1) best = { at: i, length: j - i };
    i = j;
  }
  if (best.at < 0) return groups.join(':');
  return `${groups.slice(0, best.at).join(':')}::${groups.slice(best.at + best.length).join(':')}`;
}
