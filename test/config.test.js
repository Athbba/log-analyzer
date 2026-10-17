// The config file and the address helpers it relies on.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { formatDuration, parseConfig, parseDuration, toConfig } from '../src/core/config.js';
import { networkMatcher, parseCidr, parseIp, prefixOf, sourceOf } from '../src/core/net.js';
import { resolveOptions } from '../src/core/options.js';

const BIN = fileURLToPath(new URL('../bin/analyze.js', import.meta.url));
const SAMPLE = fileURLToPath(new URL('../samples/auth.log', import.meta.url));
/** @param {string[]} args @param {string} [cwd] */
const cli = (args, cwd) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', cwd });

test('config: the defaults survive a round trip through the file format', () => {
  const defaults = resolveOptions();
  const { options, errors } = parseConfig(JSON.parse(JSON.stringify(toConfig(defaults))));
  assert.deepEqual(errors, []);
  assert.deepEqual(resolveOptions(options), defaults);
});

test('config: settings map onto the engine options, nested ones key by key', () => {
  const { options, errors } = parseConfig({
    $comment: 'ignored',
    bruteForce: { threshold: 8, window: '15m' },
    passwordSpray: { minUsers: 10 },
    trustedNetworks: ['10.0.0.0/8'],
    limits: { memory: '3d' },
  });
  assert.deepEqual(errors, []);
  const resolved = resolveOptions(options);
  assert.equal(resolved.threshold, 8);
  assert.equal(resolved.windowMs, 15 * 60_000);
  assert.equal(resolved.spray.minUsers, 10);
  assert.equal(resolved.spray.windowMs, 60 * 60_000, 'the other spray settings keep their defaults');
  assert.deepEqual(resolved.trustedNetworks, ['10.0.0.0/8']);
  assert.equal(resolved.limits.memoryMs, 3 * 86_400_000);
});

test('config: typos and wrong types are errors, not silently ignored', () => {
  const { errors } = parseConfig({
    treshold: 5,
    bruteForce: { threshold: 0, windw: '10m' },
    passwordSpray: 'yes',
    newSource: { learning: 600 },
    trustedNetworks: ['10.0.0.0/33'],
  });
  assert.deepEqual(errors, [
    'unknown setting "treshold"',
    '"bruteForce.threshold" must be a whole number from 1 up',
    'unknown setting "bruteForce.windw"',
    '"passwordSpray" must be an object',
    '"newSource.learning" must be a duration like "90s", "10m", "1h" or "7d"',
    '"trustedNetworks" must be a list of networks like "10.0.0.0/8" or "2001:db8::/32"',
  ]);
  assert.deepEqual(parseConfig([]).errors, ['the config must be a JSON object']);
});

test('config: durations need a unit, so seconds and milliseconds cannot be mixed up', () => {
  assert.deepEqual(['90s', '10m', '1h', '7d'].map(parseDuration), [90_000, 600_000, 3_600_000, 604_800_000]);
  assert.deepEqual(['10', '0m', '1.5h', 600, '-1m'].map(parseDuration), [null, null, null, null, null]);
  assert.deepEqual([90_000, 600_000, 7_200_000, 172_800_000].map(formatDuration), ['90s', '10m', '2h', '2d']);
});

test('CLI: --config is read, flags override it, and a bad file exits 2', () => {
  const dir = mkdtempSync(join(tmpdir(), 'log-analyzer-'));
  try {
    const good = join(dir, 'good.json');
    writeFileSync(good, JSON.stringify({ bruteForce: { threshold: 50 } }));
    const quiet = cli([SAMPLE, '--year', '2026', '--config', good]);
    assert.doesNotMatch(quiet.stdout, /203\.0\.113\.45/, 'attacker A (36 guesses) is under a threshold of 50');
    const flag = cli([SAMPLE, '--year', '2026', '--config', good, '--threshold', '5']);
    assert.match(flag.stdout, /MEDIUM {2}203\.0\.113\.45/, 'the flag wins');

    const bad = join(dir, 'bad.json');
    writeFileSync(bad, JSON.stringify({ bruteForce: { treshold: 5 } }));
    const rejected = cli([SAMPLE, '--config', bad]);
    assert.equal(rejected.status, 2);
    assert.match(rejected.stderr, /unknown setting "bruteForce\.treshold"/);
    assert.equal(cli([SAMPLE, '--config', join(dir, 'missing.json')]).status, 2);

    // The default file is picked up from the working directory.
    writeFileSync(join(dir, 'log-analyzer.config.json'), JSON.stringify({ unusualHour: { night: '9-11' } }));
    assert.match(cli(['--print-config'], dir).stdout, /"night": "9-11"/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('addresses: parsing, networks, and the /64 an IPv6 attacker controls', () => {
  assert.deepEqual(parseIp('192.0.2.1'), { version: 4, bytes: [192, 0, 2, 1] });
  assert.equal(parseIp('::ffff:192.0.2.1')?.version, 4, 'IPv4-mapped IPv6 is IPv4');
  for (const bad of ['1.2.3', '256.1.1.1', '1::2::3', 'x from 1.2.3.4', '', '1:2:3:4:5:6:7:8:9']) assert.equal(parseIp(bad), null, bad);
  assert.equal(sourceOf('2001:db8:4a2:7:1:2:3:4', 64), '2001:db8:4a2:7::/64');
  assert.equal(sourceOf('2001:db8::1c', 64), '2001:db8::/64');
  assert.equal(sourceOf('2001:db8::1c', 128), '2001:db8::1c');
  assert.equal(sourceOf('198.51.100.23', 64), '198.51.100.23');
  assert.equal(prefixOf('10.0.1.57', 24, 64), '10.0.1.0/24');
  assert.equal(prefixOf('not an ip', 24, 64), 'not an ip');
  const trusted = networkMatcher(['10.0.0.0/8', '2001:db8:4a2::/48'].flatMap((c) => parseCidr(c) ?? []));
  assert.deepEqual(['10.8.0.22', '11.0.0.1', '2001:db8:4a2::1c', '2001:db8:4a3::1', 'garbage'].map(trusted), [true, false, true, false, false]);
});
