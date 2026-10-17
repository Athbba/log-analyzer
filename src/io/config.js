// Reads the config file. The default location is ./log-analyzer.config.json,
// used only if it exists; a path given with --config must exist.

import { readFileSync } from 'node:fs';
import { parseConfig } from '../core/config.js';

/** @typedef {import('../types.js').AnalyzerOptions} AnalyzerOptions */

export const DEFAULT_CONFIG_PATH = 'log-analyzer.config.json';

export class ConfigError extends Error {}

/**
 * @param {string | undefined} path  From --config, or undefined for the default.
 * @returns {{ options: AnalyzerOptions, path: string | null }}
 * @throws {ConfigError} If the file can't be read or isn't valid.
 */
export function loadConfig(path) {
  const file = path ?? DEFAULT_CONFIG_PATH;
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    if (path === undefined && /** @type {NodeJS.ErrnoException} */ (err).code === 'ENOENT') return { options: {}, path: null };
    throw new ConfigError(`can't read config ${file}: ${err instanceof Error ? err.message : String(err)}`);
  }
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`config ${file} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  const { options, errors } = parseConfig(raw);
  if (errors.length > 0) throw new ConfigError(`config ${file}:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
  return { options, path: file };
}
