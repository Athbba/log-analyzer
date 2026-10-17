// Error reporting shared by the command-line entry points and the shell.

/**
 * The message of a thrown value, which need not be an Error.
 * @param {unknown} err
 */
export function errorMessage(err) {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Prints an error, with the usage text if given, and exits with status 2.
 * @param {string} message
 * @param {string} [usage]
 * @returns {never}
 */
export function fail(message, usage) {
  console.error(usage === undefined ? `error: ${message}` : `error: ${message}\n\n${usage}`);
  process.exit(2);
}
