/** Quote one executable path for the shell used by Playwright's webServer. */
export function quoteExecutable(executable: string, platform: string): string {
  if (!executable || /[\0\r\n]/.test(executable)) throw new Error('NORTHFLUX_PYTHON must be a non-empty executable path.')
  if (platform === 'win32') {
    // Windows file names cannot contain quotes. cmd expands %variables% even
    // inside quotes, so reject that ambiguous input rather than executing it.
    if (/["%]/.test(executable)) throw new Error('NORTHFLUX_PYTHON cannot contain quotes or percent signs on Windows.')
    return `"${executable}"`
  }
  return `'${executable.replaceAll("'", "'\"'\"'")}'`
}
