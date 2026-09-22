import { describe, expect, it } from 'vitest'
import { quoteExecutable } from './launch-command'

describe('Playwright Python executable quoting', () => {
  it('keeps a Windows virtual environment path with spaces as one executable', () => {
    const executable = String.raw`C:\Users\Leon\AuroraEdge 2\.venv\Scripts\python.exe`
    expect(quoteExecutable(executable, 'win32')).toBe(`"${executable}"`)
  })
  it('keeps a Linux virtual environment path with spaces as one executable', () => {
    expect(quoteExecutable('/home/leon/AuroraEdge 2/.venv/bin/python', 'linux')).toBe("'/home/leon/AuroraEdge 2/.venv/bin/python'")
  })
  it('quotes POSIX apostrophes and shell metacharacters without evaluating them', () => {
    expect(quoteExecutable("/tmp/leon's $HOME;$(echo no)/python", 'linux')).toBe("'/tmp/leon'\"'\"'s $HOME;$(echo no)/python'")
  })
  it.each(['win32', 'linux'])('supports a Python executable found on PATH on %s', (platform) => {
    expect(quoteExecutable('python', platform)).toBe(platform === 'win32' ? '"python"' : "'python'")
  })
  it.each(['', 'python\nother-command', 'python\0'])('rejects invalid executable input %j', (executable) => {
    expect(() => quoteExecutable(executable, 'linux')).toThrow('executable path')
  })
  it.each(['python" & other-command', '%UNKNOWN%\\python.exe'])('rejects Windows shell-expanded executable input %j', (executable) => {
    expect(() => quoteExecutable(executable, 'win32')).toThrow('quotes or percent')
  })
})
