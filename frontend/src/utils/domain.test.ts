import { describe, expect, it } from 'vitest'
import { normaliseDomain, parseDomainList, validateDomain } from './domain'

describe('domain input', () => {
  it('normalises pasted URLs without preserving paths, queries, or case', () => {
    expect(normaliseDomain(' HTTPS://Mail.Example.COM/path?q=1 ')).toBe('mail.example.com')
  })

  it.each(['example.com', 'mail.example.co.uk', 'a-b.example'])('accepts %s', (domain) => {
    expect(validateDomain(domain)).toBeNull()
  })

  it.each(['', 'localhost', '-bad.example', '192.0.2.10', 'bad..example'])('rejects %s', (domain) => {
    expect(validateDomain(domain)).toBeTruthy()
  })

  it('deduplicates a mixed separator batch and reports invalid domains', () => {
    const parsed = parseDomainList('Example.com, example.org\nexample.com; localhost')
    expect(parsed.domains).toEqual(['example.com', 'example.org', 'localhost'])
    expect(parsed.errors).toEqual([expect.stringContaining('localhost')])
  })

  it('enforces the server batch limit of 20 unique domains', () => {
    const parsed = parseDomainList(Array.from({ length: 21 }, (_, index) => `d${index}.example.com`).join('\n'))
    expect(parsed.errors).toContain('A batch can contain no more than 20 unique domains.')
  })
})
