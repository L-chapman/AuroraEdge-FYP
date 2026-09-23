import { describe, expect, it } from 'vitest'

import {
  classifySpfIp,
  defaultMtaStsPolicyId,
  generateBimi,
  generateDmarc,
  generateMtaSts,
  generateSpf,
  generateTlsRpt,
} from './dnsRecords'

describe('SPF generation', () => {
  it('splits long zone-file TXT output into strings of at most 255 bytes without changing the record', () => {
    const result = generateSpf({ domain: 'example.com', includes: '', ipAddresses: Array.from({ length: 24 }, (_, index) => `203.0.113.${index}`).join('\n'), policy: '-all' })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.value.length).toBeGreaterThan(255)
    const strings = [...result.value.zoneFile.matchAll(/"([^"]*)"/g)].map((match) => match[1])
    expect(strings.length).toBeGreaterThan(1)
    expect(strings.every((value) => new TextEncoder().encode(value).length <= 255)).toBe(true)
    expect(strings.join('')).toBe(result.value.value)
  })

  it.each([
    ['203.0.113.10', 'ip4:203.0.113.10'],
    ['198.51.100.0/24', 'ip4:198.51.100.0/24'],
    ['2001:db8::1', 'ip6:2001:db8::1'],
    ['2001:db8::/32', 'ip6:2001:db8::/32'],
  ])('classifies %s correctly', (input, expected) => {
    const result = classifySpfIp(input)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value).toBe(expected)
  })

  it('rejects invalid addresses and CIDR prefix lengths', () => {
    expect(classifySpfIp('203.0.113.0/64').ok).toBe(false)
    expect(classifySpfIp('2001:db8::/129').ok).toBe(false)
    expect(classifySpfIp('999.0.0.1').ok).toBe(false)
  })

  it('builds a record containing IPv4 CIDR, IPv6 CIDR, and provider includes', () => {
    const result = generateSpf({
      domain: 'Example.COM.',
      includes: '_spf.google.com, spf.example.net',
      ipAddresses: '198.51.100.0/24\n2001:db8::/32',
      policy: '-all',
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.host).toBe('example.com')
      expect(result.value.value).toBe(
        'v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 include:_spf.google.com include:spf.example.net -all',
      )
    }
  })
})

describe('DMARC generation', () => {
  it('accepts an already encoded mailto URI without encoding it twice', () => {
    const result = generateDmarc({ domain: 'example.com', policy: 'none', subdomainPolicy: '', aggregateEmails: 'mailto:reports%3Fdaily@example.com', forensicEmails: '', percentage: 100 })
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value.value).toContain('rua=mailto:reports%3Fdaily@example.com')
  })

  it('encodes mailbox URI delimiters without changing the destination address', () => {
    const result = generateDmarc({ domain: 'example.com', policy: 'none', subdomainPolicy: '', aggregateEmails: 'reports?daily#tag%quota!@example.com', forensicEmails: '', percentage: 100 })
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value.value).toContain('rua=mailto:reports%3Fdaily%23tag%25quota%21@example.com')
  })

  it('preserves an explicit zero policy percentage', () => {
    const result = generateDmarc({
      domain: 'example.com',
      policy: 'quarantine',
      subdomainPolicy: 'reject',
      aggregateEmails: 'reports@example.com',
      forensicEmails: '',
      percentage: 0,
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.value).toContain('pct=0')
      expect(result.value.value).toContain('rua=mailto:reports@example.com')
    }
    expect(result.warnings.some((warning) => warning.field === 'percentage' && /legacy/i.test(warning.message) && /not.*guarantee/i.test(warning.message))).toBe(true)
  })

  it('validates percentage and report addresses', () => {
    const result = generateDmarc({
      domain: 'example.com',
      policy: 'reject',
      subdomainPolicy: '',
      aggregateEmails: 'not-an-email',
      forensicEmails: '',
      percentage: 101,
    })
    expect(result.ok).toBe(false)
    expect(result.errors.map((issue) => issue.field)).toEqual(
      expect.arrayContaining(['percentage', 'aggregateEmails']),
    )
  })
})

describe('MTA-STS generation', () => {
  it('creates one mx line for every non-empty input line', () => {
    const result = generateMtaSts({
      domain: 'example.com',
      mode: 'enforce',
      mxHosts: 'mx1.example.com\n\nmx2.example.com\r\n*.mail.example.com',
      maxAge: 604800,
      policyId: '20260921',
    })

    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.policyFile).toBe(
        'version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmx: *.mail.example.com\nmax_age: 604800',
      )
      expect(result.value.dnsRecord.value).toBe('v=STSv1; id=20260921')
      expect(result.value.policyUrl).toBe('https://mta-sts.example.com/.well-known/mta-sts.txt')
    }
  })

  it('requires an MX host whenever the policy is active', () => {
    const result = generateMtaSts({
      domain: 'example.com',
      mode: 'testing',
      mxHosts: '',
      maxAge: 604800,
      policyId: 'revision1',
    })
    expect(result.ok).toBe(false)
    expect(result.errors.some((issue) => issue.field === 'mxHosts')).toBe(true)
  })

  it('creates a deterministic default policy ID for a supplied date', () => {
    expect(defaultMtaStsPolicyId(new Date('2026-09-21T12:00:00Z'))).toBe('20260921')
  })
})

describe('TLS-RPT generation', () => {
  it('encodes reserved mailbox characters in reporting URIs', () => {
    const result = generateTlsRpt({ domain: 'example.com', reportEmails: 'reports?daily#tag%quota@example.com' })
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value.value).toContain('rua=mailto:reports%3Fdaily%23tag%25quota@example.com')
  })

  it.each(['.reports@example.com', 'reports.@example.com', 'reports..daily@example.com'])('rejects invalid dot-atom mailbox %s', (reportEmails) => {
    expect(generateTlsRpt({ domain: 'example.com', reportEmails }).ok).toBe(false)
  })

  it.each(['mailto:reports%invalid@example.com', 'mailto:reports?daily@example.com', 'mailto:reports#daily@example.com'])('rejects malformed or unescaped mailto URI %s', (reportEmails) => {
    expect(generateTlsRpt({ domain: 'example.com', reportEmails }).ok).toBe(false)
  })

  it('rejects mailbox local parts longer than 64 octets', () => {
    expect(generateTlsRpt({ domain: 'example.com', reportEmails: `${'a'.repeat(65)}@example.com` }).ok).toBe(false)
  })

  it('creates mailto destinations for comma and line separated addresses', () => {
    const result = generateTlsRpt({
      domain: 'example.com',
      reportEmails: 'tls@example.com, second@example.net\nthird@example.org',
    })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.host).toBe('_smtp._tls.example.com')
      expect(result.value.value).toBe(
        'v=TLSRPTv1; rua=mailto:tls@example.com,mailto:second@example.net,mailto:third@example.org',
      )
    }
  })

  it('requires at least one valid reporting address', () => {
    expect(generateTlsRpt({ domain: 'example.com', reportEmails: '' }).ok).toBe(false)
    expect(generateTlsRpt({ domain: 'example.com', reportEmails: 'invalid' }).ok).toBe(false)
  })
})

describe('Generated DNS owner length', () => {
  const longDomain = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(55)}`
  it('rejects a DMARC name whose prefix exceeds the DNS name limit', () => {
    expect(generateDmarc({ domain: longDomain, policy: 'none', subdomainPolicy: '', aggregateEmails: '', forensicEmails: '', percentage: 100 }).ok).toBe(false)
  })
  it('rejects a TLS report name whose prefix exceeds the DNS name limit', () => {
    expect(generateTlsRpt({ domain: longDomain, reportEmails: 'reports@example.com' }).ok).toBe(false)
  })
  it('rejects an MTA-STS name whose prefix exceeds the DNS name limit', () => {
    expect(generateMtaSts({ domain: longDomain, mode: 'none', mxHosts: '', maxAge: 0, policyId: 'test' }).ok).toBe(false)
  })
  it('rejects a BIMI name whose selector and prefix exceed the DNS name limit', () => {
    expect(generateBimi({ domain: longDomain, selector: 'default', logoUrl: 'https://example.com/logo.svg', certificateUrl: '' }).ok).toBe(false)
  })
})

describe('BIMI generation', () => {
  it('does not let URL semicolons create extra BIMI record tags', () => {
    const result = generateBimi({ domain: 'example.com', selector: 'default', logoUrl: 'https://assets.example.com/logo;a=unexpected.svg', certificateUrl: 'https://assets.example.com/cert;v=other,extra.pem' })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.value).toBe('v=BIMI1; l=https://assets.example.com/logo%3Ba=unexpected.svg; a=https://assets.example.com/cert%3Bv=other%2Cextra.pem')
    }
  })
  it('builds a BIMI record without inventing an RFC claim', () => {
    const result = generateBimi({
      domain: 'example.com',
      selector: 'default',
      logoUrl: 'https://assets.example.com/brand.svg',
      certificateUrl: 'https://assets.example.com/vmc.pem',
    })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.host).toBe('default._bimi.example.com')
      expect(result.value.value).toBe(
        'v=BIMI1; l=https://assets.example.com/brand.svg; a=https://assets.example.com/vmc.pem',
      )
      expect(result.value.zoneFile).not.toMatch(/RFC/i)
    }
  })

  it('requires HTTPS URLs and treats the certificate as optional', () => {
    const insecure = generateBimi({
      domain: 'example.com',
      selector: 'default',
      logoUrl: 'http://example.com/logo.svg',
      certificateUrl: '',
    })
    expect(insecure.ok).toBe(false)

    const withoutCertificate = generateBimi({
      domain: 'example.com',
      selector: 'default',
      logoUrl: 'https://example.com/logo.svg',
      certificateUrl: '',
    })
    expect(withoutCertificate.ok).toBe(true)
    expect(withoutCertificate.warnings.some((warning) => warning.field === 'certificateUrl')).toBe(true)
  })
})
