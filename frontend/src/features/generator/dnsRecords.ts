export type SpfPolicy = '-all' | '~all' | '?all'
export type DmarcPolicy = 'none' | 'quarantine' | 'reject'
export type MtaStsMode = 'none' | 'testing' | 'enforce'

export interface FieldIssue {
  field: string
  message: string
}

export type GenerationResult<T> =
  | { ok: true; value: T; errors: []; warnings: FieldIssue[] }
  | { ok: false; value: null; errors: FieldIssue[]; warnings: FieldIssue[] }

export interface TxtRecord {
  host: string
  type: 'TXT'
  value: string
  zoneFile: string
}

export interface SpfInput {
  domain: string
  includes: string
  ipAddresses: string
  policy: SpfPolicy
}

export interface DmarcInput {
  domain: string
  policy: DmarcPolicy
  subdomainPolicy: DmarcPolicy | ''
  aggregateEmails: string
  forensicEmails: string
  percentage: number
}

export interface MtaStsInput {
  domain: string
  mode: MtaStsMode
  mxHosts: string
  maxAge: number
  policyId: string
}

export interface MtaStsOutput {
  dnsRecord: TxtRecord
  policyHost: string
  policyUrl: string
  policyFile: string
}

export interface TlsRptInput {
  domain: string
  reportEmails: string
}

export interface BimiInput {
  domain: string
  selector: string
  logoUrl: string
  certificateUrl: string
}

function success<T>(value: T, warnings: FieldIssue[] = []): GenerationResult<T> {
  return { ok: true, value, errors: [], warnings }
}

function failure<T>(errors: FieldIssue[], warnings: FieldIssue[] = []): GenerationResult<T> {
  return { ok: false, value: null, errors, warnings }
}

function splitCommaOrLineList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function splitLines(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function trimTrailingDot(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, '')
}

export function isDomainName(value: string, allowUnderscore = false): boolean {
  const domain = trimTrailingDot(value)
  if (!domain || domain.length > 253 || !domain.includes('.')) return false

  return domain.split('.').every((label) => {
    if (!label || label.length > 63) return false
    const pattern = allowUnderscore
      ? /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/i
      : /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i
    return pattern.test(label)
  })
}

function normaliseDomain(value: string): string {
  return trimTrailingDot(value)
}

function isIPv4Address(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false
    if (part.length > 1 && part.startsWith('0')) return false
    const number = Number(part)
    return number >= 0 && number <= 255
  })
}

function isIPv6Address(value: string): boolean {
  if (!value.includes(':') || value.includes('%')) return false
  if ((value.match(/::/g) ?? []).length > 1) return false

  const [left = '', right = ''] = value.split('::')
  const leftParts = left ? left.split(':') : []
  const rightParts = right ? right.split(':') : []
  const allParts = [...leftParts, ...rightParts]

  if (allParts.some((part) => !/^[0-9a-f]{1,4}$/i.test(part))) return false
  if (value.includes('::')) return allParts.length < 8
  return allParts.length === 8
}

export type IpMechanism = `ip4:${string}` | `ip6:${string}`

export function classifySpfIp(value: string): GenerationResult<IpMechanism> {
  const candidate = value.trim()
  const slashIndex = candidate.indexOf('/')
  const address = slashIndex === -1 ? candidate : candidate.slice(0, slashIndex)
  const prefixText = slashIndex === -1 ? '' : candidate.slice(slashIndex + 1)

  if (!address || (slashIndex !== -1 && !/^\d+$/.test(prefixText))) {
    return failure([{ field: 'ipAddresses', message: `Invalid IP address or CIDR: ${candidate}` }])
  }

  if (isIPv4Address(address)) {
    if (slashIndex !== -1 && Number(prefixText) > 32) {
      return failure([{ field: 'ipAddresses', message: `IPv4 prefix must be between 0 and 32: ${candidate}` }])
    }
    return success<IpMechanism>(`ip4:${candidate}`)
  }

  if (isIPv6Address(address)) {
    if (slashIndex !== -1 && Number(prefixText) > 128) {
      return failure([{ field: 'ipAddresses', message: `IPv6 prefix must be between 0 and 128: ${candidate}` }])
    }
    return success<IpMechanism>(`ip6:${candidate}`)
  }

  return failure([{ field: 'ipAddresses', message: `Invalid IP address or CIDR: ${candidate}` }])
}

function txtRecord(host: string, value: string): TxtRecord {
  // RFC 1035 sections 3.3/3.3.14: one TXT record may contain multiple
  // character-strings, each limited to 255 data octets. Joining them must
  // preserve the exact value, including spaces at chunk boundaries.
  const chunks: string[] = ['']
  const encoder = new TextEncoder()
  let octets = 0
  for (const character of value) {
    const size = encoder.encode(character).length
    if (octets + size > 255) { chunks.push(''); octets = 0 }
    chunks[chunks.length - 1] += character
    octets += size
  }
  const quoted = chunks.map((chunk) => `"${chunk.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`).join(' ')
  return {
    host,
    type: 'TXT',
    value,
    zoneFile: `${host}. IN TXT ${quoted}`,
  }
}

export function generateSpf(input: SpfInput): GenerationResult<TxtRecord> {
  const errors: FieldIssue[] = []
  const domain = normaliseDomain(input.domain)
  if (!isDomainName(domain)) {
    errors.push({ field: 'domain', message: 'Enter a valid domain name.' })
  }

  const includes = splitCommaOrLineList(input.includes).map(normaliseDomain)
  for (const include of includes) {
    if (!isDomainName(include, true)) {
      errors.push({ field: 'includes', message: `Invalid SPF include domain: ${include}` })
    }
  }

  const ipMechanisms: IpMechanism[] = []
  for (const candidate of splitCommaOrLineList(input.ipAddresses)) {
    const classified = classifySpfIp(candidate)
    if (classified.ok) ipMechanisms.push(classified.value)
    else errors.push(...classified.errors)
  }

  if (errors.length) return failure(errors)
  const mechanisms = [
    'v=spf1',
    ...ipMechanisms,
    ...includes.map((include) => `include:${include}`),
    input.policy,
  ]
  return success(txtRecord(domain, mechanisms.join(' ')))
}

function isEmail(value: string): boolean {
  if (value.length > 254 || /\s/.test(value)) return false
  const at = value.lastIndexOf('@')
  if (at <= 0 || at === value.length - 1) return false
  const local = value.slice(0, at)
  if (local.length > 64 || local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false
  if (!/^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(local)) return false
  return isDomainName(value.slice(at + 1))
}

function reportUri(email: string): string {
  const at = email.lastIndexOf('@')
  // RFC 6068: address characters such as ?, # and % are URI data, not
  // delimiters. Encode ! too because DMARC uses it for a report-size suffix.
  const local = encodeURIComponent(email.slice(0, at)).replaceAll('!', '%21')
  return `mailto:${local}@${normaliseDomain(email.slice(at + 1))}`
}

function parseEmails(value: string, field: string, errors: FieldIssue[]): string[] {
  const emails: string[] = []
  for (const input of splitCommaOrLineList(value)) {
    let email = input
    if (/^mailto:/i.test(input)) {
      const address = input.slice(7)
      if (/[?#]/.test(address)) {
        errors.push({ field, message: `Use a plain email address or a correctly encoded mailto URI: ${input}` })
        continue
      }
      try { email = decodeURIComponent(address) } catch {
        errors.push({ field, message: `Invalid mailto URI encoding: ${input}` })
        continue
      }
    }
    if (!isEmail(email)) errors.push({ field, message: `Invalid email address: ${email}` })
    emails.push(email)
  }
  return emails
}

export function generateDmarc(input: DmarcInput): GenerationResult<TxtRecord> {
  const errors: FieldIssue[] = []
  const warnings: FieldIssue[] = []
  const domain = normaliseDomain(input.domain)
  if (!isDomainName(domain)) errors.push({ field: 'domain', message: 'Enter a valid domain name.' })
  if (`_dmarc.${domain}`.length > 253) errors.push({ field: 'domain', message: 'The full DMARC record name would exceed the DNS name limit.' })
  if (!Number.isInteger(input.percentage) || input.percentage < 0 || input.percentage > 100) {
    errors.push({ field: 'percentage', message: 'Percentage must be a whole number from 0 to 100.' })
  }

  const aggregateEmails = parseEmails(input.aggregateEmails, 'aggregateEmails', errors)
  const forensicEmails = parseEmails(input.forensicEmails, 'forensicEmails', errors)
  if (input.policy === 'none') {
    warnings.push({ field: 'policy', message: 'A none policy monitors mail but does not enforce protection.' })
  }
  if (input.percentage < 100) {
    warnings.push({ field: 'percentage', message: 'This policy will apply to only part of the message stream.' })
  }
  if (errors.length) return failure(errors, warnings)

  const tags = ['v=DMARC1', `p=${input.policy}`]
  if (input.subdomainPolicy) tags.push(`sp=${input.subdomainPolicy}`)
  if (input.percentage < 100) tags.push(`pct=${input.percentage}`)
  if (aggregateEmails.length) tags.push(`rua=${aggregateEmails.map(reportUri).join(',')}`)
  if (forensicEmails.length) tags.push(`ruf=${forensicEmails.map(reportUri).join(',')}`)
  return success(txtRecord(`_dmarc.${domain}`, tags.join('; ')), warnings)
}

function isMxPattern(value: string): boolean {
  const candidate = trimTrailingDot(value)
  if (candidate.startsWith('*.')) return isDomainName(candidate.slice(2))
  return isDomainName(candidate)
}

export function defaultMtaStsPolicyId(date = new Date()): string {
  return date.toISOString().slice(0, 10).replaceAll('-', '')
}

export function generateMtaSts(input: MtaStsInput): GenerationResult<MtaStsOutput> {
  const errors: FieldIssue[] = []
  const warnings: FieldIssue[] = []
  const domain = normaliseDomain(input.domain)
  if (!isDomainName(domain)) errors.push({ field: 'domain', message: 'Enter a valid domain name.' })
  if (`_mta-sts.${domain}`.length > 253) errors.push({ field: 'domain', message: 'The full MTA-STS record name would exceed the DNS name limit.' })

  const mxHosts = splitLines(input.mxHosts).map(normaliseDomain)
  if (input.mode !== 'none' && mxHosts.length === 0) {
    errors.push({ field: 'mxHosts', message: 'Add at least one MX host for testing or enforce mode.' })
  }
  for (const host of mxHosts) {
    if (!isMxPattern(host)) errors.push({ field: 'mxHosts', message: `Invalid MX host: ${host}` })
  }
  if (!Number.isInteger(input.maxAge) || input.maxAge < 0 || input.maxAge > 31_557_600) {
    errors.push({ field: 'maxAge', message: 'Max age must be a whole number from 0 to 31557600.' })
  }
  if (!/^[A-Za-z0-9]{1,32}$/.test(input.policyId.trim())) {
    errors.push({ field: 'policyId', message: 'Policy ID must use 1-32 letters or numbers.' })
  }
  if (input.mode === 'none') {
    warnings.push({ field: 'mode', message: 'None mode disables MTA-STS enforcement.' })
  }
  if (errors.length) return failure(errors, warnings)

  const policyLines = [
    'version: STSv1',
    `mode: ${input.mode}`,
    ...mxHosts.map((host) => `mx: ${host}`),
    `max_age: ${input.maxAge}`,
  ]
  const policyHost = `mta-sts.${domain}`
  return success(
    {
      dnsRecord: txtRecord(`_mta-sts.${domain}`, `v=STSv1; id=${input.policyId.trim()}`),
      policyHost,
      policyUrl: `https://${policyHost}/.well-known/mta-sts.txt`,
      policyFile: policyLines.join('\n'),
    },
    warnings,
  )
}

export function generateTlsRpt(input: TlsRptInput): GenerationResult<TxtRecord> {
  const errors: FieldIssue[] = []
  const domain = normaliseDomain(input.domain)
  if (!isDomainName(domain)) errors.push({ field: 'domain', message: 'Enter a valid domain name.' })
  if (`_smtp._tls.${domain}`.length > 253) errors.push({ field: 'domain', message: 'The full TLS-RPT record name would exceed the DNS name limit.' })
  const emails = parseEmails(input.reportEmails, 'reportEmails', errors)
  if (emails.length === 0) {
    errors.push({ field: 'reportEmails', message: 'Add at least one TLS report email address.' })
  }
  if (errors.length) return failure(errors)
  const destinations = emails.map(reportUri).join(',')
  return success(txtRecord(`_smtp._tls.${domain}`, `v=TLSRPTv1; rua=${destinations}`))
}

function normaliseHttpsUrl(value: string): string | null {
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) return null
    return url.href
  } catch {
    return null
  }
}

export function generateBimi(input: BimiInput): GenerationResult<TxtRecord> {
  const errors: FieldIssue[] = []
  const warnings: FieldIssue[] = []
  const domain = normaliseDomain(input.domain)
  const selector = input.selector.trim().toLowerCase()
  const logoUrl = normaliseHttpsUrl(input.logoUrl.trim())
  const certificateUrl = input.certificateUrl.trim()
    ? normaliseHttpsUrl(input.certificateUrl.trim())
    : ''
  if (!isDomainName(domain)) errors.push({ field: 'domain', message: 'Enter a valid domain name.' })
  if (`${selector}._bimi.${domain}`.length > 253) errors.push({ field: 'domain', message: 'The selector and domain would exceed the DNS name limit.' })
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(selector)) {
    errors.push({ field: 'selector', message: 'Enter a valid BIMI selector.' })
  }
  if (!logoUrl) {
    errors.push({ field: 'logoUrl', message: 'Logo URL must be a valid HTTPS URL.' })
  }
  if (input.certificateUrl.trim() && !certificateUrl) {
    errors.push({ field: 'certificateUrl', message: 'Certificate URL must be a valid HTTPS URL.' })
  }
  if (!input.certificateUrl.trim()) {
    warnings.push({ field: 'certificateUrl', message: 'Some mailbox providers require a mark certificate.' })
  }
  if (errors.length) return failure(errors, warnings)

  const tags = ['v=BIMI1', `l=${logoUrl ?? ''}`]
  if (certificateUrl) tags.push(`a=${certificateUrl}`)
  return success(txtRecord(`${selector}._bimi.${domain}`, tags.join('; ')), warnings)
}
