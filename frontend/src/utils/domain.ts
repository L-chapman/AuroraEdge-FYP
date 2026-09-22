const domainPattern = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i

export function normaliseDomain(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/^(?:https?|ftp):\/\//, '')
    .split(/[/?#]/, 1)[0] ?? ''
}

export function validateDomain(value: string): string | null {
  const domain = normaliseDomain(value)
  if (!domain) return 'Enter a domain name.'
  if (!domainPattern.test(domain)) return 'Enter a valid domain such as example.com.'
  if (domain.split('.').every((part) => /^\d+$/.test(part))) {
    return 'IP addresses are not supported; enter a domain name.'
  }
  return null
}

export function parseDomainList(value: string): { domains: string[]; errors: string[] } {
  const inputs = value
    .split(/[\n,;]+/)
    .map(normaliseDomain)
    .filter(Boolean)
  const domains = [...new Set(inputs)]
  const errors = domains.flatMap((domain) => {
    const error = validateDomain(domain)
    return error ? [`${domain}: ${error}`] : []
  })
  if (domains.length > 20) errors.push('A batch can contain no more than 20 unique domains.')
  return { domains, errors }
}
