import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { GeneratorPage } from './GeneratorPage'

function namedSection(name: string): HTMLElement {
  return screen.getByRole('region', { name })
}

describe('GeneratorPage', () => {
  afterEach(cleanup)

  beforeEach(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    })
  })

  it('renders every generator with accessible labels and no BIMI RFC claim', () => {
    render(<GeneratorPage />)

    expect(screen.getByRole('heading', { level: 1, name: 'DNS record generator' })).toBeInTheDocument()
    expect(namedSection('SPF record')).toBeInTheDocument()
    expect(namedSection('DMARC record')).toBeInTheDocument()
    expect(namedSection('MTA-STS policy')).toBeInTheDocument()
    expect(namedSection('TLS-RPT record')).toBeInTheDocument()
    expect(namedSection('BIMI record')).toBeInTheDocument()
    expect(screen.queryByText(/RFC 9495/i)).not.toBeInTheDocument()
    expect(within(namedSection('BIMI record')).getByLabelText('SVG logo HTTPS URL')).toBeInTheDocument()
  })

  it('updates SPF output with correctly classified IPv4 and IPv6 CIDR mechanisms', async () => {
    const user = userEvent.setup()
    render(<GeneratorPage />)
    const section = namedSection('SPF record')
    const addresses = within(section).getByLabelText('IPv4 or IPv6 addresses and CIDR ranges')

    await user.type(addresses, '198.51.100.0/24{enter}2001:db8::/32')

    expect(within(section).getByLabelText('DNS TXT record')).toHaveTextContent('ip4:198.51.100.0/24')
    expect(within(section).getByLabelText('DNS TXT record')).toHaveTextContent('ip6:2001:db8::/32')
  })

  it('keeps a DMARC percentage of zero in the generated output', async () => {
    const user = userEvent.setup()
    render(<GeneratorPage />)
    const section = namedSection('DMARC record')
    const percentage = within(section).getByLabelText('Policy percentage')

    await user.clear(percentage)
    await user.type(percentage, '0')

    expect(within(section).getByLabelText('DNS TXT record')).toHaveTextContent('pct=0')
  })

  it('renders each MTA-STS MX host on its own policy line', async () => {
    const user = userEvent.setup()
    render(<GeneratorPage />)
    const section = namedSection('MTA-STS policy')
    const hosts = within(section).getByLabelText('MX hosts, one per line')

    await user.clear(hosts)
    await user.type(hosts, 'mx1.example.com{enter}mx2.example.com')

    const policy = within(section).getByLabelText('MTA-STS policy file')
    expect(policy).toHaveTextContent('mx: mx1.example.com')
    expect(policy).toHaveTextContent('mx: mx2.example.com')
  })

  it('allows clearing and correcting MTA-STS max age without an invalid React value', async () => {
    const user = userEvent.setup()
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    try {
      render(<GeneratorPage />)
      const section = namedSection('MTA-STS policy')
      const maxAge = within(section).getByLabelText('Max age in seconds')
      await user.clear(maxAge)
      expect(within(section).getByRole('alert')).toHaveTextContent('Max age must be a whole number')
      expect(consoleError).not.toHaveBeenCalled()
      await user.type(maxAge, '0')
      expect(within(section).getByLabelText('MTA-STS policy file')).toHaveTextContent('max_age: 0')
    } finally { consoleError.mockRestore() }
  })

  it('does not claim changed output has already been copied', async () => {
    const user = userEvent.setup()
    render(<GeneratorPage />)
    const section = namedSection('TLS-RPT record')
    await user.click(within(section).getByRole('button', { name: 'Copy dns txt record' }))
    expect(within(section).getByRole('status')).toHaveTextContent('Copied to clipboard.')
    await user.type(within(section).getByLabelText('Domain'), '.au')
    expect(within(section).getByRole('status')).not.toHaveTextContent('Copied to clipboard.')
  })

  it('copies an output using a native keyboard-operable button and announces success', async () => {
    const user = userEvent.setup()
    const writeText = vi.spyOn(navigator.clipboard, 'writeText')
    render(<GeneratorPage />)
    const section = namedSection('TLS-RPT record')
    const copyButton = within(section).getByRole('button', { name: 'Copy dns txt record' })

    copyButton.focus()
    await user.keyboard('{Enter}')

    expect(writeText).toHaveBeenCalledWith(
      '_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"',
    )
    expect(within(section).getByRole('status')).toHaveTextContent('Copied to clipboard.')
  })

  it('renders user input as text instead of executable markup', async () => {
    const user = userEvent.setup()
    render(<GeneratorPage />)
    const section = namedSection('BIMI record')
    const logo = within(section).getByLabelText('SVG logo HTTPS URL')

    await user.clear(logo)
    await user.type(logo, '<img src=x onerror=alert(1)>')

    expect(document.querySelector('img')).toBeNull()
    expect(within(section).getByRole('alert')).toHaveTextContent('Logo URL must be a valid HTTPS URL.')
  })
})
