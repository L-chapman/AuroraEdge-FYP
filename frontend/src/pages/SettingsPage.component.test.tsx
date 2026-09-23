import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SettingsPage } from './SettingsPage'

const settings = {
  org_name: 'NorthFlux Operator',
  alert_email: '',
  monitor_interval: '24',
  monitoring_enabled: 'false',
  automatic_remediation: 'false',
  cf_zone_id: 'zone-one',
  cf_account_id: 'account-one',
  cf_api_token_configured: true,
}

const bootstrap = {
  product: { name: 'NorthFlux Security', version: '4.0.0' },
  auth: { required: true, authenticated: true, expires_at: null },
  runtime: { production: false, demo_mode: false },
  capabilities: { scanner: true, database: true, dns_fix: true, pdf: true },
  operator: { org_name: 'NorthFlux Operator' },
}

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function renderSettings() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(<QueryClientProvider client={client}><SettingsPage /></QueryClientProvider>)
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('SettingsPage runtime safety', () => {
  it('fails closed when runtime security metadata cannot be loaded', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/api/settings')) return jsonResponse({ settings })
      if (url.endsWith('/api/v1/bootstrap')) return jsonResponse({ detail: 'Unavailable' }, 503)
      throw new Error(`Unexpected request: ${url}`)
    })

    renderSettings()

    expect(await screen.findByRole('alert')).toHaveTextContent('runtime security mode could not be loaded safely')
    expect(screen.queryByLabelText('API token')).not.toBeInTheDocument()
  })

  it('clears a prior connection verdict after saving changed Cloudflare settings', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      if (url.endsWith('/api/settings/test-cloudflare')) return jsonResponse({ ok: true, message: 'Zone read access confirmed.', permissions: { zone_read: true, dns_read: true, dns_edit: null } })
      if (url.endsWith('/api/settings') && method === 'POST') return jsonResponse({ ok: true, saved: ['cf_zone_id'] })
      if (url.endsWith('/api/settings')) return jsonResponse({ settings })
      if (url.endsWith('/api/v1/bootstrap')) return jsonResponse(bootstrap)
      throw new Error(`Unexpected request: ${method} ${url}`)
    })
    const user = userEvent.setup()
    renderSettings()

    await user.click(await screen.findByRole('button', { name: 'Check saved read access' }))
    expect(await screen.findByText('Read check completed.')).toBeVisible()
    expect(screen.getByText(/does not change DNS or verify write permission/)).toBeVisible()

    const zone = screen.getByLabelText('Zone ID')
    await user.clear(zone)
    await user.type(zone, 'zone-two')
    await user.click(screen.getByRole('button', { name: 'Save settings' }))

    await waitFor(() => expect(screen.queryByText('Read check completed.')).not.toBeInTheDocument())
    expect(await screen.findByText(/Saved 1 setting/)).toBeVisible()
  })

  it.each(['true', 'false'])('preserves legacy settings while explaining available capabilities (old preference: %s)', async (automaticRemediation) => {
    const legacyEmail = 'legacy contact value, not a valid email'
    let savedSettings: Record<string, string | boolean | number> = {
      ...settings,
      automatic_remediation: automaticRemediation,
      alert_email: legacyEmail,
    }
    const submissions: Array<Record<string, string>> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      if (url.endsWith('/api/settings') && method === 'POST') {
        const body = JSON.parse(String(init?.body)) as Record<string, string>
        submissions.push(body)
        savedSettings = { ...savedSettings, ...body }
        return jsonResponse({ ok: true, saved: Object.keys(body) })
      }
      if (url.endsWith('/api/settings')) return jsonResponse({ settings: savedSettings })
      if (url.endsWith('/api/v1/bootstrap')) return jsonResponse(bootstrap)
      throw new Error(`Unexpected request: ${method} ${url}`)
    })
    const user = userEvent.setup()
    renderSettings()

    const name = await screen.findByLabelText('Organisation name')
    expect(screen.getByRole('heading', { name: 'In-app alerts' })).toBeVisible()
    expect(screen.getByText(/Email and webhook delivery are not available/)).toBeVisible()
    expect(screen.getByText(/Generated recommendations do not change DNS/)).toBeVisible()
    expect(screen.getByText(/saved automatic-remediation preference is retained/)).toBeVisible()
    expect(screen.queryByRole('checkbox', { name: /Automatic remediation/i })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Alert email')).not.toBeInTheDocument()
    expect(screen.queryByText(legacyEmail)).not.toBeInTheDocument()

    await user.clear(name)
    await user.type(name, 'Updated organisation')
    await user.click(screen.getByRole('checkbox', { name: /Scheduled scanning/ }))
    await user.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText(/Saved 5 settings/)).toBeVisible()
    expect(submissions).toHaveLength(1)
    expect(submissions[0]).not.toHaveProperty('automatic_remediation')
    expect(submissions[0]).not.toHaveProperty('alert_email')
    expect(savedSettings).toMatchObject({
      org_name: 'Updated organisation',
      monitoring_enabled: 'true',
      automatic_remediation: automaticRemediation,
      alert_email: legacyEmail,
    })
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled()
  })
})
