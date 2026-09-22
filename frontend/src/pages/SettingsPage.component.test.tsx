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
      if (url.endsWith('/api/settings/test-cloudflare')) return jsonResponse({ ok: true, message: 'Ready' })
      if (url.endsWith('/api/settings') && method === 'POST') return jsonResponse({ ok: true, saved: ['cf_zone_id'] })
      if (url.endsWith('/api/settings')) return jsonResponse({ settings })
      if (url.endsWith('/api/v1/bootstrap')) return jsonResponse(bootstrap)
      throw new Error(`Unexpected request: ${method} ${url}`)
    })
    const user = userEvent.setup()
    renderSettings()

    await user.click(await screen.findByRole('button', { name: 'Test saved connection' }))
    expect(await screen.findByText('Connection verified.')).toBeVisible()

    const zone = screen.getByLabelText('Zone ID')
    await user.clear(zone)
    await user.type(zone, 'zone-two')
    await user.click(screen.getByRole('button', { name: 'Save settings' }))

    await waitFor(() => expect(screen.queryByText('Connection verified.')).not.toBeInTheDocument())
    expect(await screen.findByText(/Saved 1 setting/)).toBeVisible()
  })
})
