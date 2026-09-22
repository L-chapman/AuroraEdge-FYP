import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Profiler } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SettingsPage } from './SettingsPage'

const settings = {
  org_name: 'Saved organisation', alert_email: '', monitor_interval: '24',
  monitoring_enabled: false, automatic_remediation: false,
  cf_zone_id: 'saved-zone', cf_account_id: '', cf_api_token_configured: false,
}
const bootstrap = { runtime: { production: false } }

function json(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } })
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((complete) => { resolve = complete })
  return { promise, resolve }
}

function renderSettings(onCommit: () => void = () => undefined) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={client}><Profiler id="settings" onRender={onCommit}><SettingsPage /></Profiler></QueryClientProvider>)
  return client
}

afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('Settings editor hydration and draft ownership', () => {
  it('shows saved values on the very first input commit, after both delayed responses arrive', async () => {
    const pendingSettings = deferred<Response>()
    const pendingBootstrap = deferred<Response>()
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => String(input).endsWith('/api/settings') ? pendingSettings.promise : pendingBootstrap.promise)
    const committedValues: string[] = []
    renderSettings(() => {
      const input = document.querySelector<HTMLInputElement>('#org-name')
      if (input) committedValues.push(input.value)
    })
    expect(screen.queryByLabelText('Organisation name')).not.toBeInTheDocument()
    await act(async () => { pendingSettings.resolve(json({ settings })); await pendingSettings.promise })
    expect(screen.queryByLabelText('Organisation name')).not.toBeInTheDocument()
    await act(async () => { pendingBootstrap.resolve(json(bootstrap)); await pendingBootstrap.promise })
    expect(await screen.findByLabelText('Organisation name')).toHaveValue('Saved organisation')
    expect(committedValues.length).toBeGreaterThan(0)
    expect(committedValues[0]).toBe('Saved organisation')
  })

  it('preserves the draft, write-only token and text selection across a background refresh', async () => {
    let settingsReads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).endsWith('/api/settings')) {
        settingsReads += 1
        return json({ settings: { ...settings, org_name: settingsReads === 1 ? settings.org_name : 'Changed on server' } })
      }
      return json(bootstrap)
    })
    const user = userEvent.setup()
    const client = renderSettings()
    const name = await screen.findByLabelText<HTMLInputElement>('Organisation name')
    await user.clear(name)
    await user.type(name, 'My unsaved organisation')
    await user.type(screen.getByLabelText('API token'), 'test-only-draft-token')
    name.focus()
    name.setSelectionRange(3, 10)

    await act(async () => { await client.invalidateQueries({ queryKey: ['settings'] }) })
    expect(settingsReads).toBe(2)
    expect(name).toHaveValue('My unsaved organisation')
    expect(screen.getByLabelText('API token')).toHaveValue('test-only-draft-token')
    expect(name.selectionStart).toBe(3)
    expect(name.selectionEnd).toBe(10)
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeEnabled()
  })

  it('preserves a draft through a failed refresh and safely resumes after retry', async () => {
    let settingsReads = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).endsWith('/api/settings')) {
        settingsReads += 1
        return settingsReads === 2 ? json({ detail: 'Unavailable' }, 503) : json({ settings })
      }
      return json(bootstrap)
    })
    const user = userEvent.setup()
    const client = renderSettings()
    const name = await screen.findByLabelText('Organisation name')
    await user.clear(name)
    await user.type(name, 'Keep this draft')
    await act(async () => { await client.invalidateQueries({ queryKey: ['settings'] }) })
    expect(await screen.findByText(/Your draft is preserved/)).toBeVisible()
    expect(name).toHaveValue('Keep this draft')
    expect(name).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Clear all scan data' })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Retry settings' }))
    await waitFor(() => expect(name).toBeEnabled())
    expect(name).toHaveValue('Keep this draft')
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeEnabled()
  })

  it('locks editing during save and uses only the confirmed submission as its new baseline', async () => {
    const saved = deferred<Response>()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      if (String(input).endsWith('/api/settings')) return options?.method === 'POST' ? saved.promise : json({ settings })
      return json(bootstrap)
    })
    const user = userEvent.setup()
    renderSettings()
    const name = await screen.findByLabelText('Organisation name')
    await user.clear(name)
    await user.type(name, 'Confirmed organisation')
    await user.type(screen.getByLabelText('API token'), 'test-only-submitted-token')
    await user.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(name).toBeDisabled()
    expect(screen.getByLabelText('API token')).toBeDisabled()

    await act(async () => { saved.resolve(json({ ok: true, saved: ['org_name', 'cf_api_token'] })); await saved.promise })
    await waitFor(() => expect(name).toBeEnabled())
    // The mock's subsequent GET deliberately returns its old value. It must not
    // overwrite the successfully submitted name or repopulate a write-only token.
    expect(name).toHaveValue('Confirmed organisation')
    expect(screen.getByLabelText('API token')).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled()
    expect(screen.getByText('No unsaved edits')).toBeVisible()
  })
})
