import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { apiRequest } from '../api/client'
import { SessionProvider } from './SessionProvider'
import { useSession } from './session-context'

const authenticated = { required: true, authenticated: true }
const signedOut = { required: true, authenticated: false }

function json(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } })
}

function SessionProbe() {
  const { session, refresh, signOut } = useSession()
  return <>
    <p>{session?.authenticated ? 'Signed in' : 'Signed out'}</p>
    <button onClick={() => { void refresh().catch(() => undefined) }}>Refresh session</button>
    <button onClick={() => { void signOut().catch(() => undefined) }}>End session</button>
    <button onClick={() => { void apiRequest('/api/protected').catch(() => undefined) }}>Check protected data</button>
  </>
}

function renderSession(seed = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  if (seed) client.setQueryData(['session'], authenticated)
  render(<QueryClientProvider client={client}><SessionProvider><SessionProbe /></SessionProvider></QueryClientProvider>)
  return client
}

afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('Session transition races', () => {
  it.each([{}, { required: false }, { required: 'true', authenticated: false }])('fails closed on invalid session metadata %j', async (payload) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(payload))
    const client = renderSession(false)
    await waitFor(() => expect(client.getQueryState(['session'])?.status).toBe('error'))
    expect(client.getQueryData(['session'])).toBeUndefined()
    expect(screen.getByText('Signed out')).toBeVisible()
  })

  it.each(['End session', 'Check protected data'])('does not let an older read restore authentication after %s', async (action) => {
    let resolveSession!: (response: Response) => void
    const pendingSession = new Promise<Response>((resolve) => { resolveSession = resolve })
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/auth/session')) return pendingSession
      if (url.endsWith('/api/v1/auth/logout')) return json(signedOut)
      if (url.endsWith('/api/protected')) return json({ detail: 'Session expired' }, 401)
      throw new Error(`Unexpected request: ${url}`)
    })
    const user = userEvent.setup()
    const client = renderSession()
    await user.click(screen.getByRole('button', { name: 'Refresh session' }))
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1))
    await user.click(screen.getByRole('button', { name: action }))
    expect(await screen.findByText('Signed out')).toBeVisible()

    await act(async () => { resolveSession(json(authenticated)); await pendingSession })
    await waitFor(() => expect(client.isFetching({ queryKey: ['session'] })).toBe(0))
    expect(screen.getByText('Signed out')).toBeVisible()
    expect(client.getQueryData(['session'])).toMatchObject(signedOut)
  })
})
