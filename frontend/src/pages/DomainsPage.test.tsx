import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DomainsPage } from './DomainsPage'

function json(payload: unknown) {
  return new Response(JSON.stringify(payload), { headers: { 'content-type': 'application/json' } })
}

afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('Managed domain incomplete scans', () => {
  it('locks the submitted domain draft until onboarding finishes, preserving it on failure', async () => {
    let finish!: (value: Response) => void
    const pending = new Promise<Response>((resolve) => { finish = resolve })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      if (options?.method === 'POST') return pending
      if (String(input).startsWith('/api/alerts')) return json({ alerts: [], count: 0 })
      return json({ domains: [], count: 0 })
    })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const user = userEvent.setup()
    render(<QueryClientProvider client={client}><MemoryRouter><DomainsPage /></MemoryRouter></QueryClientProvider>)
    const domain = await screen.findByLabelText('Domain')
    const notes = screen.getByLabelText('Notes (optional)')
    await user.type(domain, 'example.com')
    await user.type(notes, 'Keep this draft')
    await user.click(screen.getByRole('button', { name: 'Add domain' }))
    expect(domain).toBeDisabled()
    expect(notes).toBeDisabled()
    await act(async () => { finish(new Response(JSON.stringify({ detail: 'Try again later' }), { status: 503, headers: { 'content-type': 'application/json' } })); await pending })
    expect(await screen.findByRole('alert')).toHaveTextContent('Try again later')
    expect(domain).toBeEnabled()
    expect(domain).toHaveValue('example.com')
    expect(notes).toHaveValue('Keep this draft')
  })
  it('labels incomplete scans and rescan notices without trusting provisional grades', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).startsWith('/api/rescan/')) return json({ domain: 'example.com', evaluation: { grade: 'A', score: 98 }, scan: { scan_incomplete: true } })
      if (String(input).startsWith('/api/alerts')) return json({ alerts: [], count: 0 })
      return json({ domains: [{ domain: 'example.com', last_grade: 'A', last_score: 98, last_scan_incomplete: true }], count: 1 })
    })
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const user = userEvent.setup()
    render(<QueryClientProvider client={client}><MemoryRouter><DomainsPage /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByText('Incomplete')).toBeVisible()
    expect(screen.queryByText('98')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Rescan' }))
    expect(await screen.findByRole('status')).toHaveTextContent('No grade has been assigned')
    expect(screen.queryByText(/rescanned: grade/)).not.toBeInTheDocument()
  })
})
