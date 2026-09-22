import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DomainsPage } from './DomainsPage'

function json(payload: unknown) {
  return new Response(JSON.stringify(payload), { headers: { 'content-type': 'application/json' } })
}

afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('Managed domain incomplete scans', () => {
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
