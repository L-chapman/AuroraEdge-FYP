import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DomainDetailPage } from './DomainDetailPage'

function response(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } })
}

function renderDomain(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes><Route path="/domain/:domain" element={<DomainDetailPage />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('Domain detail route safety', () => {
  it.each([
    ['/domain/example.com', 'example.com', 'example.com'],
    ['/domain/not%25valid.example', 'not%valid.example', 'not%25valid.example'],
  ])('handles %s without decoding twice or starting a scan', async (path, displayDomain, encodedDomain) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).startsWith('/api/history/')
        ? response({ domain: displayDomain, history: [], count: 0 })
        : response({ detail: 'No saved result' }, 404),
    )
    renderDomain(path)
    expect(await screen.findByRole('heading', { name: displayDomain })).toBeVisible()
    expect(screen.getByRole('heading', { name: 'No saved result' })).toBeVisible()
    expect(fetch.mock.calls.map(([url]) => url)).toContain(`/api/domain/${encodedDomain}`)
    expect(fetch.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true)
  })

  it('reports a failed history request instead of presenting an empty history, and can retry', async () => {
    let historyCalls = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).startsWith('/api/history/')) {
        historyCalls += 1
        return historyCalls === 1
          ? response({ detail: 'History unavailable' }, 503)
          : response({ domain: 'example.com', history: [], count: 0 })
      }
      return response({ domain: 'example.com', result: { score: 80, grade: 'B' }, source: 'database' })
    })
    const user = userEvent.setup()
    renderDomain('/domain/example.com')
    expect(await screen.findByRole('heading', { name: 'Unavailable' })).toBeVisible()
    expect(screen.getByRole('status')).toHaveTextContent('Scan history could not be loaded')
    expect(screen.queryByText('No historical scans are available.')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry history' }))
    expect(await screen.findByRole('heading', { name: '0 scans' })).toBeVisible()
    expect(screen.getByText('No historical scans are available.')).toBeVisible()
    expect(historyCalls).toBe(2)
  })
})
