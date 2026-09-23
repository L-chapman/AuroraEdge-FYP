import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom'
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
        <Link to="/domain/second.example.com">Open second domain</Link>
        <Routes><Route path="/domain/:domain" element={<DomainDetailPage />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('Domain detail route safety', () => {
  it('explains Null MX from saved raw evidence without claiming outgoing authentication is safe', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).startsWith('/api/history/')
      ? response({ domain: 'example.com', count: 0, history: [] })
      : response({ domain: 'example.com', result: { grade: 'B', score: 80, raw_json: JSON.stringify({ null_mx: true }) }, source: 'database' }))
    renderDomain('/domain/example.com')
    expect(await screen.findByText('No incoming mail')).toBeVisible()
    expect(screen.getByRole('status')).toHaveTextContent('Outgoing email authentication still needs review')
    expect(screen.getAllByText('Not applicable')).toHaveLength(2)
  })
  it('reports an incomplete rescan as a warning instead of a successful grade', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).startsWith('/api/rescan/')) return response({ evaluation: { grade: 'A', score: 98 }, scan: { scan_incomplete: true } })
      return String(input).startsWith('/api/history/')
        ? response({ domain: 'example.com', count: 0, history: [] })
        : response({ domain: 'example.com', result: { grade: 'B', score: 80 }, source: 'database' })
    })
    const user = userEvent.setup()
    renderDomain('/domain/example.com')
    await user.click(await screen.findByRole('button', { name: 'Rescan now' }))
    expect(await screen.findByRole('status')).toHaveTextContent('rescan is incomplete')
    expect(screen.queryByText(/Rescan complete: grade/)).not.toBeInTheDocument()
  })

  it('labels an incomplete saved scan and its history without displaying a confident grade', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const result = { grade: 'A', score: 98, scan_incomplete: true, notes: 'DMARC lookup timed out.' }
      return String(input).startsWith('/api/history/')
        ? response({ domain: 'example.com', count: 1, history: [result] })
        : response({ domain: 'example.com', result, source: 'database' })
    })
    renderDomain('/domain/example.com')
    expect(await screen.findByRole('heading', { name: 'example.com' })).toBeVisible()
    expect(screen.getByRole('status')).toHaveTextContent('DMARC lookup timed out.')
    expect(screen.queryAllByText('98')).toHaveLength(0)
    expect(screen.getAllByText('Incomplete').length).toBeGreaterThanOrEqual(2)
  })

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

  it('does not carry a deletion result into a different domain on an in-app route change', async () => {
    Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.open = true } })
    try {
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
        const domain = String(input).includes('second.example.com') ? 'second.example.com' : 'example.com'
        if (options?.method === 'DELETE') return response({ deleted_records: 1 })
        if (String(input).startsWith('/api/history/')) return response({ domain, count: 1, history: [{ grade: 'B', score: 80 }] })
        return response({ domain, result: { grade: 'B', score: 80 }, source: 'database' })
      })
      const user = userEvent.setup()
      renderDomain('/domain/example.com')
      await user.click(await screen.findByRole('button', { name: 'Delete history' }))
      await user.click(screen.getByRole('button', { name: 'Delete scan history' }))
      expect(await screen.findByRole('status')).toHaveTextContent('1 historical record deleted')

      await user.click(screen.getByRole('link', { name: 'Open second domain' }))
      expect(await screen.findByRole('heading', { name: 'second.example.com' })).toBeVisible()
      expect(screen.queryByText(/historical record deleted/)).not.toBeInTheDocument()
      expect(await screen.findByRole('heading', { name: 'Email authentication coverage' })).toBeVisible()
    } finally {
      Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
    }
  })
})
