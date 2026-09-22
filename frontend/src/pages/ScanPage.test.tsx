import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ScanPage } from './ScanPage'

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function successfulScan(domain: string, saved = true) {
  return {
    status: 'success',
    count: 1,
    results: [{
      domain,
      saved,
      scan: { spf_present: true, dmarc_present: true, mx_present: true },
      evaluation: { grade: 'A', score: 90, severity: 'INFO' },
    }],
  }
}

function renderScanner() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter><ScanPage /></MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('ScanPage completed-result state', () => {
  it('keeps report availability tied to the server-confirmed result', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(successfulScan('example.com')))
    const user = userEvent.setup()
    renderScanner()

    await user.type(screen.getByLabelText('Domain'), 'example.com')
    await user.click(screen.getByRole('button', { name: 'Run security scan' }))
    expect(await screen.findByRole('heading', { name: 'example.com' })).toBeVisible()
    expect(screen.getByRole('link', { name: 'Download PDF' })).toBeVisible()

    await user.click(screen.getByRole('checkbox', { name: /Save to scan history/ }))
    expect(screen.getByRole('link', { name: 'Download PDF' })).toBeVisible()
  })

  it('does not offer a report when the server says persistence was skipped', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(successfulScan('example.com', false)))
    const user = userEvent.setup()
    renderScanner()

    await user.type(screen.getByLabelText('Domain'), 'example.com')
    await user.click(screen.getByRole('button', { name: 'Run security scan' }))
    expect(await screen.findByRole('heading', { name: 'example.com' })).toBeVisible()
    expect(screen.getByRole('checkbox', { name: /Save to scan history/ })).toBeChecked()
    expect(screen.queryByRole('link', { name: 'Download PDF' })).not.toBeInTheDocument()
  })

  it('clears an earlier result before a subsequent request fails', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(successfulScan('example.com')))
      .mockResolvedValueOnce(jsonResponse({ detail: 'Scanner unavailable' }, 503))
    const user = userEvent.setup()
    renderScanner()

    const domain = screen.getByLabelText('Domain')
    await user.type(domain, 'example.com')
    await user.click(screen.getByRole('button', { name: 'Run security scan' }))
    expect(await screen.findByRole('heading', { name: 'example.com' })).toBeVisible()

    await user.clear(domain)
    await user.type(domain, 'example.org')
    await user.click(screen.getByRole('button', { name: 'Run security scan' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Scanner unavailable')
    expect(screen.queryByRole('heading', { name: 'example.com' })).not.toBeInTheDocument()
  })
})
