import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { DashboardPayload } from '../api/types'
import { DashboardPage } from './DashboardPage'

function payload(overrides: Partial<DashboardPayload> = {}): DashboardPayload {
  return { stats: { total_scans: 0, total_results: 0, average_score: 0, alert_count: 0, grade_distribution: {} }, domains: [], alerts: [], settings: { monitoring_enabled: false }, ...overrides }
}

function response(data: DashboardPayload) {
  return new Response(JSON.stringify(data), { status: 200, headers: { 'content-type': 'application/json' } })
}

function renderDashboard() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><MemoryRouter><DashboardPage /></MemoryRouter></QueryClientProvider>)
}

afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('Dashboard overview', () => {
  it('distinguishes incomplete checks from unscanned domains without showing a provisional score', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(payload({ stats: { average_score: 98 }, domains: [{ domain: 'example.com', last_scan_incomplete: true, last_grade: 'A', last_score: 98 }] })))
    renderDashboard()
    expect(await screen.findByText('Incomplete')).toBeVisible()
    expect(screen.queryAllByText('98')).toHaveLength(0)
    expect(within(screen.getByText('Average score').closest('section')!).getByText('—')).toBeVisible()
  })

  it('does not invent a score or an active monitoring state for an empty workspace', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(payload()))
    renderDashboard()
    expect(await screen.findByRole('heading', { name: 'Email security, at a glance' })).toBeVisible()
    expect(screen.getByText('Scheduled monitoring is paused')).toBeVisible()
    expect(screen.getByText('No managed domains yet')).toBeVisible()
    const metric = screen.getByText('Average score').closest('section')!
    expect(within(metric).getByText('—')).toBeVisible()
    expect(screen.getByText(/No unacknowledged changes in your saved alerts/)).toBeVisible()
  })

  it('shows saved results and gives each domain a distinct accessible link', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(payload({
      stats: { average_score: 78, grade_distribution: { B: 1 } },
      domains: [{ domain: 'example.com', last_grade: 'B', last_score: 78 }],
      settings: { monitoring_enabled: true },
    })))
    renderDashboard()
    expect(await screen.findByText('Scheduled monitoring is on')).toBeVisible()
    expect(screen.getByRole('link', { name: 'View example.com' })).toHaveAttribute('href', '/domain/example.com')
    expect(screen.getByRole('progressbar', { name: 'B: 1 domains' })).toHaveAttribute('value', '1')
  })

  it('refreshes saved data without starting a new domain scan', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(response(payload()))
      .mockResolvedValueOnce(response(payload({ settings: { monitoring_enabled: true } })))
    const user = userEvent.setup()
    renderDashboard()
    await screen.findByText('Scheduled monitoring is paused')
    await user.click(screen.getByRole('button', { name: 'Refresh overview' }))
    expect(await screen.findByText('Scheduled monitoring is on')).toBeVisible()
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(fetch.mock.calls.every(([path, options]) => path === '/api/v1/dashboard' && options?.method === 'GET')).toBe(true)
  })
})
