import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
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

const originalShowModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'showModal')
beforeEach(() => {
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value: function (this: HTMLDialogElement) { this.open = true } })
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  if (originalShowModal) Object.defineProperty(HTMLDialogElement.prototype, 'showModal', originalShowModal)
  else Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
})

describe('ScanPage completed-result state', () => {
  it('separates managed-domain enrolment from scheduled scanning and DNS changes', () => {
    renderScanner()
    expect(screen.getByRole('checkbox', { name: /Add to managed domains/ })).not.toBeChecked()
    expect(screen.getByText(/Scheduled scanning must be enabled separately in Settings/)).toBeVisible()
    expect(screen.getByText(/All recommendations require manual review; a scan does not change DNS/)).toBeVisible()
    expect(screen.queryByRole('checkbox', { name: /continuous monitoring/i })).not.toBeInTheDocument()
  })

  it('distinguishes intentional Null MX from a broken inbound-mail configuration', async () => {
    const payload = successfulScan('example.com')
    Object.assign(payload.results[0]!.scan, { null_mx: true, mx_present: false, spf_present: false })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(payload))
    const user = userEvent.setup()
    renderScanner()
    await user.type(screen.getByLabelText('Domain'), 'example.com')
    await user.click(screen.getByRole('button', { name: 'Run security scan' }))
    expect(await screen.findByText('No incoming mail')).toBeVisible()
    const controls = screen.getByRole('list', { name: 'example.com security controls' })
    const spf = within(controls).getByText('SPF').closest('li')!
    expect(spf).toHaveTextContent('Needs attention')
    expect(within(controls).getAllByText('Not applicable')).toHaveLength(2)
  })
  it('does not present a confident grade or offer DNS changes when essential checks were incomplete', async () => {
    const payload = successfulScan('example.com')
    Object.assign(payload.results[0]!.scan, { scan_incomplete: true, notes: ['SPF lookup timed out.'] })
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(payload))
    const user = userEvent.setup()
    renderScanner()
    await user.type(screen.getByLabelText('Domain'), 'example.com')
    await user.click(screen.getByRole('button', { name: 'Run security scan' }))
    expect(await screen.findByRole('heading', { name: 'example.com' })).toBeVisible()
    expect(screen.getByLabelText('Scan incomplete; no security grade is available')).toBeVisible()
    expect(screen.getByRole('status')).toHaveTextContent('SPF lookup timed out.')
    expect(screen.getByRole('button', { name: 'Review DNS recommendations' })).toBeDisabled()
    expect(screen.queryByLabelText('Grade A, score 90 out of 100')).not.toBeInTheDocument()
  })

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
    expect(screen.queryByRole('link', { name: 'View detail' })).not.toBeInTheDocument()
    expect(screen.getByText(/This result was not saved/)).toBeVisible()
  })

  it('supports arrow, Home and End navigation with one tabbable scan-mode tab', async () => {
    const user = userEvent.setup()
    renderScanner()
    const single = screen.getByRole('tab', { name: 'Single domain' })
    const batch = screen.getByRole('tab', { name: 'Batch scan' })
    expect(single).toHaveAttribute('tabindex', '0')
    expect(batch).toHaveAttribute('tabindex', '-1')
    single.focus()
    await user.keyboard('{ArrowRight}')
    expect(batch).toHaveFocus()
    expect(batch).toHaveAttribute('aria-selected', 'true')
    expect(within(screen.getByRole('tabpanel', { name: 'Batch scan' })).getByLabelText('Domains')).toBeVisible()
    await user.keyboard('{ArrowRight}')
    expect(single).toHaveFocus()
    await user.keyboard('{End}')
    expect(batch).toHaveFocus()
    await user.keyboard('{Home}')
    expect(single).toHaveFocus()
    await user.keyboard('{ArrowLeft}')
    expect(batch).toHaveFocus()
  })

  it.each([
    { status: 'failed', applied: [], failed: [], manual_actions: [{ type: 'SCAN-REVIEW', description: 'DNS lookup failed; retry before making changes.' }], verification: '', verification_status: 'not_run', expected: 'DNS lookup failed; retry before making changes.' },
    { status: 'partial', applied: [{ type: 'DMARC', message: 'Record changed.' }], failed: [{ type: 'TLS-RPT', message: 'Provider rejected this change.' }], manual_actions: [], verification: 'Latest verification could not finish.', verification_status: 'incomplete', expected: 'Provider rejected this change.' },
    { status: 'success', applied: [{ type: 'DMARC', message: 'Record changed.' }], failed: [], manual_actions: [], verification: 'Public verification is pending.', verification_status: 'pending', expected: 'Public verification is pending.' },
  ])('shows a non-success outcome for $status / $verification_status', async (outcome) => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse(successfulScan('example.com')))
      .mockResolvedValueOnce(jsonResponse({ domain: 'example.com', ...outcome }))
    const user = userEvent.setup()
    renderScanner()
    await user.type(screen.getByLabelText('Domain'), 'example.com')
    await user.click(screen.getByRole('button', { name: 'Run security scan' }))
    await user.click(await screen.findByRole('button', { name: 'Review DNS recommendations' }))
    const dialog = screen.getByRole('dialog', { name: 'Review DNS recommendations for example.com?' })
    expect(dialog).toHaveTextContent('This review does not change DNS records.')
    expect(within(dialog).queryByRole('button', { name: 'Verify and apply' })).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Review recommendations' }))
    const result = await screen.findByRole('region', { name: 'DNS change outcome for example.com' })
    expect(within(result).getByText(outcome.expected)).toBeVisible()
    expect(result.querySelector('.notice--success')).toBeNull()
    if (outcome.applied.length) expect(screen.queryByLabelText('Grade A, score 90 out of 100')).not.toBeInTheDocument()
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
