import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it } from 'vitest'
import type { RemediationResponse } from '../api/types'
import { RemediationOutcome } from './RemediationOutcome'

afterEach(cleanup)

describe('Remediation outcome presentation', () => {
  it.each([
    [{ status: 'success', verification_status: 'observed', applied: [{ type: 'DMARC' }], score: 90, pre_fix_score: 60 }, 'success'],
    [{ status: 'success', verification_status: 'observed', applied: [{ type: 'DMARC' }], score: 40, pre_fix_score: 60 }, 'warning'],
    [{ status: 'failed', failed: [{ type: 'DMARC', message: 'Write refused' }] }, 'danger'],
    [{ status: 'no_action', applied: [], failed: [], manual_actions: [] }, 'info'],
    [{ status: 'failed', manual_actions: [{ type: 'SPF', description: 'Confirm senders', recommended: 'One SPF record', steps: 'Ask your provider' }], verification: '' }, 'warning'],
  ] satisfies [Partial<RemediationResponse>, string][])('uses a truthful tone for %j', (details, tone) => {
    const result: RemediationResponse = { domain: 'example.com', ...details }
    render(<MemoryRouter><RemediationOutcome result={result} /></MemoryRouter>)
    const region = screen.getByRole('region', { name: 'DNS change outcome for example.com' })
    expect(region.querySelector(`.notice--${tone}`)).not.toBeNull()
    if (tone !== 'success') expect(region.querySelector('.notice--success')).toBeNull()
    if (result.manual_actions?.length) expect(screen.getByText('Ask your provider')).toBeVisible()
    expect(screen.queryByRole('link', { name: 'Review saved verification' })).not.toBeInTheDocument()
  })

  it('offers saved verification only when persistence was confirmed', () => {
    render(<MemoryRouter><RemediationOutcome result={{ domain: 'example.com', status: 'partial', history_saved: true }} /></MemoryRouter>)
    expect(screen.getByRole('link', { name: 'Review saved verification' })).toHaveAttribute('href', '/domain/example.com')
  })

  it('distinguishes manual review from a failed change or a clean no-action result', () => {
    render(<MemoryRouter><RemediationOutcome result={{
      domain: 'example.com', status: 'manual_review', applied: [], failed: [],
      manual_actions: [{ type: 'SPF', description: 'Confirm every sending service.', steps: 'Ask your mail provider before changing the record.' }],
      pre_fix_score: null, score: null, verification_status: 'not_run', history_saved: false,
    }} /></MemoryRouter>)
    const region = screen.getByRole('region', { name: 'DNS change outcome for example.com' })
    expect(region.querySelector('.notice--info')).toHaveTextContent('Manual review is required before making these DNS changes. No automatic changes were attempted.')
    expect(region.querySelector('.notice--danger')).toBeNull()
    expect(region.querySelector('.notice--success')).toBeNull()
    expect(screen.queryByText('No automatic changes were needed.')).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Changes not completed' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Manual review required' })).toBeVisible()
    expect(screen.getByText('Ask your mail provider before changing the record.')).toBeVisible()
  })
})
