import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ApiError, apiRequest, asBoolean, asNumber, displayDate } from '../api/client'
import type { DomainDetailResponse, DomainHistoryResponse } from '../api/types'
import { Button, Card, ConfirmDialog, ErrorState, InlineNotice, LoadingState, PageHeader, StatusBadge } from '../components/ui'

const controls = [
  ['spf_present', 'SPF', 'Sender Policy Framework'],
  ['dmarc_present', 'DMARC', 'Domain-based authentication policy'],
  ['dkim_present', 'DKIM', 'Cryptographic message signing'],
  ['mta_sts_present', 'MTA-STS', 'Enforced transport security'],
  ['tls_rpt_present', 'TLS-RPT', 'Transport failure reporting'],
  ['bimi_present', 'BIMI', 'Verified brand indicator'],
  ['mx_present', 'MX', 'Mail exchanger records'],
] as const

function canonicalResult(input: Record<string, unknown>): Record<string, unknown> {
  const raw = input.raw_json
  if (typeof raw !== 'string') return input
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    return { ...parsed, ...input }
  } catch {
    return input
  }
}

export function DomainDetailPage() {
  const { domain: routeDomain = '' } = useParams()
  const domain = decodeURIComponent(routeDomain)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [message, setMessage] = useState('')
  const [deletedRecords, setDeletedRecords] = useState<number | null>(null)
  const queryClient = useQueryClient()
  const detail = useQuery({
    queryKey: ['domain', domain],
    queryFn: () => apiRequest<DomainDetailResponse>(`/api/domain/${encodeURIComponent(domain)}`),
    retry: false,
  })
  const history = useQuery({
    queryKey: ['history', domain],
    queryFn: () => apiRequest<DomainHistoryResponse>(`/api/history/${encodeURIComponent(domain)}?limit=50`),
    retry: false,
  })

  const rescan = useMutation({
    mutationFn: () => apiRequest<{ evaluation: { grade?: string; score?: number } }>(`/api/rescan/${encodeURIComponent(domain)}`, { method: 'POST' }),
    onSuccess: async (result) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['domain', domain] }),
        queryClient.invalidateQueries({ queryKey: ['history', domain] }),
        queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
      ])
      setMessage(`Rescan complete: grade ${result.evaluation.grade ?? 'unknown'}, score ${result.evaluation.score ?? 0}.`)
    },
  })

  const deleteHistory = useMutation({
    mutationFn: () => apiRequest<{ deleted_records: number }>(`/api/history/${encodeURIComponent(domain)}`, { method: 'DELETE' }),
    onSuccess: async (result) => {
      setDeleteOpen(false)
      setDeletedRecords(result.deleted_records)
      queryClient.setQueryData(['history', domain], { domain, history: [], count: 0 })
      queryClient.removeQueries({ queryKey: ['domain', domain], exact: true })
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['managed-domains'] }),
        queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
        queryClient.invalidateQueries({ queryKey: ['alerts'] }),
      ])
    },
  })

  if (deletedRecords !== null) {
    return (
      <div className="page-stack">
        <PageHeader title={domain} eyebrow="Domain detail" />
        <InlineNotice tone="success">{deletedRecords} historical record{deletedRecords === 1 ? '' : 's'} deleted. The monitoring card has been reset to an unscanned state.</InlineNotice>
        <Card><div className="button-row"><Link className="button button--primary" to="/domains">Back to managed domains</Link><Link className="button button--secondary" to={`/scan?domain=${encodeURIComponent(domain)}`}>Run a new scan</Link></div></Card>
      </div>
    )
  }

  if (detail.isLoading) return <LoadingState label={`Loading ${domain}`} />
  if (!detail.data) {
    const messageText = detail.error instanceof ApiError && detail.error.status === 404
      ? `${domain} has no saved scan. Reading this page never starts or stores a scan automatically.`
      : `NorthFlux could not load ${domain}.`
    return (
      <div className="page-stack">
        <PageHeader title={domain} eyebrow="Domain detail" />
        <ErrorState title="No saved result" message={messageText} action={<Link className="button button--primary" to={`/scan?domain=${encodeURIComponent(domain)}`}>Scan explicitly</Link>} />
      </div>
    )
  }

  const result = canonicalResult(detail.data.result)
  const grade = String(result.grade ?? '—')
  const score = asNumber(result.score, 0)
  const mutationError = rescan.error ?? deleteHistory.error
  const deleteError = deleteHistory.error instanceof ApiError ? deleteHistory.error.detail : deleteHistory.error ? 'Scan history could not be deleted.' : undefined

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Domain intelligence"
        title={domain}
        description={`Latest saved scan from ${displayDate(result.scanned_at)}.`}
        actions={<div className="button-row"><Button onClick={() => rescan.mutate()} disabled={rescan.isPending}>{rescan.isPending ? 'Rescanning…' : 'Rescan now'}</Button><a className="button button--secondary" href={`/api/report/pdf/${encodeURIComponent(domain)}`}>Download PDF</a></div>}
      />
      {message ? <InlineNotice tone="success">{message}</InlineNotice> : null}
      {detail.isError ? <InlineNotice tone="warning">The saved result is shown, but the latest background refresh could not be loaded.</InlineNotice> : null}
      {mutationError ? <InlineNotice tone="danger">{mutationError instanceof ApiError ? mutationError.detail : 'The operation failed.'}</InlineNotice> : null}
      <section className="detail-hero" aria-label="Domain score">
        <Card><p className="eyebrow">Security grade</p><div className="detail-grade"><StatusBadge value={grade} /><strong>{score}<small>/100</small></strong></div></Card>
        <Card><p className="eyebrow">Highest severity</p><h2><StatusBadge value={String(result.severity ?? 'Unknown')} /></h2><p>{String(result.advice ?? 'No additional guidance recorded.')}</p></Card>
        <Card><p className="eyebrow">History</p><h2>{history.data?.count ?? 0} scans</h2><p>Source: {detail.data.source}</p></Card>
      </section>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Controls</p><h2>Email authentication coverage</h2></div></div>
        <div className="control-list">{controls.map(([key, name, description]) => { const passed = asBoolean(result[key]); return <article key={key} className={passed ? 'control control--pass' : 'control control--fail'}><span aria-hidden="true">{passed ? '✓' : '!'}</span><div><h3>{name}</h3><p>{description}</p></div><strong>{passed ? 'Pass' : 'Needs attention'}</strong></article> })}</div>
      </Card>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Timeline</p><h2>Scan history</h2></div><Button variant="danger" type="button" onClick={() => setDeleteOpen(true)} disabled={!history.data?.count}>Delete history</Button></div>
        {history.isLoading ? <LoadingState label="Loading history" /> : history.data?.history.length ? (
          <div className="table-wrap"><table><caption className="sr-only">Scan history for {domain}</caption><thead><tr><th>Date</th><th>Grade</th><th>Score</th><th>Severity</th><th>Violations</th></tr></thead><tbody>{history.data.history.map((entry, index) => <tr key={String(entry.scan_id ?? `${entry.scanned_at}-${index}`)}><td>{displayDate(entry.scanned_at)}</td><td><StatusBadge value={String(entry.grade ?? '—')} /></td><td>{asNumber(entry.score, 0)}</td><td><StatusBadge value={String(entry.severity ?? 'Unknown')} /></td><td>{asNumber(entry.violation_count, 0)}</td></tr>)}</tbody></table></div>
        ) : <p>No historical scans are available.</p>}
      </Card>

      <ConfirmDialog
        open={deleteOpen}
        title={`Delete all scan history for ${domain}?`}
        description="This permanently removes every saved result and alert for the domain. Monitoring enrolment is managed separately. This cannot be undone."
        confirmLabel="Delete scan history"
        error={deleteError}
        dangerous
        busy={deleteHistory.isPending}
        onCancel={() => { if (!deleteHistory.isPending) setDeleteOpen(false) }}
        onConfirm={() => deleteHistory.mutate()}
      />
    </div>
  )
}
