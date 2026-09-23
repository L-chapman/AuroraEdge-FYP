import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ApiError, apiRequest, asBoolean, asNumber, displayDate } from '../api/client'
import type { DomainDetailResponse, DomainHistoryResponse } from '../api/types'
import { IncompleteScanNotice } from '../components/IncompleteScanNotice'
import { Button, Card, ConfirmDialog, ErrorState, InlineNotice, LoadingState, PageHeader, StatusBadge } from '../components/ui'
import { emailControlStatus } from '../utils/emailControl'

const controls = [
  ['spf_present', 'SPF', 'Which services can send your email'],
  ['dmarc_present', 'DMARC', 'How to handle messages that fail checks'],
  ['dkim_present', 'DKIM', 'A signature to help verify the sender'],
  ['mta_sts_present', 'MTA-STS', 'Rules for secure email delivery'],
  ['tls_rpt_present', 'TLS-RPT', 'Reports about secure delivery problems'],
  ['bimi_present', 'BIMI', 'Your brand logo in supporting inboxes'],
  ['mx_present', 'MX', 'Where incoming email is delivered'],
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
  // Router parameters are already decoded. A second decode can throw for a
  // literal percent sign, preventing the API's normal validation error state.
  const { domain = '' } = useParams()
  // Router parameter changes reuse the route component. Keep confirmations,
  // mutation results and deletion state scoped to the domain they belong to.
  return <DomainDetail key={domain} domain={domain} />
}

function DomainDetail({ domain }: { domain: string }) {
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [message, setMessage] = useState('')
  const [messageTone, setMessageTone] = useState<'success' | 'warning'>('success')
  const [deletedRecords, setDeletedRecords] = useState<number | null>(null)
  const queryClient = useQueryClient()
  const detail = useQuery({
    queryKey: ['domain', domain],
    queryFn: ({ signal }) => apiRequest<DomainDetailResponse>(`/api/domain/${encodeURIComponent(domain)}`, { signal }),
    retry: false,
  })
  const history = useQuery({
    queryKey: ['history', domain],
    queryFn: ({ signal }) => apiRequest<DomainHistoryResponse>(`/api/history/${encodeURIComponent(domain)}?limit=50`, { signal }),
    retry: false,
  })

  const rescan = useMutation({
    mutationFn: () => apiRequest<{ evaluation: { grade?: string; score?: number }; scan?: { scan_incomplete?: boolean } }>(`/api/rescan/${encodeURIComponent(domain)}`, { method: 'POST' }),
    onSuccess: async (result) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['domain', domain] }),
        queryClient.invalidateQueries({ queryKey: ['history', domain] }),
        queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
      ])
      const incomplete = asBoolean(result.scan?.scan_incomplete)
      setMessageTone(incomplete ? 'warning' : 'success')
      setMessage(incomplete ? 'The rescan is incomplete. Some checks could not finish; no grade has been assigned. Try again when the lookup service is available.' : `Rescan complete: grade ${result.evaluation.grade ?? 'unknown'}, score ${result.evaluation.score ?? 0}.`)
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
  const incomplete = asBoolean(result.scan_incomplete)
  const grade = String(result.grade ?? '—')
  const score = asNumber(result.score, 0)
  const mutationError = rescan.error ?? deleteHistory.error
  const deleteError = deleteHistory.error instanceof ApiError ? deleteHistory.error.detail : deleteHistory.error ? 'Scan history could not be deleted.' : undefined

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Your domain in detail"
        title={domain}
        description={`Latest saved scan from ${displayDate(result.scanned_at)}.`}
        actions={<div className="button-row"><Button onClick={() => rescan.mutate()} disabled={rescan.isPending}>{rescan.isPending ? 'Rescanning…' : 'Rescan now'}</Button><a className="button button--secondary" href={`/api/report/pdf/${encodeURIComponent(domain)}`}>Download PDF</a></div>}
      />
      {message ? <InlineNotice tone={messageTone}>{message}</InlineNotice> : null}
      {incomplete ? <IncompleteScanNotice notes={result.notes} /> : null}
      {asBoolean(result.null_mx) ? <InlineNotice>This domain explicitly declines incoming email (Null MX). Outgoing email authentication still needs review.</InlineNotice> : null}
      {detail.isError ? <InlineNotice tone="warning">The saved result is shown, but the latest background refresh could not be loaded.</InlineNotice> : null}
      {mutationError ? <InlineNotice tone="danger">{mutationError instanceof ApiError ? mutationError.detail : 'The operation failed.'}</InlineNotice> : null}
      <section className="detail-hero" aria-label="Domain score">
        <Card><p className="eyebrow">Security grade</p><div className="detail-grade"><StatusBadge value={incomplete ? 'Incomplete' : grade} /><strong>{incomplete ? '—' : <>{score}<small>/100</small></>}</strong></div></Card>
        <Card><p className="eyebrow">Highest severity</p><h2><StatusBadge value={incomplete ? 'Unknown' : String(result.severity ?? 'Unknown')} /></h2><p>{incomplete ? 'Complete the scan before drawing a security conclusion.' : String(result.advice ?? 'No additional guidance recorded.')}</p></Card>
        <Card><p className="eyebrow">History</p><h2>{history.isError ? 'Unavailable' : history.isLoading ? 'Loading…' : `${history.data?.count ?? 0} scans`}</h2><p>Source: {detail.data.source}</p></Card>
      </section>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Records checked</p><h2>Email authentication coverage</h2><p className="section-description">These checks show whether records were found, not whether every policy setting is safe.</p></div></div>
        <div className="control-list">{controls.map(([key, name, description]) => {
          const status = emailControlStatus(result, key)
          return <article key={key} className={`control${status.tone ? ` control${status.tone}` : ''}`}><span aria-hidden="true">{status.marker}</span><div><h3>{name}</h3><p>{description}</p></div><strong>{status.label}</strong></article>
        })}</div>
      </Card>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Timeline</p><h2>Scan history</h2></div><Button variant="danger" type="button" onClick={() => setDeleteOpen(true)} disabled={!history.data?.count}>Delete history</Button></div>
        {history.isLoading ? <LoadingState label="Loading history" /> : history.isError ? <InlineNotice tone="warning">Scan history could not be loaded. Your saved results have not been deleted. <Button type="button" variant="ghost" onClick={() => void history.refetch()}>Retry history</Button></InlineNotice> : history.data?.history.length ? (
          <div className="table-wrap"><table><caption className="sr-only">Scan history for {domain}</caption><thead><tr><th>Date</th><th>Grade</th><th>Score</th><th>Severity</th><th>Violations</th></tr></thead><tbody>{history.data.history.map((entry, index) => {
            const entryIncomplete = asBoolean(canonicalResult(entry).scan_incomplete)
            return <tr key={String(entry.scan_id ?? `${entry.scanned_at}-${index}`)}><td>{displayDate(entry.scanned_at)}</td><td><StatusBadge value={entryIncomplete ? 'Incomplete' : String(entry.grade ?? '—')} /></td><td>{entryIncomplete ? '—' : asNumber(entry.score, 0)}</td><td><StatusBadge value={entryIncomplete ? 'Unknown' : String(entry.severity ?? 'Unknown')} /></td><td>{entryIncomplete ? '—' : asNumber(entry.violation_count, 0)}</td></tr>
          })}</tbody></table></div>
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
