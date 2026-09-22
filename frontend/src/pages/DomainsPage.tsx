import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, apiRequest, asBoolean, displayDate } from '../api/client'
import type { AlertsResponse, ManagedDomainsResponse } from '../api/types'
import { Button, Card, ConfirmDialog, EmptyState, ErrorState, Field, InlineNotice, LoadingState, PageHeader, StatusBadge } from '../components/ui'
import { normaliseDomain, validateDomain } from '../utils/domain'
import { onboardingNotice } from './onboardingNotice'
import type { InitialScan } from './onboardingNotice'

export function DomainsPage() {
  const [domain, setDomain] = useState('')
  const [notes, setNotes] = useState('')
  const [error, setError] = useState('')
  const [removeDomain, setRemoveDomain] = useState<string | null>(null)
  const [message, setMessage] = useState('')
  const [messageTone, setMessageTone] = useState<'success' | 'warning'>('success')
  const queryClient = useQueryClient()

  const domainsQuery = useQuery({ queryKey: ['managed-domains'], queryFn: ({ signal }) => apiRequest<ManagedDomainsResponse>('/api/managed-domains', { signal }) })
  const alertsQuery = useQuery({ queryKey: ['alerts'], queryFn: ({ signal }) => apiRequest<AlertsResponse>('/api/alerts', { signal }) })
  const invalidate = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['managed-domains'] }),
      queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
      queryClient.invalidateQueries({ queryKey: ['alerts'] }),
    ])
  }

  const addMutation = useMutation({
    mutationFn: () => apiRequest<{
      ok: boolean
      domain: string
      initial_scan?: InitialScan
    }>('/api/managed-domains', {
      method: 'POST',
      body: { domain: normaliseDomain(domain), notes, automatic_remediation: false },
    }),
    onSuccess: async (result) => {
      setDomain('')
      setNotes('')
      await invalidate()
      const notice = onboardingNotice(result.domain, result.initial_scan)
      setMessageTone(notice.tone)
      setMessage(notice.message)
    },
  })

  const removeMutation = useMutation({
    mutationFn: (value: string) => apiRequest<{ ok: boolean }>(`/api/managed-domains/${encodeURIComponent(value)}`, { method: 'DELETE' }),
    onSuccess: async () => {
      const removed = removeDomain ?? 'The domain'
      setRemoveDomain(null)
      await invalidate()
      setMessageTone('success')
      setMessage(`${removed} was removed from monitoring. Its scan history is retained.`)
    },
  })

  const rescanMutation = useMutation({
    mutationFn: (value: string) => apiRequest<{ domain: string; evaluation: { grade?: string; score?: number }; scan?: { scan_incomplete?: boolean } }>(`/api/rescan/${encodeURIComponent(value)}`, { method: 'POST' }),
    onSuccess: async (result) => {
      await invalidate()
      const incomplete = asBoolean(result.scan?.scan_incomplete)
      setMessageTone(incomplete ? 'warning' : 'success')
      setMessage(incomplete ? `${result.domain} could not be fully checked. No grade has been assigned; try Rescan again when the lookup service is available.` : `${result.domain} rescanned: grade ${result.evaluation.grade ?? 'unknown'}, score ${result.evaluation.score ?? 0}.`)
    },
  })

  const acknowledgeMutation = useMutation({
    mutationFn: (id: number) => apiRequest<{ ok: boolean }>(`/api/alerts/${id}/acknowledge`, { method: 'POST' }),
    onSuccess: invalidate,
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    const validation = validateDomain(domain)
    setError(validation ?? '')
    setMessage('')
    if (!validation) addMutation.mutate()
  }

  if (domainsQuery.isLoading) return <LoadingState label="Loading managed domains" />
  if (domainsQuery.isError || !domainsQuery.data) return <ErrorState message="Managed domains could not be loaded." action={<Button onClick={() => void domainsQuery.refetch()}>Try again</Button>} />

  const mutationError = addMutation.error ?? removeMutation.error ?? rescanMutation.error ?? acknowledgeMutation.error
  const errorMessage = mutationError instanceof ApiError ? mutationError.detail : mutationError ? 'The operation could not be completed.' : ''
  const removeError = removeMutation.error instanceof ApiError ? removeMutation.error.detail : removeMutation.error ? 'The domain could not be removed.' : undefined

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Your domains" title="Managed domains" description="Keep track of your domains, compare past checks, and review changes to their email protections." />
      <Card>
        <div className="section-heading"><div><p className="eyebrow">Start with a domain</p><h2>Add a business domain</h2></div></div>
        <form className="inline-form" onSubmit={submit} noValidate>
          <Field label="Domain" htmlFor="managed-domain" error={error || undefined}>
            <input id="managed-domain" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.com" />
          </Field>
          <Field label="Notes (optional)" htmlFor="managed-notes">
            <input id="managed-notes" value={notes} maxLength={500} onChange={(event) => setNotes(event.target.value)} placeholder="Primary customer mail domain" />
          </Field>
          <Button type="submit" disabled={addMutation.isPending}>{addMutation.isPending ? 'Adding and scanning…' : 'Add domain'}</Button>
        </form>
        <p className="field__hint">Adding a domain runs an initial read-only scan. It never changes DNS automatically.</p>
      </Card>
      {message ? <InlineNotice tone={messageTone}>{message}</InlineNotice> : null}
      {errorMessage ? <InlineNotice tone="danger">{errorMessage}</InlineNotice> : null}

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Portfolio</p><h2>{domainsQuery.data.count} monitored domain{domainsQuery.data.count === 1 ? '' : 's'}</h2></div></div>
        {domainsQuery.data.domains.length === 0 ? (
          <EmptyState title="No domains under management" description="Add your first domain above, or run a one-off scan without adding it to monitoring." action={<Link className="button button--secondary" to="/scan">Open scanner</Link>} />
        ) : (
          <div className="domain-card-grid">
            {domainsQuery.data.domains.map((item) => (
              <article className="domain-card" key={item.domain}>
                <div className="domain-card__head"><h3>{item.domain}</h3><StatusBadge value={asBoolean(item.last_scan_incomplete) ? 'Incomplete' : item.last_grade ?? 'Unscanned'} /></div>
                <p>{item.notes || 'No notes added.'}</p>
                <dl><div><dt>Score</dt><dd>{asBoolean(item.last_scan_incomplete) ? '—' : item.last_score ?? '—'}</dd></div><div><dt>Last scan</dt><dd>{displayDate(item.last_scan_at)}</dd></div></dl>
                <div className="button-row">
                  <Link className="button button--secondary" to={`/domain/${encodeURIComponent(item.domain)}`}>Details</Link>
                  <Button variant="ghost" type="button" disabled={rescanMutation.isPending} onClick={() => rescanMutation.mutate(item.domain)}>Rescan</Button>
                  <Button variant="danger" type="button" onClick={() => setRemoveDomain(item.domain)}>Remove</Button>
                </div>
              </article>
            ))}
          </div>
        )}
      </Card>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Alerts</p><h2>Security drift</h2></div><span>{alertsQuery.isLoading ? 'Loading' : alertsQuery.isError ? 'Unavailable' : `${alertsQuery.data?.count ?? 0} open`}</span></div>
        {alertsQuery.isLoading ? <LoadingState label="Loading security drift" /> : alertsQuery.isError ? <InlineNotice tone="warning">Security drift alerts could not be loaded. Do not treat this as an all-clear state.</InlineNotice> : alertsQuery.data?.alerts.length ? <ul className="alert-list">{alertsQuery.data.alerts.map((alert) => <li key={alert.id}><div><StatusBadge value={alert.severity} /><strong>{alert.domain}</strong></div><p>{alert.message}</p><div className="button-row"><small>{displayDate(alert.created_at)}</small><Button variant="ghost" type="button" onClick={() => acknowledgeMutation.mutate(alert.id)} disabled={acknowledgeMutation.isPending}>Acknowledge</Button></div></li>)}</ul> : <p className="quiet-success">No unacknowledged security drift.</p>}
      </Card>

      <ConfirmDialog
        open={Boolean(removeDomain)}
        title={`Stop monitoring ${removeDomain ?? 'this domain'}?`}
        description="The domain will leave continuous monitoring. Existing scan history and reports are retained until you explicitly delete them."
        confirmLabel="Remove from monitoring"
        error={removeError}
        dangerous
        busy={removeMutation.isPending}
        onCancel={() => { if (!removeMutation.isPending) setRemoveDomain(null) }}
        onConfirm={() => { if (removeDomain) removeMutation.mutate(removeDomain) }}
      />
    </div>
  )
}
