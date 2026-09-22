import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ApiError, apiRequest, asBoolean, asNumber } from '../api/client'
import type { ScanResponse, ScanResult } from '../api/types'
import { Button, Card, ConfirmDialog, Field, InlineNotice, PageHeader, StatusBadge } from '../components/ui'
import { normaliseDomain, parseDomainList, validateDomain } from '../utils/domain'

type ScanMode = 'single' | 'batch'

interface ScanRequest {
  domains: string[]
  saveHistory: boolean
  manageDomains: boolean
  includeGuidance: boolean
}

const checkFields = [
  ['spf_present', 'SPF'],
  ['dmarc_present', 'DMARC'],
  ['dkim_present', 'DKIM'],
  ['mta_sts_present', 'MTA-STS'],
  ['tls_rpt_present', 'TLS-RPT'],
  ['bimi_present', 'BIMI'],
  ['mx_present', 'MX'],
] as const

function ResultCard({ result, onFix }: { result: ScanResult; onFix: (domain: string) => void }) {
  if (result.error) {
    return <Card className="scan-result scan-result--error"><h2>{result.domain}</h2><InlineNotice tone="danger">{result.error}</InlineNotice></Card>
  }
  const evaluation = result.evaluation ?? {}
  const scan = result.scan ?? {}
  const score = asNumber(evaluation.score, 0)
  return (
    <Card className="scan-result">
      <div className="scan-result__header">
        <div><p className="eyebrow">Scan result</p><h2>{result.domain}</h2></div>
        <div className="score-lockup" aria-label={`Grade ${evaluation.grade ?? 'unknown'}, score ${score} out of 100`}>
          <StatusBadge value={evaluation.grade ?? '—'} />
          <strong>{score}<small>/100</small></strong>
        </div>
      </div>
      <div className="result-summary">
        <StatusBadge value={evaluation.severity ?? 'Unknown'} />
        <p>{evaluation.severity_description ?? evaluation.advice ?? 'Review the individual controls below.'}</p>
      </div>
      <ul className="check-grid" aria-label={`${result.domain} security controls`}>
        {checkFields.map(([key, label]) => {
          const passed = asBoolean(scan[key])
          return <li key={key} className={passed ? 'check check--pass' : 'check check--fail'}><span aria-hidden="true">{passed ? '✓' : '!'}</span><strong>{label}</strong><small>{passed ? 'Present' : 'Needs attention'}</small></li>
        })}
      </ul>
      {evaluation.violations ? (
        <details className="details-panel"><summary>Violations and guidance</summary><p>{Array.isArray(evaluation.violations) ? evaluation.violations.join(', ') : evaluation.violations}</p>{evaluation.advice ? <p>{evaluation.advice}</p> : null}</details>
      ) : null}
      {result.remediation?.length ? (
        <details className="details-panel"><summary>{result.remediation.length} recommended remediation step{result.remediation.length === 1 ? '' : 's'}</summary><ul>{result.remediation.map((item, index) => <li key={`${String(item.rule ?? item.type ?? 'step')}-${index}`}><strong>{String(item.type ?? item.rule ?? 'Recommendation')}</strong>{item.how_to_fix || item.why ? <p>{String(item.how_to_fix ?? item.why)}</p> : null}</li>)}</ul></details>
      ) : null}
      <div className="button-row">
        <Link className="button button--secondary" to={`/domain/${encodeURIComponent(result.domain)}`}>View detail</Link>
        {result.saved ? <a className="button button--ghost" href={`/api/report/pdf/${encodeURIComponent(result.domain)}`}>Download PDF</a> : null}
        <Button variant="danger" type="button" onClick={() => onFix(result.domain)}>Plan DNS fix</Button>
      </div>
    </Card>
  )
}

export function ScanPage() {
  const [searchParams] = useSearchParams()
  const [mode, setMode] = useState<ScanMode>('single')
  const [single, setSingle] = useState(searchParams.get('domain') ?? '')
  const [batch, setBatch] = useState('')
  const [saveHistory, setSaveHistory] = useState(true)
  const [manageDomains, setManageDomains] = useState(false)
  const [includeGuidance, setIncludeGuidance] = useState(true)
  const [formError, setFormError] = useState('')
  const [results, setResults] = useState<ScanResult[]>([])
  const [fixDomain, setFixDomain] = useState<string | null>(null)
  const [fixMessage, setFixMessage] = useState('')
  const queryClient = useQueryClient()

  const parsedBatch = useMemo(() => parseDomainList(batch), [batch])
  const scanMutation = useMutation({
    mutationFn: (request: ScanRequest) => apiRequest<ScanResponse>('/api/scan', {
      method: 'POST',
      body: {
        domains: request.domains,
        save_to_db: request.saveHistory,
        manage_domains: request.manageDomains,
        remediation: request.includeGuidance,
      },
    }),
    onSuccess: (response) => {
      setResults(response.results)
      void queryClient.invalidateQueries({ queryKey: ['dashboard'] })
      void queryClient.invalidateQueries({ queryKey: ['managed-domains'] })
    },
  })

  const fixMutation = useMutation({
    mutationFn: (domain: string) => apiRequest<{ status: string; verification?: string }>('/api/apply-fix', {
      method: 'POST',
      body: { domain },
    }),
    onSuccess: (response) => {
      setFixMessage(response.verification ?? `DNS remediation finished with status: ${response.status}.`)
      setFixDomain(null)
      void queryClient.invalidateQueries()
    },
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    setFormError('')
    setFixMessage('')
    const domains = mode === 'single' ? [normaliseDomain(single)] : parsedBatch.domains
    const errors = mode === 'single'
      ? [validateDomain(single)].filter((value): value is string => Boolean(value))
      : parsedBatch.errors
    if (!domains.length) errors.push('Enter at least one domain.')
    if (errors.length) {
      setFormError(errors.join(' '))
      return
    }
    setResults([])
    scanMutation.mutate({ domains, saveHistory, manageDomains, includeGuidance })
  }

  const requestError = scanMutation.error instanceof ApiError ? scanMutation.error.detail : scanMutation.error ? 'The scan could not be completed.' : ''
  const pendingDomainCount = scanMutation.variables?.domains.length ?? (mode === 'batch' ? parsedBatch.domains.length : 1)

  return (
    <div className="page-stack">
      <PageHeader eyebrow="On-demand analysis" title="Scan email security controls" description="Check one domain or submit a single, rate-limit-safe batch of up to 20 domains." />
      <Card>
        <div className="segmented" role="tablist" aria-label="Scan mode">
          <button type="button" role="tab" aria-selected={mode === 'single'} onClick={() => setMode('single')}>Single domain</button>
          <button type="button" role="tab" aria-selected={mode === 'batch'} onClick={() => setMode('batch')}>Batch scan</button>
        </div>
        <form onSubmit={submit} noValidate className="form-stack">
          {mode === 'single' ? (
            <Field label="Domain" htmlFor="scan-domain" hint="Paste a domain or URL; NorthFlux will safely normalise it.">
              <input id="scan-domain" value={single} onChange={(event) => setSingle(event.target.value)} placeholder="example.com" autoComplete="url" />
            </Field>
          ) : (
            <Field label="Domains" htmlFor="scan-domains" hint={`${parsedBatch.domains.length}/20 unique domains. Separate entries with a new line, comma, or semicolon.`}>
              <textarea id="scan-domains" rows={7} value={batch} onChange={(event) => setBatch(event.target.value)} placeholder={'example.com\nexample.org'} />
            </Field>
          )}
          <fieldset className="option-grid">
            <legend>Scan options</legend>
            <label><input type="checkbox" checked={saveHistory} onChange={(event) => setSaveHistory(event.target.checked)} /><span><strong>Save to scan history</strong><small>Required for PDF reports and historical comparisons.</small></span></label>
            <label><input type="checkbox" checked={manageDomains} onChange={(event) => setManageDomains(event.target.checked)} /><span><strong>Add to continuous monitoring</strong><small>Explicitly enrol successful domains in My Domains.</small></span></label>
            <label><input type="checkbox" checked={includeGuidance} onChange={(event) => setIncludeGuidance(event.target.checked)} /><span><strong>Generate remediation guidance</strong><small>Recommendations only; no DNS records are changed.</small></span></label>
          </fieldset>
          {formError ? <InlineNotice tone="danger">{formError}</InlineNotice> : null}
          {requestError ? <InlineNotice tone="danger">{requestError}</InlineNotice> : null}
          <Button type="submit" disabled={scanMutation.isPending}>{scanMutation.isPending ? `Scanning ${pendingDomainCount} domain${pendingDomainCount !== 1 ? 's' : ''}…` : 'Run security scan'}</Button>
        </form>
      </Card>

      {fixMessage ? <InlineNotice tone="success">{fixMessage}</InlineNotice> : null}
      {results.length ? <section className="results-stack" aria-live="polite" aria-label="Scan results">{results.map((result, index) => <ResultCard key={`${result.domain}-${index}`} result={result} onFix={setFixDomain} />)}</section> : null}

      <ConfirmDialog
        open={Boolean(fixDomain)}
        title={`Apply DNS remediation for ${fixDomain ?? 'this domain'}?`}
        description="NorthFlux will first verify that the configured Cloudflare zone owns this domain, then apply supported DNS changes. DNS changes can affect mail delivery. Review your Cloudflare configuration and continue only when authorised."
        confirmLabel="Verify and apply"
        error={fixMutation.error instanceof ApiError ? fixMutation.error.detail : fixMutation.error ? 'DNS remediation failed.' : undefined}
        dangerous
        busy={fixMutation.isPending}
        onCancel={() => { if (!fixMutation.isPending) setFixDomain(null) }}
        onConfirm={() => { if (fixDomain) fixMutation.mutate(fixDomain) }}
      />
    </div>
  )
}
