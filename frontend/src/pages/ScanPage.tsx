import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useMemo, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ApiError, apiRequest, asBoolean, asNumber } from '../api/client'
import type { RemediationResponse, ScanResponse, ScanResult } from '../api/types'
import { IncompleteScanNotice } from '../components/IncompleteScanNotice'
import { RemediationOutcome } from '../components/RemediationOutcome'
import { Button, Card, ConfirmDialog, Field, InlineNotice, PageHeader, StatusBadge } from '../components/ui'
import { normaliseDomain, parseDomainList, validateDomain } from '../utils/domain'
import { emailControlStatus } from '../utils/emailControl'

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
  const incomplete = asBoolean(scan.scan_incomplete)
  const score = asNumber(evaluation.score, 0)
  return (
    <Card className="scan-result">
      <div className="scan-result__header">
        <div><p className="eyebrow">Scan result</p><h2>{result.domain}</h2></div>
        <div className="score-lockup" aria-label={incomplete ? 'Scan incomplete; no security grade is available' : `Grade ${evaluation.grade ?? 'unknown'}, score ${score} out of 100`}>
          <StatusBadge value={incomplete ? 'Incomplete' : evaluation.grade ?? '—'} />
          <strong>{incomplete ? '—' : <>{score}<small>/100</small></>}</strong>
        </div>
      </div>
      {incomplete ? <IncompleteScanNotice notes={scan.notes} /> : <div className="result-summary">
        <StatusBadge value={evaluation.severity ?? 'Unknown'} />
        <p>{evaluation.severity_description ?? evaluation.advice ?? 'Review the individual controls below.'}</p>
      </div>}
      {asBoolean(scan.null_mx) ? <InlineNotice>This domain explicitly declines incoming email (Null MX). Outgoing email authentication still needs review.</InlineNotice> : null}
      <ul className="check-grid" aria-label={`${result.domain} security controls`}>
        {checkFields.map(([key, label]) => {
          const status = emailControlStatus(scan, key, 'Needs attention')
          return <li key={key} className={`check${status.tone ? ` check${status.tone}` : ''}`}><span aria-hidden="true">{status.marker}</span><strong>{label}</strong><small>{status.label}</small></li>
        })}
      </ul>
      {evaluation.violations ? (
        <details className="details-panel"><summary>Findings and guidance</summary><p>{Array.isArray(evaluation.violations) ? evaluation.violations.join(', ') : evaluation.violations}</p>{evaluation.advice ? <p>{evaluation.advice}</p> : null}</details>
      ) : null}
      {result.remediation?.length ? (
        <details className="details-panel"><summary>{result.remediation.length} recommended improvement{result.remediation.length === 1 ? '' : 's'}</summary><ul>{result.remediation.map((item, index) => <li key={`${String(item.rule ?? item.type ?? 'step')}-${index}`}><strong>{String(item.type ?? item.rule ?? 'Recommendation')}</strong>{item.how_to_fix || item.why ? <p>{String(item.how_to_fix ?? item.why)}</p> : null}</li>)}</ul></details>
      ) : null}
      {!result.saved ? <InlineNotice>This result was not saved. Saved history and PDF reports do not include this scan.</InlineNotice> : null}
      <div className="button-row">
        {result.saved ? <Link className="button button--secondary" to={`/domain/${encodeURIComponent(result.domain)}`}>View detail</Link> : null}
        {result.saved ? <a className="button button--ghost" href={`/api/report/pdf/${encodeURIComponent(result.domain)}`}>Download PDF</a> : null}
        <Button variant="danger" type="button" disabled={incomplete} onClick={() => onFix(result.domain)}>Plan DNS fix</Button>
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
  const [fixResult, setFixResult] = useState<RemediationResponse | null>(null)
  const tabRefs = useRef<Record<ScanMode, HTMLButtonElement | null>>({ single: null, batch: null })
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
    mutationFn: (domain: string) => apiRequest<RemediationResponse>('/api/apply-fix', {
      method: 'POST',
      body: { domain },
    }),
    onSuccess: (response, domain) => {
      setFixResult({ ...response, domain })
      // The displayed scan is pre-change evidence, not verification of the
      // operation that just ran. Do not leave its old grade beside the outcome.
      if (response.applied?.length) setResults((previous) => previous.filter((result) => result.domain !== domain))
      setFixDomain(null)
      void queryClient.invalidateQueries()
    },
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    setFormError('')
    setFixResult(null)
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

  const moveTab = (event: KeyboardEvent<HTMLButtonElement>) => {
    let next: ScanMode
    if (event.key === 'Home') next = 'single'
    else if (event.key === 'End') next = 'batch'
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') next = mode === 'single' ? 'batch' : 'single'
    else return
    event.preventDefault()
    setMode(next)
    tabRefs.current[next]?.focus()
  }

  return (
    <div className="page-stack">
      <PageHeader eyebrow="A fresh look" title="Scan email security controls" description="Check one domain or up to 20 together. Get a clear summary of the email protections in place and where to improve." />
      <Card>
        <div className="segmented" role="tablist" aria-label="Scan mode">
          <button ref={(element) => { tabRefs.current.single = element }} id="scan-single-tab" type="button" role="tab" aria-controls="scan-single-panel" aria-selected={mode === 'single'} tabIndex={mode === 'single' ? 0 : -1} onKeyDown={moveTab} onClick={() => setMode('single')}>Single domain</button>
          <button ref={(element) => { tabRefs.current.batch = element }} id="scan-batch-tab" type="button" role="tab" aria-controls="scan-batch-panel" aria-selected={mode === 'batch'} tabIndex={mode === 'batch' ? 0 : -1} onKeyDown={moveTab} onClick={() => setMode('batch')}>Batch scan</button>
        </div>
        <form onSubmit={submit} noValidate className="form-stack">
          <div id="scan-single-panel" role="tabpanel" aria-labelledby="scan-single-tab" hidden={mode !== 'single'}>
            <Field label="Domain" htmlFor="scan-domain" hint="Enter a domain or paste a website address. NorthFlux will use just the domain name.">
              <input id="scan-domain" value={single} onChange={(event) => setSingle(event.target.value)} placeholder="example.com" autoComplete="url" />
            </Field>
          </div>
          <div id="scan-batch-panel" role="tabpanel" aria-labelledby="scan-batch-tab" hidden={mode !== 'batch'}>
            <Field label="Domains" htmlFor="scan-domains" hint={`${parsedBatch.domains.length}/20 unique domains. Separate entries with a new line, comma, or semicolon.`}>
              <textarea id="scan-domains" rows={7} value={batch} onChange={(event) => setBatch(event.target.value)} placeholder={'example.com\nexample.org'} />
            </Field>
          </div>
          <fieldset className="option-grid">
            <legend>Scan options</legend>
            <label><input type="checkbox" checked={saveHistory} onChange={(event) => setSaveHistory(event.target.checked)} /><span><strong>Save to scan history</strong><small>Required for PDF reports and historical comparisons.</small></span></label>
            <label><input type="checkbox" checked={manageDomains} onChange={(event) => setManageDomains(event.target.checked)} /><span><strong>Add to continuous monitoring</strong><small>Add successfully scanned domains to your managed list.</small></span></label>
            <label><input type="checkbox" checked={includeGuidance} onChange={(event) => setIncludeGuidance(event.target.checked)} /><span><strong>Generate remediation guidance</strong><small>Suggestions may require manual review; no DNS records are changed by a scan.</small></span></label>
          </fieldset>
          {formError ? <InlineNotice tone="danger">{formError}</InlineNotice> : null}
          {requestError ? <InlineNotice tone="danger">{requestError}</InlineNotice> : null}
          <Button type="submit" disabled={scanMutation.isPending}>{scanMutation.isPending ? `Scanning ${pendingDomainCount} domain${pendingDomainCount !== 1 ? 's' : ''}…` : 'Run security scan'}</Button>
        </form>
      </Card>

      {fixResult ? <RemediationOutcome result={fixResult} /> : null}
      {results.length ? <section className="results-stack" aria-live="polite" aria-label="Scan results">{results.map((result, index) => <ResultCard key={`${result.domain}-${index}`} result={result} onFix={(domain) => { fixMutation.reset(); setFixDomain(domain) }} />)}</section> : null}

      <ConfirmDialog
        open={Boolean(fixDomain)}
        title={`Review DNS recommendations for ${fixDomain ?? 'this domain'}?`}
        description="NorthFlux will check the configured Cloudflare zone and prepare recommendations for manual review. This review does not change DNS records. Confirm your sending services and your mail provider's instructions before publishing changes yourself."
        confirmLabel="Review recommendations"
        error={fixMutation.error instanceof ApiError ? fixMutation.error.detail : fixMutation.error ? 'DNS recommendations could not be prepared.' : undefined}
        busy={fixMutation.isPending}
        onCancel={() => { if (!fixMutation.isPending) setFixDomain(null) }}
        onConfirm={() => { if (fixDomain) fixMutation.mutate(fixDomain) }}
      />
    </div>
  )
}
