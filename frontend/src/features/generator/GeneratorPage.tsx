import { type FormEvent, type ReactNode, useMemo, useState } from 'react'

import {
  defaultMtaStsPolicyId,
  generateBimi,
  generateDmarc,
  generateMtaSts,
  generateSpf,
  generateTlsRpt,
  type BimiInput,
  type DmarcInput,
  type FieldIssue,
  type GenerationResult,
  type MtaStsInput,
  type MtaStsOutput,
  type SpfInput,
  type TlsRptInput,
  type TxtRecord,
} from './dnsRecords'
import './GeneratorPage.css'

interface GeneratorCardProps {
  title: string
  description: string
  children: ReactNode
}

function GeneratorCard({ title, description, children }: GeneratorCardProps) {
  return (
    <section className="dns-generator-card" aria-labelledby={`${title.toLowerCase().replaceAll(' ', '-')}-title`}>
      <header className="dns-generator-card__header">
        <h2 id={`${title.toLowerCase().replaceAll(' ', '-')}-title`}>{title}</h2>
        <p>{description}</p>
      </header>
      {children}
    </section>
  )
}

function Issues({ errors, warnings }: { errors: FieldIssue[]; warnings: FieldIssue[] }) {
  if (!errors.length && !warnings.length) return null
  return (
    <div className="dns-generator-issues">
      {errors.length > 0 && (
        <div className="dns-generator-issues__errors" role="alert">
          <strong>Check these fields:</strong>
          <ul>{errors.map((issue) => <li key={`${issue.field}-${issue.message}`}>{issue.message}</li>)}</ul>
        </div>
      )}
      {warnings.length > 0 && (
        <div className="dns-generator-issues__warnings" role="status">
          <strong>Configuration notes:</strong>
          <ul>{warnings.map((issue) => <li key={`${issue.field}-${issue.message}`}>{issue.message}</li>)}</ul>
        </div>
      )}
    </div>
  )
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [message, setMessage] = useState('')

  async function copy() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable')
      await navigator.clipboard.writeText(text)
      setMessage('Copied to clipboard.')
    } catch {
      setMessage('Copy is unavailable. Select the text and copy it manually.')
    }
  }

  return (
    <div className="dns-generator-copy">
      <button type="button" className="dns-generator-copy__button" onClick={copy}>
        {label}
      </button>
      <span className="dns-generator-copy__status" role="status" aria-live="polite">
        {message}
      </span>
    </div>
  )
}

function TextOutput({ label, text }: { label: string; text: string }) {
  return (
    <div className="dns-generator-output">
      <div className="dns-generator-output__heading">
        <h3>{label}</h3>
        <CopyButton text={text} label={`Copy ${label.toLowerCase()}`} />
      </div>
      <pre tabIndex={0} aria-label={label}><code>{text}</code></pre>
    </div>
  )
}

function TxtRecordOutput({ result }: { result: GenerationResult<TxtRecord> }) {
  return (
    <>
      <Issues errors={result.errors} warnings={result.warnings} />
      {result.ok && <TextOutput label="DNS TXT record" text={result.value.zoneFile} />}
    </>
  )
}

function SpfGenerator() {
  const [input, setInput] = useState<SpfInput>({
    domain: 'example.com',
    includes: '',
    ipAddresses: '',
    policy: '-all',
  })
  const result = useMemo(() => generateSpf(input), [input])

  return (
    <GeneratorCard title="SPF record" description="List the services and addresses allowed to send email for your domain.">
      <form onSubmit={(event) => event.preventDefault()} noValidate>
        <div className="dns-generator-field">
          <label htmlFor="spf-domain">Domain</label>
          <input id="spf-domain" value={input.domain} onChange={(event) => setInput({ ...input, domain: event.target.value })} autoComplete="off" />
        </div>
        <div className="dns-generator-field">
          <label htmlFor="spf-includes">Provider include domains</label>
          <input id="spf-includes" value={input.includes} onChange={(event) => setInput({ ...input, includes: event.target.value })} placeholder="_spf.google.com, spf.protection.outlook.com" autoComplete="off" />
          <p id="spf-includes-help">Separate multiple domains with commas or new lines.</p>
        </div>
        <div className="dns-generator-field">
          <label htmlFor="spf-addresses">IPv4 or IPv6 addresses and CIDR ranges</label>
          <textarea id="spf-addresses" value={input.ipAddresses} onChange={(event) => setInput({ ...input, ipAddresses: event.target.value })} placeholder={'203.0.113.0/24\n2001:db8::/32'} rows={3} aria-describedby="spf-addresses-help" />
          <p id="spf-addresses-help">Separate multiple entries with commas or new lines.</p>
        </div>
        <div className="dns-generator-field">
          <label htmlFor="spf-policy">Failure policy</label>
          <select id="spf-policy" value={input.policy} onChange={(event) => setInput({ ...input, policy: event.target.value as SpfInput['policy'] })}>
            <option value="-all">Hard fail (-all)</option>
            <option value="~all">Soft fail (~all)</option>
            <option value="?all">Neutral (?all)</option>
          </select>
        </div>
      </form>
      <TxtRecordOutput result={result} />
    </GeneratorCard>
  )
}

function DmarcGenerator() {
  const [input, setInput] = useState<DmarcInput>({
    domain: 'example.com',
    policy: 'reject',
    subdomainPolicy: '',
    aggregateEmails: 'dmarc@example.com',
    forensicEmails: '',
    percentage: 100,
  })
  const result = useMemo(() => generateDmarc(input), [input])

  return (
    <GeneratorCard title="DMARC record" description="Tell receiving mail services what to do with messages that fail your checks.">
      <form onSubmit={(event) => event.preventDefault()} noValidate>
        <div className="dns-generator-field">
          <label htmlFor="dmarc-domain">Domain</label>
          <input id="dmarc-domain" value={input.domain} onChange={(event) => setInput({ ...input, domain: event.target.value })} autoComplete="off" />
        </div>
        <div className="dns-generator-field-row">
          <div className="dns-generator-field">
            <label htmlFor="dmarc-policy">Policy</label>
            <select id="dmarc-policy" value={input.policy} onChange={(event) => setInput({ ...input, policy: event.target.value as DmarcInput['policy'] })}>
              <option value="reject">Reject</option>
              <option value="quarantine">Quarantine</option>
              <option value="none">Monitor only</option>
            </select>
          </div>
          <div className="dns-generator-field">
            <label htmlFor="dmarc-subdomain-policy">Subdomain policy</label>
            <select id="dmarc-subdomain-policy" value={input.subdomainPolicy} onChange={(event) => setInput({ ...input, subdomainPolicy: event.target.value as DmarcInput['subdomainPolicy'] })}>
              <option value="">Inherit</option>
              <option value="reject">Reject</option>
              <option value="quarantine">Quarantine</option>
              <option value="none">Monitor only</option>
            </select>
          </div>
        </div>
        <div className="dns-generator-field">
          <label htmlFor="dmarc-percentage">Policy percentage</label>
          <input id="dmarc-percentage" type="number" min={0} max={100} step={1} value={Number.isNaN(input.percentage) ? '' : input.percentage} onChange={(event) => setInput({ ...input, percentage: event.target.valueAsNumber })} />
        </div>
        <div className="dns-generator-field">
          <label htmlFor="dmarc-aggregate">Aggregate report email addresses</label>
          <textarea id="dmarc-aggregate" value={input.aggregateEmails} onChange={(event) => setInput({ ...input, aggregateEmails: event.target.value })} rows={2} />
        </div>
        <div className="dns-generator-field">
          <label htmlFor="dmarc-forensic">Forensic report email addresses (optional)</label>
          <textarea id="dmarc-forensic" value={input.forensicEmails} onChange={(event) => setInput({ ...input, forensicEmails: event.target.value })} rows={2} />
        </div>
      </form>
      <TxtRecordOutput result={result} />
    </GeneratorCard>
  )
}

function MtaStsGenerator() {
  const [input, setInput] = useState<MtaStsInput>({
    domain: 'example.com',
    mode: 'enforce',
    mxHosts: 'mail.example.com',
    maxAge: 604800,
    policyId: defaultMtaStsPolicyId(),
  })
  const result = useMemo(() => generateMtaSts(input), [input])

  return (
    <GeneratorCard title="MTA-STS policy" description="Ask supporting mail services to use secure connections when delivering to your domain.">
      <form onSubmit={(event: FormEvent) => event.preventDefault()} noValidate>
        <div className="dns-generator-field">
          <label htmlFor="mta-domain">Domain</label>
          <input id="mta-domain" value={input.domain} onChange={(event) => setInput({ ...input, domain: event.target.value })} autoComplete="off" />
        </div>
        <div className="dns-generator-field-row">
          <div className="dns-generator-field">
            <label htmlFor="mta-mode">Policy mode</label>
            <select id="mta-mode" value={input.mode} onChange={(event) => setInput({ ...input, mode: event.target.value as MtaStsInput['mode'] })}>
              <option value="enforce">Enforce</option>
              <option value="testing">Testing</option>
              <option value="none">None</option>
            </select>
          </div>
          <div className="dns-generator-field">
            <label htmlFor="mta-max-age">Max age in seconds</label>
            <input id="mta-max-age" type="number" min={0} max={31557600} step={1} value={input.maxAge} onChange={(event) => setInput({ ...input, maxAge: event.target.valueAsNumber })} />
          </div>
        </div>
        <div className="dns-generator-field">
          <label htmlFor="mta-policy-id">Policy ID</label>
          <input id="mta-policy-id" value={input.policyId} onChange={(event) => setInput({ ...input, policyId: event.target.value })} maxLength={32} autoComplete="off" />
          <p>Change this value whenever the hosted policy changes.</p>
        </div>
        <div className="dns-generator-field">
          <label htmlFor="mta-mx-hosts">MX hosts, one per line</label>
          <textarea id="mta-mx-hosts" value={input.mxHosts} onChange={(event) => setInput({ ...input, mxHosts: event.target.value })} rows={4} placeholder={'mx1.example.com\nmx2.example.com'} />
        </div>
      </form>
      <Issues errors={result.errors} warnings={result.warnings} />
      {result.ok && <MtaStsOutputs value={result.value} />}
    </GeneratorCard>
  )
}

function MtaStsOutputs({ value }: { value: MtaStsOutput }) {
  return (
    <>
      <TextOutput label="MTA-STS DNS TXT record" text={value.dnsRecord.zoneFile} />
      <TextOutput label="MTA-STS policy file" text={value.policyFile} />
      <p className="dns-generator-deployment-note">
        Serve the policy as plain text at <code>{value.policyUrl}</code>.
      </p>
    </>
  )
}

function TlsRptGenerator() {
  const [input, setInput] = useState<TlsRptInput>({ domain: 'example.com', reportEmails: 'tlsrpt@example.com' })
  const result = useMemo(() => generateTlsRpt(input), [input])

  return (
    <GeneratorCard title="TLS-RPT record" description="Choose where to receive reports about problems with secure email delivery.">
      <form onSubmit={(event) => event.preventDefault()} noValidate>
        <div className="dns-generator-field">
          <label htmlFor="tls-domain">Domain</label>
          <input id="tls-domain" value={input.domain} onChange={(event) => setInput({ ...input, domain: event.target.value })} autoComplete="off" />
        </div>
        <div className="dns-generator-field">
          <label htmlFor="tls-emails">Report email addresses</label>
          <textarea id="tls-emails" value={input.reportEmails} onChange={(event) => setInput({ ...input, reportEmails: event.target.value })} rows={3} />
          <p>Separate multiple addresses with commas or new lines.</p>
        </div>
      </form>
      <TxtRecordOutput result={result} />
    </GeneratorCard>
  )
}

function BimiGenerator() {
  const [input, setInput] = useState<BimiInput>({
    domain: 'example.com',
    selector: 'default',
    logoUrl: 'https://example.com/logo.svg',
    certificateUrl: '',
  })
  const result = useMemo(() => generateBimi(input), [input])

  return (
    <GeneratorCard title="BIMI record" description="Provide a brand logo for supporting inboxes, with a certificate where required.">
      <form onSubmit={(event) => event.preventDefault()} noValidate>
        <div className="dns-generator-field-row">
          <div className="dns-generator-field">
            <label htmlFor="bimi-domain">Domain</label>
            <input id="bimi-domain" value={input.domain} onChange={(event) => setInput({ ...input, domain: event.target.value })} autoComplete="off" />
          </div>
          <div className="dns-generator-field">
            <label htmlFor="bimi-selector">Selector</label>
            <input id="bimi-selector" value={input.selector} onChange={(event) => setInput({ ...input, selector: event.target.value })} autoComplete="off" />
          </div>
        </div>
        <div className="dns-generator-field">
          <label htmlFor="bimi-logo">SVG logo HTTPS URL</label>
          <input id="bimi-logo" type="url" value={input.logoUrl} onChange={(event) => setInput({ ...input, logoUrl: event.target.value })} autoComplete="url" />
        </div>
        <div className="dns-generator-field">
          <label htmlFor="bimi-certificate">Mark certificate HTTPS URL (optional)</label>
          <input id="bimi-certificate" type="url" value={input.certificateUrl} onChange={(event) => setInput({ ...input, certificateUrl: event.target.value })} autoComplete="url" />
        </div>
      </form>
      <TxtRecordOutput result={result} />
    </GeneratorCard>
  )
}

export function GeneratorPage() {
  return (
    <div className="dns-generator-page page-stack">
      <header className="dns-generator-page__header">
        <p className="dns-generator-page__eyebrow">Configuration workspace</p>
        <h1>DNS record generator</h1>
        <p>
          Build records locally in your browser. Review each value with your email provider before publishing it.
        </p>
      </header>
      <div className="dns-generator-grid">
        <SpfGenerator />
        <DmarcGenerator />
        <MtaStsGenerator />
        <TlsRptGenerator />
        <BimiGenerator />
      </div>
    </div>
  )
}

export default GeneratorPage
