import { Link } from 'react-router-dom'
import { Card, PageHeader } from '../components/ui'

export function PrivacyPage() {
  return (
    <main className="public-page">
      <PageHeader
        eyebrow="Privacy & data"
        title="Operator-controlled by design"
        description="NorthFlux checks your domains' email protections and runs on your own infrastructure. You control where its data lives and who can access it."
        actions={<Link className="button button--secondary" to="/">Back to NorthFlux</Link>}
      />
      <div className="content-grid">
        <Card><h2>What is stored</h2><p>Scan results, domain notes, alerts, and non-secret settings are saved in a local database on the machine running NorthFlux.</p></Card>
        <Card><h2>Credentials</h2><p>In production, access tokens belong in the server's private environment settings. Saved tokens are not sent back to the browser or included in the website's code.</p></Card>
        <Card><h2>Network activity</h2><p>Scans check public domain records and email-security services for the domains you submit or add to monitoring. DNS changes are off by default. You must authorise a manual change or explicitly enable automatic changes with the required Cloudflare access.</p></Card>
        <Card><h2>Retention</h2><p>Operators can delete a domain's history or clear operational data from Settings. A full clear removes scan history, managed domains, alerts, and generated reports; application settings and audit logs are retained.</p></Card>
      </div>
    </main>
  )
}
