import { Link } from 'react-router-dom'
import { Card, PageHeader } from '../components/ui'

export function PrivacyPage() {
  return (
    <main className="public-page">
      <PageHeader
        eyebrow="Privacy & data"
        title="Operator-controlled by design"
        description="NorthFlux is a self-hosted email security posture tool. Your deployment controls where operational data lives and who can access it."
        actions={<Link className="button button--secondary" to="/">Back to NorthFlux</Link>}
      />
      <div className="content-grid">
        <Card><h2>What is stored</h2><p>Scan results, managed-domain metadata, alerts, and non-secret configuration are stored in the deployment's local SQLite database.</p></Card>
        <Card><h2>Credentials</h2><p>Production credentials and the dashboard token belong in runtime environment variables. They are not returned by the application API or bundled into the React application.</p></Card>
        <Card><h2>Network activity</h2><p>Scans query public DNS and mail-security endpoints for domains you explicitly submit. DNS remediation is never attempted without operator confirmation.</p></Card>
        <Card><h2>Retention</h2><p>Operators can delete a domain's history or clear operational data from Settings. A full clear removes scan history, managed domains, alerts, and generated reports; application settings and audit logs are retained.</p></Card>
      </div>
    </main>
  )
}
