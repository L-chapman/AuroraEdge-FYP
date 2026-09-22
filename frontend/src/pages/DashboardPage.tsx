import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { apiRequest, asNumber, displayDate } from '../api/client'
import type { DashboardPayload, DomainSummary } from '../api/types'
import { Button, Card, EmptyState, ErrorState, LoadingState, Metric, PageHeader, StatusBadge } from '../components/ui'

function scoreOf(domain: DomainSummary): number {
  return asNumber(domain.last_score, 0)
}

export function DashboardPage() {
  const dashboard = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => apiRequest<DashboardPayload>('/api/v1/dashboard'),
    refetchInterval: 60_000,
  })

  if (dashboard.isLoading) return <LoadingState label="Loading security posture" />
  if (dashboard.isError || !dashboard.data) {
    return <ErrorState message="The dashboard data could not be loaded." action={<Button onClick={() => void dashboard.refetch()}>Try again</Button>} />
  }

  const { stats, domains, alerts, settings } = dashboard.data
  const sortedDomains = [...domains].sort((a, b) => scoreOf(a) - scoreOf(b))
  const average = asNumber(stats.average_score, 0)
  const scoredDomains = domains.filter((domain) => domain.last_score !== null && domain.last_score !== undefined)
  const monitoring = String(settings.monitoring_enabled ?? 'false').toLowerCase() === 'true'

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Security operations"
        title="Your email security posture"
        description="One clear view of authentication controls, drift, and domains that need attention."
        actions={<Link className="button button--primary" to="/scan">Run a scan</Link>}
      />

      <section className="metric-grid" aria-label="Security summary">
        <Metric label="Managed domains" value={domains.length} detail={monitoring ? 'Continuous monitoring active' : 'Monitoring is paused'} />
        <Metric label="Average score" value={scoredDomains.length ? Math.round(average) : '—'} detail="Across scored managed domains" />
        <Metric label="Open alerts" value={stats.alert_count ?? 0} detail={stats.alert_count ? 'Review required' : 'No active drift alerts'} />
        <Metric label="Completed scans" value={stats.total_scans ?? 0} detail={`${stats.total_results ?? 0} recorded results`} />
      </section>

      <div className="dashboard-grid">
        <Card className="dashboard-grid__primary">
          <div className="section-heading">
            <div><p className="eyebrow">Priority queue</p><h2>Domains needing attention</h2></div>
            <Link to="/domains">Manage domains</Link>
          </div>
          {sortedDomains.length === 0 ? (
            <EmptyState
              title="No managed domains yet"
              description="Add a business domain to begin monitoring its email authentication posture."
              action={<Link className="button button--secondary" to="/domains">Add a domain</Link>}
            />
          ) : (
            <div className="table-wrap">
              <table>
                <caption className="sr-only">Managed domains ordered from lowest to highest score</caption>
                <thead><tr><th>Domain</th><th>Grade</th><th>Score</th><th>Last scan</th><th><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {sortedDomains.slice(0, 8).map((domain) => (
                    <tr key={domain.domain}>
                      <td><strong>{domain.domain}</strong></td>
                      <td><StatusBadge value={domain.last_grade ?? 'Unscanned'} /></td>
                      <td>{domain.last_score ?? '—'}</td>
                      <td>{displayDate(domain.last_scan_at)}</td>
                      <td><Link to={`/domain/${encodeURIComponent(domain.domain)}`}>View</Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card>
          <div className="section-heading"><div><p className="eyebrow">Drift watch</p><h2>Active alerts</h2></div></div>
          {alerts.length === 0 ? (
            <p className="quiet-success"><span aria-hidden="true">✓</span> No unacknowledged security drift.</p>
          ) : (
            <ul className="alert-list">
              {alerts.slice(0, 5).map((alert) => (
                <li key={alert.id}>
                  <div><StatusBadge value={alert.severity} /><strong>{alert.domain}</strong></div>
                  <p>{alert.message}</p>
                  <small>{displayDate(alert.created_at)}</small>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card>
        <div className="section-heading"><div><p className="eyebrow">Distribution</p><h2>Current grade profile</h2></div></div>
        <div className="grade-bars">
          {['A+', 'A', 'B', 'C', 'D', 'F'].map((grade) => {
            const count = stats.grade_distribution?.[grade] ?? 0
            const maximum = Math.max(1, ...Object.values(stats.grade_distribution ?? {}))
            return (
              <div className="grade-bar" key={grade}>
                <span>{grade}</span>
                <progress className="grade-bar__progress" max={maximum} value={count} aria-label={`${grade}: ${count} domains`} />
                <strong>{count}</strong>
              </div>
            )
          })}
        </div>
      </Card>
    </div>
  )
}
