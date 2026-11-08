import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, severityClass, timeAgo } from '../api'
import styles from './Overview.module.css'

// SPEC §15 screen 1. TODO(Phase 1): tenant grid needs GET /api/overview to return per-tenant states.
export function Overview() {
  const { data, error, isLoading } = useQuery({ queryKey: ['overview'], queryFn: api.overview, refetchInterval: 10_000 })

  if (isLoading) return <div className="page"><div className="cap">Loading…</div></div>
  if (error) return <div className="page"><div className="error">Could not load the overview: {error.message}</div></div>
  if (!data) return null

  const headline =
    data.openIncidents === 0 ? 'All quiet. No open incidents.'
      : data.pendingApprovals > 0 ? `${data.openIncidents} open incident${data.openIncidents > 1 ? 's' : ''}, ${data.pendingApprovals} waiting for you`
      : `${data.openIncidents} open incident${data.openIncidents > 1 ? 's' : ''}, contained automatically`

  return (
    <div className="page">
      <div className={styles.status}>
        <div className={styles.title}>
          <h1>{headline}</h1>
          <div className="sub">{data.serversTotal} servers and {data.tenants} tenants.</div>
        </div>
        <Stat value={`${data.serversOnline}/${data.serversTotal}`} label="Servers online" />
        <Stat value={data.tenants} label="Tenants" />
        <Stat value={data.pendingApprovals} label="Needs your approval" alert={data.pendingApprovals > 0} />
      </div>

      <section className="panel">
        <div className="panel-head"><h2>Open incidents</h2><Link to="/incidents" className="cap">See all</Link></div>
        {data.activeIncidents.length === 0 ? (
          <div className="empty">Nothing needs attention. Kella will alert you when something does.</div>
        ) : (
          <table>
            <thead><tr><th>Incident</th><th>What happened</th><th>Severity</th><th>Status</th><th>Opened</th></tr></thead>
            <tbody>
              {data.activeIncidents.map((i) => (
                <tr key={i.id}>
                  <td><Link to={`/incidents/${i.id}`}>{i.number}</Link></td>
                  <td>{i.title}</td>
                  <td><span className={`pill ${severityClass[i.severity]}`}>{i.severity}</span></td>
                  <td>{i.status}</td>
                  <td className="cap">{timeAgo(i.openedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}

function Stat({ value, label, alert }: { value: number | string; label: string; alert?: boolean }) {
  return (
    <div className={styles.stat}>
      <div className={`num ${styles.value}`} style={alert ? { color: 'var(--crit)' } : undefined}>{value}</div>
      <div className="cap">{label}</div>
    </div>
  )
}
