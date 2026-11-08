import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { api, severityClass, timeAgo } from '../api'

export function Incidents() {
  const { data, error } = useQuery({ queryKey: ['incidents'], queryFn: () => api.incidents(), refetchInterval: 10_000 })
  return (
    <div className="page">
      <h1>Incidents</h1>
      <section className="panel">
        {error && <div className="error">Could not load incidents: {error.message}</div>}
        {data?.length === 0 && <div className="empty">No incidents yet.</div>}
        {!!data?.length && (
          <table>
            <thead><tr><th>Incident</th><th>What happened</th><th>Severity</th><th>Status</th><th>Opened</th></tr></thead>
            <tbody>
              {data.map((i) => (
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

// SPEC §15 screen 2 (simplified). TODO(Phase 2): timeline, AI analysis box, impact panel, top source IPs.
export function IncidentDetail() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const { data, error } = useQuery({ queryKey: ['incident', id], queryFn: () => api.incident(id), refetchInterval: 5_000 })
  const approve = useMutation({
    mutationFn: api.approveAction,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incident', id] }),
  })

  if (error) return <div className="page"><div className="error">Could not load the incident: {error.message}</div></div>
  if (!data) return <div className="page"><div className="cap">Loading…</div></div>

  const pending = data.actions.filter((a) => a.status === 'PendingApproval')
  const done = data.actions.filter((a) => a.status !== 'PendingApproval')

  return (
    <div className="page">
      <div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <span className={`pill ${severityClass[data.incident.severity]}`}>{data.incident.severity}</span>
          <span className="pill info">{data.incident.status}</span>
        </div>
        <h1>{data.incident.title}</h1>
        <div className="sub">{data.incident.number}. Opened {timeAgo(data.incident.openedAt)}. {data.summary}</div>
      </div>

      <div className="row">
        <section className="panel" style={{ flex: 1.3, minWidth: 320 }}>
          <h2 style={{ marginBottom: 12 }}>What Kella did</h2>
          {done.length === 0 && <div className="cap">No actions yet.</div>}
          <table>
            <tbody>
              {done.map((a) => (
                <tr key={a.id}>
                  <td>{a.label ?? a.kind}</td>
                  <td><span className={`pill ${a.status === 'Succeeded' ? 'ok' : a.status === 'Failed' ? 'crit' : ''}`}>{a.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section className="panel" style={{ flex: 1, minWidth: 300 }}>
          <h2 style={{ marginBottom: 12 }}>Waiting for your decision</h2>
          {approve.error && <div className="error">{approve.error.message}</div>}
          {pending.length === 0 && <div className="cap">Nothing to approve.</div>}
          {pending.map((a) => (
            <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0' }}>
              <div style={{ flex: 1 }}>{a.label ?? a.kind}</div>
              <button className="btn primary" onClick={() => approve.mutate(a.id)} disabled={approve.isPending}>Approve</button>
            </div>
          ))}
        </section>
      </div>
    </div>
  )
}
