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

// SPEC §15 screen 2 (Incident detail: timeline, impact, top source IPs, actions & approval)
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

  // Extract source IPs and Mailboxes from findings evidence
  const sourceIps = new Set<string>()
  const mailboxes = new Set<string>()
  data.findings.forEach((f) => {
    if (f.evidence?.sourceIp) sourceIps.add(f.evidence.sourceIp)
    if (f.evidence?.sender) mailboxes.add(f.evidence.sender)
    if (f.evidence?.mailbox) mailboxes.add(f.evidence.mailbox)
    if (f.evidence?.lastUser) mailboxes.add(f.evidence.lastUser)
  })

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

      {/* Impact & Scope Highlights */}
      {(sourceIps.size > 0 || mailboxes.size > 0) && (
        <section className="panel" style={{ display: 'flex', gap: 24, padding: '12px 18px' }}>
          {mailboxes.size > 0 && (
            <div>
              <span className="cap" style={{ display: 'block', marginBottom: 4 }}>Affected Targets</span>
              <div style={{ display: 'flex', gap: 6 }}>
                {Array.from(mailboxes).map((m) => (
                  <span key={m} className="chip">{m}</span>
                ))}
              </div>
            </div>
          )}
          {sourceIps.size > 0 && (
            <div>
              <span className="cap" style={{ display: 'block', marginBottom: 4 }}>Source IPs</span>
              <div style={{ display: 'flex', gap: 6 }}>
                {Array.from(sourceIps).map((ip) => (
                  <span key={ip} className="chip mono">{ip}</span>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      <div className="row">
        {/* Timeline (Events, Findings, and Actions) */}
        <section className="panel" style={{ flex: 1.5, minWidth: 320 }}>
          <h2 style={{ marginBottom: 12 }}>Incident Timeline</h2>
          {data.findings.length === 0 && (!data.events || data.events.length === 0) && (
            <div className="cap">No events recorded.</div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {/* Merged chronological timeline items */}
            {(() => {
              type TimelineItem = {
                id: string
                ts: string
                badge: string
                badgeClass: string
                title: string
                detail: string
              }

              const items: TimelineItem[] = []

              data.findings.forEach((f) => {
                items.push({
                  id: `f-${f.id}`,
                  ts: f.firstSeen,
                  badge: 'Finding',
                  badgeClass: 'crit',
                  title: f.title,
                  detail: `${f.ruleCode} · ${Object.entries(f.evidence || {}).map(([k, v]) => `${k}=${v}`).join(', ')}`,
                })
              })

              data.actions.forEach((a) => {
                items.push({
                  id: `a-${a.id}`,
                  ts: a.executedAt ?? a.createdAt ?? data.incident.openedAt,
                  badge: a.mode === 'Auto' ? 'Auto Action' : 'Action',
                  badgeClass: a.status === 'Succeeded' ? 'ok' : a.status === 'PendingApproval' ? 'warn' : 'info',
                  title: `${a.label ?? a.kind} (${a.status})`,
                  detail: a.params ? JSON.stringify(a.params) : '',
                })
              })

              data.events?.slice(0, 15).forEach((e) => {
                items.push({
                  id: `e-${e.id}`,
                  ts: e.ts,
                  badge: e.type,
                  badgeClass: '',
                  title: `${e.module}.${e.type}`,
                  detail: `${e.sourceIp ? `IP: ${e.sourceIp} ` : ''}${Object.entries(e.attrs || {}).map(([k, v]) => `${k}=${v}`).join(', ')}`,
                })
              })

              items.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime())

              return items.map((it) => (
                <div key={it.id} style={{ borderLeft: '2px solid var(--line)', paddingLeft: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className={`pill ${it.badgeClass}`} style={{ fontSize: '0.75rem', padding: '2px 8px' }}>{it.badge}</span>
                      <b style={{ fontWeight: 500 }}>{it.title}</b>
                    </div>
                    <span className="cap">{timeAgo(it.ts)}</span>
                  </div>
                  {it.detail && (
                    <div className="cap" style={{ marginTop: 4, fontFamily: 'var(--mono)' }}>
                      {it.detail}
                    </div>
                  )}
                </div>
              ))
            })()}
          </div>
        </section>

        {/* What Kella did + Approval Actions */}
        <div style={{ flex: 1.2, minWidth: 300, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <section className="panel">
            <h2 style={{ marginBottom: 12 }}>Waiting for your decision</h2>
            {approve.error && <div className="error">{approve.error.message}</div>}
            {pending.length === 0 && <div className="cap">Nothing to approve.</div>}
            {pending.map((a) => (
              <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--line)' }}>
                <div style={{ flex: 1 }}>
                  <div>{a.label ?? a.kind}</div>
                  {a.params && Object.keys(a.params).length > 0 && (
                    <div className="cap mono">{JSON.stringify(a.params)}</div>
                  )}
                </div>
                <button className="btn primary" onClick={() => approve.mutate(a.id)} disabled={approve.isPending}>Approve</button>
              </div>
            ))}
          </section>

          <section className="panel">
            <h2 style={{ marginBottom: 12 }}>Automated Actions</h2>
            {done.length === 0 && <div className="cap">No actions yet.</div>}
            <table>
              <tbody>
                {done.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <div>{a.label ?? a.kind}</div>
                      {a.params && Object.keys(a.params).length > 0 && (
                        <div className="cap mono">{JSON.stringify(a.params)}</div>
                      )}
                    </td>
                    <td><span className={`pill ${a.status === 'Succeeded' ? 'ok' : a.status === 'Failed' ? 'crit' : ''}`}>{a.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>
      </div>
    </div>
  )
}
