import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { api, timeAgo, type EnrollmentKey } from '../api'

// SPEC §15 screen 6 (simplified). TODO(Phase 1): live detection steps for the server being added.
export function Servers() {
  const servers = useQuery({ queryKey: ['servers'], queryFn: api.servers, refetchInterval: 5_000 })
  const [key, setKey] = useState<EnrollmentKey | null>(null)
  const [copied, setCopied] = useState(false)
  const create = useMutation({ mutationFn: api.createEnrollmentKey, onSuccess: (k) => { setKey(k); setCopied(false) } })

  return (
    <div className="page">
      <div>
        <h1>Servers</h1>
        <div className="sub">Run one command on a Linux server. Kella finds what is running and turns on the right protection.</div>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2>Add a server</h2>
          <button className="btn primary" onClick={() => create.mutate()} disabled={create.isPending}>
            {create.isPending ? 'Creating…' : 'Create install command'}
          </button>
        </div>
        {create.error && <div className="error">Could not create a key: {create.error.message}</div>}
        {key ? (
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', background: 'var(--rail)', color: '#E3EAF3', borderRadius: 10, padding: '14px 18px' }}>
            <code className="mono" style={{ flex: 1, overflowX: 'auto', whiteSpace: 'nowrap' }}>{key.installCommand}</code>
            <button className="btn" onClick={() => { navigator.clipboard.writeText(key.installCommand); setCopied(true) }}>
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        ) : (
          <div className="cap">The command works once and expires in 24 hours.</div>
        )}
      </section>

      <section className="panel">
        <div className="panel-head"><h2>All servers</h2><span className="cap">Services detected automatically at install</span></div>
        {servers.error && <div className="error">Could not load servers: {servers.error.message}</div>}
        {servers.data?.length === 0 && <div className="empty">No servers yet. Create an install command above to add your first one.</div>}
        {!!servers.data?.length && (
          <table>
            <thead><tr><th>Server</th><th>Detected</th><th>Guards on</th><th>Status</th><th>Last seen</th></tr></thead>
            <tbody>
              {servers.data.map((s) => (
                <tr key={s.id}>
                  <td><b style={{ fontWeight: 500 }}>{s.name}</b><div className="cap mono">{s.publicIp ?? '—'}</div></td>
                  <td>{s.detected.map((d) => <span key={d} className="chip">{d}</span>)}</td>
                  <td>{s.guards.map((g) => <span key={g} className="chip guard">{g}</span>)}</td>
                  <td><span className={`pill ${s.status === 'Online' ? 'ok' : s.status === 'Offline' ? 'crit' : ''}`}>{s.status}</span></td>
                  <td className="cap">{timeAgo(s.lastSeenAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
