import { useMutation, useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { api, timeAgo, type EnrollmentKey, type ServerListItem } from '../api'
import styles from './Servers.module.css'

type Step = { label: string; status: 'waiting' | 'done' | 'active' }

function buildSteps(server: ServerListItem | null): Step[] {
  if (!server) {
    return [
      { label: 'Waiting for agent to connect…', status: 'active' },
      { label: 'Detecting services', status: 'waiting' },
      { label: 'Turning on guards', status: 'waiting' },
    ]
  }
  const online = server.status === 'Online'
  const hasDetected = server.detected.length > 0
  return [
    { label: 'Agent connected', status: 'done' },
    {
      label: hasDetected
        ? `Services found: ${server.detected.join(', ')}`
        : 'Detecting services…',
      status: online && hasDetected ? 'done' : online ? 'active' : 'waiting',
    },
    {
      label:
        server.guards.length > 0
          ? `Guards on: ${server.guards.join(', ')}`
          : 'Turning on guards…',
      status: online && server.guards.length > 0 ? 'done' : online ? 'active' : 'waiting',
    },
  ]
}

function LiveDetection({ serverId }: { serverId: string }) {
  const [server, setServer] = useState<ServerListItem | null>(null)
  const [done, setDone] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    const es = new EventSource(`/api/servers/${serverId}/status-stream`)
    esRef.current = es
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data) as ServerListItem
        setServer(data)
        if (data.status === 'Online') {
          setDone(true)
          es.close()
        }
      } catch { /* ignore */ }
    }
    es.onerror = () => { es.close(); setDone(true) }
    return () => es.close()
  }, [serverId])

  const steps = buildSteps(done ? server : server)

  return (
    <div className={styles.detection}>
      <div className={styles.detectionTitle}>
        {done ? '✅ Server is online' : '⏳ Setting up…'}
      </div>
      <ul className={styles.steps}>
        {steps.map((s, i) => (
          <li key={i} className={styles[s.status]}>
            <span className={styles.dot} />
            {s.label}
          </li>
        ))}
      </ul>
      {done && server && (
        <div className={styles.detectionResult}>
          <span className="pill ok">{server.status}</span>
          {server.detected.map((d) => <span key={d} className="chip">{d}</span>)}
          {server.guards.map((g) => <span key={g} className="chip guard">{g}</span>)}
        </div>
      )}
    </div>
  )
}

export function Servers() {
  const servers = useQuery({ queryKey: ['servers'], queryFn: api.servers, refetchInterval: 5_000 })
  const [key, setKey] = useState<EnrollmentKey | null>(null)
  const [copied, setCopied] = useState(false)
  const [watchId, setWatchId] = useState<string | null>(null)
  const create = useMutation({
    mutationFn: api.createEnrollmentKey,
    onSuccess: (k) => { setKey(k); setCopied(false); setWatchId(null) },
  })

  // when a new server appears that matches our pending key, start watching it
  useEffect(() => {
    if (!key || watchId) return
    // find newest server not yet watched — just take the first pending/online one
    const newest = servers.data?.find((s) => s.status === 'Pending' || s.status === 'Online')
    if (newest) setWatchId(newest.id)
  }, [key, servers.data, watchId])

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
          <div className={styles.installBlock}>
            <div className={styles.installCmd}>
              <code className="mono">{key.installCommand}</code>
              <button className="btn" onClick={() => { navigator.clipboard.writeText(key.installCommand); setCopied(true) }}>
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <div className="cap">Expires {new Date(key.expiresAt).toLocaleString()} · one use only</div>
            {watchId ? (
              <LiveDetection serverId={watchId} />
            ) : (
              <div className="cap" style={{ marginTop: 12 }}>Waiting for the agent to connect…</div>
            )}
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
