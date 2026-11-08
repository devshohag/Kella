// Typed client for the dashboard API (SPEC §14). Keep types in sync with backend/src/Kella.Api/Endpoints.

export type Severity = 'Info' | 'Warning' | 'Critical' | 'Down'
export type IncidentStatus = 'Open' | 'Contained' | 'Resolved'

export interface IncidentListItem {
  id: string
  number: string
  title: string
  severity: Severity
  status: IncidentStatus
  openedAt: string
}

export interface Overview {
  serversOnline: number
  serversTotal: number
  tenants: number
  openIncidents: number
  pendingApprovals: number
  activeIncidents: IncidentListItem[]
}

export interface ServerListItem {
  id: string
  name: string
  publicIp: string | null
  status: 'Pending' | 'Online' | 'Offline' | 'Disabled'
  detected: string[]
  guards: string[]
  lastSeenAt: string | null
}

export interface EnrollmentKey {
  key: string
  expiresAt: string
  installCommand: string
}

export interface KellaAction {
  id: string
  kind: string
  params: Record<string, string>
  mode: 'Auto' | 'Approval'
  status: string
  label: string | null
}

export interface IncidentDetail {
  incident: IncidentListItem
  summary: string
  findings: { id: string; ruleCode: string; title: string; evidence: Record<string, string>; firstSeen: string }[]
  actions: KellaAction[]
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'include', headers: { 'Content-Type': 'application/json' }, ...init })
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const problem = await res.json()
      detail = problem.detail ?? problem.title ?? detail
    } catch { /* not JSON */ }
    throw new Error(detail)
  }
  return res.status === 204 ? (undefined as T) : res.json()
}

export const api = {
  overview: () => request<Overview>('/api/overview'),
  servers: () => request<ServerListItem[]>('/api/servers'),
  createEnrollmentKey: () => request<EnrollmentKey>('/api/servers/enrollment-keys', { method: 'POST' }),
  incidents: (status?: IncidentStatus) => request<IncidentListItem[]>(`/api/incidents${status ? `?status=${status}` : ''}`),
  incident: (id: string) => request<IncidentDetail>(`/api/incidents/${id}`),
  approveAction: (id: string) => request<void>(`/api/actions/${id}/approve`, { method: 'POST' }),
}

export const severityClass: Record<Severity, string> = { Info: '', Warning: 'warn', Critical: 'crit', Down: 'crit' }

export function timeAgo(iso: string | null): string {
  if (!iso) return 'never'
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s} s ago`
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} d ago`
}
