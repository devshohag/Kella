# Kella — Product & Technical Specification

Version 0.1 · Product name **Kella** (decided 2026-11-08; do not hard-code the brand outside `branding` config).

This is the single source of truth for what to build. The coding agent must read this file and `CLAUDE.md` before every task. When code and this spec disagree, the spec wins unless a change to the spec is committed first.

---

## 1. Product in one paragraph

Kella is a multi-tenant security and reliability platform for companies that run infrastructure **for other people**: hosting providers, mail providers, VoIP / call-center operators, ISPs, agencies and SaaS companies. A customer installs a small agent on each Linux server with one command. The agent detects what runs there (Postfix, Nginx, Asterisk, PostgreSQL, Docker…), switches on the matching protection module ("Guard"), streams events to the Kella cloud, and executes approved actions (block IP, hold a mailbox, cap a site). The cloud correlates events **per tenant** (the provider's end customer), runs detection rules, takes automatic containment actions, asks a human for risky actions, routes alerts (dashboard, email, Telegram, WhatsApp, voice call) and uses an LLM only to explain incidents and write reports.

**Core differentiator:** tenant awareness. Every event, incident and action is attributed to a specific tenant (domain, mailbox, site, SIP trunk), so a provider sees "billing@rahmantraders.com was hijacked; 1 of 412 tenants affected; shared IP still clean" instead of "IP 1.2.3.4 blocked".

---

## 2. Glossary

| Term | Meaning |
|---|---|
| Organization | A Kella customer account (e.g. a hosting company). Billing unit. |
| User | A person who logs into the dashboard. Belongs to one Organization. Roles: Owner, Admin, Responder, Viewer. |
| Server | A machine running the Kella agent. Belongs to an Organization. |
| Tenant | An end customer of the Organization (e.g. "Rahman Traders"). |
| Asset | Something a Tenant owns that lives on a Server: `domain`, `mailbox`, `site`, `sip_trunk`, `database`, `container`. |
| Guard | A protection module: Server, Mail, Web, Voice, Database, Container. Enabled per server by auto-detection. |
| Event | A normalized fact reported by an agent or produced by the cloud (e.g. `mail.auth_failed`). |
| Signal | An aggregated metric window computed from events (e.g. failed logins per IP per 10 min). |
| Rule | Deterministic detection logic that turns signals into a Finding. |
| Finding | A rule match with severity, evidence and suggested actions. |
| Incident | One or more related Findings grouped by tenant + type + time window. |
| Action | Something done to infrastructure: `block_ip`, `hold_sender`, … Executed by the agent. |
| Playbook | Mapping from a Finding type to automatic and approval-required Actions. |

---

## 3. Users and primary jobs

1. **On-call engineer at a provider** — "Wake me only for real emergencies, tell me what happened in one message, let me fix it from my phone."
2. **Provider owner / manager** — "Show me that my customers are safe, which tenants cause trouble, and give me reports I can send to customers."
3. **Provider's end customer (tenant admin)** — later phase, white-label portal: "Show me my own sites/mailboxes only."

---

## 4. System architecture

```
 Customer servers                         Kella cloud
 ┌─────────────────────┐   HTTPS 443   ┌──────────────────────────────────────────┐
 │ kella-agent (Go)    │──────────────▶│ Ingest API  (ASP.NET Core)               │
 │  - detectors         │   events,     │   └▶ NATS JetStream  (event bus)          │
 │  - collectors        │   metrics,    │        ├▶ Signal Aggregator (worker)      │
 │  - log tailers       │   heartbeat   │        ├▶ Rule Engine (worker)            │
 │  - actuators         │◀──────────────│        │    └▶ Incident Manager            │
 └─────────────────────┘ signed commands│        │         ├▶ Playbook Runner        │
                                         │        │         ├▶ Alert Router           │
                                         │        │         └▶ AI Analyst (async)     │
                                         │        └▶ Event Store                     │
                                         │ PostgreSQL (state) · VictoriaMetrics      │
                                         │ (metrics) · Object storage (reports)      │
                                         │ Dashboard API + React web app             │
                                         └──────────────────────────────────────────┘
```

Key decisions:

- **Agent connects outbound only.** No inbound port on customer servers. Commands are fetched by long-poll (`GET /api/agent/commands?wait=30`), not pushed.
- **Hot path is deterministic.** Detection and containment never call an LLM. AI runs asynchronously after an incident exists.
- **One backend codebase**, multiple processes: `Kella.Api` (HTTP) and `Kella.Worker` (consumers). Both reference `Kella.Core` and `Kella.Infrastructure`.
- **Multi-tenancy by `OrganizationId`** on every row, enforced in EF Core global query filters. A request can never read another organization's data.

---

## 5. Tech stack (fixed — do not substitute without updating this spec)

| Area | Choice |
|---|---|
| Backend | .NET 10, ASP.NET Core minimal APIs, EF Core 10, Npgsql |
| Workers | .NET 10 `BackgroundService` in `Kella.Worker` |
| Event bus | NATS JetStream (`NATS.Net` client). Phase 1 may use an in-process `Channel<T>` behind `IEventBus`. |
| Database | PostgreSQL 16 |
| Metrics | VictoriaMetrics (Prometheus remote-write compatible) |
| Agent | Go 1.24, single static binary, no CGO, systemd service |
| Web | React 19 + TypeScript + Vite, React Router, TanStack Query, plain CSS modules with design tokens (see §15). No UI kit. |
| Auth | Email + password (ASP.NET Identity), TOTP 2FA, JWT access + refresh cookies. Agents authenticate with per-server keys. |
| AI | `IAiProvider` interface; implementations: Anthropic, OpenAI, Gemini, Ollama (local). |
| Alerts | SMTP email, Telegram Bot API, WhatsApp Cloud API, voice call via SIP/Twilio adapter (`IVoiceCaller`). |
| Infra | Docker Compose for dev; containers for prod. |

---

## 6. Data model (PostgreSQL)

All tables have `id uuid pk`, `organization_id uuid not null` (except `organizations`), `created_at timestamptz`, `updated_at timestamptz`.

```
organizations(id, name, plan, settings jsonb)
users(id, organization_id, email, password_hash, name, role, totp_secret, phone, telegram_chat_id,
      failed_login_count, lockout_until null)   -- lockout after 5 failures (see 16)
servers(id, organization_id, name, hostname, public_ip inet, os, cpu_count, ram_mb,
        agent_version, key_hash, status[pending|online|offline|disabled],
        last_seen_at, detected jsonb, guards text[])
tenants(id, organization_id, name, external_ref, contact_email, contact_phone, plan, status)
assets(id, organization_id, tenant_id, server_id, kind[domain|mailbox|site|sip_trunk|database|container],
       identifier text, meta jsonb, unique(organization_id, kind, identifier))
events(id, organization_id, server_id, tenant_id null, asset_id null, ts, module, type,
       severity, source_ip inet null, attrs jsonb)            -- range-partitioned by ts, 30-day retention
findings(id, organization_id, rule_code text, tenant_id null, server_id, severity, title, summary,
         evidence jsonb, first_seen, last_seen, incident_id)
incidents(id, organization_id, number int, tenant_id null, server_id null, type, severity,
          status[open|contained|resolved], title, summary, opened_at, contained_at, resolved_at,
          ai_analysis jsonb null)
actions(id, organization_id, incident_id null, server_id, kind, params jsonb,
        mode[auto|approval], status[pending_approval|queued|sent|succeeded|failed|rejected|expired|reverted],
        requested_by, approved_by null, expires_at null, result jsonb, created_at, executed_at)
agent_commands(id, server_id, action_id, payload jsonb, signature, status, fetched_at, acked_at)
rules(id, organization_id null /* null = built-in */, code, enabled, params jsonb)
alert_routes(id, organization_id, severity, channels text[])
alert_deliveries(id, organization_id, incident_id, channel, recipient, status, sent_at, reply)
audit_log(id, organization_id, actor_type[user|system|agent], actor_id, verb, target, data jsonb, ts)
baselines(id, organization_id, entity_kind, entity_id, hour_of_week, p50, p95, updated_at)
```

Rules for the agent:
- Every write that changes infrastructure or settings also writes `audit_log`.
- `incidents.number` is per organization, sequential, shown as `INC-2041`.

---

## 7. Event contract (agent → cloud)

`POST /api/agent/events` — gzip JSON, max 1 MB, batch of up to 1,000 events.

```json
{
  "agentVersion": "0.1.0",
  "serverId": "uuid",
  "sentAt": "2026-11-08T02:14:03Z",
  "events": [
    {
      "id": "ulid",
      "ts": "2026-11-08T02:14:01.123Z",
      "module": "mail",
      "type": "mail.auth_failed",
      "severity": "info",
      "sourceIp": "45.148.10.92",
      "attrs": { "user": "billing@rahmantraders.com", "service": "imap", "method": "PLAIN" }
    }
  ]
}
```

Event types required in Phase 1 (names are stable API — never rename):

| Type | Module | Required attrs |
|---|---|---|
| `server.heartbeat` | server | `cpuPct, memPct, diskPct, load1, uptimeSec` |
| `server.ssh_auth_failed` | server | `user` |
| `server.ssh_auth_succeeded` | server | `user, method` |
| `server.service_down` / `server.service_up` | server | `service` |
| `server.package_updates` | server | `total, security` |
| `mail.auth_failed` | mail | `user, service` |
| `mail.auth_succeeded` | mail | `user, service, country?` |
| `mail.message_queued` | mail | `sender, recipients, size, queueId` |
| `mail.queue_size` | mail | `active, deferred` |
| `web.request_summary` | web | `site, rpm, status5xx, uniqueIps, topPaths[]` (1-minute rollups, not raw requests) |
| `voice.sip_auth_failed` | voice | `user, userAgent` |
| `voice.call_started` | voice | `trunk, destination, direction` |

Raw logs never leave the server in Phase 1. The agent parses locally and sends normalized events or 1-minute rollups.

---

## 8. Agent (Go)

### 8.1 Install
```
curl -sSL https://get.<domain>/install.sh | sudo sh -s -- --key <enrollment-key>
```
`install.sh` downloads the binary for the arch, writes `/etc/kella/agent.yaml`, creates `kella` system user, installs `kella-agent.service`, starts it.

### 8.2 Enrollment
1. Agent calls `POST /api/agent/enroll` with enrollment key + host facts.
2. Cloud returns `serverId` and a per-server `agentToken` (store at `/etc/kella/token`, mode 0600).
3. All later calls send `Authorization: Bearer <agentToken>`.

### 8.3 Detectors (run at start and every 6 h)
Detect by binary path, running process and listening port:

| Detect | Enables |
|---|---|
| always | Server Guard |
| `postfix`, `exim4`, `dovecot` | Mail Guard |
| `nginx`, `apache2`/`httpd`, `php-fpm*`, `node`, `dotnet` | Web Guard |
| `asterisk`, `freeswitch`, `kamailio` | Voice Guard |
| `postgres`, `mysqld`/`mariadbd`, `redis-server` | Database |
| `dockerd` | Containers |

Report as `PUT /api/agent/facts` → `servers.detected`, `servers.guards`.

### 8.4 Collectors
- `/proc` metrics every 15 s → `server.heartbeat` every 60 s (avg) and remote-write to VictoriaMetrics via cloud proxy.
- Log tailers (inotify, handle rotation): `/var/log/auth.log` or journald, `/var/log/mail.log`, nginx access log (rollups), Asterisk `full` log.
- Parsers live in `agent/internal/parsers/<name>.go` with table-driven tests using real log samples in `testdata/`.

### 8.5 Actuators
Commands arrive via long-poll. Each command is **signed** by the cloud (Ed25519, public key shipped in config). The agent rejects unsigned, expired or unknown commands.

| Command | Implementation | Reversible |
|---|---|---|
| `block_ip {ip, ttlSec}` | nftables set `kella_block` with timeout | yes (`unblock_ip`) |
| `unblock_ip {ip}` | delete from set | — |
| `hold_sender {sender}` | Postfix: add to `check_sender_access` hash map with `HOLD`, `postmap`, reload | yes |
| `release_sender {sender}` | remove + `postsuper -H` for that sender's held queue IDs | — |
| `cap_site_cpu {site, pct}` | systemd slice `CPUQuota` for the site's php-fpm pool | yes |
| `run_check {name}` | built-in diagnostic (e.g. `postqueue -p` summary) | — |

Safety rules: never block IPs in the allowlist (`/etc/kella/allowlist` + org allowlist from cloud), never block the IP the agent uses to reach the cloud, max 5,000 blocked IPs, every executed command is acked with result.

### 8.6 Resource budget
< 50 MB RSS, < 1% CPU average on a 4-core server. Buffer events on disk (`/var/lib/kella/queue`, max 100 MB) when the cloud is unreachable.

---

## 9. Detection rules (Phase 1 built-ins)

Rules are C# classes implementing `IRule` in `Kella.Core/Rules`. Params are overridable per organization.

| Code | Signal | Default threshold | Severity | Playbook |
|---|---|---|---|---|
| `ssh.bruteforce` | failed SSH per IP / 10 min | ≥ 10 | warning | auto `block_ip 24h` |
| `mail.bruteforce_ip` | `mail.auth_failed` per IP / 10 min | ≥ 10 | warning | auto `block_ip 24h` |
| `mail.bruteforce_account` | failed logins on one mailbox / 30 min, ≥ 20 distinct IPs | ≥ 200 | warning | alert only |
| `mail.new_country_login` | successful login from a country not seen for this mailbox in 90 days | — | warning | alert only |
| `mail.outbound_spike` | messages queued by one sender / 10 min vs. its own 30-day hourly p95 | > 20× and > 100 msgs | critical | auto `hold_sender`; approval: reset password |
| `mail.account_takeover` | `mail.bruteforce_account` or `new_country_login` followed by `outbound_spike` on same mailbox within 2 h | — | critical | auto `hold_sender`; approval: reset password, delete held |
| `mail.queue_growth` | deferred queue size | > 5,000 or +300%/h | warning | alert |
| `server.cpu_high` / `mem_high` / `disk_high` | 5-min avg | 90% / 90% / 85% | warning | alert |
| `server.down` | no heartbeat | 3 min | down | alert all channels |
| `server.service_down` | service stopped | 1 min | critical | alert |
| `web.spike` | site rpm vs. 7-day same-hour baseline | > 5× | warning | run classifier (§10) |
| `voice.sip_bruteforce` | `voice.sip_auth_failed` per IP / 5 min | ≥ 20 | warning | auto `block_ip 24h` |
| `voice.toll_fraud` | international calls per trunk / 15 min vs. baseline, or destination in high-risk prefix list | > 10× or any high-risk | critical | approval: block trunk outbound |

Baselines: compute per entity (mailbox, site, trunk) in the Signal Aggregator; store rolling hourly percentiles in Postgres table `baselines(entity_kind, entity_id, hour_of_week, p50, p95, updated_at)`. Until 24 h of data exist, use fixed thresholds only.

---

## 10. Web spike classifier: "real customers or attack?"

Deterministic score, no AI. Inputs from `web.request_summary` rollups:

| Signal | Points to customers when |
|---|---|
| Share of requests from the site's usual countries | within ±10% of baseline |
| Distinct IP networks (/24 or ASN) | grows with traffic |
| Share hitting login / xmlrpc / wp-login | not increased |
| Share of non-browser clients (no cookies / JS) | not increased |
| Cart / checkout path share (if e-commerce paths configured) | stable or increased |
| Tenant sent a campaign email in the last hour (from Mail Guard) | yes |

Score ≥ 0.7 → "real traffic": suggest/auto (if enabled) `cap_site_cpu` to protect neighbours, enable cache, never block.
Score ≤ 0.3 → "attack": auto Cloudflare challenge (if integration connected) + per-IP rate limit.
Between → alert with evidence, human decides.

---

## 11. Incidents and playbooks

- A Finding joins an open Incident with the same `(organization, tenant or server, type family)` within 2 h; otherwise opens a new one.
- Incident `status`: `open` → `contained` (all auto actions succeeded) → `resolved` (human or auto after 24 h quiet).
- Playbook definition (YAML in `Kella.Core/Playbooks/*.yaml`):

```yaml
finding: mail.account_takeover
auto:
  - kind: hold_sender
    params: { sender: "{{finding.evidence.mailbox}}" }
approval:
  - kind: reset_mailbox_password
    label: "Reset password and sign out all sessions"
  - kind: delete_held_messages
    label: "Delete held messages"
    danger: true
notify: critical
```

- Approval actions expire after 24 h. Approval is possible from the dashboard and by replying to a WhatsApp/Telegram alert (§12).

---

## 12. Alerting

Severity → channels is configured per organization (`alert_routes`). Defaults:

| Severity | Dashboard | Email | Telegram | WhatsApp | Voice call |
|---|---|---|---|---|---|
| info | ✓ | | | | |
| warning | ✓ | | ✓ | | |
| critical | ✓ | ✓ | ✓ | ✓ | |
| down | ✓ | ✓ | ✓ | ✓ | ✓ |

Rules:
- One message per incident; updates are replies in the same thread.
- Night mode (org setting) suppresses warning/info on phone channels.
- Escalation: if the primary on-call does not acknowledge in 10 min, notify backup.
- Reply commands (Telegram + WhatsApp): `1`, `2` … map to the incident's pending approval actions in listed order; `ack` acknowledges; `status` returns the incident summary. Replies are accepted only from the registered phone / chat id of a user with Responder role or higher.
- Daily summary email at 09:00 org time.

Message template (critical):
```
🔴 Critical: {{incident.title}}
{{incident.summary_short}}

✅ {{auto action 1 result}}
✅ {{auto action 2 result}}

Reply 1 to {{approval 1 label}}
Reply 2 to open the incident
```

---

## 13. AI Analyst

- Triggered asynchronously when an incident is opened or escalates, and for the daily summary.
- Input: a **context pack** built by code — incident, findings, top evidence (max 50 rows), tenant name, server facts, actions taken. Never raw logs.
- **Masking** before sending: passwords, tokens, message bodies, email local-parts of non-affected mailboxes, phone numbers. Implemented in `Kella.Core/Ai/Redactor.cs` with unit tests.
- Output (JSON schema enforced): `{ "what_happened": str, "impact": str, "recommended_actions": [str], "customer_note": str, "confidence": "low|medium|high" }`. Shown in the Incident page "Analysis" box. Language follows the organization's language (`en` or `bn`).
- Provider is chosen per organization; Ollama option for customers who forbid external AI.
- The AI never triggers actions by itself.

---

## 14. API surface (Phase 1)

Agent API (bearer agent token):
```
POST /api/agent/enroll
PUT  /api/agent/facts
POST /api/agent/events
GET  /api/agent/commands?wait=30
POST /api/agent/commands/{id}/ack
```

Dashboard API (JWT cookie, organization scoped):
```
POST /api/auth/login | /api/auth/refresh | /api/auth/logout
GET  /api/overview                       # counts, tenant grid states, active incidents
GET  /api/servers | /api/servers/{id}
POST /api/servers/enrollment-keys
GET  /api/tenants | /api/tenants/{id}
POST /api/tenants | PUT /api/tenants/{id}
POST /api/tenants/{id}/assets
GET  /api/incidents?status=open | /api/incidents/{id}
POST /api/incidents/{id}/resolve
POST /api/actions/{id}/approve | /api/actions/{id}/reject
GET  /api/mail/summary | /api/web/sites/{id}/traffic
GET  /api/settings/alerts | PUT /api/settings/alerts
POST /api/settings/alerts/test
GET  /api/audit
```
Webhooks in: `POST /api/hooks/telegram`, `POST /api/hooks/whatsapp` (verify signatures).

All list endpoints: cursor pagination `?cursor=&limit=` (max 200). Errors: RFC 7807 problem+json.

---

## 15. Web app

Screens (see `docs/design/Kella-Frontend-Design.pdf`):
1. Overview — status headline, tenant grid (one square per tenant), active incident card, servers table, attacks-blocked chart.
2. Incident detail — timeline, AI analysis box, pending approvals, impact, top source IPs.
3. Web Guard site view — traffic chart with event markers, classifier evidence table, actions taken.
4. Mail Guard — login chart, unusual senders, IP reputation matrix, protection rules toggles.
5. Alerts settings — severity × channel matrix, on-call, quiet rules, test alert.
6. Add server — install command, live detection steps, risks found.

Design tokens (must be used; do not invent new colors):
```
--canvas #E9EDF1  --surface #FFFFFF  --ink #0E1A2B  --muted #5B6778  --faint #8A95A4
--line #D6DDE5    --rail #13233A     --rail-ink #AEBBCD
--crit #D7263D    --warn #E08A0B     --ok #1C9C74   --info #2F5BEA
Font: IBM Plex Sans (UI), IBM Plex Sans Condensed (big numbers), IBM Plex Mono (IPs, commands only)
Radius: 10px panels, 8px buttons, 20px pills. Sentence case everywhere. No ALL-CAPS labels.
```
Copy rules: say what happened in plain words ("Hijacked mailbox sending spam"), never vague ("Anomaly detected"). Buttons name the action ("Reset password", not "Submit").

---

## 16. Security of Kella itself

- Agent tokens stored hashed (SHA-256) server-side; rotate via dashboard.
- Commands signed with Ed25519; private key only in the cloud's secret store.
- Org isolation: EF Core global query filter on `OrganizationId` + integration test that tries cross-org access on every endpoint.
- Rate limits on all public endpoints; login lockout; mandatory TOTP for Owner/Admin.
- Every user and system action in `audit_log`; audit log is append-only (no UPDATE/DELETE grants for the app role).
- Secrets via environment variables only. No secrets in repo, logs or AI prompts.
- Dependency scanning in CI (`dotnet list package --vulnerable`, `govulncheck`, `npm audit`).

---

## 17. Roadmap and acceptance criteria

Build strictly in this order. A phase is done only when all its acceptance criteria pass in CI or in the documented manual test.

### Phase 0 — Foundations (template already provides the skeleton)
- [x] `docker compose up` starts Postgres, NATS, VictoriaMetrics, API, worker, web.
- [x] EF Core migrations for all tables in §6; seed one organization + owner user.
- [x] Login works; JWT cookie; org query filter with cross-org test.

### Phase 1 — Agent + Server Guard
- [ ] Agent enrolls, reports facts and heartbeats; server shows Online in dashboard.
- [ ] SSH brute-force parser + `ssh.bruteforce` rule + auto `block_ip`; verified on a test VM with `hydra` against SSH.
- [ ] `server.down` alert reaches Telegram within 3 min of stopping the agent.
- [ ] Add server screen shows live detection steps.

### Phase 2 — Mail Guard
- [ ] Postfix + Dovecot parsers with tests from real logs.
- [ ] Rules `mail.bruteforce_ip`, `mail.outbound_spike`, `mail.account_takeover` with baselines.
- [ ] `hold_sender` / `release_sender` actuators verified on Postfix.
- [ ] Incident page with timeline, approvals; approve from dashboard and from Telegram reply.
- [ ] IP reputation checker (DNSBL lookups every 15 min) per sending IP.

### Phase 3 — Web Guard
- [ ] Nginx access log rollups; `web.spike` rule; classifier (§10) with unit tests.
- [ ] `cap_site_cpu` actuator; Cloudflare integration (API token) for challenge mode.

### Phase 4 — Alerts and AI
- [ ] WhatsApp Cloud API channel with reply commands; escalation; night mode; daily summary.
- [ ] AI Analyst with redactor tests and provider switch; Bangla and English output.
- [ ] Voice call alert for `down` severity via `IVoiceCaller`.

### Phase 5 — Voice Guard and tenant portal
- [ ] Asterisk/FreeSWITCH parsers, `voice.sip_bruteforce`, `voice.toll_fraud`.
- [ ] White-label tenant portal (tenant admin sees only own assets).

### Phase 6 — Reliability (Sentinel)
- [ ] Deploy markers (Git webhook), correlation "incident started within 30 min of deploy X".
- [ ] Capacity forecast per server (linear trend on disk and RAM).

---

## 18. Non-goals (do not build)

- Volumetric DDoS scrubbing. Kella orchestrates upstream (Cloudflare API, provider) but does not absorb traffic.
- Storing raw logs or email contents in the cloud.
- Windows agent and Kubernetes operator before Phase 6.
- Any feature where the LLM executes actions without a rule or human approval.
