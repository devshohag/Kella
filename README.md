# Kella

Multi-tenant security and reliability platform for companies that run mail, web, voice and cloud infrastructure for other people. One command installs an agent; Kella detects what runs on the server, protects it, and tells you about real emergencies on WhatsApp, Telegram, email or a phone call.

- **Product and technical spec:** [docs/SPEC.md](docs/SPEC.md)
- **Rules for coding agents:** [CLAUDE.md](CLAUDE.md)
- **Target screens:** [docs/design/Kella-Frontend-Design.pdf](docs/design/Kella-Frontend-Design.pdf)

## Run it locally in 2 minutes (no Docker needed)

Requires .NET 10 SDK, Go 1.24+, Node 22+.

```bash
# 1. API (in-memory database, demo organization, no login in Development)
cd backend && dotnet run --project src/Kella.Api            # http://localhost:5080

# 2. Web dashboard
cd web && npm install && npm run dev                          # http://localhost:5173

# 3. Agent on your own machine, in dry-run mode
cd agent && mkdir -p .dev && touch .dev/auth.log
go run ./cmd/kella-agent --config ./dev-agent.yaml

# 4. Simulate an SSH attack and watch an incident appear in the dashboard
for i in $(seq 1 12); do
  echo "Nov  8 02:14:01 host sshd[1]: Failed password for root from 45.148.10.92 port 5 ssh2" >> agent/.dev/auth.log
done
```

The agent logs `dry run: nft add element inet kella kella_block { 45.148.10.92 timeout 86400s }` and the dashboard shows the incident with the block marked as done.

## Run the full stack with Docker

```bash
docker compose up -d --build          # Postgres, NATS, VictoriaMetrics, API, worker, web on http://localhost:8080
```

Sign in at http://localhost:8080/login as `owner@example.com` / `kella-dev-password`; the first sign-in sets up two-factor authentication. The compose API runs with `Kella__DevOrg__Enabled=false` so the real login path is exercised.

## Check everything

```bash
cd backend && dotnet build -warnaserror && dotnet test
cd agent && gofmt -l . && go vet ./... && go test ./...
cd web && npm run lint && npm run build
```

## Repository

```
backend/   .NET 10: Kella.Core, Kella.Infrastructure, Kella.Api, Kella.Worker, tests
agent/     Go agent: detection, metrics, log parsers, cloud client, actuators
web/       React + TypeScript + Vite dashboard
deploy/    install.sh, systemd unit
docs/      SPEC.md, design, decisions
```

## Status

Phase 0 complete: EF Core migrations for every table in SPEC §6 (with `events` range-partitioned), seeded organization + owner, email/password login with mandatory TOTP for Owner/Admin, JWT access/refresh cookies, and integration tests proving cross-organization isolation. Next: Phase 1 (agent + server guard). See `docs/SPEC.md` §17 for the live checklist.

## Telegram Webhook Setup

Configure `Kella:Telegram:WebhookSecretToken` (or `Kella__Telegram__WebhookSecretToken` environment variable) with a secret token (1-256 characters, `[A-Za-z0-9_-]`).

Register your webhook with Telegram using `secret_token`:
```bash
curl -F "url=https://kella.example.com/api/hooks/telegram" \
     -F "secret_token=YOUR_WEBHOOK_SECRET_TOKEN" \
     https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook
```

## Emergency: release a held sender

`hold_sender` normally releases itself after `Kella:Mail:HoldTtlSeconds` (four hours by default). If you must release a sender immediately:

1. In the dashboard open the incident and press **Release** next to the hold action.
2. From Telegram, reply `release` to the incident alert (Responder role or higher).
3. If Kella is unreachable, do it on the mail server as root:

```bash
# 1. Remove the sender's HOLD line from the Postfix access map.
sudo cp /etc/postfix/sender_access /root/sender_access.backup
sudo sed -i '/^sender@example\.com[[:space:]]\+HOLD$/d' /etc/postfix/sender_access

# 2. Rebuild the indexed map and reload Postfix.
sudo postmap /etc/postfix/sender_access
sudo postfix reload

# 3. Release that sender's held queue items.
sudo postqueue -p | awk '/^[A-F0-9]/ { id=$1 } /sender@example\.com/ { print id }' | \
  xargs -r sudo postsuper -H
```

Confirm with `postqueue -p` (the held items should disappear from the `!` queue) and `postmap -q sender@example.com /etc/postfix/sender_access` (it should print nothing).
