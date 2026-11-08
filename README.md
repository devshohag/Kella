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
docker compose up -d --build          # Postgres, NATS, VictoriaMetrics, API, web on http://localhost:8080
```

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

## First prompt for your coding agent

> Read CLAUDE.md and docs/SPEC.md. We are starting Phase 0 in SPEC §17. Replace EnsureCreated with EF Core migrations for every table in SPEC §6, then implement login with ASP.NET Identity, TOTP and JWT cookies, removing DevOrgMiddleware from non-development environments. Add an integration test that proves a user of one organization cannot read another organization's servers, incidents or actions through any endpoint. Run all checks, tick the Phase 0 boxes you completed, and commit.
