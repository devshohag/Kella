# Instructions for the coding agent

You are building **Shield**, a multi-tenant security and reliability platform. Read `docs/SPEC.md` fully before starting any task. The spec is the source of truth; if a task needs a spec change, change the spec in the same commit and say so.

## Repository layout

```
backend/                 .NET 10 solution (Shield.slnx)
  src/Shield.Core/            domain models, rules, playbooks, interfaces. No EF, no ASP.NET.
  src/Shield.Infrastructure/  EF Core DbContext, migrations, NATS, alert channels, AI providers
  src/Shield.Api/             ASP.NET Core minimal APIs (agent API + dashboard API)
  src/Shield.Worker/          background consumers: aggregator, rule engine, playbooks, alerts, AI
  tests/Shield.Tests/         xUnit tests
agent/                   Go agent (cmd/shield-agent, internal/...)
web/                     React + TypeScript + Vite dashboard
deploy/                  install.sh, systemd unit, docker files
docs/                    SPEC.md, design PDF, decisions/
docker-compose.yml       local stack
```

## How to run

```bash
docker compose up -d postgres nats victoriametrics      # infra
cd backend && dotnet run --project src/Shield.Api          # API on :5080
cd backend && dotnet run --project src/Shield.Worker       # workers
cd agent && go run ./cmd/shield-agent --config ./dev-agent.yaml
cd web && npm install && npm run dev                       # web on :5173
```

## How to check your work (run all before every commit)

```bash
cd backend && dotnet build -warnaserror && dotnet test
cd agent && gofmt -l . && go vet ./... && go test ./...
cd web && npm run build && npm run lint
```
Never commit with failing builds or tests. Never delete or skip a test to make it pass.

## What already exists (template state)

- Backend: entities for all core tables, org-scoped DbContext, agent API (enroll, facts, events, long-poll commands, ack), dashboard API (overview, servers, enrollment keys, incidents, approve), in-process event bus, rule engine with `ssh.bruteforce` and `mail.bruteforce_ip`, AI redactor. 15 tests including an end-to-end brute-force → block_ip test.
- Agent: enrollment + token storage, service detection, /proc metrics heartbeat, auth.log tailer + parser, gzip event batches, long-poll command loop, `block_ip`/`unblock_ip` via nftables with allowlist, expiry and Ed25519 signature checks.
- Web: layout, Overview, Incidents, Incident detail with approve, Servers with install command. Other screens are placeholders.
- Dev mode runs without Postgres (in-memory DB) and without login. Search for `TODO(Phase` to see what each phase must replace.

## Working rules

1. **Follow the roadmap order** in SPEC §17. Do not start a phase before the previous one's acceptance criteria pass. Tick the checkbox in SPEC.md when a criterion is met.
2. **Small vertical slices.** One feature end to end (agent → API → worker → UI) per task, with tests.
3. **Event type names, API routes and table names in the spec are a contract.** Do not rename them.
4. **Hot path stays deterministic.** No LLM calls in ingest, aggregation, rules or playbooks. AI only in `Shield.Worker/Ai`.
5. **Tenant scoping.** Every query goes through `ShieldDbContext` with the organization filter. `IgnoreQueryFilters()` is allowed only in: agent enrollment and agent token lookup (`AgentEndpoints.cs`), migrations/seeding, and tests. Nowhere else.
6. **Every infrastructure-changing action** goes through `actions` + `agent_commands` + `audit_log`. No shortcuts.
7. **Agent safety.** Agent must refuse unsigned/expired commands, never block allowlisted IPs or the cloud endpoint IP, and keep RSS < 50 MB.
8. **Parsers need real log samples** in `agent/internal/parsers/testdata/` and table-driven tests.
9. **No secrets in code.** Configuration from environment variables (`SHIELD__...`) and `appsettings.Development.json` only for local dev values.
10. **UI uses the design tokens** in `web/src/styles/tokens.css`, shared primitives in `web/src/styles/app.css`, and the screens in `docs/design/`. Page-specific styles go in a `*.module.css` next to the component. Sentence case, plain words, buttons name the action.
11. **Do not add new dependencies** without a one-line reason in the commit message. Prefer the standard library.
12. If something in the spec is ambiguous, write the question in `docs/decisions/OPEN_QUESTIONS.md`, choose the simplest reasonable option, note it there, and continue.

## Code style

- C#: nullable enabled, file-scoped namespaces, records for DTOs, `async` all the way, `CancellationToken` on every async method. Minimal API endpoints grouped per feature in `Endpoints/<Feature>Endpoints.cs`.
- Go: standard layout, `context.Context` first param, errors wrapped with `%w`, no global state except config, `slog` for logging.
- TypeScript: strict mode, functional components, TanStack Query for server state, API types in `web/src/api.ts` kept in sync with the C# DTOs.

## Commits

Conventional commits: `feat(mail): hold_sender actuator`, `fix(agent): handle log rotation`, `test(rules): outbound spike baseline`. Commit on the current branch; do not push unless asked.

## Definition of done for a task

- Code + tests written, all checks above pass.
- SPEC checkbox ticked if a criterion was completed.
- Short note of what changed and how it was tested in the final message.
