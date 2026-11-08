# Open questions and decisions

When the spec is ambiguous, add an entry here, pick the simplest reasonable option, and continue.

| Date | Question | Decision taken | Status |
|---|---|---|---|
| 2026-11-08 | Product name and domain | Product name **Kella** (renamed from working name "Shield"; repo `github.com/devshohag/Kella`). Domain placeholder `kella.example`; trademark and domain clearance still to do. Keep brand strings in config. | Decided |
| 2026-11-08 | Command signing key distribution to agents | Plan: return the cloud's Ed25519 public key in the enroll response and store it in agent.yaml. | Open |
| 2026-11-08 | `findings.rule_id` in SPEC §6 vs code-defined rules | Rules live in C# (`IRule.Code`); the `rules` table holds per-organization overrides. Findings store `rule_code text` instead of a foreign key, so no built-in row must exist before the first event. Spec line updated to match. | Decided |
| 2026-11-08 | `events` partitioning granularity | SPEC §6 says "partitioned by day"; Phase 0 creates `events` with `PARTITION BY RANGE (ts)` plus an `events_default` partition. The retention job will add monthly partitions and drop old ones, so no empty daily partitions accumulate. | Decided |
| 2026-11-08 | Login lockout counters have no column in SPEC §6 | Added `users.failed_login_count` and `users.lockout_until` (5 failures → 15-minute lockout) and updated the SPEC table line. | Decided |
| 2026-11-08 | "ASP.NET Identity" vs the fixed `users` table in SPEC §6 | Used ASP.NET Identity's `PasswordHasher<User>` only, keeping the SPEC columns, and implemented TOTP (RFC 6238), access/refresh JWTs and lockout in Kella itself. Full Identity EF stores would add tables the spec does not list. | Decided |
| 2026-11-08 | Refresh token storage | Refresh tokens are stateless JWTs (`typ=refresh`, 30 days) in an httpOnly cookie; logout clears cookies. No `refresh_tokens` table until revocation lists are needed. | Decided |
