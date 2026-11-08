# Open questions and decisions

When the spec is ambiguous, add an entry here, pick the simplest reasonable option, and continue.

| Date | Question | Decision taken | Status |
|---|---|---|---|
| 2026-11-08 | Product name and domain | Product name **Kella** (renamed from working name "Shield"; repo `github.com/devshohag/Kella`). Domain placeholder `kella.example`; trademark and domain clearance still to do. Keep brand strings in config. | Decided |
| 2026-11-08 | Command signing key distribution to agents | Plan: return the cloud's Ed25519 public key in the enroll response and store it in agent.yaml. | Open |
