# Open questions and decisions

When the spec is ambiguous, add an entry here, pick the simplest reasonable option, and continue.

| Date | Question | Decision taken | Status |
|---|---|---|---|
| 2026-11-08 | Product name and domain | Working name "Shield", placeholder domain `shield.example`. Keep brand strings in config. | Open |
| 2026-11-08 | Command signing key distribution to agents | Plan: return the cloud's Ed25519 public key in the enroll response and store it in agent.yaml. | Open |
