# Architecture (target) and current state

Two binaries sharing PostgreSQL: `polinchaser` (API, webhooks, dashboard) and
`polinchaser-worker` (scan jobs, notifications, schedules). Webhooks only verify,
persist (dedupe on delivery ID) and enqueue. Queue is a PostgreSQL table using
`FOR UPDATE SKIP LOCKED`, leases, backoff and dead-letter state.

Packages (planned): `internal/{config,db,store,github,webhook,queue,worker,policy,notify,intel,api}`,
`pkg/scanner` (reusable engine).

## Built so far
All of this is covered by tests against a local PostgreSQL. None of it has been run against real GitHub, Resend, Render, Neon or OSV.
- `pkg/scanner`: layered detection engine (exact signatures, hidden payloads, static heuristics, persistence, secrets, dependencies, CI) and the local CLI
- Config, embedded migrations, tenant-scoped store
- GitHub App auth, webhook receiver (HMAC, delivery dedupe, repo-name validation), safe in-memory tarball fetch
- Durable PostgreSQL job queue and worker: scan jobs, Check Runs, policy
- Resend alerts (grouped, deduplicated, masked) and a delivery webhook that records bounces and complaints
- Passkey-only operator auth; first passkey gated by `ADMIN_SETUP_TOKEN`; one-time enrollment links
- Dashboard: embedded SPA, strict CSP, noindex everywhere, observability charts, triage with expiring suppressions
- Scheduler: periodic rescans, and rescans when the rule version changes
- Threat-intel feeds: operator-chosen, validated, SSRF-guarded, exact-match only
- OSV dependency advisories (opt-in, sends package names and versions to OSV)
- Retention: expires suppressions, purges old rows in bounded batches

## Not built yet
Deployment gating (GitHub Actions check and Render integration), a verified Docker build, end-to-end tests with real services.

## Data flow
GitHub push or PR -> `POST /webhooks/github` (verified) -> `jobs` table -> worker claims a job -> fetches the tarball into memory ->
engine scans -> findings and scan status stored -> Check Run completed -> alert job -> Resend. The worker also runs the scheduler,
feed refresh and retention loops. Everything durable lives in PostgreSQL.
