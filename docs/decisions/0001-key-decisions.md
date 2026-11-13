# Key decisions

Short records of choices that are costly to reverse. Each has the reason and what would change it.

## 1. PostgreSQL is the only infrastructure
Jobs, sessions, findings and audit all live in Postgres (Neon in production). The queue uses `FOR UPDATE SKIP LOCKED` with leases.
- Why: one thing to run, back up and secure; durable by default; fits a small self-hosted deployment.
- Cost: needs a direct (non-pooled) connection; throughput is limited versus a dedicated broker.
- Revisit if: scan volume outgrows a single database.

## 2. Passkey-only sign-in, no accounts
The dashboard is a single-operator console. No passwords, no registration page, no password reset.
- Why: nothing to phish, stuff or leak; fits an open-source project where the code is public.
- Cost: no account recovery. Losing every registered device means server access is needed (set a new `ADMIN_SETUP_TOKEN` and clear the passkey tables).
- Revisit if: several people need separate access; that is a multi-tenant redesign.

## 3. Exact signatures are the only "confirmed" findings
Heuristics, external malicious-package reports (OSV `MAL-`) and policy hits are never labelled confirmed malware.
- Why: a wrong "this is malware" damages trust in a security tool; severity and confidence are separate fields.
- Cost: some real malware shows as "high confidence" rather than "confirmed".

## 4. Repositories are hostile input
Content is read in memory with hard limits and never executed, installed or written to disk. Anything skipped makes the scan incomplete, never clean.

## 5. Nothing third-party is bundled
Threat-intel feeds are operator-chosen; OSV is queried live and opt-in. Built-in signatures are few, marked with their provenance, and flagged "verify" where the source is secondary.
- Why: licences and trust. A bundled feed would carry both risks for every user.

## 6. Dependency vulnerabilities warn, they do not block
A CVE in a library is a different problem from malware. It is a warning at most, shown in the dashboard and not emailed.
- Revisit if: users want to gate merges on critical advisories; make it a policy setting.

## 7. Suppressions expire
Risk acceptance and any suppression of a confirmed signature match must expire. Expiry reopens the finding and writes an audit entry.

## 8. Vanilla JavaScript dashboard, embedded in the Go binary
No framework, no build step, no CDN. Required for a strict CSP and a tiny supply-chain surface.
- Cost: more hand-written UI code.

## 9. Deployment gating is not claimed until verified
No document or UI says a deployment is protected unless a gate is configured and has been exercised.
