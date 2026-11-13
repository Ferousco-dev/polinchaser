# Threat model

PolinChaser reads repositories it does not control and tells people whether code looks malicious.
That makes it a target and a risk in itself. This document lists who might attack it, what they
want, and what stops them. Status words are literal: **Done** means implemented and covered by a test.
**Partial** and **Open** mean there is a gap.

## Assets
1. Source code of connected repositories (private repos included), held only in memory during a scan.
2. GitHub App private key and installation tokens.
3. Operator access to the dashboard (passkeys, sessions).
4. Findings, which describe weaknesses in customers' code.
5. The trustworthiness of results: a false "clean" is worse than a false alarm.

## Actors
- **Hostile repository author**: controls every byte of scanned content, file names, tarball structure, commit metadata.
- **Internet attacker**: can reach the public web service, webhook endpoint and login page.
- **Webhook forger**: pretends to be GitHub.
- **Network or feed attacker**: tampers with or poisons threat-intel feeds.
- **Phisher**: tries to capture the operator's sign-in.
- **Curious or malicious tenant**: only relevant if PolinChaser is ever run for several organisations.

## Threats and controls

| # | Threat | Control | Status |
|---|---|---|---|
| 1 | Scanned code is executed | The scanner only reads bytes. No `exec`, no `eval`, no package installs, no repository scripts. | Done (by design; no code path runs repo content) |
| 2 | Malicious tarball (path traversal, symlinks, zip-bomb, huge entries) | In-memory extraction only, never to disk. Limits: 200 MiB compressed, 1 GiB expanded, 100000 entries, 2 MiB kept per file. Unsafe paths and links are skipped and reported, which makes the scan `incomplete` rather than clean. | Done |
| 3 | A scan that fails is shown as safe | Statuses are explicit: `incomplete`, `failed`, `timed_out`. Check Runs and the dashboard never call these clean. | Done |
| 4 | Heuristic hit presented as proof | Only exact signatures can be `confirmed_signature`. Severity and confidence are separate fields. | Done |
| 5 | Forged webhooks | HMAC-SHA256 over the raw body, constant-time compare, 25 MiB cap, delivery-ID dedupe. | Done |
| 6 | Webhook names another tenant's repo | Repository must belong to the installation named in the payload; unknown ones are ignored. Repo names are validated before use in API URLs. | Done |
| 7 | SSRF through redirects (GitHub tarball) | Redirects limited to GitHub hosts over https, max 3. | Done |
| 8 | SSRF through feed URLs | Feed URLs come from operator config only. The client refuses loopback, private, link-local and CGNAT addresses at connect time, https-only redirects, 2 MiB cap, 20s timeout. | Done |
| 9 | Poisoned feed causes mass false positives | Strict schema, 8-byte minimum substring, reserved `PC-` ids, exact matches only, every signature carries its feed. A feed is still trusted to say what is malicious. | Partial: operator must vet feeds |
| 10 | Dashboard takeover by password attack | There are no passwords. Passkey (WebAuthn) only. | Done |
| 11 | First-passkey hijack | Registering the first passkey needs `ADMIN_SETUP_TOKEN`, and setup closes permanently once a passkey exists. | Done |
| 12 | Enrollment-link theft | One-time, 10-minute link, token in the URL fragment (never sent to servers or logs), consumed atomically. | Done |
| 13 | Phishing the passkey | Credentials are bound to the exact origin; a wrong origin fails. | Done (tested with a software authenticator) |
| 14 | Cloned authenticator | Sign-count regression is rejected. | Done |
| 15 | CSRF | `SameSite=Strict` cookie plus an Origin check on every non-GET request. | Done |
| 16 | XSS in the dashboard | Strict CSP (`script-src 'self'`, no inline script or style), all dynamic text set via `textContent`, no `innerHTML`. | Done |
| 17 | Session theft | Random 256-bit tokens, only a SHA-256 stored, HttpOnly, Secure and `__Host-` prefix on https, 12h absolute and 2h idle expiry. | Done |
| 18 | Brute force of login and setup | Per-IP sliding-window rate limit; `X-Forwarded-For` trusted only for the configured proxy hop count. | Done |
| 19 | Secrets leaking into findings, logs or email | Evidence is masked. Config prints with secrets redacted. Emails and check output carry no payloads. No request-body logging. | Done |
| 20 | SQL injection | All queries parameterised; filters validated against allow-lists. A test attempts injection through filters. | Done |
| 21 | Search-engine exposure of the dashboard | `X-Robots-Tag: noindex...` on every response, `robots.txt` disallow, meta tag. | Done |
| 22 | Dependency and toolchain vulnerabilities | `govulncheck` is clean as of Go 1.27.4. | Done at time of writing; must be re-run |
| 23 | Database growth from unauthenticated traffic (audit rows, challenges, webhook deliveries) | Rate limits bound the rate. Retention purge. | Partial until the retention job lands |
| 24 | Operator account compromise via lost device | Remove a passkey from Settings; the last passkey cannot be removed. No recovery path other than server access. | Partial: no recovery flow by design |
| 25 | Check Run annotations leak sensitive code | Annotations hold the finding title, explanation, rule id, path and line. They include no code excerpt. | Done |

## Not covered
- Malware that does not match a signature or heuristic. Detection is limited to what is implemented; see `docs/DETECTION-ENGINE.md`.
- Compromise of the host (Render, Neon, GitHub). Secrets live in environment variables there.
- Multi-tenant use. The dashboard is a single-operator console that sees every installation. Do not give it to untrusted users.
- Denial of service by a flood of valid webhooks. Jobs are queued durably, but there is no per-installation quota.
- A malicious GitHub App owner changing permissions after install.

## Residual risks to watch
- Third-party indicators in the built-in set are marked "secondary reporting; verify". Verify them against primary sources before relying on them.
- No end-to-end test with real GitHub, Resend or Render has been run.
