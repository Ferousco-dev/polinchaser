# Configuration

All configuration is environment variables, read at startup by `internal/config`.
A bad value stops the process with a clear message. Secrets are masked when the config is logged.
`.env.example` has a template.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | yes | – | Postgres URL. On Neon use the direct host (no `-pooler`) with `sslmode=require`. |
| `BASE_URL` | production | – | Public dashboard URL. https only in production. Passkeys bind to this origin. |
| `APP_ENV` | no | `development` | `production` or `development`. |
| `PORT` | no | `8080` | Render sets this itself. |
| `LOG_LEVEL` | no | `info` | |
| `ADMIN_SETUP_TOKEN` | for first sign-in | – | 32+ chars. Only registers the first passkey. Remove it once you are in. |
| `TRUSTED_PROXY_HOPS` | no | `1` | Reverse proxies before the app (0 to 5). Controls which `X-Forwarded-For` entry is trusted. |
| `GITHUB_APP_ID` | for GitHub | – | Without it the webhook endpoint is disabled. |
| `GITHUB_APP_PRIVATE_KEY` | with app id | – | PEM with `\n` escapes, or base64 of the PEM. |
| `GITHUB_WEBHOOK_SECRET` | with app id | – | Must match the GitHub App's webhook secret. |
| `GITHUB_API_BASE` | no | `https://api.github.com` | For GitHub Enterprise or tests. |
| `RESEND_API_KEY` | for email | – | Without it no alert emails are sent. |
| `EMAIL_FROM` | with Resend | – | A sender on a domain verified in Resend. |
| `RESEND_WEBHOOK_SECRET` | no | – | The `whsec_` signing secret of a Resend webhook pointed at `<BASE_URL>/webhooks/resend`. Without it bounces and complaints are not recorded. |
| `NOTIFY_DEFAULT_RECIPIENTS` | no | – | Comma-separated fallback recipients. |
| `NOTIFY_MIN_SEVERITY` | no | `high` | Lowest severity that triggers an email. |
| `WORKER_CONCURRENCY` | no | `2` | Parallel jobs per worker. |
| `JOB_LEASE` | no | `5m` | How long a worker owns a job before it can be reclaimed. |
| `SCHEDULE_INTERVAL` | no | `24h` | Worker rescans each repository at least this often (min `1h`) or `off`. A repository is also rescanned when the rule version changes. Failed or incomplete scans do not count as coverage and are retried once per interval. |
| `INTEL_FEED_URLS` | no | none | Comma-separated https URLs of threat-intel feeds you chose (see docs/THREAT-INTEL.md). Nothing third-party ships by default. |
| `INTEL_REFRESH_INTERVAL` | no | `6h` | How often feeds are re-fetched (min `15m`) or `off`. |
| `RETENTION_SCAN_DAYS` | no | `180` | Scans older than this (with their occurrences) are deleted. 30 to 3650, or `off`. |
| `RETENTION_AUDIT_DAYS` | no | `365` | Audit rows older than this are deleted. 30 to 3650, or `off`. Other housekeeping (old jobs, webhook deliveries, expired sessions, resolved findings after a year) is fixed. |
| `OSV_ENABLED` | no | `false` | Look up known vulnerabilities and malicious-package reports for pinned dependencies. Sends package names, versions and ecosystems to OSV. See docs/DEPENDENCY-ADVISORIES.md. |
| `OSV_API_BASE` | no | `https://api.osv.dev` | Override for a self-hosted OSV mirror. |
| `SCAN_TIMEOUT` | no | `10m` | Per-scan limit. A timed-out scan is reported as unverified, never clean. |
| `SESSION_SECRET` | no | – | Reserved. Sessions are random tokens stored as hashes, so this is unused today. |

The web service and the worker both read the same variables. The worker needs `DATABASE_URL`,
the GitHub and Resend settings, and `BASE_URL` (used for links in emails).
