# HTTP API

All JSON. Errors look like `{"error":"message"}`. Dashboard endpoints need a signed-in session cookie, and every
non-GET request must send an `Origin` header equal to `BASE_URL`. Responses always carry `X-Robots-Tag: noindex`.

## Public
| Method and path | Purpose |
|---|---|
| `GET /healthz` | Process is up. |
| `GET /readyz` | Database reachable; returns queue depth. 503 when the database is down. |
| `POST /webhooks/github` | GitHub App events. Verified by `X-Hub-Signature-256`. 503 if the app is not configured. |
| `POST /webhooks/resend` | Resend delivery events (bounce, complaint). Verified by Svix signature headers. 503 if `RESEND_WEBHOOK_SECRET` is unset. |
| `GET /robots.txt` | `Disallow: /`. |

## Authentication (`/api/auth/*`)
| Method and path | Auth | Purpose |
|---|---|---|
| `GET /api/auth/status` | none | Whether first-time setup is available. |
| `POST /api/auth/login/begin`, `/login/finish` | none, rate limited | Passkey sign-in (discoverable credentials). |
| `POST /api/auth/setup/begin`, `/setup/finish` | setup token, rate limited | Register the first passkey. Refused once any passkey exists. |
| `POST /api/auth/enroll/begin`, `/enroll/finish` | one-time link token, rate limited | Register another device. |
| `GET /api/auth/me` | session | Current passkey id. |
| `POST /api/auth/logout` | session | End the session. |
| `GET /api/auth/passkeys`, `DELETE /api/auth/passkeys/{id}` | session | List and remove passkeys. The last one cannot be removed. |
| `POST /api/auth/enroll-link` | session | Create a one-time 10-minute enrollment link. |

## Dashboard data (session required)
| Method and path | Notes |
|---|---|
| `GET /api/overview` | Counts, severity breakdown, recent scans. |
| `GET /api/repositories` | |
| `GET /api/scans`, `GET /api/scans/{id}` | Filter `status`; `limit` (max 100) and `offset`. |
| `GET /api/findings`, `GET /api/findings/{id}` | Filters `severity`, `confidence`, `status`, `category`, `repo_id`, `q`. Unknown filter values return 400. |
| `PATCH /api/findings/{id}` | Body `{status, reason, expires_in_days}`. Suppressing needs a reason of 10+ characters. Risk acceptance and any suppression of a confirmed signature match must expire (max 365 and 90 days). Audited. |
| `GET /api/observability?days=7..90` | Zero-filled daily series for charts. |
| `GET /api/intel` | Built-in signatures and external feed status (hosts only, never full URLs). |
| `GET /api/system` | Queue, integrations, email delivery counts including bounces. |
| `GET /api/audit` | |
| `GET /api/installations`, `PUT /api/installations/{id}/notifications` | Alert recipients and minimum severity. Recipients are validated as plain addresses. |

Anything else under `/api/` or `/webhooks/` that does not exist returns 404 JSON, never the app shell.
