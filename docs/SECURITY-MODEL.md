# Security model

How PolinChaser is built to behave. Read with `THREAT-MODEL.md`.

## Principles
1. **Repositories are hostile input.** Content is read as bytes, in memory, with hard limits. Nothing from a repository is executed, installed, written to disk or followed as a link.
2. **No false comfort.** Anything the scanner could not fully inspect is reported as incomplete, failed or timed out. It is never shown as clean.
3. **Say what you know.** Only an exact signature match is a confirmed finding. Heuristics are labelled as heuristics. Severity (how bad) and confidence (how sure) are separate.
4. **Don't carry secrets around.** Evidence is masked before it is stored. Emails and Check Run output omit payloads. Logs omit request bodies, tokens and keys.
5. **Least trust at every boundary.** Webhooks are verified, repositories are checked against their installation, feed URLs come only from the operator, and every external fetch has size, time and address limits.

## Authentication and sessions
- Operator sign-in is passkey-only (WebAuthn, user verification required). There are no accounts and no passwords.
- First passkey: requires `ADMIN_SETUP_TOKEN`. Setup is refused once any passkey exists.
- Extra devices: a signed-in operator creates a one-time link valid for 10 minutes. The token travels in the URL fragment, is stored hashed, and is consumed in the same transaction as the registration.
- Sessions: random token, only its SHA-256 stored, cookie `HttpOnly`, `SameSite=Strict`, `Secure` and `__Host-` on https. 12-hour maximum, 2-hour idle timeout. Removing a passkey signs out its sessions.
- Non-GET requests must carry an `Origin` equal to `BASE_URL`.
- Login, setup and enrollment endpoints are rate limited per client IP.

## Data
- Source code is never stored. Findings store rule, path, line, a masked excerpt and a fingerprint.
- Only SHA-256 hashes of session and enrollment tokens are stored.
- Installation tokens are cached in memory only. The GitHub private key is read from the environment and never written or logged.
- Every suppression, passkey change, settings change and failed sign-in is written to the audit log. Suppressing a finding requires a reason.

## Web hardening
- Strict CSP with no inline script or style and no external origins. `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, a restrictive `Permissions-Policy`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, HSTS.
- Request bodies are size-limited on every endpoint. HTTP server timeouts are set.
- The dashboard sends `noindex` on every response.

## Supply chain
- Go modules are pinned by `go.sum`. Run `govulncheck ./...` and `staticcheck ./...` before releases.
- The Docker image uses a distroless, non-root base. The image build has not been exercised yet.

## Reporting a vulnerability
Do not open a public issue for a security problem. Contact the maintainers privately (set a contact address in the repository's security policy before publishing it).
