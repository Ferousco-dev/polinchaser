# Deployment (Render + Neon)

Status: written but not executed. Nothing here has been deployed or tested against real
Render, Neon, GitHub or Resend. The Docker image build has not been run yet either.
Check each step as you go.

## Pieces
- **Neon**: PostgreSQL.
- **Render**: `polinchaser-web` (dashboard, API, webhook) and `polinchaser-worker` (scans, emails), from `render.yaml`.
- **GitHub App**: you create and publish it.
- **Resend**: sends alerts from a domain you verify.

## 1. Neon
1. Create a project and database.
2. Copy the **direct** connection string (host without `-pooler`). It must end in `sslmode=require`.
   The pooler runs in transaction mode, which breaks the migration lock and queue locking.
3. Neon suspends idle compute. A running worker polls the queue, which keeps it awake. A cron job
   that calls `GET /readyz` (it pings the database) also wakes it. Pick one rhythm and keep it modest.

## 2. Dashboard domain
Use a subdomain such as `chaser.yourdomain.com`. Point it at the Render web service and set
`BASE_URL=https://chaser.yourdomain.com`. Passkeys are tied to this host: changing it later
invalidates every registered passkey.

## 3. GitHub App (you do this)
- Webhook URL: `<BASE_URL>/webhooks/github`. Webhook secret: a long random string, also set as `GITHUB_WEBHOOK_SECRET`.
- Repository permissions: Contents (read), Metadata (read), Checks (read and write), Pull requests (read).
- Events: Push, Pull request, Installation, Installation repositories.
- Generate a private key, then set `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY`.
- Keep the app private until you have tested it on your own repositories.

## 4. Resend
Verify a sending domain, create an API key, set `RESEND_API_KEY` and `EMAIL_FROM`.

## 5. Render
1. Review `render.yaml`. `autoDeploy` is off on purpose.
2. Create the Blueprint, then fill in every `sync: false` value in the dashboard.
3. Generate `ADMIN_SETUP_TOKEN` with `openssl rand -base64 36`.
4. Deploy. Migrations run automatically at boot (guarded by an advisory lock).
5. Check `https://<your domain>/readyz` returns `{"status":"ready"}`.

## 6. First sign-in
1. Open the dashboard on your Mac. Choose "First-time setup", enter the setup token, register the Touch ID passkey.
2. Sign in with it.
3. In Settings choose "Add a device", open the one-time link on your phone within 10 minutes, and register.
4. Delete `ADMIN_SETUP_TOKEN` from Render. Setup is already closed once a passkey exists, so this is extra safety.

## Open items before relying on this
- Run `docker build .` locally. The base image tag `golang:1.27.1` is unverified.
- Confirm `TRUSTED_PROXY_HOPS=1` matches what Render's proxy actually sends.
- Run one real push through the GitHub App and confirm a scan, a finding and an email.
