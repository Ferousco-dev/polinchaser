# Development

## Requirements
Go 1.27.4 (the `go` line in `go.mod`; newer toolchains download automatically), PostgreSQL 14+.

## Run the tests
Database tests need a throwaway database. Each test gets its own schema and is skipped if the variable is unset.

```bash
createdb polinchaser_test
PC_TEST_DATABASE_URL="postgres:///polinchaser_test?host=/tmp" go test -race ./...
```

Adjust the URL for your Postgres socket or host. Never point it at a database you care about.

## Checks to run before a release
```bash
gofmt -l .
go vet ./...
staticcheck ./...
govulncheck ./...
```

## Run locally
Copy `.env.example` to `.env`, set `DATABASE_URL`, `BASE_URL=http://localhost:8080` and `APP_ENV=development`, export the variables, then:

```bash
go run ./cmd/polinchaser          # web: dashboard, API, webhooks
go run ./cmd/polinchaser-worker   # worker: scans, emails, schedule, retention, feed refresh
go run ./cmd/polinchaser-scan .   # scan a local directory (exit 0 clean, 1 findings, 2 incomplete or failed)
```

Migrations run automatically at start-up. The first passkey needs `ADMIN_SETUP_TOKEN` (32+ characters).
Passkeys work on `http://localhost` but nowhere else over plain http.

## Layout
- `pkg/scanner`: detection engine. No network, no GitHub. Safe to import elsewhere.
- `internal/worker`: scan job handler. `internal/queue`: durable Postgres job queue.
- `internal/webhook`, `internal/github`: GitHub App flow. `internal/notify`: Resend alerts and delivery webhooks.
- `internal/auth`, `internal/dashboard`: passkey auth, dashboard API and embedded UI (`internal/dashboard/web`).
- `internal/scheduler`, `internal/retention`, `internal/intel`, `internal/osv`: background jobs run by the worker.
- `internal/db/migrations`: numbered SQL files applied in order, each in a transaction.

## Rules for contributors
- Test fixtures must be synthetic. Never commit or download real malware.
- Never execute scanned content. Never log tokens, keys, request bodies or payloads.
- A heuristic finding must not be described as confirmed malware. A failed scan must not be shown as clean.
- Third-party signature data needs a licence check before it is included.
- No README files; keep documentation under `docs/`.
