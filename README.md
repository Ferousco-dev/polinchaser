# PolinChaser

PolinChaser is a self-hosted GitHub App that scans your repositories for signs of malware and supply-chain tampering, then reports the result as a check on each commit. It is written in Go, stores its data in PostgreSQL, and you run it yourself, so your code and scan history stay on infrastructure you control.

It exists because attacks like the PolinRider campaign hide in places review tools skip: payloads appended to build config files after hundreds of blank lines, scripts tucked inside fake font files, and VS Code tasks that run the moment a folder is opened. PolinChaser looks for those patterns and for exact indicators from public reports, and it never runs any code from the repositories it scans.

Status: early. It runs end to end against GitHub, but detection has only been tested on synthetic fixtures, not on real malware samples. See [Limitations](#limitations).

## Quick start

You need Go 1.27 or newer and a local PostgreSQL to try the scanner and tests.

Scan a local folder without GitHub or a database:

```bash
go run ./cmd/polinchaser-scan ./path/to/repo
```

The exit code is 0 for clean, 1 for findings, and 2 when the scan was incomplete, failed or timed out. Add `-json` for machine-readable output.

To run the whole service locally, copy the example settings and start it:

```bash
cp .env.example .env
# set DATABASE_URL (and the GitHub App values, see Configuration)
set -a; . ./.env; set +a
RUN_WORKER=true go run ./cmd/polinchaser
```

The server applies its database migrations on start. Check `http://localhost:8080/readyz`; it reports the database and whether the GitHub App is configured.

## How scanning works

Scans start from four events, and a worker runs them from a PostgreSQL job queue:

- A push to a repository scans the changed files plus build and CI files such as `package.json`, `.vscode/` and workflows.
- A pull request that is opened, updated or reopened is scanned the same way.
- Installing the app, or adding repositories to it, queues a full scan of each repository.
- A scheduler re-scans active repositories every 24 hours with the latest rules. Set `SCHEDULE_INTERVAL=off` to turn it off.

Each result is posted to the commit as a check run named `PolinChaser Security Scan` and saved to the dashboard. Repositories are downloaded as archives and read in memory. Nothing from a repository is executed or written to disk.

A scan ends in one of five states: clean, findings detected, incomplete, timed out, or failed. A scan that could not finish is never reported as clean.

## What it detects

Findings carry a severity and a confidence. Only an exact match against a known indicator is labelled a confirmed signature. Everything else is a heuristic and is described that way.

| Area | Examples |
|---|---|
| Known indicators | PolinRider markers and the command-and-control hosts and blockchain accounts named in the [OpenSourceMalware dossier](https://github.com/OpenSourceMalware/PolinRider) |
| Hidden code | Code after long blank-line gaps, scripts inside font or image files, executables with the wrong extension, NUL bytes in source |
| Persistence | VS Code tasks that run on folder open, automatic task settings, hooks that download code, the `temp_auto_push.bat` script name |
| Secrets | API keys and tokens, with the evidence masked in every output |
| Dependencies | Typosquatted package names, and advisories from OSV if you turn it on |
| CI | Unpinned actions and risky workflow patterns |

The full rule list is on the Detection rules page of the dashboard and in [docs/DETECTION-ENGINE.md](docs/DETECTION-ENGINE.md). Threat-intelligence feeds are opt-in and chosen by the operator; see [docs/THREAT-INTEL.md](docs/THREAT-INTEL.md).

## Deploy

PolinChaser runs as one Docker service with a PostgreSQL database. The steps below are the path that has been tried: Render for hosting and Neon for the database.

1. Create a GitHub App with a webhook URL of `https://your-host/webhooks/github`. It needs read access to Contents, Metadata and Pull requests, and read and write access to Checks. Subscribe it to Push and Pull request events. Download its private key.
2. Create a Neon database and copy the direct connection string, not the pooled one, because migrations and the job queue use features pooling breaks.
3. Create a Render web service from this repository using the `Dockerfile`, with the health check path `/readyz`.
4. Set the environment variables below. Set `RUN_WORKER=true` so the same process runs scans, which lets a single free instance do everything.
5. Open the dashboard, choose first-time setup, enter `ADMIN_SETUP_TOKEN`, and register a passkey. Add a second device from Settings, then remove the token.

Free Render instances sleep when idle, which pauses scans and delays webhooks. Pinging `/healthz` every five minutes keeps the service awake. Full instructions are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Configuration

Settings come from environment variables. `.env.example` lists all of them.

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | PostgreSQL connection string |
| `BASE_URL` | in production | Public https URL; passkeys are bound to this host |
| `APP_ENV` | no | Set to `production` to enforce https and secure cookies |
| `ADMIN_SETUP_TOKEN` | first run | 32 or more characters; allows registering the first passkey |
| `GITHUB_APP_ID` | for scanning | Numeric App ID |
| `GITHUB_APP_PRIVATE_KEY` | for scanning | PEM text, escaped `\n` form, or base64 |
| `GITHUB_WEBHOOK_SECRET` | for scanning | Must match the secret set in the GitHub App |
| `RUN_WORKER` | no | `true` runs the worker inside the web process |
| `TRUSTED_PROXY_HOPS` | no | Number of proxies in front of the server (1 on Render) |
| `RESEND_API_KEY`, `EMAIL_FROM` | for alerts | Alert emails through Resend |
| `NOTIFY_DEFAULT_RECIPIENTS`, `NOTIFY_MIN_SEVERITY` | no | Who gets alerts and the lowest severity that triggers one |
| `OSV_ENABLED` | no | Look up dependency advisories at osv.dev (sends package names and versions) |

More options are covered in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Gating deployments

`deploy/gate/wait-for-polinchaser.sh` and the workflow in `deploy/github-actions/` hold a deploy until the scan check on that commit passes. A missing, failed, timed-out or incomplete result blocks it. The script is tested against a stubbed GitHub CLI only, so treat it as unverified until you have run it on a real repository. See [docs/DEPLOYMENT-GATING.md](docs/DEPLOYMENT-GATING.md).

## Development

```bash
createdb polinchaser_test
PC_TEST_DATABASE_URL="postgres:///polinchaser_test" go test -race ./...
go vet ./...
bash deploy/gate/test.sh
```

Each database test uses its own schema. The layout is:

- `cmd/` holds the web server, the worker and the local scanner.
- `pkg/scanner/` holds the detection engine, with no dependency on GitHub or the database.
- `internal/` holds the GitHub client, webhook handler, job queue, dashboard, passkey authentication and notifications.
- `docs/` holds the architecture, threat model and design decisions.

Use synthetic fixtures in tests. Do not commit real malware.

## Limitations

- Detection has not been tested against real malware samples, only synthetic fixtures. Heuristic findings need a person to look at them.
- Indicators come from public reporting. The PolinRider rules were checked against the OpenSourceMalware dossier, but only part of it was read, and no file hashes are included.
- A clean result is not proof of safety. Attackers can rewrite git history, and the scanner skips files that are too large and reports the scan as incomplete when it does.
- The Resend bounce webhook and the OSV lookups have not been checked against the live services.
- The Docker image build has not been verified in this repository's history.

## Security

Repositories are treated as hostile input. Sign-in uses passkeys only, and webhooks are verified with an HMAC. Evidence and secrets are masked in emails, logs and check output. To report a vulnerability, open a private security advisory on this repository. The design is described in [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Contributing

Open an issue before starting large changes. Run the tests and `go vet` from the Development section before sending a pull request, and add a test for any new rule or behaviour. Rules that match exact indicators must name a public source in their provenance.

## License

MIT. See [LICENSE](LICENSE).
