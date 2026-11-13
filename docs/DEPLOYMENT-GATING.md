# Deployment gating

**Status: NOT VERIFIED.** The script is tested against a stubbed `gh` only (`bash deploy/gate/test.sh`). It has not run against a real check run.

## How it works
1. The GitHub App scans each push and posts a check run named `PolinChaser Security Scan`.
2. `deploy/github-actions/polinchaser-gate.yml` runs `deploy/gate/wait-for-polinchaser.sh` on the commit.
3. Pass: `success`, or `neutral` with a title containing "warning" (when `ALLOW_WARNINGS=true`). Anything else blocks (exit 1). No finished check before the timeout exits 2.
4. Optional `deploy` job posts to the Render deploy hook only after the gate passes. Set `autoDeploy: false` on the Render services (already the default in `render.yaml`).

Render's own `checksPass` trigger is not relied on: the check run appears asynchronously, so it can race.

## Verify before trusting it
1. Install the app on a test repo and add the workflow.
2. Push a clean commit: the job must pass.
3. Push a synthetic fixture that triggers a high-severity rule: the job must fail and no deploy may happen.
4. Suspend the app or stop the worker and push: the job must exit 2 after the timeout.
Only after all three behave may this be called active.
