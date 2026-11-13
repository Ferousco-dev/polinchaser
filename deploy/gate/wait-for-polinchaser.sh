#!/usr/bin/env bash
# Waits for the PolinChaser check run on a commit and decides whether a deployment may proceed.
# Exit 0: the scan finished and is safe to deploy. Exit 1: blocked. Exit 2: no result (timeout or check missing).
# Never passes on a missing, running, failed, timed-out or incomplete scan.
#
# Environment: GH_REPO (owner/name), SHA (commit). Optional: CHECK_NAME (default "PolinChaser Security Scan"),
# TIMEOUT_SECONDS (900), INTERVAL_SECONDS (15), ALLOW_WARNINGS (true: a "warnings" result may pass).
set -euo pipefail

: "${GH_REPO:?GH_REPO is required}"
: "${SHA:?SHA is required}"
CHECK_NAME="${CHECK_NAME:-PolinChaser Security Scan}"
TIMEOUT="${TIMEOUT_SECONDS:-900}"
INTERVAL="${INTERVAL_SECONDS:-15}"
ALLOW_WARNINGS="${ALLOW_WARNINGS:-true}"
deadline=$(( $(date +%s) + TIMEOUT ))

while :; do
  run=$(gh api "repos/${GH_REPO}/commits/${SHA}/check-runs?per_page=100" \
    --jq "[.check_runs[] | select(.name==\"${CHECK_NAME}\")] | sort_by(.started_at) | last // empty" 2>/dev/null || true)

  if [ -n "$run" ]; then
    status=$(jq -r '.status' <<<"$run")
    if [ "$status" = "completed" ]; then
      conclusion=$(jq -r '.conclusion' <<<"$run")
      title=$(jq -r '.output.title // ""' <<<"$run" | tr -d '\r\n' | cut -c1-200)
      case "$conclusion" in
        success)
          echo "PolinChaser: ${title:-passed}"; exit 0 ;;
        neutral)
          # "neutral" means either warnings or an incomplete scan. Only warnings may pass.
          if [ "$ALLOW_WARNINGS" = "true" ] && [[ "$title" == *warning* ]] && [[ "$title" != *ncomplete* ]]; then
            echo "PolinChaser: ${title} (warnings allowed)"; exit 0
          fi
          echo "::error::PolinChaser did not verify this commit: ${title:-neutral}"; exit 1 ;;
        *)
          echo "::error::PolinChaser blocked this commit (${conclusion}): ${title}"; exit 1 ;;
      esac
    fi
  fi

  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "::error::No finished '${CHECK_NAME}' check for ${SHA} after ${TIMEOUT}s. The scanner may be down or the GitHub App is not installed on this repository. Not deploying."
    exit 2
  fi
  sleep "$INTERVAL"
done
