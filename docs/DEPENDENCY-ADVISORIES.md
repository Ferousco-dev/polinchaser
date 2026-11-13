# Dependency advisories (OSV)

Off by default. Set `OSV_ENABLED=true` on the worker to turn it on.

## What it does
After the normal scan, the worker reads pinned dependencies from lockfiles in the scanned snapshot
and asks OSV (https://osv.dev) whether any are known to be vulnerable or reported malicious.

Supported files: `package-lock.json` (npm, lockfile v1 to v3), `go.mod` (Go) and `requirements.txt`
(PyPI, `==` pins only). Unpinned ranges, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock` and similar are not read yet.

## Privacy
Enabling this sends **package names, versions and ecosystems** from scanned repositories to the OSV service.
It does not send repository names, file paths, source code or tokens. If your repositories are private
and even their dependency lists are sensitive, leave it off or point `OSV_API_BASE` at a mirror you run.

## How results are reported
- **Vulnerabilities** (`vulnerable_dependency`): severity comes from the advisory when present, otherwise medium.
  They are a different category from malware, and the text says "not evidence of malware".
  They are warnings at most: a dependency vulnerability never fails the check by itself.
  They are shown in the dashboard and not emailed.
- **Malicious-package reports** (`MAL-` advisories, `malicious_dependency`): critical severity, high confidence.
  These are an external report, so they are never labelled `confirmed_signature`. They do block the check and are emailed.
- If OSV cannot be reached, the scan is marked **incomplete** (never clean) with a note that dependency advisories were not checked.

## Limits
- Tested against a local fake of the OSV API only, not the live service. In particular, the Go version format
  (no `v` prefix) follows OSV's documented convention and has not been confirmed against live results.
- Only the first page of results per package is read. Details are fetched for up to 300 advisories per scan;
  further advisories are still reported with unknown severity.
- Transitive dependencies are included only when the lockfile lists them.
- OSV data is published under open licences; check the terms before redistributing any of it.
