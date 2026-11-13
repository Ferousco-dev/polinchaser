# Detection engine (`pkg/scanner`)

Pure Go, no network, no GitHub types, never executes scanned content.

Pipeline: `Source.Walk` (enforces path safety, per-file/total/count limits, no symlinks,
skips `.git`) → each `Detector.Detect(File)` → dedupe by fingerprint → sort by severity.

Result status: `clean`, `findings_detected`, `incomplete` (any skip or truncation),
`timed_out`, `failed`. A scan that was cut short is never `clean`.

| Detector | Rules | Confidence ceiling |
|---|---|---|
| signature | exact substring / SHA-256 from `RuleSet` | confirmed_signature (only source of it) |
| hidden_payload | blank-line gap, NUL bytes, magic-byte mismatch, disguised executables | high |
| static | decoded-eval, PS cradles, pipe-to-shell, child_process, WS-to-IP, RPC loader, `_0x` obfuscation, cred-read+network | high (heuristic) |
| persistence | VS Code folderOpen tasks, automatic tasks, git hooks, `.npmrc` registry, Dockerfile | high |
| secrets | AWS, GitHub, private keys, Slack, Stripe, Resend, Render, DB URLs (masked) | high |
| dependencies | npm lifecycle scripts, URL deps, typosquats, pip extra index | medium |
| actions | unpinned actions, injection, pull_request_target, write-all, pipe-to-shell | high (never known_malware) |

Not yet implemented: YARA, Semgrep, Gitleaks integration, AST analysis, OSV/GHSA lookups
(must live outside this package), lockfile diffing, Go/Cargo/Maven/Gradle/Gem/Composer manifests.
