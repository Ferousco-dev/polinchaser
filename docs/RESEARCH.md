# Research notes (Phase 0)

Status: partial. Items marked **verify** come from secondary reporting and must be
checked against primary sources before being relied on for blocking.

## PolinRider (from public reporting, 2026)
Sources: OpenSourceMalware/PolinRider dossier and blog, Socket blog posts
(socket.dev/blog/polinrider-github-packagist), ThaiCERT and Gurucul summaries.

- DPRK-linked campaign (Contagious Interview cluster). Spreads via lure repos, fake
  take-home tasks, typosquatted packages, compromised maintainer accounts.
- Payload: obfuscated JavaScript appended to config files (`postcss.config.mjs`,
  `tailwind.config.js`, `eslint.config.mjs`, `next.config.mjs`, `vite.config.js`,
  `webpack.config.js`, `App.js`) after hundreds of blank lines. **Implemented:** PC-HID-GAP-001.
- Variants: fake `.woff2` files carrying JS; PHP `index.php` using `shell_exec`.
  **Implemented:** PC-HID-MAGIC-001, PC-STA-PHP-001 (heuristic only).
- Persistence: `.vscode/tasks.json` with `runOn: folderOpen`; `temp_auto_push.bat`.
  **Implemented:** PC-PER-VSC-001, PC-PER-BAT-001.
- Loaders reportedly fetch encrypted stage-two from blockchain RPC and XOR-decrypt.
  **Implemented (heuristic):** PC-STA-RPC-001.
- Exact IOCs shipped (rule set builtin-2), checked against the OpenSourceMalware/PolinRider
  README (read in part, not the whole file): markers `rmcej` + `%otb%` (split here on purpose) and `Cot%3t` + `=shtP` (split here on purpose); six
  Vercel C2 hosts; two TRON C2 accounts; two Aptos fallback C2 hashes.
- Removed in builtin-2: `gowreesh-vt.github.io` and `shop.ceenami.com`. They do not appear
  in the dossier text I read, so they were unsupported and could flag unrelated sites.
- Not shipped: SHA-256 file hashes (none seen in the portion read), the npm package names
  (tailwindcss-style-animate and similar; would need a dependency rule), XOR keys, IPs
  (the dossier states none). The unread tail of the README may hold more.
- Reports say git history may be rewritten, so a clean history is not proof of safety.

Not confirmed: the `meSingh/polinrider-scanner` repo named in the brief could not be
found by search; no code or signatures were taken from it.

## Licensing posture
No third-party signature database is bundled. YARA/OSV/GHSA/Gitleaks integrations
must fetch at runtime or be re-implemented; redistribution terms to be checked per source.

## Still to research against official docs before implementing
GitHub App JWT/installation tokens, webhook HMAC (X-Hub-Signature-256), Check Runs
limits (annotations, output size), rulesets/required checks; Render blueprint
(`render.yaml`), background workers, deploy hooks, deploy API; Resend send API,
idempotency keys, webhook signing (Svix).
