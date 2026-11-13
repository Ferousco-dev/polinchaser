# Threat-intelligence feeds

PolinChaser ships a small built-in signature set. You can add exact-match signatures
from feeds you choose. **No third-party feed is included or enabled by default.** You are
responsible for checking that you may use a feed's data; every feed must declare its license,
and the dashboard shows it under Detection rules.

## What a feed can do
- Add exact indicators only: a substring (8 to 512 bytes) or a whole-file SHA-256.
- A match is reported as `confirmed_signature`, labelled with the feed it came from.
- A feed cannot add heuristics, change policy, or alter built-in rules (`PC-` ids are reserved).

## What happens on refresh
- The worker fetches each feed on `INTEL_REFRESH_INTERVAL` (default 6h) using a conditional request.
- Feeds are validated strictly (unknown fields, bad severities, duplicate ids and oversized files are rejected).
- A failed or invalid refresh keeps the previous signatures and records the error in the dashboard.
- Feeds dropped from `INTEL_FEED_URLS` stop applying at the next worker start or refresh.
- When the active set changes, the rule version changes (`builtin-2+intel.<hash>`), and the scheduler
  rescans repositories under the new rules.

## Safety
- Feed URLs come from your environment, never from repository content.
- The fetcher refuses loopback, private, link-local and carrier-grade-NAT addresses (checked when connecting),
  allows https redirects only, caps size at 2 MiB, and times out after 20 seconds.
- Feed URLs are not shown in full in the dashboard or stored errors (only the host), because a URL can carry a token.
- A feed is trusted to say what is malicious. A bad or compromised feed can cause false positives that block merges.
  Review what you subscribe to, and prefer feeds you can verify.

## Feed format (version 1)
```json
{
  "format": 1,
  "name": "My team's indicators",
  "license": "CC0-1.0",
  "signatures": [
    {
      "id": "ACME-0001",
      "family": "ExampleFamily",
      "substring": "an-exact-string-seen-in-the-malware",
      "severity": "critical",
      "provenance": "Internal incident 2026-03, analyst name"
    },
    {
      "id": "ACME-0002",
      "family": "ExampleFamily",
      "sha256": "<64 lowercase hex characters>",
      "severity": "high",
      "provenance": "Vendor report URL"
    }
  ]
}
```

## Limits and status
- Tested against a local test server only. Not tested against any real feed.
- Hostname-based indicators are plain substrings; there is no URL or domain normalisation.
- At most 10 feeds and 5000 signatures per feed.
