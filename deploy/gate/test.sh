#!/usr/bin/env bash
# Tests wait-for-polinchaser.sh against a stubbed `gh`. Run: bash deploy/gate/test.sh
set -u
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail=0
cat > "$tmp/gh" <<'STUB'
#!/usr/bin/env bash
# Emits the check run named in $STUB_RUN (a JSON object) or nothing, ignoring --jq and applying it only for emptiness.
[ -n "${STUB_RUN:-}" ] && printf '%s\n' "$STUB_RUN"
exit 0
STUB
chmod +x "$tmp/gh"
run() { # name expected_exit run_json
  local name="$1" want="$2" json="$3" got
  PATH="$tmp:$PATH" GH_REPO=o/r SHA=abc TIMEOUT_SECONDS=1 INTERVAL_SECONDS=1 STUB_RUN="$json" bash "$here/wait-for-polinchaser.sh" >/dev/null 2>&1
  got=$?
  if [ "$got" -ne "$want" ]; then echo "FAIL $name: exit $got, want $want"; fail=1; else echo "ok   $name"; fi
}
run "success passes"            0 '{"status":"completed","conclusion":"success","output":{"title":"No findings"}}'
run "warnings pass"             0 '{"status":"completed","conclusion":"neutral","output":{"title":"2 warning(s)"}}'
run "incomplete blocks"         1 '{"status":"completed","conclusion":"neutral","output":{"title":"Scan incomplete: some files were not analysed"}}'
run "failure blocks"            1 '{"status":"completed","conclusion":"failure","output":{"title":"Known malware indicator detected"}}'
run "timed_out blocks"          1 '{"status":"completed","conclusion":"timed_out","output":{"title":"Scan timed out"}}'
run "still running times out"   2 '{"status":"in_progress","conclusion":null,"output":{"title":""}}'
run "missing check times out"   2 ''
PATH="$tmp:$PATH" GH_REPO=o/r SHA=abc TIMEOUT_SECONDS=1 INTERVAL_SECONDS=1 ALLOW_WARNINGS=false STUB_RUN='{"status":"completed","conclusion":"neutral","output":{"title":"2 warning(s)"}}' bash "$here/wait-for-polinchaser.sh" >/dev/null 2>&1
if [ $? -eq 1 ]; then echo "ok   warnings blocked when ALLOW_WARNINGS=false"; else echo "FAIL warnings policy"; fail=1; fi
exit $fail
