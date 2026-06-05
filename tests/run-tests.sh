#!/usr/bin/env bash

set -u
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
SCRIPT_PATH="${ROOT_DIR}/mac-diagnostics.sh"
FIXTURE_BIN="${ROOT_DIR}/tests/fixtures/bin"
FAILURES=0
TMP_DIRS=()
GENERATED_REPORTS_DIR="${ROOT_DIR}/reports"

# shellcheck disable=SC2329
cleanup() {
  local dir

  if [[ "${#TMP_DIRS[@]}" -gt 0 ]]; then
    for dir in "${TMP_DIRS[@]}"; do
      rm -rf "$dir"
    done
  fi

  rm -rf "$GENERATED_REPORTS_DIR"
}

trap cleanup EXIT

pass() {
  printf 'PASS %s\n' "$1"
}

fail() {
  printf 'FAIL %s\n' "$1" >&2
  FAILURES=$((FAILURES + 1))
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  local label="$3"

  if grep -Fq -- "$pattern" "$file"; then
    pass "$label"
  else
    fail "$label"
  fi
}

assert_not_contains() {
  local file="$1"
  local pattern="$2"
  local label="$3"

  if grep -Fq -- "$pattern" "$file"; then
    fail "$label"
  else
    pass "$label"
  fi
}

assert_empty() {
  local file="$1"
  local label="$2"

  if [[ ! -s "$file" ]]; then
    pass "$label"
  else
    fail "$label"
  fi
}

assert_occurrences() {
  local file="$1"
  local pattern="$2"
  local expected="$3"
  local label="$4"
  local actual

  actual="$(grep -F -c -- "$pattern" "$file")"
  if [[ "$actual" == "$expected" ]]; then
    pass "$label"
  else
    fail "$label"
  fi
}

make_temp_dir() {
  local dir

  dir="$(mktemp -d "${TMPDIR:-/tmp}/mac-diagnostics-test.XXXXXX")"
  TMP_DIRS+=("$dir")
  printf '%s\n' "$dir"
}

run_with_fixtures() {
  local output_dir="$1"
  shift

  MAC_DIAGNOSTICS_PATH_PREFIX="$FIXTURE_BIN" "$SCRIPT_PATH" --output-dir "$output_dir" "$@" >/dev/null
}

latest_report() {
  local output_dir="$1"

  find "$output_dir" -maxdepth 1 -type f -name 'mac-diagnostics-*.txt' -print | sort | tail -n 1
}

test_syntax_and_lint() {
  if bash -n "$SCRIPT_PATH"; then
    pass "bash syntax check"
  else
    fail "bash syntax check"
  fi

  if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck "$SCRIPT_PATH" "$ROOT_DIR/tests/run-tests.sh" "$FIXTURE_BIN/fixture-command"; then
      pass "shellcheck"
    else
      fail "shellcheck"
    fi
  else
    printf 'SKIP shellcheck (not installed)\n'
  fi
}

test_cli_metadata_commands() {
  local output_dir
  local stdout_file
  local stderr_file

  output_dir="$(make_temp_dir)"
  stdout_file="${output_dir}/help.stdout"
  stderr_file="${output_dir}/help.stderr"

  if "$SCRIPT_PATH" --help >"$stdout_file" 2>"$stderr_file"; then
    pass "help exits successfully"
  else
    fail "help exits successfully"
  fi

  assert_contains "$stdout_file" "Usage: bash mac-diagnostics.sh" "help usage text"
  assert_empty "$stderr_file" "help stderr clean"

  stdout_file="${output_dir}/list.stdout"
  stderr_file="${output_dir}/list.stderr"

  if "$SCRIPT_PATH" --list-checks >"$stdout_file" 2>"$stderr_file"; then
    pass "list-checks exits successfully"
  else
    fail "list-checks exits successfully"
  fi

  assert_contains "$stdout_file" "Available support categories:" "list-checks category text"
  assert_contains "$stdout_file" "storage    disk health clues" "list-checks storage text"
  assert_empty "$stderr_file" "list-checks stderr clean"
}

test_cli_argument_errors() {
  local output_dir
  local stdout_file
  local stderr_file

  output_dir="$(make_temp_dir)"
  stdout_file="${output_dir}/unknown-check.stdout"
  stderr_file="${output_dir}/unknown-check.stderr"

  if "$SCRIPT_PATH" --checks nope >"$stdout_file" 2>"$stderr_file"; then
    fail "unknown check exits with failure"
  else
    pass "unknown check exits with failure"
  fi

  assert_contains "$stderr_file" "unknown diagnostic topic: nope" "unknown check error text"

  stdout_file="${output_dir}/noncanonical-check.stdout"
  stderr_file="${output_dir}/noncanonical-check.stderr"

  if "$SCRIPT_PATH" --checks battery >"$stdout_file" 2>"$stderr_file"; then
    fail "noncanonical topic exits with failure"
  else
    pass "noncanonical topic exits with failure"
  fi

  assert_contains "$stderr_file" "unknown diagnostic topic: battery" "noncanonical topic error text"

  stdout_file="${output_dir}/missing-checks-value.stdout"
  stderr_file="${output_dir}/missing-checks-value.stderr"

  if "$SCRIPT_PATH" --checks >"$stdout_file" 2>"$stderr_file"; then
    fail "missing checks value exits with failure"
  else
    pass "missing checks value exits with failure"
  fi

  assert_contains "$stderr_file" "--checks requires a comma-separated topic list" "missing checks value error text"

  stdout_file="${output_dir}/missing-output-dir.stdout"
  stderr_file="${output_dir}/missing-output-dir.stderr"

  if "$SCRIPT_PATH" --output-dir "${output_dir}/missing" >"$stdout_file" 2>"$stderr_file"; then
    fail "missing output directory exits with failure"
  else
    pass "missing output directory exits with failure"
  fi

  assert_contains "$stderr_file" "output directory does not exist:" "missing output directory error text"
}

test_default_output_dir() {
  local default_output_dir="${ROOT_DIR}/reports/2026-06-01"
  local report

  rm -rf "$GENERATED_REPORTS_DIR"
  MAC_DIAGNOSTICS_PATH_PREFIX="$FIXTURE_BIN" "$SCRIPT_PATH" --checks system >/dev/null
  report="$(latest_report "$default_output_dir")"

  if [[ -f "$report" ]]; then
    pass "default report created in script reports date folder"
  else
    fail "default report created in script reports date folder"
    return
  fi

  assert_contains "$report" "Diagnostic topics: system" "default output report content"
}

test_fixture_findings() {
  local output_dir
  local report

  output_dir="$(make_temp_dir)"
  run_with_fixtures "$output_dir" --checks storage,power,network,stability,updates
  report="$(latest_report "$output_dir")"

  if [[ -f "$report" ]]; then
    pass "fixture report created"
  else
    fail "fixture report created"
    return
  fi

  assert_not_contains "$report" "Report path:" "report omits file path"
  assert_contains "$report" "Startup disk usage: 91% used" "storage usage finding"
  assert_contains "$report" "Maximum Capacity: 76%" "battery capacity finding"
  assert_contains "$report" "Cycle Count: 1201 (At or above model maximum 1000)" "model-specific cycle count finding"
  assert_contains "$report" "Active sleep-prevention assertions: PreventUserIdleSystemSleep" "power assertion finding"
  assert_contains "$report" "Self-assigned IPv4 address: 169.254.10.20" "self-assigned IP finding"
  assert_contains "$report" "Packet loss to apple.com: 10.0%" "packet loss finding"
  assert_contains "$report" "Recent panic reports: 1 in last 7 days" "panic finding"
  assert_contains "$report" "Available updates: macOS Test Update" "software update finding"
  assert_contains "$report" "=== NEEDS ATTENTION ===" "needs attention severity banner"
  assert_contains "$report" "=== WARNING ===" "warning severity banner"
  assert_contains "$report" "=== INFO ===" "info severity banner"
  assert_contains "$report" "Diagnostic result: Startup disk usage: 91% used" "finding uses diagnostic result label"
  assert_contains "$report" "To confirm: Open System Settings > General > Storage" "finding uses confirmation label"
  assert_contains "$report" "Problem: Network configuration or connectivity problem" "issue summary emitted"
  assert_contains "$report" "Evidence: Self-assigned IPv4 address" "issue summary uses evidence label"
  assert_contains "$report" "Risk: Web browsing, iCloud, software updates" "issue summary uses risk label"
  assert_contains "$report" "What to do: Start with the active network service" "issue summary uses action label"
  assert_contains "$report" "Triage note: Active process may be preventing sleep" "power assertion triage note emitted"
}

test_network_dns_linked_evidence() {
  local output_dir
  local report

  output_dir="$(make_temp_dir)"
  MAC_DIAGNOSTICS_FIXTURE_DNS_MISSING=1 MAC_DIAGNOSTICS_PATH_PREFIX="$FIXTURE_BIN" "$SCRIPT_PATH" --output-dir "$output_dir" --checks network >/dev/null
  report="$(latest_report "$output_dir")"

  if [[ -f "$report" ]]; then
    pass "network DNS fixture report created"
  else
    fail "network DNS fixture report created"
    return
  fi

  assert_contains "$report" "DNS servers: none found" "missing DNS finding emitted"
  assert_contains "$report" "corroborating evidence: self-assigned IPv4 address, packet loss 10.0%" "missing DNS links stronger evidence"
}

test_network_dns_check_unavailable() {
  local output_dir
  local report

  output_dir="$(make_temp_dir)"
  MAC_DIAGNOSTICS_FIXTURE_DNS_FAIL=1 MAC_DIAGNOSTICS_FIXTURE_NETWORK_OK=1 MAC_DIAGNOSTICS_PATH_PREFIX="$FIXTURE_BIN" "$SCRIPT_PATH" --output-dir "$output_dir" --checks network >/dev/null
  report="$(latest_report "$output_dir")"

  if [[ -f "$report" ]]; then
    pass "network DNS failure fixture report created"
  else
    fail "network DNS failure fixture report created"
    return
  fi

  assert_contains "$report" "DNS check: unavailable (scutil --dns failed with exit code 1)" "DNS check failure is caveated"
  assert_not_contains "$report" "DNS servers: none found" "DNS failure does not become missing DNS"
  assert_not_contains "$report" "Problem: Network configuration or connectivity problem" "DNS check failure alone does not create network problem"
}

test_fixture_full_deep_run() {
  local output_dir
  local report

  output_dir="$(make_temp_dir)"
  run_with_fixtures "$output_dir" --deep --checks all
  report="$(latest_report "$output_dir")"

  if [[ -f "$report" ]]; then
    pass "full deep fixture report created"
  else
    fail "full deep fixture report created"
    return
  fi

  assert_contains "$report" "Diagnostic topics: system storage power network logs stability updates" "all topics selected"
  assert_contains "$report" "SYSTEM OVERVIEW" "system section"
  assert_contains "$report" "STORAGE" "storage section in full run"
  assert_contains "$report" "POWER AND BATTERY" "power section"
  assert_contains "$report" "NETWORK" "network section in full run"
  assert_contains "$report" "RECENT WARNINGS AND ERRORS" "logs section"
  assert_contains "$report" "SYSTEM STABILITY" "stability section"
  assert_contains "$report" "SOFTWARE UPDATE" "updates section"
  assert_contains "$report" "DEEP SYSTEM" "deep system section"
  assert_contains "$report" "DEEP STORAGE" "deep storage section"
  assert_contains "$report" "DEEP POWER AND BATTERY" "deep power section"
  assert_contains "$report" "DEEP NETWORK" "deep network section"
  assert_contains "$report" "DEEP RECENT LOGS" "deep logs section"
  assert_contains "$report" "DEEP SYSTEM STABILITY" "deep stability section"
  assert_contains "$report" '$ pmset -g sched' "deep power scheduled events command"
  assert_contains "$report" '$ pmset -g log' "deep power log command"
  assert_contains "$report" "[showing last 120 of 125 lines]" "deep power log is bounded"
  assert_not_contains "$report" "power log fixture line 001" "deep power log omits oldest overflow"
  assert_contains "$report" "power log fixture line 125" "deep power log includes recent output"
  assert_occurrences "$report" '$ system_profiler SPPowerDataType' 1 "power profiler command emitted once"
  assert_occurrences "$report" '$ pmset -g assertions' 1 "power assertions command emitted once"
  assert_contains "$report" "macOS Test Update" "dummy software update present"
  assert_contains "$report" "FixtureApp" "dummy log and stability values present"
}

test_redaction() {
  local output_dir
  local report

  output_dir="$(make_temp_dir)"
  run_with_fixtures "$output_dir" --redact --checks system,network,logs,stability
  report="$(latest_report "$output_dir")"

  if [[ -f "$report" ]]; then
    pass "redacted report created"
  else
    fail "redacted report created"
    return
  fi

  assert_contains "$report" "Redaction: enabled" "redaction header"
  assert_contains "$report" "[redacted-serial]" "serial redacted"
  assert_contains "$report" "[redacted-uuid]" "uuid redacted"
  assert_contains "$report" "[redacted-mac]" "MAC address redacted"
  assert_contains "$report" "[redacted-ipv6]" "IPv6 address redacted"
  assert_contains "$report" "[redacted-ipv4]" "IPv4 address redacted"
  assert_contains "$report" "/Users/[redacted-user]" "user path redacted"
  assert_contains "$report" "2026-06-01 12:00:00" "log timestamp preserved"
  assert_not_contains "$report" "ABC123SECRET" "raw serial absent"
  assert_not_contains "$report" "AA:BB:CC:DD:EE:FF" "raw MAC absent"
  assert_not_contains "$report" "fe80::aede:48ff:fe00:1122%en0" "raw IPv6 absent"
  assert_not_contains "$report" "192.168.50.25" "raw IPv4 absent"
  assert_not_contains "$report" "fixtureuser" "raw username absent"

  case "$(basename "$report")" in
    *fixtureuser*|*"Fixture_Support_Mac"*)
      fail "redacted filename avoids user and Mac name"
      ;;
    *)
      pass "redacted filename avoids user and Mac name"
      ;;
  esac
}

test_integration_sections() {
  local output_dir
  local report

  output_dir="$(make_temp_dir)"
  run_with_fixtures "$output_dir" --checks storage,network
  report="$(latest_report "$output_dir")"

  if [[ -f "$report" ]]; then
    pass "integration report created"
  else
    fail "integration report created"
    return
  fi

  assert_contains "$report" "REPORT SUMMARY" "summary section"
  assert_contains "$report" "FINDINGS" "findings section"
  assert_contains "$report" "POTENTIAL ISSUES" "potential issues section"
  assert_contains "$report" "STORAGE" "storage section"
  assert_contains "$report" "NETWORK" "network section"
  assert_contains "$report" "-- STORAGE --" "findings subsection style"
  assert_contains "$report" '$ df -h' "raw storage command"
  assert_contains "$report" '$ ifconfig' "raw network command"
}

test_syntax_and_lint
test_cli_metadata_commands
test_cli_argument_errors
test_default_output_dir
test_fixture_findings
test_network_dns_linked_evidence
test_network_dns_check_unavailable
test_fixture_full_deep_run
test_redaction
test_integration_sections

if [[ "$FAILURES" -eq 0 ]]; then
  printf 'All tests passed.\n'
  exit 0
fi

printf '%s test(s) failed.\n' "$FAILURES" >&2
exit 1
