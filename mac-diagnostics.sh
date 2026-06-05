#!/usr/bin/env bash

set -u
set -o pipefail

SCRIPT_NAME="$(basename "$0")"
DEEP_MODE=0
REDACT_MODE=0
OUTPUT_DIR=""
REPORT_PATH=""
REPORT_BASE_PATH=""
SELECTED_TOPICS=""

# Tests can inject fixture commands ahead of real macOS tools without losing the
# standard system command paths the script expects on a normal Mac.
PATH="${MAC_DIAGNOSTICS_PATH_PREFIX:+${MAC_DIAGNOSTICS_PATH_PREFIX}:}/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"
LOG_TIMEOUT_SECONDS=45
COMMAND_TIMEOUT_SECONDS=60
SOFTWAREUPDATE_TIMEOUT_SECONDS=60
DEEP_COMMAND_TIMEOUT_SECONDS=90
POWER_LOG_LINE_LIMIT=120
LOG_TOP_LIMIT=10
LOG_RECENT_LIMIT=25
STARTUP_DISK_USAGE_WARNING_LIMIT=85
STARTUP_DISK_USAGE_ATTENTION_LIMIT=90
STARTUP_DISK_FREE_WARNING_GB_LIMIT=25
STARTUP_DISK_FREE_ATTENTION_GB_LIMIT=15
BATTERY_CAPACITY_INFO_LIMIT=85
BATTERY_CAPACITY_WARNING_LIMIT=80
BATTERY_CAPACITY_ATTENTION_LIMIT=70
BATTERY_CYCLE_INFO_PERCENT=80
PACKET_LOSS_PING_COUNT=20
PACKET_LOSS_ATTENTION_LIMIT=5
FINDINGS_FOUND=0
CURRENT_FINDINGS_FILE=""
FINDING_INDEX_FILE=""
POTENTIAL_ISSUES_FILE=""
ISSUE_SUMMARY_IDS_FILE=""
POWER_PROFILER_OUTPUT_FILE=""
POWER_PROFILER_STATUS=""
POWER_ASSERTIONS_OUTPUT_FILE=""
POWER_ASSERTIONS_STATUS=""
STABILITY_PANIC_REPORTS_FILE=""
STABILITY_PANIC_STATUS=""
STABILITY_CRASH_REPORTS_FILE=""
STABILITY_CRASH_STATUS=""
STABILITY_HANG_REPORTS_FILE=""
STABILITY_HANG_STATUS=""
SOFTWAREUPDATE_OUTPUT_FILE=""
SOFTWAREUPDATE_STATUS=""
TEMP_FILES=()

# Keep temporary-file ownership centralized so signal handling and normal exits
# clean up the same set of paths.
make_temp_file() {
  local variable_name="$1"
  local template="$2"
  local path

  path="$(mktemp "$template")" || return 1
  TEMP_FILES+=("$path")
  printf -v "$variable_name" '%s' "$path"
}

cleanup_temp_files() {
  local file

  if [[ "${#TEMP_FILES[@]}" -eq 0 ]]; then
    return
  fi

  for file in "${TEMP_FILES[@]}"; do
    rm -f "$file"
  done
}

handle_exit_signal() {
  local status="$1"

  cleanup_temp_files
  exit "$status"
}

trap cleanup_temp_files EXIT
trap 'handle_exit_signal 130' INT
trap 'handle_exit_signal 143' TERM

usage() {
  cat <<USAGE
Usage: bash ${SCRIPT_NAME} [--deep] [--redact] [--checks <list>] [--output-dir <path>] [--help]

Collect text diagnostics for this Mac and save them to a timestamped report.

Options:
  --checks <list>      Run only specific diagnostic topics. Use comma-separated values.
                       Example: --checks storage,network
  --deep               Include slower, more detailed diagnostics for selected topics.
  --redact             Redact common device, network, username, and path identifiers in the report.
  --list-checks        Show available diagnostic topics.
  --output-dir <path>  Save the report in a specific directory.
  --help               Show this help message.
USAGE
}

error() {
  printf 'Error: %s\n' "$*" >&2
}

list_checks() {
  cat <<CHECKS
Available support categories:
  system     inventory baseline: macOS version, uptime, hardware summary
  storage    disk health clues: usage, layout, APFS/root volume details
  power      battery and charging: power source, health, power settings
  network    connectivity: services, interfaces, DNS, routing, packet loss
  logs       recent evidence: warning/error log summary
  stability  reliability: recent reboot, panic, crash, and hang reports
  updates    maintenance: Apple software update availability
CHECKS
}

sanitize_filename_part() {
  local value="${1:-unknown}"

  value="$(printf '%s' "$value" | tr -c '[:alnum:]._- ' '_' | tr ' ' '_')"
  value="$(printf '%s' "$value" | sed 's/_\{2,\}/_/g; s/^_//; s/_$//')"

  if [[ -z "$value" ]]; then
    printf 'unknown'
  else
    printf '%s' "$value"
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Stream redaction keeps reports from being loaded into memory and lets the same
# filter apply to command output, cached files, and generated header text.
redact_text() {
  perl -pe '
    s#(Current user:).*#$1 [redacted-user]#g;
    s#(Computer name:).*#$1 [redacted-computer-name]#g;
    s#(Local host name:).*#$1 [redacted-local-hostname]#g;
    s#(Hostname:).*#$1 [redacted-hostname]#g;
    s#(Serial Number([[:space:]]*\([^)]*\))?:)[[:space:]]*[^[:space:]]+#$1 [redacted-serial]#g;
    s#(Provisioning UDID:)[[:space:]]*[^[:space:]]+#$1 [redacted-udid]#g;
    s#[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}#[redacted-uuid]#g;
    s#([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}#[redacted-mac]#g;
    s{(?<![[:alnum:]_.-])(?=[[:xdigit:]:]*:)(?=(?:[[:xdigit:]]*:){3,}|[[:xdigit:]:]*::)[[:xdigit:]:]+(?:%[[:alnum:]_.-]+)?(?![[:alnum:]_.-])}{[redacted-ipv6]}gx;
    s#([0-9]{1,3}\.){3}[0-9]{1,3}#[redacted-ipv4]#g;
    s#/Users/[[:alnum:]_.-]+#/Users/[redacted-user]#g;
  '
}

append_report_text() {
  if [[ "$REDACT_MODE" -eq 1 ]]; then
    redact_text >>"$REPORT_PATH"
  else
    cat >>"$REPORT_PATH"
  fi
}

append_report_file() {
  local input_file="$1"

  if [[ "$REDACT_MODE" -eq 1 ]]; then
    redact_text <"$input_file" >>"$REPORT_PATH"
  else
    cat "$input_file" >>"$REPORT_PATH"
  fi
}

append_command_line() {
  {
    printf '\n'
    printf '$'
    printf ' %q' "$@"
    printf '\n'
  } | append_report_text
}

# Cache slow or stateful command output to avoid rerunning.
append_cached_command_output() {
  local label="$1"
  local status="$2"
  local output_file="$3"
  shift 3

  append_command_line "$@"

  if [[ -f "$output_file" ]]; then
    append_report_file "$output_file"
  fi

  if [[ "$status" -eq 124 ]]; then
    printf '[command timed out]\n' >>"$REPORT_PATH"
  elif [[ "$status" -eq 127 && ! -s "$output_file" ]]; then
    printf '[command unavailable: %s]\n' "$1" >>"$REPORT_PATH"
  elif [[ "$status" -ne 0 ]]; then
    printf '[command failed with exit code %s]\n' "$status" >>"$REPORT_PATH"
  fi

  printf '\n' >>"$REPORT_PATH"
  printf '  - %s\n' "$label"
}

# Some diagnostics can trigger system-level issues or become unresponsive. Attempt
# graceful termination first, but force kill if the process does not exit in a reasonable time.
terminate_process() {
  local pid="$1"
  local grace_seconds=0

  kill "$pid" 2>/dev/null
  while kill -0 "$pid" 2>/dev/null && [[ "$grace_seconds" -lt 5 ]]; do
    sleep 1
    grace_seconds=$((grace_seconds + 1))
  done

  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null
  fi
}

join_lines_with_comma() {
  awk 'NF { if (out) out = out ", " $0; else out = $0 } END { print out }'
}

join_lines_with_semicolon() {
  awk 'NF { if (out) out = out "; " $0; else out = $0 } END { print out }'
}

is_number_above() {
  local value="$1"
  local threshold="$2"

  awk -v value="$value" -v threshold="$threshold" 'BEGIN { exit !(value > threshold) }'
}

normalize_topic() {
  local topic="$1"

  topic="$(printf '%s' "$topic" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]' | tr '_' '-')"

  case "$topic" in
    all)
      printf 'all'
      ;;
    system)
      printf 'system'
      ;;
    storage)
      printf 'storage'
      ;;
    power)
      printf 'power'
      ;;
    network)
      printf 'network'
      ;;
    logs)
      printf 'logs'
      ;;
    stability)
      printf 'stability'
      ;;
    updates)
      printf 'updates'
      ;;
    *)
      return 1
      ;;
  esac
}

select_all_topics() {
  SELECTED_TOPICS=" system storage power network logs stability updates "
}

add_selected_topic() {
  local raw_topic="$1"
  local topic

  if [[ -z "$raw_topic" ]]; then
    error "empty diagnostic topic in --checks"
    exit 1
  fi

  if ! topic="$(normalize_topic "$raw_topic")"; then
    error "unknown diagnostic topic: $raw_topic"
    printf '\n' >&2
    list_checks >&2
    exit 1
  fi

  if [[ "$topic" == "all" ]]; then
    select_all_topics
    return
  fi

  if [[ " ${SELECTED_TOPICS} " != *" ${topic} "* ]]; then
    SELECTED_TOPICS="${SELECTED_TOPICS} ${topic} "
  fi
}

add_selected_topics() {
  local topics="$1"
  local topic

  while [[ "$topics" == *,* ]]; do
    topic="${topics%%,*}"
    add_selected_topic "$topic"
    topics="${topics#*,}"
  done

  add_selected_topic "$topics"
}

topic_selected() {
  local topic="$1"

  [[ " ${SELECTED_TOPICS} " == *" ${topic} "* ]]
}

selected_topics_label() {
  printf '%s' "$SELECTED_TOPICS" | awk '{$1=$1; print}'
}

# Diagnostic commands can block on permissions, system services, or network
# state. The wrapper records output and exit status while a watcher enforces the
# timeout from outside the child process.
run_command_with_timeout_to_file() {
  local output_file="$1"
  local timeout_seconds="$2"
  local write_mode="$3"
  local pid
  local timeout_marker
  local status_file
  local watcher_pid
  local status
  shift 3

  if [[ "$write_mode" != "append" && "$write_mode" != "replace" ]]; then
    error "internal error: unknown output write mode: $write_mode"
    return 2
  fi

  if ! command_exists "$1"; then
    if [[ "$write_mode" == "append" ]]; then
      printf '[command unavailable: %s]\n' "$1" >>"$output_file"
    else
      printf '[command unavailable: %s]\n' "$1" >"$output_file"
    fi
    return 127
  fi

  make_temp_file timeout_marker "${TMPDIR:-/tmp}/mac-diagnostics-timeout.XXXXXX"
  make_temp_file status_file "${TMPDIR:-/tmp}/mac-diagnostics-status.XXXXXX"

  (
    if [[ "$write_mode" == "append" ]]; then
      "$@" >>"$output_file" 2>&1 &
    else
      "$@" >"$output_file" 2>&1 &
    fi
    child_pid=$!
    trap 'kill "$child_pid" 2>/dev/null; sleep 1; kill -KILL "$child_pid" 2>/dev/null; exit 124' TERM INT
    wait "$child_pid"
    child_status=$?
    printf '%s\n' "$child_status" >"$status_file"
    exit 0
  ) 2>>"$output_file" &
  pid=$!

  (
    sleep "$timeout_seconds"
    if kill -0 "$pid" 2>/dev/null; then
      printf 'timed out\n' >"$timeout_marker"
      terminate_process "$pid"
    fi
  ) &
  watcher_pid=$!

  wait "$pid"
  status=$?
  kill "$watcher_pid" 2>/dev/null
  wait "$watcher_pid" 2>/dev/null

  if [[ -s "$timeout_marker" ]]; then
    status=124
  elif [[ -s "$status_file" ]]; then
    status="$(cat "$status_file")"
  fi

  rm -f "$timeout_marker"
  rm -f "$status_file"

  return "$status"
}

capture_command_with_timeout() {
  local output_file="$1"
  local timeout_seconds="$2"
  shift 2

  run_command_with_timeout_to_file "$output_file" "$timeout_seconds" replace "$@"
}

run_for_value() {
  local fallback="$1"
  shift
  local output

  if output="$("$@" 2>/dev/null)"; then
    printf '%s' "$output"
  else
    printf '%s' "$fallback"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --deep)
        DEEP_MODE=1
        shift
        ;;
      --redact)
        REDACT_MODE=1
        shift
        ;;
      --checks)
        if [[ $# -lt 2 || -z "${2:-}" ]]; then
          error "$1 requires a comma-separated topic list"
          exit 1
        fi
        add_selected_topics "$2"
        shift 2
        ;;
      --list-checks)
        list_checks
        exit 0
        ;;
      --output-dir)
        if [[ $# -lt 2 || -z "${2:-}" ]]; then
          error "--output-dir requires a path"
          exit 1
        fi
        OUTPUT_DIR="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        error "unknown option: $1"
        usage >&2
        exit 1
        ;;
    esac
  done
}

validate_output_dir() {
  if [[ ! -d "$OUTPUT_DIR" ]]; then
    error "output directory does not exist: $OUTPUT_DIR"
    exit 1
  fi

  if [[ ! -w "$OUTPUT_DIR" ]]; then
    error "output directory is not writable: $OUTPUT_DIR"
    exit 1
  fi
}

resolve_script_dir() {
  local source_path="${BASH_SOURCE[0]:-$0}"
  local dir

  if [[ "$source_path" != /* ]]; then
    source_path="${PWD}/${source_path}"
  fi

  dir="$(cd "$(dirname "$source_path")" >/dev/null 2>&1 && pwd -P)"
  if [[ -z "$dir" ]]; then
    error "could not determine script directory"
    exit 1
  fi

  printf '%s' "$dir"
}

set_default_output_dir() {
  local script_dir
  local report_date

  script_dir="$(resolve_script_dir)"
  report_date="$(date '+%Y-%m-%d')"
  OUTPUT_DIR="${script_dir}/reports/${report_date}"

  if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
    error "could not create default report directory: $OUTPUT_DIR"
    error "Use --output-dir <path> to choose a writable location."
    exit 1
  fi
}

build_report_path() {
  local timestamp
  local user_name
  local mac_name
  local safe_user
  local safe_mac
  local counter

  timestamp="$(date '+%Y-%m-%d-%H%M%S')"
  user_name="$(id -un 2>/dev/null || whoami 2>/dev/null || printf 'unknown-user')"
  mac_name="$(scutil --get ComputerName 2>/dev/null || hostname 2>/dev/null || printf 'unknown-mac')"
  if [[ "$REDACT_MODE" -eq 1 ]]; then
    safe_user="redacted-user"
    safe_mac="redacted-mac"
  else
    safe_user="$(sanitize_filename_part "$user_name")"
    safe_mac="$(sanitize_filename_part "$mac_name")"
  fi

  REPORT_BASE_PATH="${OUTPUT_DIR}/mac-diagnostics-${timestamp}-${safe_user}-${safe_mac}"
  REPORT_PATH="${REPORT_BASE_PATH}.txt"
  counter=2

  while [[ -e "$REPORT_PATH" ]]; do
    REPORT_PATH="${REPORT_BASE_PATH}-${counter}.txt"
    counter=$((counter + 1))
  done
}

create_report_file() {
  local counter=2

  while true; do
    if (set -C; : >"$REPORT_PATH") 2>/dev/null; then
      return 0
    fi

    if [[ -e "$REPORT_PATH" ]]; then
      REPORT_PATH="${REPORT_BASE_PATH}-${counter}.txt"
      counter=$((counter + 1))
    else
      return 1
    fi
  done
}

# Primary report sections use full-width separators.
# Nested findings topics use lighter subsection headers.
write_section_header() {
  local title="$1"

  {
    printf '\n'
    printf '================================================================\n'
    printf '%s\n' "$title"
    printf '================================================================\n'
  } >>"$REPORT_PATH"
}

write_subsection_header() {
  local title="$1"

  {
    printf '\n'
    printf -- '-- %s --\n' "$title"
    printf -- '----------------------------------------------------------------\n'
  } >>"$REPORT_PATH"
}

section() {
  local title="$1"

  write_section_header "$title"
  printf 'Collecting: %s\n' "$title"
}

append_kv() {
  local key="$1"
  local value="$2"

  printf '%s: %s\n' "$key" "$value" | append_report_text
}

append_command() {
  local label="$1"
  shift

  append_command_with_timeout "$label" "$COMMAND_TIMEOUT_SECONDS" "$@"
}

append_command_with_line_limit() {
  local label="$1"
  local timeout_seconds="$2"
  local line_limit="$3"
  local status
  local command_available=1
  local output_file
  local line_count
  shift 3

  {
    printf '\n'
    printf '$'
    printf ' %q' "$@"
    printf '\n'
  } | append_report_text

  if ! command_exists "$1"; then
    command_available=0
  fi

  make_temp_file output_file "${TMPDIR:-/tmp}/mac-diagnostics-command.XXXXXX"
  run_command_with_timeout_to_file "$output_file" "$timeout_seconds" replace "$@"
  status=$?

  line_count="$(wc -l <"$output_file" | awk '{ print $1 }')"
  if [[ "$line_count" =~ ^[0-9]+$ && "$line_count" -gt "$line_limit" ]]; then
    printf '[showing last %s of %s lines]\n' "$line_limit" "$line_count" | append_report_text
    tail -n "$line_limit" "$output_file" | append_report_text
  else
    append_report_file "$output_file"
  fi

  rm -f "$output_file"

  if [[ "$status" -eq 124 ]]; then
    printf '[command timed out after %s seconds]\n' "$timeout_seconds" >>"$REPORT_PATH"
  elif [[ "$status" -ne 0 && "$command_available" -eq 1 ]]; then
    printf '[command failed with exit code %s]\n' "$status" >>"$REPORT_PATH"
  fi

  printf '\n' >>"$REPORT_PATH"
  printf '  - %s\n' "$label"
}

append_command_with_timeout() {
  local label="$1"
  local timeout_seconds="$2"
  local status
  local command_available=1
  local output_file="$REPORT_PATH"
  local write_mode="append"
  local command_output_file=""
  shift 2

  {
    printf '\n'
    printf '$'
    printf ' %q' "$@"
    printf '\n'
  } | append_report_text

  if ! command_exists "$1"; then
    command_available=0
  fi

  if [[ "$REDACT_MODE" -eq 1 ]]; then
    make_temp_file command_output_file "${TMPDIR:-/tmp}/mac-diagnostics-command.XXXXXX"
    output_file="$command_output_file"
    write_mode="replace"
  fi

  run_command_with_timeout_to_file "$output_file" "$timeout_seconds" "$write_mode" "$@"
  status=$?

  if [[ "$REDACT_MODE" -eq 1 ]]; then
    append_report_file "$command_output_file"
    rm -f "$command_output_file"
  fi

  if [[ "$status" -eq 124 ]]; then
    printf '[command timed out after %s seconds]\n' "$timeout_seconds" >>"$REPORT_PATH"
  elif [[ "$status" -ne 0 && "$command_available" -eq 1 ]]; then
    printf '[command failed with exit code %s]\n' "$status" >>"$REPORT_PATH"
  fi

  printf '\n' >>"$REPORT_PATH"
  printf '  - %s\n' "$label"
}

append_log_show() {
  local label="$1"
  local last_window="$2"
  local predicate="$3"
  local log_output_file
  local status

  {
    printf '\n'
    printf '$ log show --style syslog --last %s --predicate %q\n' "$last_window" "$predicate"
  } | append_report_text

  make_temp_file log_output_file "${TMPDIR:-/tmp}/mac-diagnostics-log.XXXXXX"
  run_command_with_timeout_to_file "$log_output_file" "$LOG_TIMEOUT_SECONDS" replace log show --style syslog --last "$last_window" --predicate "$predicate"
  status=$?

  if [[ "$status" -eq 124 ]]; then
    printf '[command timed out after %s seconds]\n' "$LOG_TIMEOUT_SECONDS" >>"$REPORT_PATH"
  elif [[ "$status" -ne 0 ]]; then
    append_report_file "$log_output_file"
    if [[ "$status" -ne 127 ]]; then
      printf '[command failed with exit code %s]\n' "$status" >>"$REPORT_PATH"
    fi
  else
    append_log_summary "$log_output_file"
  fi

  rm -f "$log_output_file"
  printf '\n' >>"$REPORT_PATH"
  printf '  - %s\n' "$label"
}

# Normalize timestamps and process IDs so repeated messages group together.
append_log_summary() {
  local log_file="$1"

  awk -v top_limit="$LOG_TOP_LIMIT" -v recent_limit="$LOG_RECENT_LIMIT" '
    function normalized(line, value) {
      value = line
      sub(/^[0-9-]+ [0-9:.+-]+[[:space:]]+[^[:space:]]+[[:space:]]+/, "", value)
      gsub(/\[[0-9]+\]/, "[pid]", value)
      return value
    }

    {
      total += 1
      key = normalized($0)
      if (!(key in count)) {
        unique += 1
        first[key] = $0
        order[unique] = key
      }
      count[key] += 1
    }

    END {
      printf("Total matching log entries: %d\n", total)
      printf("Unique normalized messages: %d\n", unique)

      if (total == 0) {
        print "No matching log entries found."
        exit
      }

      print ""
      print "Top repeated messages:"
      for (rank = 1; rank <= top_limit; rank += 1) {
        max_count = 0
        max_key = ""
        for (i = 1; i <= unique; i += 1) {
          key = order[i]
          if (!seen[key] && count[key] > max_count) {
            max_count = count[key]
            max_key = key
          }
        }

        if (max_key == "") {
          break
        }

        seen[max_key] = 1
        printf("[%d occurrences] %s\n", max_count, first[max_key])
      }

      print ""
      print "Recent unique examples:"
      printed = 0
      for (i = unique; i >= 1 && printed < recent_limit; i -= 1) {
        key = order[i]
        print first[key]
        printed += 1
      }
    }
  ' "$log_file" | append_report_text
}

severity_banner() {
  local severity="$1"

  case "$severity" in
    info)
      printf '=== INFO ==='
      ;;
    warning)
      printf '=== WARNING ==='
      ;;
    "needs attention")
      printf '=== NEEDS ATTENTION ==='
      ;;
    *)
      printf '=== %s ===' "$(printf '%s' "$severity" | tr '[:lower:]' '[:upper:]')"
      ;;
  esac
}

# Findings describe observed diagnostic results. The index file keeps findings
# available for the later POTENTIAL ISSUES summary.
emit_finding_code() {
  local code="$1"
  local severity="$2"
  local diagnostic="$3"
  local confirmation="$4"

  if [[ -n "$CURRENT_FINDINGS_FILE" ]]; then
    {
      severity_banner "$severity"
      printf '\n'
      printf 'Diagnostic result: %s\n' "$diagnostic"
      printf 'To confirm: %s\n' "$confirmation"
      printf '\n'
    } >>"$CURRENT_FINDINGS_FILE"
  fi

  if [[ -n "$FINDING_INDEX_FILE" ]]; then
    printf '%s\t%s\t%s\t%s\n' "$code" "$severity" "$diagnostic" "$confirmation" >>"$FINDING_INDEX_FILE"
  fi
}

has_finding_code() {
  local code="$1"

  [[ -n "$FINDING_INDEX_FILE" && -f "$FINDING_INDEX_FILE" ]] || return 1
  awk -F '\t' -v code="$code" '$1 == code { found = 1; exit } END { exit !found }' "$FINDING_INDEX_FILE"
}

finding_texts_for_codes() {
  local code

  [[ -n "$FINDING_INDEX_FILE" && -f "$FINDING_INDEX_FILE" ]] || return

  for code in "$@"; do
    awk -F '\t' -v code="$code" '$1 == code { print $3 }' "$FINDING_INDEX_FILE"
  done | join_lines_with_semicolon
}

run_findings_topic() {
  local title="$1"
  local finder="$2"
  local findings_file

  make_temp_file findings_file "${TMPDIR:-/tmp}/mac-diagnostics-findings.XXXXXX"
  CURRENT_FINDINGS_FILE="$findings_file"
  "$finder"
  CURRENT_FINDINGS_FILE=""

  if [[ -s "$findings_file" ]]; then
    write_subsection_header "$title"
    append_report_file "$findings_file"
    FINDINGS_FOUND=1
  fi

  rm -f "$findings_file"
}

# - Startup disk usage >= 85%: warning
# - Startup disk usage >= 90%: needs attention
# - Startup disk free space < 25 GB: warning
# - Startup disk free space < 15 GB: needs attention
find_storage_findings() {
  local df_values
  local usage_percent
  local free_kb
  local free_gb
  local free_warning_threshold_kb
  local free_attention_threshold_kb
  local usage_severity
  local usage_threshold
  local free_severity
  local free_threshold_gb

  df_values="$(df -Pk / 2>/dev/null | awk 'NR == 2 { gsub(/%/, "", $5); print $5, $4 }')"
  usage_percent="${df_values%% *}"
  free_kb="${df_values##* }"
  free_warning_threshold_kb=$((STARTUP_DISK_FREE_WARNING_GB_LIMIT * 1024 * 1024))
  free_attention_threshold_kb=$((STARTUP_DISK_FREE_ATTENTION_GB_LIMIT * 1024 * 1024))

  if [[ "$usage_percent" =~ ^[0-9]+$ ]] && [[ "$usage_percent" -ge "$STARTUP_DISK_USAGE_WARNING_LIMIT" ]]; then
    usage_severity="warning"
    usage_threshold="$STARTUP_DISK_USAGE_WARNING_LIMIT"
    if [[ "$usage_percent" -ge "$STARTUP_DISK_USAGE_ATTENTION_LIMIT" ]]; then
      usage_severity="needs attention"
      usage_threshold="$STARTUP_DISK_USAGE_ATTENTION_LIMIT"
    fi

    emit_finding_code \
      "storage_usage_high" \
      "$usage_severity" \
      "Startup disk usage: ${usage_percent}% used (At or above ${usage_threshold}%)" \
      "Open System Settings > General > Storage or rerun df -h / and confirm startup disk usage is still above the threshold."
  fi

  if [[ "$free_kb" =~ ^[0-9]+$ ]] && [[ "$free_kb" -lt "$free_warning_threshold_kb" ]]; then
    free_gb="$(awk -v kb="$free_kb" 'BEGIN { printf "%.1f", kb / 1048576 }')"
    free_severity="warning"
    free_threshold_gb="$STARTUP_DISK_FREE_WARNING_GB_LIMIT"
    if [[ "$free_kb" -lt "$free_attention_threshold_kb" ]]; then
      free_severity="needs attention"
      free_threshold_gb="$STARTUP_DISK_FREE_ATTENTION_GB_LIMIT"
    fi

    emit_finding_code \
      "storage_free_low" \
      "$free_severity" \
      "Startup disk free space: ${free_gb} GB (Below ${free_threshold_gb} GB)" \
      "Open System Settings > General > Storage or rerun df -h / and confirm startup disk free space is still below the threshold."
  fi
}

ensure_power_profiler_cache() {
  local timeout_seconds="$COMMAND_TIMEOUT_SECONDS"

  if [[ -n "$POWER_PROFILER_OUTPUT_FILE" ]]; then
    return
  fi

  if [[ "$DEEP_MODE" -eq 1 ]]; then
    timeout_seconds="$DEEP_COMMAND_TIMEOUT_SECONDS"
  fi

  make_temp_file POWER_PROFILER_OUTPUT_FILE "${TMPDIR:-/tmp}/mac-diagnostics-power.XXXXXX"
  capture_command_with_timeout "$POWER_PROFILER_OUTPUT_FILE" "$timeout_seconds" system_profiler SPPowerDataType
  POWER_PROFILER_STATUS=$?
}

ensure_power_assertions_cache() {
  if [[ -n "$POWER_ASSERTIONS_OUTPUT_FILE" ]]; then
    return
  fi

  make_temp_file POWER_ASSERTIONS_OUTPUT_FILE "${TMPDIR:-/tmp}/mac-diagnostics-power-assertions.XXXXXX"
  capture_command_with_timeout "$POWER_ASSERTIONS_OUTPUT_FILE" "$COMMAND_TIMEOUT_SECONDS" pmset -g assertions
  POWER_ASSERTIONS_STATUS=$?
}

# Different Mac models have different battery cycle limits.
battery_cycle_limit_for_model_identifier() {
  local model_identifier="$1"

  case "$model_identifier" in
    MacBookAir1,1)
      printf '300'
      ;;
    MacBookAir2,1)
      printf '500'
      ;;
    MacBookPro1,*|MacBookPro2,*|MacBookPro3,*|MacBookPro4,*)
      printf '300'
      ;;
    MacBookPro5,1)
      printf '500'
      ;;
    MacBookPro*)
      printf '1000'
      ;;
    MacBookAir*|Mac[0-9]*,*)
      printf '1000'
      ;;
    MacBook5,1)
      printf '500'
      ;;
    MacBook1,*|MacBook2,*|MacBook3,*|MacBook4,*|MacBook5,2)
      printf '300'
      ;;
    MacBook*)
      printf '1000'
      ;;
  esac
}

# Prefer the system-reported cycle limit, then fall back to the model table.
determine_battery_cycle_limit() {
  local profiler_limit
  local model_identifier

  profiler_limit="$(awk -F': ' '/^[[:space:]]*Maximum Cycle Count:/ { gsub(/[^0-9]/, "", $2); print $2; exit }' "$POWER_PROFILER_OUTPUT_FILE")"
  if [[ "$profiler_limit" =~ ^[0-9]+$ && "$profiler_limit" -gt 0 ]]; then
    printf '%s' "$profiler_limit"
    return
  fi

  model_identifier="$(run_for_value '' sysctl -n hw.model)"
  battery_cycle_limit_for_model_identifier "$model_identifier"
}

# - Battery condition other than Normal: needs attention
# - Battery maximum capacity < 85%: info
# - Battery maximum capacity < 80%: warning
# - Battery maximum capacity < 70%: needs attention
# - Cycle count >= 80% of model maximum: info
# - Cycle count >= model maximum: warning
# - Active sleep-prevention assertions: info
find_power_battery_findings() {
  local condition
  local maximum_capacity
  local cycle_count
  local cycle_limit
  local cycle_info_threshold
  local capacity_severity
  local capacity_detail
  local active_sleep_assertions
  local assertion_processes
  local assertion_detail

  ensure_power_profiler_cache
  if [[ "$POWER_PROFILER_STATUS" -eq 0 && -s "$POWER_PROFILER_OUTPUT_FILE" ]]; then
    condition="$(awk -F': ' '/^[[:space:]]*Condition:/ { print $2; exit }' "$POWER_PROFILER_OUTPUT_FILE")"
    if [[ -n "$condition" && "$condition" != "Normal" ]]; then
      emit_finding_code \
        "battery_condition_not_normal" \
        "needs attention" \
        "Condition: $condition" \
        "Check Battery Health in System Settings > Battery and compare it with System Information > Power."
    fi

    maximum_capacity="$(awk -F': ' '/^[[:space:]]*Maximum Capacity:/ { gsub(/%/, "", $2); print $2; exit }' "$POWER_PROFILER_OUTPUT_FILE")"
    if [[ "$maximum_capacity" =~ ^[0-9]+$ ]] && [[ "$maximum_capacity" -lt "$BATTERY_CAPACITY_INFO_LIMIT" ]]; then
      capacity_severity="info"
      capacity_detail="Near ${BATTERY_CAPACITY_WARNING_LIMIT}% battery service threshold"
      if [[ "$maximum_capacity" -lt "$BATTERY_CAPACITY_WARNING_LIMIT" ]]; then
        capacity_severity="warning"
        capacity_detail="Below ${BATTERY_CAPACITY_WARNING_LIMIT}% battery service threshold"
      fi
      if [[ "$maximum_capacity" -lt "$BATTERY_CAPACITY_ATTENTION_LIMIT" ]]; then
        capacity_severity="needs attention"
        capacity_detail="Well below ${BATTERY_CAPACITY_WARNING_LIMIT}% battery service threshold"
      fi

      emit_finding_code \
        "battery_capacity_low" \
        "$capacity_severity" \
        "Maximum Capacity: ${maximum_capacity}% (${capacity_detail})" \
        "Check Maximum Capacity in Battery Health or System Information > Power and compare it with reported runtime symptoms."
    fi

    cycle_count="$(awk -F': ' '/^[[:space:]]*Cycle Count:/ { gsub(/[^0-9]/, "", $2); print $2; exit }' "$POWER_PROFILER_OUTPUT_FILE")"
    cycle_limit="$(determine_battery_cycle_limit)"
    if [[ "$cycle_count" =~ ^[0-9]+$ && "$cycle_limit" =~ ^[0-9]+$ && "$cycle_limit" -gt 0 ]]; then
      cycle_info_threshold=$(((cycle_limit * BATTERY_CYCLE_INFO_PERCENT + 99) / 100))

      if [[ "$cycle_count" -ge "$cycle_limit" ]]; then
        emit_finding_code \
          "battery_cycle_high" \
          "warning" \
          "Cycle Count: ${cycle_count} (At or above model maximum ${cycle_limit})" \
          "Check Cycle Count in System Information > Power and verify the model-specific maximum cycle count."
      elif [[ "$cycle_count" -ge "$cycle_info_threshold" ]]; then
        emit_finding_code \
          "battery_cycle_near_limit" \
          "info" \
          "Cycle Count: ${cycle_count} (At or above ${BATTERY_CYCLE_INFO_PERCENT}% of model maximum ${cycle_limit})" \
          "Check Cycle Count in System Information > Power and compare it with the model-specific maximum cycle count."
      fi
    elif [[ "$cycle_count" =~ ^[0-9]+$ && "$cycle_count" -gt 0 ]]; then
      emit_finding_code \
        "battery_cycle_limit_unknown" \
        "info" \
        "Cycle Count: ${cycle_count} (Model-specific cycle limit unavailable)" \
        "Look up the Mac model in Apple's cycle count table and compare it with System Information > Power."
    fi
  fi

  ensure_power_assertions_cache
  if [[ "$POWER_ASSERTIONS_STATUS" -ne 0 || ! -s "$POWER_ASSERTIONS_OUTPUT_FILE" ]]; then
    return
  fi

  active_sleep_assertions="$(awk '
    /^[[:space:]]*(PreventSystemSleep|PreventUserIdleSystemSleep|PreventUserIdleDisplaySleep)[[:space:]]+[1-9][0-9]*[[:space:]]*$/ {
      print $1
    }
  ' "$POWER_ASSERTIONS_OUTPUT_FILE" | join_lines_with_comma)"

  if [[ -n "$active_sleep_assertions" ]]; then
    assertion_processes="$(awk '
      /^Listed by owning process:/ { in_processes = 1; next }
      /^Kernel Assertions:/ { in_processes = 0 }
      in_processes && /^[[:space:]]*pid [0-9]+\(/ {
        value = $0
        sub(/^[[:space:]]*pid [0-9]+\(/, "", value)
        sub(/\):.*/, "", value)
        if (value != "" && !seen[value]++) print value
      }
    ' "$POWER_ASSERTIONS_OUTPUT_FILE" | join_lines_with_comma)"

    assertion_detail="Active sleep-prevention assertions: ${active_sleep_assertions}"
    if [[ -n "$assertion_processes" ]]; then
      assertion_detail="${assertion_detail} (Processes: ${assertion_processes})"
    fi

    emit_finding_code \
      "sleep_prevention_assertions_active" \
      "info" \
      "$assertion_detail" \
      "Run pmset -g assertions while the symptom is happening and confirm whether the listed process still holds a sleep-prevention assertion."
  fi
}

# - DNS servers missing: warning
# - DNS servers missing plus stronger network evidence: needs attention
# - DNS check unavailable: warning
# - Default route missing: needs attention
# - Self-assigned IPv4 address: needs attention
# - Active VPN/tunnel interface: info
# - Packet loss > 0% across 20 pings: warning
# - Packet loss > 5% across 20 pings: needs attention
# - Packet loss unable to determine: warning
find_network_findings() {
  local dns_output
  local dns_status
  local dns_servers
  local dns_missing=0
  local dns_severity="warning"
  local dns_diagnostic
  local route_output
  local route_status
  local default_gateway
  local default_route_missing=0
  local ifconfig_output
  local self_assigned_ips
  local active_tunnels
  local linked_network_evidence=""
  local ping_output
  local ping_status
  local packet_loss
  local packet_loss_severity=""
  local packet_loss_detail=""

  dns_output="$(scutil --dns 2>&1)"
  dns_status=$?
  dns_servers="$(printf '%s\n' "$dns_output" | awk '/nameserver\[[0-9]+\]/ { if (!seen[$3]++) print $3 }' | join_lines_with_comma)"
  if [[ "$dns_status" -eq 0 && -z "$dns_servers" ]]; then
    dns_missing=1
  fi

  route_output="$(route -n get default 2>&1)"
  route_status=$?
  default_gateway="$(printf '%s\n' "$route_output" | awk '/gateway:/ { print $2; exit }')"
  if [[ "$route_status" -ne 0 || -z "$default_gateway" ]] && [[ "$route_output" != *"Operation not permitted"* ]]; then
    default_route_missing=1
    linked_network_evidence="default route missing"
  fi

  ifconfig_output="$(ifconfig 2>/dev/null)"
  self_assigned_ips="$(printf '%s\n' "$ifconfig_output" | awk '/inet 169\.254\./ { print $2 }' | join_lines_with_comma)"
  if [[ -n "$self_assigned_ips" ]]; then
    if [[ -n "$linked_network_evidence" ]]; then
      linked_network_evidence="${linked_network_evidence}, self-assigned IPv4 address"
    else
      linked_network_evidence="self-assigned IPv4 address"
    fi
  fi

  active_tunnels="$(printf '%s\n' "$ifconfig_output" | awk -F: '/^(utun[0-9]+|tun[0-9]+|tap[0-9]+|ppp[0-9]+):/ && $0 ~ /<[^>]*UP[^>]*>/ { print $1 }' | sort -u | join_lines_with_comma)"

  ping_output="$(ping -c "$PACKET_LOSS_PING_COUNT" -W 1000 apple.com 2>&1)"
  ping_status=$?
  packet_loss="$(printf '%s\n' "$ping_output" | awk -F, '/packet loss/ {
    for (i = 1; i <= NF; i += 1) {
      if ($i ~ /packet loss/) {
        gsub(/^[[:space:]]+/, "", $i)
        sub(/% packet loss.*/, "", $i)
        print $i
        exit
      }
    }
  }')"

  if [[ -n "$packet_loss" ]]; then
    if is_number_above "$packet_loss" "$PACKET_LOSS_ATTENTION_LIMIT"; then
      packet_loss_severity="needs attention"
      packet_loss_detail="Above ${PACKET_LOSS_ATTENTION_LIMIT}% across ${PACKET_LOSS_PING_COUNT} pings"
      if [[ -n "$linked_network_evidence" ]]; then
        linked_network_evidence="${linked_network_evidence}, packet loss ${packet_loss}%"
      else
        linked_network_evidence="packet loss ${packet_loss}%"
      fi
    elif is_number_above "$packet_loss" 0; then
      packet_loss_severity="warning"
      packet_loss_detail="Any packet loss detected across ${PACKET_LOSS_PING_COUNT} pings"
    fi
  fi

  if [[ "$dns_missing" -eq 1 ]]; then
    dns_diagnostic="DNS servers: none found (Expected: at least one DNS resolver)"
    if [[ -n "$linked_network_evidence" ]]; then
      dns_severity="needs attention"
      dns_diagnostic="${dns_diagnostic}; corroborating evidence: ${linked_network_evidence}"
    fi

    emit_finding_code \
      "dns_missing" \
      "$dns_severity" \
      "$dns_diagnostic" \
      "Check the active Network service and run scutil --dns to confirm at least one expected DNS resolver is present."
  elif [[ "$dns_status" -ne 0 ]]; then
    emit_finding_code \
      "dns_check_unavailable" \
      "warning" \
      "DNS check: unavailable (scutil --dns failed with exit code ${dns_status})" \
      "Run scutil --dns again from a normal Terminal session or check DNS servers in Network settings."
  fi

  if [[ "$default_route_missing" -eq 1 ]]; then
    emit_finding_code \
      "default_route_missing" \
      "needs attention" \
      "Default route: missing (Expected: one active default route)" \
      "Run route -n get default or inspect Network settings and confirm the active service has a router."
  fi

  if [[ -n "$self_assigned_ips" ]]; then
    emit_finding_code \
      "self_assigned_ip" \
      "needs attention" \
      "Self-assigned IPv4 address: $self_assigned_ips (Expected: DHCP/router-assigned address)" \
      "Check Network settings or ifconfig and confirm the active interface still has a 169.254.x.x IPv4 address."
  fi

  if [[ -n "$active_tunnels" ]]; then
    emit_finding_code \
      "active_tunnel_interfaces" \
      "info" \
      "Active VPN/tunnel interfaces: $active_tunnels (May affect routing or DNS)" \
      "Check VPN, private relay, or security software status and confirm whether the listed tunnel interface is expected."
  fi

  if [[ -n "$packet_loss_severity" ]]; then
    emit_finding_code \
      "packet_loss_high" \
      "$packet_loss_severity" \
      "Packet loss to apple.com: ${packet_loss}% (${packet_loss_detail})" \
      "Rerun a packet-loss test from a normal network and confirm whether loss persists with VPN or filtering software disabled."
  elif [[ "$ping_status" -ne 0 ]]; then
    emit_finding_code \
      "packet_loss_unknown" \
      "warning" \
      "Packet loss to apple.com: unable to determine (Expected: successful ${PACKET_LOSS_PING_COUNT}-packet sample)" \
      "Confirm DNS and internet access manually, then rerun the packet-loss check from a normal unrestricted network."
  fi
}

# Panic, crash, and hang report paths are used for counts, examples, and raw
# report output. Cache each search once so those views stay consistent.
ensure_stability_reports_cache() {
  if [[ -n "$STABILITY_PANIC_REPORTS_FILE" ]]; then
    return
  fi

  make_temp_file STABILITY_PANIC_REPORTS_FILE "${TMPDIR:-/tmp}/mac-diagnostics-panics.XXXXXX"
  find /Library/Logs/DiagnosticReports "${HOME}/Library/Logs/DiagnosticReports" \
    -type f \( -iname '*panic*' -o -name '*.panic' \) -mtime -7 -print >"$STABILITY_PANIC_REPORTS_FILE" 2>/dev/null
  STABILITY_PANIC_STATUS=$?

  make_temp_file STABILITY_CRASH_REPORTS_FILE "${TMPDIR:-/tmp}/mac-diagnostics-crashes.XXXXXX"
  find /Library/Logs/DiagnosticReports "${HOME}/Library/Logs/DiagnosticReports" \
    -type f -name '*.crash' -mtime -1 -print >"$STABILITY_CRASH_REPORTS_FILE" 2>/dev/null
  STABILITY_CRASH_STATUS=$?

  make_temp_file STABILITY_HANG_REPORTS_FILE "${TMPDIR:-/tmp}/mac-diagnostics-hangs.XXXXXX"
  find /Library/Logs/DiagnosticReports "${HOME}/Library/Logs/DiagnosticReports" \
    -type f -name '*.hang' -mtime -1 -print >"$STABILITY_HANG_REPORTS_FILE" 2>/dev/null
  STABILITY_HANG_STATUS=$?
}

report_count_from_file() {
  local report_file="$1"

  wc -l <"$report_file" | awk '{ print $1 }'
}

report_names_from_file() {
  local report_file="$1"
  local max_examples="$2"

  sed 's|.*/||' "$report_file" |
    head -n "$max_examples" |
    join_lines_with_comma
}

severity_for_recent_report_count() {
  local count="$1"

  if [[ "$count" -ge 5 ]]; then
    printf 'needs attention'
  elif [[ "$count" -ge 2 ]]; then
    printf 'warning'
  else
    printf 'info'
  fi
}

# - Any panic report in the last 7 days: needs attention
# - 1 crash or hang report in the last 24 hours: info
# - 2-4 crash or hang reports in the last 24 hours: warning
# - 5+ crash or hang reports in the last 24 hours: needs attention
find_system_stability_findings() {
  local panic_count
  local panic_examples
  local crash_count
  local crash_examples
  local crash_severity
  local hang_count
  local hang_examples
  local hang_severity

  ensure_stability_reports_cache

  panic_count="$(report_count_from_file "$STABILITY_PANIC_REPORTS_FILE")"
  if [[ "$panic_count" =~ ^[0-9]+$ && "$panic_count" -gt 0 ]]; then
    panic_examples="$(report_names_from_file "$STABILITY_PANIC_REPORTS_FILE" 5)"
    emit_finding_code \
      "panic_reports_recent" \
      "needs attention" \
      "Recent panic reports: ${panic_count} in last 7 days (Expected: none; Examples: ${panic_examples})" \
      "Open the listed panic reports and confirm their timestamps match recent unexpected restarts or shutdowns."
  fi

  crash_count="$(report_count_from_file "$STABILITY_CRASH_REPORTS_FILE")"
  if [[ "$crash_count" =~ ^[0-9]+$ && "$crash_count" -gt 0 ]]; then
    crash_examples="$(report_names_from_file "$STABILITY_CRASH_REPORTS_FILE" 5)"
    crash_severity="$(severity_for_recent_report_count "$crash_count")"
    emit_finding_code \
      "crash_reports_recent" \
      "$crash_severity" \
      "Recent crash reports: ${crash_count} in last 24 hours (Expected: none or rare; Examples: ${crash_examples})" \
      "Open the listed crash reports and confirm the app names and timestamps match reported crashes or app quits."
  fi

  hang_count="$(report_count_from_file "$STABILITY_HANG_REPORTS_FILE")"
  if [[ "$hang_count" =~ ^[0-9]+$ && "$hang_count" -gt 0 ]]; then
    hang_examples="$(report_names_from_file "$STABILITY_HANG_REPORTS_FILE" 5)"
    hang_severity="$(severity_for_recent_report_count "$hang_count")"
    emit_finding_code \
      "hang_reports_recent" \
      "$hang_severity" \
      "Recent hang reports: ${hang_count} in last 24 hours (Expected: none or rare; Examples: ${hang_examples})" \
      "Open the listed hang reports and confirm the app names and timestamps match reported freezes or force quits."
  fi
}

# Software update checks are slow and can behave differently across repeated
# calls, so findings and raw output share a single cached result.
ensure_softwareupdate_cache() {
  if [[ -n "$SOFTWAREUPDATE_OUTPUT_FILE" ]]; then
    return
  fi

  make_temp_file SOFTWAREUPDATE_OUTPUT_FILE "${TMPDIR:-/tmp}/mac-diagnostics-softwareupdate.XXXXXX"
  capture_command_with_timeout "$SOFTWAREUPDATE_OUTPUT_FILE" "$SOFTWAREUPDATE_TIMEOUT_SECONDS" softwareupdate -l
  SOFTWAREUPDATE_STATUS=$?
}

# - Software update check times out: warning
# - softwareupdate command missing: warning
# - Software updates available: info
# - Software update check fails: warning
find_software_update_findings() {
  local updates
  local labels

  ensure_softwareupdate_cache

  if [[ "$SOFTWAREUPDATE_STATUS" -eq 124 ]]; then
    emit_finding_code \
      "software_update_check_timeout" \
      "warning" \
      "Available updates: unable to check (Expected: softwareupdate -l to finish within ${SOFTWAREUPDATE_TIMEOUT_SECONDS} seconds)" \
      "Open System Settings > General > Software Update and confirm whether update status loads successfully."
    return
  fi

  if [[ "$SOFTWAREUPDATE_STATUS" -eq 127 ]]; then
    emit_finding_code \
      "software_update_command_missing" \
      "warning" \
      "Available updates: unable to check (Expected: softwareupdate command available)" \
      "Confirm the script is running on macOS and check update status in System Settings > General > Software Update."
    return
  fi

  updates="$(awk -F'Title: ' '/^[[:space:]]*Title:/ {
    value = $2
    sub(/,[[:space:]]*Version:.*/, "", value)
    if (value != "" && !seen[value]++) print value
  }' "$SOFTWAREUPDATE_OUTPUT_FILE" | join_lines_with_comma)"

  if [[ -z "$updates" ]]; then
    labels="$(awk -F'Label: ' '/^[[:space:]]*\*?[[:space:]]*Label:/ {
      value = $2
      if (value != "" && !seen[value]++) print value
    }' "$SOFTWAREUPDATE_OUTPUT_FILE" | join_lines_with_comma)"
    updates="$labels"
  fi

  if [[ -n "$updates" ]]; then
    emit_finding_code \
      "software_updates_available" \
      "info" \
      "Available updates: $updates" \
      "Open System Settings > General > Software Update and confirm the listed updates are still available."
  elif [[ "$SOFTWAREUPDATE_STATUS" -ne 0 ]] && ! grep -qi 'No new software available' "$SOFTWAREUPDATE_OUTPUT_FILE"; then
    emit_finding_code \
      "software_update_check_failed" \
      "warning" \
      "Available updates: unable to check (Expected: softwareupdate -l to complete successfully)" \
      "Open System Settings > General > Software Update and confirm whether the update check succeeds there."
  fi
}

emit_issue_summary() {
  local issue_id="$1"
  local label="$2"
  local title="$3"
  local diagnostics="$4"
  local effect="$5"
  local approach="$6"

  [[ -n "$POTENTIAL_ISSUES_FILE" && -n "$ISSUE_SUMMARY_IDS_FILE" ]] || return

  if grep -Fxq "$issue_id" "$ISSUE_SUMMARY_IDS_FILE" 2>/dev/null; then
    return
  fi

  printf '%s\n' "$issue_id" >>"$ISSUE_SUMMARY_IDS_FILE"

  {
    printf '%s: %s\n' "$label" "$title"
    printf 'Evidence: %s\n' "$diagnostics"
    printf 'Risk: %s\n' "$effect"
    printf 'What to do: %s\n' "$approach"
    printf '\n'
  } >>"$POTENTIAL_ISSUES_FILE"
}

# POTENTIAL ISSUES labels reflect the strongest finding level in each group:
# warnings and needs-attention findings become problems; info-only groups stay
# triage notes unless they are routine maintenance.
issue_summary_label_for_codes() {
  local code
  local finding_code
  local severity
  local rank
  local max_rank=0

  [[ -n "$FINDING_INDEX_FILE" && -f "$FINDING_INDEX_FILE" ]] || return

  for code in "$@"; do
    while IFS=$'\t' read -r finding_code severity _; do
      [[ "$finding_code" == "$code" ]] || continue

      case "$severity" in
        "needs attention")
          rank=3
          ;;
        warning)
          rank=2
          ;;
        *)
          rank=1
          ;;
      esac

      if [[ "$rank" -gt "$max_rank" ]]; then
        max_rank="$rank"
      fi
    done <"$FINDING_INDEX_FILE"
  done

  if [[ "$max_rank" -gt 1 ]]; then
    printf 'Problem'
  else
    printf 'Triage note'
  fi
}

issue_summary_label() {
  local issue_id="$1"
  shift

  if [[ "$issue_id" == "software_updates_pending" ]]; then
    printf 'Maintenance item'
    return
  fi

  issue_summary_label_for_codes "$@"
}

# Potential issues group one or more findings into a user-facing summary.
emit_issue_from_codes() {
  local issue_id="$1"
  local title="$2"
  local effect="$3"
  local approach="$4"
  local diagnostics
  local label
  shift 4

  diagnostics="$(finding_texts_for_codes "$@")"
  if [[ -n "$diagnostics" ]]; then
    label="$(issue_summary_label "$issue_id" "$@")"
    emit_issue_summary "$issue_id" "$label" "$title" "$diagnostics" "$effect" "$approach"
  fi
}

evaluate_storage_issues() {
  if has_finding_code "storage_usage_high" || has_finding_code "storage_free_low"; then
    emit_issue_from_codes \
      "low_startup_disk_space" \
      "Startup disk is low on usable storage" \
      "macOS updates, app launches, caching, virtual memory, and normal system cleanup may fail or slow down." \
      "Free or move large files, empty trash if appropriate, and leave enough free space before major updates or installs." \
      "storage_usage_high" "storage_free_low"
  fi
}

evaluate_power_battery_issues() {
  if has_finding_code "battery_condition_not_normal" || has_finding_code "battery_capacity_low" || has_finding_code "battery_cycle_high"; then
    emit_issue_from_codes \
      "battery_service_or_wear" \
      "Battery health may require service" \
      "The Mac may have short runtime, charging problems, reduced peak performance, or unexpected shutdowns on battery power." \
      "Compare the battery findings with real runtime, charging, and shutdown symptoms before recommending service." \
      "battery_condition_not_normal" "battery_capacity_low" "battery_cycle_high"
  fi

  if has_finding_code "sleep_prevention_assertions_active"; then
    emit_issue_from_codes \
      "sleep_prevention_may_affect_power" \
      "Active process may be preventing sleep" \
      "The Mac may stay awake, drain battery faster, run warmer, or fail to enter expected idle sleep until the assertion clears." \
      "Review the listed process, then close, update, or reconfigure it if it is not expected to keep the Mac awake." \
      "sleep_prevention_assertions_active"
  fi
}

evaluate_network_issues() {
  if has_finding_code "dns_missing" || has_finding_code "default_route_missing" || has_finding_code "self_assigned_ip" || has_finding_code "packet_loss_high" || has_finding_code "packet_loss_unknown"; then
    emit_issue_from_codes \
      "network_connectivity_problem" \
      "Network configuration or connectivity problem" \
      "Web browsing, iCloud, software updates, app sign-in, and remote support may fail or behave intermittently." \
      "Start with the active network service, DHCP/router assignment, DNS settings, VPN state, and a retest on a known-good network." \
      "dns_missing" "default_route_missing" "self_assigned_ip" "packet_loss_high" "packet_loss_unknown"
  fi

  if has_finding_code "active_tunnel_interfaces"; then
    emit_issue_from_codes \
      "vpn_or_tunnel_may_affect_network" \
      "VPN or tunnel interface may be affecting networking" \
      "Traffic may route through VPN, security, or private relay software, which can affect DNS, routing, speed, and access to local devices." \
      "Decide whether the VPN or tunnel is expected, then compare behavior with it enabled and disabled if policy allows." \
      "active_tunnel_interfaces"
  fi
}

evaluate_system_stability_issues() {
  if has_finding_code "panic_reports_recent"; then
    emit_issue_from_codes \
      "recent_kernel_panic" \
      "Recent kernel panic or system-level crash" \
      "The Mac may restart unexpectedly or have a lower-level driver, firmware, hardware, or kernel extension problem." \
      "Compare panic times with hardware, software, peripheral, and update changes, then escalate with the panic reports if repeats continue." \
      "panic_reports_recent"
  fi

  if has_finding_code "crash_reports_recent" || has_finding_code "hang_reports_recent"; then
    emit_issue_from_codes \
      "recent_app_crashes_or_hangs" \
      "Recent application crashes or hangs" \
      "One or more apps may be unstable, incompatible, corrupted, or affected by resource pressure." \
      "Focus on recurring app names first, then update, reinstall, remove extensions, or compare with resource pressure around the same timestamps." \
      "crash_reports_recent" "hang_reports_recent"
  fi
}

evaluate_software_update_issues() {
  if has_finding_code "software_updates_available"; then
    emit_issue_from_codes \
      "software_updates_pending" \
      "Apple software updates are available" \
      "Known macOS, Safari, security, firmware, and compatibility issues may already have fixes available." \
      "Review the update details, confirm backups and restart impact, then install during an appropriate maintenance window." \
      "software_updates_available"
  fi

  if has_finding_code "software_update_check_timeout" || has_finding_code "software_update_check_failed" || has_finding_code "software_update_command_missing"; then
    emit_issue_from_codes \
      "software_update_check_problem" \
      "Software update status could not be confirmed" \
      "The Mac may have a network, Apple service, permissions, or software update subsystem problem that prevents checking for updates." \
      "Retry from System Settings on a known-good network, then check network access to Apple update services if the failure persists." \
      "software_update_check_timeout" "software_update_check_failed" "software_update_command_missing"
  fi
}

collect_potential_issues() {
  make_temp_file POTENTIAL_ISSUES_FILE "${TMPDIR:-/tmp}/mac-diagnostics-potential-issues.XXXXXX"
  make_temp_file ISSUE_SUMMARY_IDS_FILE "${TMPDIR:-/tmp}/mac-diagnostics-issue-summary-ids.XXXXXX"

  evaluate_storage_issues
  evaluate_power_battery_issues
  evaluate_network_issues
  evaluate_system_stability_issues
  evaluate_software_update_issues

  write_section_header "POTENTIAL ISSUES"

  if [[ -s "$POTENTIAL_ISSUES_FILE" ]]; then
    append_report_file "$POTENTIAL_ISSUES_FILE"
  else
    printf 'No potential issues identified from current findings.\n' >>"$REPORT_PATH"
  fi

  rm -f "$POTENTIAL_ISSUES_FILE"
  rm -f "$ISSUE_SUMMARY_IDS_FILE"
  POTENTIAL_ISSUES_FILE=""
  ISSUE_SUMMARY_IDS_FILE=""
}

collect_findings() {
  section "FINDINGS"
  FINDINGS_FOUND=0
  make_temp_file FINDING_INDEX_FILE "${TMPDIR:-/tmp}/mac-diagnostics-finding-index.XXXXXX"

  if topic_selected "storage"; then
    run_findings_topic "STORAGE" find_storage_findings
  fi

  if topic_selected "power"; then
    run_findings_topic "POWER AND BATTERY" find_power_battery_findings
  fi

  if topic_selected "network"; then
    run_findings_topic "NETWORK" find_network_findings
  fi

  if topic_selected "stability"; then
    run_findings_topic "SYSTEM STABILITY" find_system_stability_findings
  fi

  if topic_selected "updates"; then
    run_findings_topic "SOFTWARE UPDATE" find_software_update_findings
  fi

  if [[ "$FINDINGS_FOUND" -eq 0 ]]; then
    printf 'No findings detected by the current checks.\n' >>"$REPORT_PATH"
  fi

  collect_potential_issues
  rm -f "$FINDING_INDEX_FILE"
  FINDING_INDEX_FILE=""
}

collect_report_header() {
  local computer_name
  local host_name
  local local_host_name

  computer_name="$(run_for_value 'unavailable' scutil --get ComputerName)"
  host_name="$(run_for_value 'unavailable' hostname)"
  local_host_name="$(run_for_value 'unavailable' scutil --get LocalHostName)"

  section "REPORT SUMMARY"
  append_kv "Report generated" "$(date)"
  append_kv "Diagnostic note" "Informational triage only; verify findings manually before deciding on service or repair steps."
  append_kv "Deep diagnostics" "$([[ "$DEEP_MODE" -eq 1 ]] && printf 'enabled' || printf 'disabled')"
  append_kv "Redaction" "$([[ "$REDACT_MODE" -eq 1 ]] && printf 'enabled' || printf 'disabled')"
  append_kv "Diagnostic topics" "$(selected_topics_label)"
  append_kv "Current user" "$(id -un 2>/dev/null || whoami 2>/dev/null || printf 'unavailable')"
  append_kv "Computer name" "$computer_name"
  append_kv "Local host name" "$local_host_name"
  append_kv "Hostname" "$host_name"
}

collect_system_overview() {
  section "SYSTEM OVERVIEW"
  append_command "macOS version" sw_vers
  append_command "Uptime" uptime
  append_command "Hardware summary" system_profiler SPHardwareDataType
}

collect_storage() {
  section "STORAGE"
  append_command "Filesystem usage" df -h
  append_command "Disk layout" diskutil list
  append_command "Root volume details" diskutil info /
}

collect_power() {
  section "POWER AND BATTERY"
  append_command "Power source" pmset -g ps
  append_command "Battery details" pmset -g batt
  append_command "Power management settings" pmset -g
  ensure_power_assertions_cache
  append_cached_command_output "Power assertions" "$POWER_ASSERTIONS_STATUS" "$POWER_ASSERTIONS_OUTPUT_FILE" pmset -g assertions
  ensure_power_profiler_cache
  append_cached_command_output "Battery health details" "$POWER_PROFILER_STATUS" "$POWER_PROFILER_OUTPUT_FILE" system_profiler SPPowerDataType
}

collect_network() {
  section "NETWORK"
  append_command "Network service order" networksetup -listnetworkserviceorder
  append_command "Hardware ports" networksetup -listallhardwareports
  append_command "Interface configuration" ifconfig
  append_command "DNS configuration" scutil --dns
}

collect_recent_logs() {
  section "RECENT WARNINGS AND ERRORS"
  append_log_show "Errors and faults from the last hour" "1h" 'eventType == logEvent AND (messageType == error OR messageType == fault)'
}

collect_system_stability() {
  section "SYSTEM STABILITY"
  append_command "Recent reboot history" last reboot
  ensure_stability_reports_cache
  append_cached_command_output "Recent panic reports" "$STABILITY_PANIC_STATUS" "$STABILITY_PANIC_REPORTS_FILE" find /Library/Logs/DiagnosticReports "${HOME}/Library/Logs/DiagnosticReports" -type f '(' -iname '*panic*' -o -name '*.panic' ')' -mtime -7 -print
  append_cached_command_output "Recent crash reports" "$STABILITY_CRASH_STATUS" "$STABILITY_CRASH_REPORTS_FILE" find /Library/Logs/DiagnosticReports "${HOME}/Library/Logs/DiagnosticReports" -type f -name '*.crash' -mtime -1 -print
  append_cached_command_output "Recent hang reports" "$STABILITY_HANG_STATUS" "$STABILITY_HANG_REPORTS_FILE" find /Library/Logs/DiagnosticReports "${HOME}/Library/Logs/DiagnosticReports" -type f -name '*.hang' -mtime -1 -print
}

collect_software_updates() {
  section "SOFTWARE UPDATE"
  {
    printf '\n'
    printf '$ softwareupdate -l\n'
  } >>"$REPORT_PATH"

  ensure_softwareupdate_cache
  append_report_file "$SOFTWAREUPDATE_OUTPUT_FILE"

  if [[ "$SOFTWAREUPDATE_STATUS" -eq 124 ]]; then
    printf '[command timed out after %s seconds]\n' "$SOFTWAREUPDATE_TIMEOUT_SECONDS" >>"$REPORT_PATH"
  elif [[ "$SOFTWAREUPDATE_STATUS" -ne 0 ]]; then
    printf '[command failed with exit code %s]\n' "$SOFTWAREUPDATE_STATUS" >>"$REPORT_PATH"
  fi

  printf '\n' >>"$REPORT_PATH"
  printf '  - Available software updates\n'
}

collect_deep_system() {
  section "DEEP SYSTEM"
  append_command_with_timeout "Software profiler details" "$DEEP_COMMAND_TIMEOUT_SECONDS" system_profiler SPSoftwareDataType
}

collect_deep_storage() {
  section "DEEP STORAGE"
  append_command_with_timeout "Storage profiler details" "$DEEP_COMMAND_TIMEOUT_SECONDS" system_profiler SPStorageDataType
  append_command "APFS containers" diskutil apfs list
  append_command "All mounted volumes" mount
}

collect_deep_power() {
  section "DEEP POWER AND BATTERY"
  append_command_with_timeout "Scheduled power events" "$DEEP_COMMAND_TIMEOUT_SECONDS" pmset -g sched
  append_command_with_line_limit "Recent power event log" "$DEEP_COMMAND_TIMEOUT_SECONDS" "$POWER_LOG_LINE_LIMIT" pmset -g log
}

collect_deep_network() {
  section "DEEP NETWORK"
  append_command_with_timeout "Network profiler details" "$DEEP_COMMAND_TIMEOUT_SECONDS" system_profiler SPNetworkDataType
  append_command "Network reachability" scutil -r www.apple.com
  append_command "Routing table" netstat -rn
}

collect_deep_logs() {
  section "DEEP RECENT LOGS"
  append_log_show "Errors and faults from the last six hours" "6h" 'eventType == logEvent AND (messageType == error OR messageType == fault)'
}

collect_deep_stability() {
  section "DEEP SYSTEM STABILITY"
  append_log_show "Kernel messages from the last six hours" "6h" 'process == "kernel"'
}

collect_deep_diagnostics() {
  if topic_selected "system"; then
    collect_deep_system
  fi

  if topic_selected "storage"; then
    collect_deep_storage
  fi

  if topic_selected "power"; then
    collect_deep_power
  fi

  if topic_selected "network"; then
    collect_deep_network
  fi

  if topic_selected "logs"; then
    collect_deep_logs
  fi

  if topic_selected "stability"; then
    collect_deep_stability
  fi
}

main() {
  parse_args "$@"

  if [[ -z "$SELECTED_TOPICS" ]]; then
    select_all_topics
  fi

  if [[ -z "$OUTPUT_DIR" ]]; then
    set_default_output_dir
  fi

  validate_output_dir
  build_report_path

  if ! create_report_file; then
    error "could not create report: $REPORT_PATH"
    exit 1
  fi

  printf 'Saving diagnostics to: %s\n' "$REPORT_PATH"

  collect_report_header
  collect_findings

  if topic_selected "system"; then
    collect_system_overview
  fi

  if topic_selected "storage"; then
    collect_storage
  fi

  if topic_selected "power"; then
    collect_power
  fi

  if topic_selected "network"; then
    collect_network
  fi

  if topic_selected "logs"; then
    collect_recent_logs
  fi

  if topic_selected "stability"; then
    collect_system_stability
  fi

  if topic_selected "updates"; then
    collect_software_updates
  fi

  if [[ "$DEEP_MODE" -eq 1 ]]; then
    collect_deep_diagnostics
  fi

  printf '\nDiagnostics complete.\nReport saved to: %s\n' "$REPORT_PATH"
}

main "$@"
