# Mac Diagnostics Tool

A Bash-based macOS diagnostics collector for first-pass support triage.
The script gathers common system, storage, battery, network, stability, log, and
software update information into a timestamped text report.

The report starts with findings and potential issues, followed by raw command
output. These top sections call out results that may need review, with
confirmation steps, risk context, and suggested next actions.

## Privacy

Generated reports can include sensitive device and user information, including
serial numbers, hardware UUIDs, network addresses, local paths, usernames, and
log details. Do not publish or share a real report without reviewing and
redacting it first.

Generate a partially redacted report with common identifiers redacted:

```sh
./mac-diagnostics.sh --redact
```

Redaction is opt-in. Normal reports preserve raw diagnostic output for local
support work.

## Quick Start

```sh
./mac-diagnostics.sh
```

By default, reports are written next to the script in a dated folder:

```text
reports/YYYY-MM-DD/
```

Report filenames look like:

```text
mac-diagnostics-YYYY-MM-DD-HHMMSS-user-mac-name.txt
```

To save output somewhere else:

```sh
./mac-diagnostics.sh --output-dir /path/to/reports
```

Run only selected support categories:

```sh
./mac-diagnostics.sh --checks storage,network
```

Include slower checks:

```sh
./mac-diagnostics.sh --deep
```

Generate a report with common identifiers redacted:

```sh
./mac-diagnostics.sh --redact
```

List available categories:

```sh
./mac-diagnostics.sh --list-checks
```

To bring up these options from in the program:

```sh
./mac-diagnostics.sh --help
```

## Support Categories

- `system`: Establishes the Mac model, macOS version, uptime, and hardware
  baseline.
- `storage`: Checks startup disk usage, APFS layout, and root volume details.
- `power`: Reviews battery condition, charging state, cycle count, power
  settings, and sleep-prevention assertions.
- `network`: Captures service order, hardware ports, interface state, DNS,
  routing-related evidence, and packet loss checks.
- `logs`: Summarizes recent warnings and errors without dumping every matching
  log entry.
- `stability`: Looks for recent reboots, kernel panic reports, crashes, and
  hangs.
- `updates`: Checks whether Apple software updates are available.

## Finding Severity

The report uses three severity levels, rendered as banner labels in the
`FINDINGS` section:

- `=== INFO ===`: Useful context that may explain behavior but is not necessarily a
  problem.
- `=== WARNING ===`: A condition that should be verified manually before deciding on a
  fix.
- `=== NEEDS ATTENTION ===`: A condition that is more likely to affect normal Mac use
  and should be reviewed promptly.

Findings call out checks that need review and include a direct confirmation
step. Potential issues group those findings into possible real-world problems,
cite the evidence, summarize the risk, and suggest what to do next. These
sections are intended to guide triage, not replace manual verification.

## Issue Summary Labels

The `POTENTIAL ISSUES` section groups related findings using these labels:

- `Problem`: A finding or group of findings that may affect normal Mac use.
- `Triage note`: Useful context to verify, but not necessarily a problem.
- `Maintenance item`: Routine action, such as available software updates.

## Example Output

The excerpt below uses fake fixture data. Each finding shown here is also
included in the matching `POTENTIAL ISSUES` item.

```text
FINDINGS
================================================================

-- STORAGE --
----------------------------------------------------------------
=== NEEDS ATTENTION ===
Diagnostic result: Startup disk usage: 91% used (At or above 90%)
To confirm: Open System Settings > General > Storage or rerun df -h / and confirm startup disk usage is still above the threshold.

-- NETWORK --
----------------------------------------------------------------
=== INFO ===
Diagnostic result: Active VPN/tunnel interfaces: utun9 (May affect routing or DNS)
To confirm: Check VPN, private relay, or security software status and confirm whether the listed tunnel interface is expected.

-- SOFTWARE UPDATE --
----------------------------------------------------------------
=== INFO ===
Diagnostic result: Available updates: macOS Test Update
To confirm: Open System Settings > General > Software Update and confirm the listed updates are still available.

POTENTIAL ISSUES
================================================================
Problem: Startup disk is low on usable storage
Evidence: Startup disk usage: 91% used (At or above 90%)
Risk: macOS updates, app launches, caching, virtual memory, and normal system cleanup may fail or slow down.
What to do: Free or move large files, empty Trash if appropriate, and leave enough free space before major updates or installs.

Triage note: VPN or tunnel interface may be affecting networking
Evidence: Active VPN/tunnel interfaces: utun9 (May affect routing or DNS)
Risk: Traffic may route through VPN, security, or private relay software, which can affect DNS, routing, speed, and access to local devices.
What to do: Decide whether the VPN or tunnel is expected, then compare behavior with it enabled and disabled if policy allows.

Maintenance item: Apple software updates are available
Evidence: Available updates: macOS Test Update
Risk: Known macOS, Safari, security, firmware, and compatibility issues may already have fixes available.
What to do: Review the update details, confirm backups and restart impact, then install during an appropriate maintenance window.
```

## Support Workflow

1. Run the narrowest relevant category first when the symptom is known.
2. Review `FINDINGS` and `POTENTIAL ISSUES`, then confirm against the raw command
   output.
3. Manually verify anything that could be affected by permissions, sandboxing,
   VPN software, offline state, or captive networks.
4. Redact the report before attaching it to a ticket or sharing it outside the
   local support workflow.

## Development Checks

Run the test suite:

```sh
tests/run-tests.sh
```

The suite checks Bash syntax, runs `shellcheck` when installed, verifies finding
logic with fixtures, checks redaction behavior, and creates a report in a
temporary directory.
