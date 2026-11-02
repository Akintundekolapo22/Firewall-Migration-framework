#!/usr/bin/env bash
# ==============================================================================
# Script: scripts/asa_security_audit.sh
# Purpose: Static security hardening and best-practice audit for Cisco ASA configs
# Mode: Offline text analysis (no live network connections or active changes)
# Exit Codes:
#   0 - Audit completed successfully with no high-severity (FAIL) findings
#   1 - Runtime error (invalid arguments, file missing/unreadable, empty config)
#   2 - Audit completed, but one or more high-severity (FAIL) findings were detected
# ==============================================================================

set -o pipefail

VERSION="1.2.0"
SCRIPT_NAME=$(basename "$0")

# Color formatting for terminal (disabled if not a tty or writing to file)
if [[ -t 1 ]]; then
    COLOR_RESET="\033[0m"
    COLOR_RED="\033[1;31m"
    COLOR_YELLOW="\033[1;33m"
    COLOR_GREEN="\033[1;32m"
    COLOR_BLUE="\033[1;34m"
    COLOR_BOLD="\033[1m"
else
    COLOR_RESET=""
    COLOR_RED=""
    COLOR_YELLOW=""
    COLOR_GREEN=""
    COLOR_BLUE=""
    COLOR_BOLD=""
fi

# Counters
TOTAL_CHECKS=0
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
INFO_COUNT=0

# Arguments
INPUT_FILE=""
OUTPUT_FILE=""
STRICT_MODE=false

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS] --input <path-to-asa-config>

Options:
  -i, --input <FILE>     Path to the Cisco ASA configuration file (required)
  -o, --output <FILE>    Path to write the audit report (optional)
  -s, --strict           Exit with code 2 on any WARN or FAIL finding
  -v, --version          Print script version
  -h, --help             Display this help message

Description:
  Performs an offline static analysis of a Cisco ASA running/saved configuration.
  Evaluates administrative services, AAA, logging, broad ACLs, interface security
  levels, and identifies sensitive unencrypted credentials while masking secrets.

Examples:
  ${SCRIPT_NAME} -i data/sample/asa-secure.cfg
  ${SCRIPT_NAME} -i data/sample/asa-insecure.cfg -o reports/audit-report.txt
EOF
}

# Parse Command-Line Options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--input)
            INPUT_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -s|--strict)
            STRICT_MODE=true
            shift
            ;;
        -v|--version)
            echo "${SCRIPT_NAME} version ${VERSION}"
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# Validate Input
if [[ -z "${INPUT_FILE}" ]]; then
    echo "Error: Missing required option --input <path-to-asa-config>" >&2
    usage >&2
    exit 1
fi

if [[ ! -e "${INPUT_FILE}" ]]; then
    echo "Error: Input file '${INPUT_FILE}' does not exist." >&2
    exit 1
fi

if [[ ! -f "${INPUT_FILE}" ]]; then
    echo "Error: Input path '${INPUT_FILE}' is not a regular file." >&2
    exit 1
fi

if [[ ! -r "${INPUT_FILE}" ]]; then
    echo "Error: Input file '${INPUT_FILE}' is not readable." >&2
    exit 1
fi

if [[ ! -s "${INPUT_FILE}" ]]; then
    echo "Error: Input file '${INPUT_FILE}' is empty." >&2
    exit 1
fi

# Sanitize/Mask function to ensure zero credentials leak into reports
mask_secrets() {
    local text="$1"
    # Mask password hashes or cleartext in lines like 'password <secret>', 'enable password <secret>', 'key <secret>'
    echo "$text" | sed -E \
        -e 's/(password[[:space:]]+)([0-9][[:space:]]+)?[^[:space:]]+/\1[REDACTED_SECRET]/g' \
        -e 's/(secret[[:space:]]+)([0-9][[:space:]]+)?[^[:space:]]+/\1[REDACTED_SECRET]/g' \
        -e 's/(key[[:space:]]+)([0-9][[:space:]]+)?[^[:space:]]+/\1[REDACTED_SECRET]/g' \
        -e 's/(pre-shared-key[[:space:]]+)[^[:space:]]+/\1[REDACTED_SECRET]/g'
}

# Buffer for Report Generation
REPORT_BUFFER=""

log_report() {
    local line="$1"
    REPORT_BUFFER+="${line}"$'\n'
}

record_result() {
    local check_id="$1"
    local check_name="$2"
    local status="$3"
    local severity="$4"
    local finding="$5"
    local remediation="$6"

    ((TOTAL_CHECKS++))
    case "$status" in
        PASS)
            ((PASS_COUNT++))
            status_color="${COLOR_GREEN}[ PASS ]${COLOR_RESET}"
            ;;
        WARN)
            ((WARN_COUNT++))
            status_color="${COLOR_YELLOW}[ WARN ]${COLOR_RESET}"
            ;;
        FAIL)
            ((FAIL_COUNT++))
            status_color="${COLOR_RED}[ FAIL ]${COLOR_RESET}"
            ;;
        INFO)
            ((INFO_COUNT++))
            status_color="${COLOR_BLUE}[ INFO ]${COLOR_RESET}"
            ;;
        *)
            status_color="[ ${status} ]"
            ;;
    esac

    # Clean findings of potential secret strings
    local safe_finding
    safe_finding=$(mask_secrets "$finding")

    log_report "--------------------------------------------------------------------------------"
    log_report "Check ID    : ${check_id} - ${check_name}"
    log_report "Status      : ${status} | Severity: ${severity}"
    log_report "Finding     : ${safe_finding}"
    log_report "Remediation : ${remediation}"
}

# Read configuration into memory, stripping carriage returns
CONFIG_CONTENT=$(tr -d '\r' < "${INPUT_FILE}")

# Quick format check: does it look like a Cisco ASA config?
if ! grep -qE "(ASA Version|ciscoasa|interface|access-list|nat|object network)" <<< "$CONFIG_CONTENT"; then
    log_report "WARNING: Input file does not contain typical Cisco ASA configuration keywords."
    log_report "Audit will proceed, but results may indicate an unsupported or non-standard format."
fi

# ==============================================================================
# AUDIT CHECKS
# ==============================================================================

# ------------------------------------------------------------------------------
# Check 1: Telnet Configuration (Insecure Management Protocol)
# ------------------------------------------------------------------------------
audit_check_telnet() {
    local matches
    matches=$(grep -nE "^[[:space:]]*telnet[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -n "$matches" ]]; then
        record_result "SEC-01" "Telnet Daemon & Access" "FAIL" "HIGH" \
            "Unencrypted Telnet service configured:\n${matches}" \
            "Disable Telnet globally and remove all 'telnet <ip> <mask> <interface>' statements. Enforce SSH v2 exclusively."
    else
        record_result "SEC-01" "Telnet Daemon & Access" "PASS" "HIGH" \
            "No Telnet listener or access rules detected in configuration." \
            "Maintain policy prohibiting Telnet."
    fi
}

# ------------------------------------------------------------------------------
# Check 2: SSH Version and Access Restrictions
# ------------------------------------------------------------------------------
audit_check_ssh() {
    local ssh_entries
    local ssh_ver
    local broad_ssh

    ssh_entries=$(grep -nE "^[[:space:]]*ssh[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    ssh_ver=$(grep -nE "^[[:space:]]*ssh[[:space:]]+version[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    broad_ssh=$(grep -nE "^[[:space:]]*ssh[[:space:]]+(0\.0\.0\.0[[:space:]]+0\.0\.0\.0|0[[:space:]]+0)[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -z "$ssh_entries" ]]; then
        record_result "SEC-02" "SSH Management Access" "WARN" "MEDIUM" \
            "No explicit SSH management access commands found." \
            "Configure 'ssh <management-subnet> <mask> <interface>' and 'ssh version 2' to enable secure administration."
    elif [[ -n "$broad_ssh" ]]; then
        record_result "SEC-02" "SSH Management Access" "FAIL" "HIGH" \
            "SSH is permitted from unrestricted source networks (0.0.0.0/0):\n${broad_ssh}" \
            "Restrict SSH access to trusted administrative bastion hosts or dedicated management subnets."
    else
        if grep -q "ssh version 2" <<< "$ssh_ver"; then
            record_result "SEC-02" "SSH Management Access" "PASS" "MEDIUM" \
                "SSH is restricted to designated subnets and strictly enforces version 2." \
                "Ensure source subnets are audited regularly against bastion host allocations."
        else
            record_result "SEC-02" "SSH Management Access" "WARN" "MEDIUM" \
                "SSH is defined but 'ssh version 2' is not explicitly mandated (may permit legacy v1 negotiation)." \
                "Append 'ssh version 2' to global configuration."
        fi
    fi
}

# ------------------------------------------------------------------------------
# Check 3: HTTP/ASDM Exposure and Restrictions
# ------------------------------------------------------------------------------
audit_check_http() {
    local http_enabled
    local broad_http
    local outside_http

    http_enabled=$(grep -nE "^[[:space:]]*http[[:space:]]+server[[:space:]]+enable" <<< "$CONFIG_CONTENT" || true)
    broad_http=$(grep -nE "^[[:space:]]*http[[:space:]]+(0\.0\.0\.0[[:space:]]+0\.0\.0\.0|0[[:space:]]+0)[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    outside_http=$(grep -nEi "^[[:space:]]*http[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+(outside|internet)" <<< "$CONFIG_CONTENT" || true)

    if [[ -n "$http_enabled" ]]; then
        if [[ -n "$broad_http" ]] || [[ -n "$outside_http" ]]; then
            record_result "SEC-03" "HTTP/ASDM Management Exposure" "FAIL" "HIGH" \
                "ASDM/HTTP server is enabled with open or outside-facing listener:\n${broad_http}\n${outside_http}" \
                "Disable external HTTP server or restrict strictly to dedicated out-of-band management subnets."
        else
            record_result "SEC-03" "HTTP/ASDM Management Exposure" "WARN" "MEDIUM" \
                "HTTP server is enabled for ASDM access, bound to specific internal subnets." \
                "If ASDM GUI is not required, disable with 'no http server enable' to reduce attack surface."
        fi
    else
        record_result "SEC-03" "HTTP/ASDM Management Exposure" "PASS" "LOW" \
            "HTTP/ASDM server is not enabled in configuration." \
            "Continue using SSH/CLI or dedicated OOB management plane."
    fi
}

# ------------------------------------------------------------------------------
# Check 4: Logging and Monitoring Configuration
# ------------------------------------------------------------------------------
audit_check_logging() {
    local logging_on
    local syslog_hosts
    local log_timestamp

    logging_on=$(grep -nE "^[[:space:]]*logging[[:space:]]+enable" <<< "$CONFIG_CONTENT" || true)
    syslog_hosts=$(grep -nE "^[[:space:]]*logging[[:space:]]+host[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    log_timestamp=$(grep -nE "^[[:space:]]*logging[[:space:]]+timestamp" <<< "$CONFIG_CONTENT" || true)

    if [[ -z "$logging_on" ]]; then
        record_result "SEC-04" "Syslog & Security Event Logging" "FAIL" "HIGH" \
            "Global logging is disabled or missing ('logging enable' not present)." \
            "Enable syslog with 'logging enable', configure remote syslog hosts, and enable timestamps."
    elif [[ -z "$syslog_hosts" ]]; then
        record_result "SEC-04" "Syslog & Security Event Logging" "WARN" "MEDIUM" \
            "Logging is enabled locally, but no remote syslog hosts ('logging host <if> <ip>') are defined." \
            "Direct security logs to central SIEM / syslog collector for tamper-evident retention."
    else
        if [[ -n "$log_timestamp" ]]; then
            record_result "SEC-04" "Syslog & Security Event Logging" "PASS" "MEDIUM" \
                "Logging is enabled, forwarded to remote syslog collectors, and configured with timestamps." \
                "Verify NTP synchronization across all syslog endpoints."
        else
            record_result "SEC-04" "Syslog & Security Event Logging" "WARN" "LOW" \
                "Remote syslog host configured, but 'logging timestamp' is missing." \
                "Add 'logging timestamp' to provide precise forensic event timelines."
        fi
    fi
}

# ------------------------------------------------------------------------------
# Check 5: AAA Authentication, Authorization & Accounting
# ------------------------------------------------------------------------------
audit_check_aaa() {
    local aaa_auth
    local aaa_servers

    aaa_auth=$(grep -nE "^[[:space:]]*aaa[[:space:]]+authentication[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    aaa_servers=$(grep -nE "^[[:space:]]*aaa-server[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -z "$aaa_auth" ]] && [[ -z "$aaa_servers" ]]; then
        record_result "SEC-05" "AAA Framework & Centralized Auth" "WARN" "HIGH" \
            "No AAA authentication or centralized server groups (RADIUS/TACACS+) configured." \
            "Configure 'aaa-server' groups pointing to enterprise identity providers (e.g. Cisco ISE) and bind to SSH/enable."
    elif [[ -z "$aaa_auth" ]] && [[ -n "$aaa_servers" ]]; then
        record_result "SEC-05" "AAA Framework & Centralized Auth" "WARN" "MEDIUM" \
            "AAA server group is defined, but no active 'aaa authentication ssh/serial console' statements applied." \
            "Bind authentication commands: 'aaa authentication ssh console <GROUP> LOCAL'."
    else
        record_result "SEC-05" "AAA Framework & Centralized Auth" "PASS" "MEDIUM" \
            "AAA authentication policies and server groups are present with local fallback configuration." \
            "Verify failover behavior when RADIUS/TACACS+ servers are unreachable."
    fi
}

# ------------------------------------------------------------------------------
# Check 6: Overly Permissive Access-Control Lists (Any-Any)
# ------------------------------------------------------------------------------
audit_check_acls() {
    local any_any_rules
    local permit_ip_any

    # Match rules permitting ip/tcp/udp from any to any without port/object restrictions
    any_any_rules=$(grep -nE "^[[:space:]]*access-list[[:space:]]+[^[:space:]]+[[:space:]]+(extended[[:space:]]+)?permit[[:space:]]+ip[[:space:]]+any[[:space:]]+any" <<< "$CONFIG_CONTENT" || true)
    permit_ip_any=$(grep -nE "^[[:space:]]*access-list[[:space:]]+[^[:space:]]+[[:space:]]+(extended[[:space:]]+)?permit[[:space:]]+(tcp|udp|ip)[[:space:]]+any[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -n "$any_any_rules" ]]; then
        record_result "SEC-06" "Overly Permissive ACL Rules" "FAIL" "HIGH" \
            "Discovered unrestricted 'permit ip any any' rules:\n${any_any_rules}" \
            "Remove wide-open permit rules. Adopt zero-trust microsegmentation using explicit network objects and destination ports."
    elif [[ -n "$permit_ip_any" ]]; then
        record_result "SEC-06" "Overly Permissive ACL Rules" "WARN" "MEDIUM" \
            "Found rules permitting traffic from 'any' source to targeted destinations:\n${permit_ip_any}" \
            "Audit rules to ensure source addresses are restricted to expected partner or internal subnets where feasible."
    else
        record_result "SEC-06" "Overly Permissive ACL Rules" "PASS" "HIGH" \
            "No unrestricted 'permit ip any any' access rules detected." \
            "Continue periodic rule auditing and retire unused access-list entries."
    fi
}

# ------------------------------------------------------------------------------
# Check 7: Management Plane & Console Timeout Restrictions
# ------------------------------------------------------------------------------
audit_check_mgmt_access() {
    local timeout_set
    local mgmt_only

    timeout_set=$(grep -nE "^[[:space:]]*console[[:space:]]+timeout" <<< "$CONFIG_CONTENT" || true)
    mgmt_only=$(grep -nE "^[[:space:]]*management-only" <<< "$CONFIG_CONTENT" || true)

    if [[ -z "$timeout_set" ]]; then
        record_result "SEC-07" "Management Session Timeout" "WARN" "LOW" \
            "No explicit 'console timeout <minutes>' configured (defaults to 0 / never or vendor preset)." \
            "Set 'console timeout 15' to terminate idle administrative sessions automatically."
    else
        record_result "SEC-07" "Management Session Timeout" "PASS" "LOW" \
            "Explicit console session timeout is configured: ${timeout_set}" \
            "Maintain session timeout policy <= 15 minutes."
    fi
}

# ------------------------------------------------------------------------------
# Check 8: Sensitive Secrets and Plaintext Passwords Exposure
# ------------------------------------------------------------------------------
audit_check_plaintext_passwords() {
    local unencrypted_enable
    local unencrypted_user

    # In ASA, unencrypted passwords often appear as 'enable password <str>' (type 0) vs 'enable secret <hash>'
    unencrypted_enable=$(grep -nE "^[[:space:]]*enable[[:space:]]+password[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    unencrypted_user=$(grep -nE "^[[:space:]]*username[[:space:]]+[^[:space:]]+[[:space:]]+password[[:space:]]+[^\*[:space:]]+" <<< "$CONFIG_CONTENT" | grep -vE "(encrypted|pbkdf2)" || true)

    if [[ -n "$unencrypted_enable" ]] || [[ -n "$unencrypted_user" ]]; then
        local raw_matches=""
        if [[ -n "$unencrypted_enable" ]]; then
            raw_matches+="${unencrypted_enable}"$'\n'
        fi
        if [[ -n "$unencrypted_user" ]]; then
            raw_matches+="${unencrypted_user}"
        fi
        record_result "SEC-08" "Unencrypted Credentials & Hashes" "FAIL" "CRITICAL" \
            "Legacy unencrypted or weakly hashed passwords detected:\n${raw_matches}" \
            "Replace 'enable password' with salted 'enable secret' and use 'password <hash> encrypted' or external AAA."
    else
        record_result "SEC-08" "Unencrypted Credentials & Hashes" "PASS" "HIGH" \
            "No plaintext 'enable password' or unencrypted username passwords detected." \
            "Ensure 'password encryption aes' is enabled if storing local reversible keys."
    fi
}

# ------------------------------------------------------------------------------
# Check 9: Interface Security Levels and Inter-Interface Traffic
# ------------------------------------------------------------------------------
audit_check_interfaces() {
    local same_sec
    local iface_count

    same_sec=$(grep -nE "^[[:space:]]*same-security-traffic[[:space:]]+permit" <<< "$CONFIG_CONTENT" || true)
    iface_count=$(grep -cE "^[[:space:]]*interface[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -n "$same_sec" ]]; then
        record_result "SEC-09" "Interface Security Isolation" "WARN" "MEDIUM" \
            "Permissive intra/inter-interface traffic enabled:\n${same_sec}" \
            "Verify that bypassing interface security-level boundaries is intended and governed by explicit ACLs."
    else
        record_result "SEC-09" "Interface Security Isolation" "PASS" "MEDIUM" \
            "Default interface boundary isolation is enforced (no global 'same-security-traffic permit')." \
            "Maintain strict separation between different zone trust tiers."
    fi
}

# ------------------------------------------------------------------------------
# Check 10: Manual Review & Advanced Features Inspection
# ------------------------------------------------------------------------------
audit_check_manual_review() {
    local inspect_default
    local nat_zero

    inspect_default=$(grep -nE "^[[:space:]]*policy-map[[:space:]]+global_policy" <<< "$CONFIG_CONTENT" || true)
    nat_zero=$(grep -nE "^[[:space:]]*nat[[:space:]]+.*(any|0.0.0.0)" <<< "$CONFIG_CONTENT" || true)

    local review_items=()
    if [[ -z "$inspect_default" ]]; then
        review_items+=("Global Modular Policy Framework (MPF) inspection policy is absent or modified.")
    fi
    if [[ -n "$nat_zero" ]]; then
        review_items+=("Dynamic/static NAT rules with wide ranges require egress validation.")
    fi

    if [[ ${#review_items[@]} -gt 0 ]]; then
        local joined
        joined=$(printf " - %s\n" "${review_items[@]}")
        record_result "SEC-10" "Manual Security Review Items" "INFO" "LOW" \
            "Features requiring engineering architecture review:\n${joined}" \
            "Perform manual review of MPF stateful protocol inspection, NAT boundary translations, and crypto maps."
    else
        record_result "SEC-10" "Manual Security Review Items" "INFO" "LOW" \
            "Standard MPF inspection framework baseline detected." \
            "Review application inspection settings (e.g., DNS, SIP, HTTP deep inspection) based on threat model."
    fi
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

# Run checks
audit_check_telnet
audit_check_ssh
audit_check_http
audit_check_logging
audit_check_aaa
audit_check_acls
audit_check_mgmt_access
audit_check_plaintext_passwords
audit_check_interfaces
audit_check_manual_review

# Generate Header and Summary
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%SZ")

HEADER="================================================================================
CISCO ASA SECURITY CONFIGURATION AUDIT REPORT
================================================================================
Timestamp   : ${TIMESTAMP}
Target File : ${INPUT_FILE}
Audit Tool  : ${SCRIPT_NAME} v${VERSION}
Execution   : Static Offline Text Parser
================================================================================
"

SUMMARY="
================================================================================
AUDIT SUMMARY & METRICS
================================================================================
Total Evaluated Checks : ${TOTAL_CHECKS}
Passed Checks          : ${PASS_COUNT}
Warnings (Review)      : ${WARN_COUNT}
Failures (High/Crit)   : ${FAIL_COUNT}
Informational Items    : ${INFO_COUNT}
================================================================================
"

if [[ $FAIL_COUNT -gt 0 ]]; then
    OVERALL_STATUS="FAIL"
    STATUS_MSG="CRITICAL/HIGH SECURITY DEFECTS DETECTED. HARDENING REMEDIATION REQUIRED."
elif [[ $WARN_COUNT -gt 0 ]]; then
    OVERALL_STATUS="WARN"
    STATUS_MSG="AUDIT PASSED WITH WARNINGS. SECURITY IMPROVEMENTS RECOMMENDED."
else
    OVERALL_STATUS="PASS"
    STATUS_MSG="ALL BASELINE SECURITY CONTROLS COMPLIED WITH."
fi

STATUS_BLOCK="OVERALL AUDIT OUTCOME  : [ ${OVERALL_STATUS} ]
ASSESSMENT CONCLUSION  : ${STATUS_MSG}
================================================================================
"

FULL_REPORT="${HEADER}${REPORT_BUFFER}${SUMMARY}${STATUS_BLOCK}"

# Output to console
echo -e "${FULL_REPORT}"

# Output to file if specified
if [[ -n "${OUTPUT_FILE}" ]]; then
    OUTPUT_DIR=$(dirname "${OUTPUT_FILE}")
    if [[ ! -d "${OUTPUT_DIR}" ]]; then
        mkdir -p "${OUTPUT_DIR}"
    fi
    # Strip any ANSI color codes if writing to file
    echo "${FULL_REPORT}" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" > "${OUTPUT_FILE}"
    echo "Audit report saved to: ${OUTPUT_FILE}"
fi

# Determine Exit Code
if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 2
fi

if [[ "$STRICT_MODE" = true && $WARN_COUNT -gt 0 ]]; then
    exit 2
fi

exit 0
