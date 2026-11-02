#!/usr/bin/env bash
# ==============================================================================
# Script: scripts/asa-hardening-audit.sh
# Purpose: Enterprise Cisco ASA Security Hardening Audit Tool
# Framework Alignments: NIST SP 800-53 Rev. 5, CIS Cisco ASA Benchmark v4.1.0
# Formats Supported: TXT, CSV, JSON
# Mode: Offline static configuration analysis (no live device access required)
# Exit Codes:
#   0 - Audit passed without HIGH/CRITICAL findings
#   1 - Runtime error (invalid arguments, file missing, unreadable, or empty)
#   2 - High or Critical security findings detected (or WARN in strict mode)
# ==============================================================================

set -uo pipefail

VERSION="2.1.0"
SCRIPT_NAME=$(basename "$0")

# Color formatting (disabled when writing to file or non-interactive shell)
if [[ -t 1 ]]; then
    COLOR_RESET="\033[0m"
    COLOR_RED="\033[1;31m"
    COLOR_YELLOW="\033[1;33m"
    COLOR_GREEN="\033[1;32m"
    COLOR_BLUE="\033[1;34m"
    COLOR_CYAN="\033[1;36m"
    COLOR_BOLD="\033[1m"
else
    COLOR_RESET=""
    COLOR_RED=""
    COLOR_YELLOW=""
    COLOR_GREEN=""
    COLOR_BLUE=""
    COLOR_CYAN=""
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
OUTPUT_FORMAT="txt"
STRICT_MODE=false

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS] --input <path-to-asa-config>

Options:
  -i, --input <FILE>       Path to Cisco ASA configuration file (required)
  -o, --output <FILE>      Path to write audit report (optional, defaults to stdout)
  -f, --format <FORMAT>    Report format: txt, csv, or json (default: txt)
  -s, --strict             Exit with code 2 on any WARN or FAIL finding
  -v, --version            Display script version
  -h, --help               Display this help guide

Audited Security Domains & Framework Mappings:
  1. Administrative Services & Protocols (Telnet, HTTP/ASDM) -> NIST CM-7, AC-17
  2. SSH Management Security (v2 enforcement, subnets, ciphers) -> NIST AC-3, SC-8
  3. AAA & Authentication Controls (Local fallback, enable secret) -> NIST IA-2, IA-5
  4. Audit Logging & Forensic Monitoring (Syslog, timestamps) -> NIST AU-2, AU-6, AU-12
  5. SNMP Monitoring Security (v3 vs v1/v2c, default communities) -> NIST IA-5, SC-8
  6. Cryptographic Policy (Legacy 3DES/DES/RC4/MD5, DH groups) -> NIST SC-13, SC-28
  7. Access Control Lists & Permissive Rules (any-any) -> NIST AC-3, AC-4
  8. Interface Security Boundaries & Inter-Zone Isolation -> NIST SC-7
  9. Session Management & Console Timeouts -> NIST AC-11, AC-12
 10. Modular Policy Framework (MPF) Baseline Inspection -> NIST SI-4, SC-7

Examples:
  ${SCRIPT_NAME} -i tests/sample-asa-config.txt
  ${SCRIPT_NAME} -i tests/sample-asa-config.txt -f json -o reports/asa-audit.json
  ${SCRIPT_NAME} -i tests/sample-asa-config.txt -f csv -o reports/asa-audit.csv
EOF
}

# Parse Command-Line Arguments
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
        -f|--format)
            OUTPUT_FORMAT="$(echo "$2" | tr '[:upper:]' '[:lower:]')"
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

# Validate Input Arguments
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

if [[ "${OUTPUT_FORMAT}" != "txt" && "${OUTPUT_FORMAT}" != "csv" && "${OUTPUT_FORMAT}" != "json" ]]; then
    echo "Error: Invalid format '${OUTPUT_FORMAT}'. Must be 'txt', 'csv', or 'json'." >&2
    exit 1
fi

# Mask and sanitize sensitive tokens (passwords, secrets, keys, hashes)
mask_secrets() {
    local text="$1"
    echo "$text" | sed -E \
        -e 's/(password[[:space:]]+)([0-9][[:space:]]+)?[^[:space:]]+/\1[REDACTED_SECRET]/g' \
        -e 's/(secret[[:space:]]+)([0-9][[:space:]]+)?[^[:space:]]+/\1[REDACTED_SECRET]/g' \
        -e 's/(key[[:space:]]+)([0-9][[:space:]]+)?[^[:space:]]+/\1[REDACTED_SECRET]/g' \
        -e 's/(pre-shared-key[[:space:]]+)[^[:space:]]+/\1[REDACTED_SECRET]/g' \
        -e 's/(community[[:space:]]+)[^[:space:]]+/\1[REDACTED_COMMUNITY]/g'
}

# Data Storage for Multi-Format Output
declare -a REPORT_CHECK_IDS=()
declare -a REPORT_CHECK_NAMES=()
declare -a REPORT_STATUSES=()
declare -a REPORT_SEVERITIES=()
declare -a REPORT_FINDINGS=()
declare -a REPORT_REMEDIATIONS=()
declare -a REPORT_NIST_CONTROLS=()
declare -a REPORT_CIS_CONTROLS=()

record_finding() {
    local check_id="$1"
    local check_name="$2"
    local status="$3"
    local severity="$4"
    local finding="$5"
    local remediation="$6"
    local nist_ctrl="$7"
    local cis_ctrl="$8"

    ((TOTAL_CHECKS++))
    case "$status" in
        PASS) ((PASS_COUNT++)) ;;
        WARN) ((WARN_COUNT++)) ;;
        FAIL) ((FAIL_COUNT++)) ;;
        INFO) ((INFO_COUNT++)) ;;
    esac

    local safe_finding
    safe_finding=$(mask_secrets "$finding")

    REPORT_CHECK_IDS+=("${check_id}")
    REPORT_CHECK_NAMES+=("${check_name}")
    REPORT_STATUSES+=("${status}")
    REPORT_SEVERITIES+=("${severity}")
    REPORT_FINDINGS+=("${safe_finding}")
    REPORT_REMEDIATIONS+=("${remediation}")
    REPORT_NIST_CONTROLS+=("${nist_ctrl}")
    REPORT_CIS_CONTROLS+=("${cis_ctrl}")
}

# Ingest configuration text (normalize line endings)
CONFIG_CONTENT=$(tr -d '\r' < "${INPUT_FILE}")

# ==============================================================================
# AUDIT RULES IMPLEMENTATION
# ==============================================================================

# 1. Telnet Configuration
audit_check_telnet() {
    local matches
    matches=$(grep -nE "^[[:space:]]*telnet[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -n "$matches" ]]; then
        record_finding "ASA-AUD-01" "Insecure Telnet Management Service" "FAIL" "HIGH" \
            "Unencrypted Telnet daemon configured:\n${matches}" \
            "Disable Telnet globally with 'no telnet 0.0.0.0 0.0.0.0 <interface>'. Enforce SSH v2 exclusively." \
            "NIST SP 800-53: CM-7, AC-17, SC-8" "CIS Cisco ASA Benchmark: 1.1.1"
    else
        record_finding "ASA-AUD-01" "Insecure Telnet Management Service" "PASS" "HIGH" \
            "No Telnet listener or access rules detected." \
            "Maintain policy prohibiting Telnet." \
            "NIST SP 800-53: CM-7, AC-17, SC-8" "CIS Cisco ASA Benchmark: 1.1.1"
    fi
}

# 2. SSH Management Security
audit_check_ssh() {
    local ssh_entries
    local ssh_ver
    local broad_ssh

    ssh_entries=$(grep -nE "^[[:space:]]*ssh[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    ssh_ver=$(grep -nE "^[[:space:]]*ssh[[:space:]]+version[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    broad_ssh=$(grep -nE "^[[:space:]]*ssh[[:space:]]+(0\.0\.0\.0[[:space:]]+0\.0\.0\.0|0[[:space:]]+0)[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -z "$ssh_entries" ]]; then
        record_finding "ASA-AUD-02" "SSH Management Access Restrictions" "WARN" "MEDIUM" \
            "No explicit SSH management access statements configured." \
            "Configure 'ssh <management-subnet> <mask corruption> <interface>' and 'ssh version 2'." \
            "NIST SP 800-53: AC-3, SC-8" "CIS Cisco ASA Benchmark: 1.2.1"
    elif [[ -n "$broad_ssh" ]]; then
        record_finding "ASA-AUD-02" "SSH Management Access Restrictions" "FAIL" "HIGH" \
            "SSH is permitted from unrestricted source networks (0.0.0.0/0):\n${broad_ssh}" \
            "Restrict SSH access to trusted administrative bastion hosts or dedicated out-of-band management subnets." \
            "NIST SP 800-53: AC-3, SC-8" "CIS Cisco ASA Benchmark: 1.2.1"
    else
        if grep -q "ssh version 2" <<< "$ssh_ver"; then
            record_finding "ASA-AUD-02" "SSH Management Access Restrictions" "PASS" "MEDIUM" \
                "SSH is restricted to designated subnets and enforces SSH version 2." \
                "Audit authorized management subnet allocations periodically." \
                "NIST SP 800-53: AC-3, SC-8" "CIS Cisco ASA Benchmark: 1.2.1"
        else
            record_finding "ASA-AUD-02" "SSH Management Access Restrictions" "WARN" "MEDIUM" \
                "SSH subnets are restricted, but 'ssh version 2' is not explicitly mandated." \
                "Add 'ssh version 2' to enforce strong protocol negotiation." \
                "NIST SP 800-53: AC-3, SC-8" "CIS Cisco ASA Benchmark: 1.2.1"
        fi
    fi
}

# 3. HTTP / ASDM Web Exposure
audit_check_http() {
    local http_enabled
    local broad_http
    local outside_http

    http_enabled=$(grep -nE "^[[:space:]]*http[[:space:]]+server[[:space:]]+enable" <<< "$CONFIG_CONTENT" || true)
    broad_http=$(grep -nE "^[[:space:]]*http[[:space:]]+(0\.0\.0\.0[[:space:]]+0\.0\.0\.0|0[[:space:]]+0)[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    outside_http=$(grep -nEi "^[[:space:]]*http[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+(outside|internet)" <<< "$CONFIG_CONTENT" || true)

    if [[ -n "$http_enabled" ]]; then
        if [[ -n "$broad_http" ]] || [[ -n "$outside_http" ]]; then
            record_finding "ASA-AUD-03" "HTTP/ASDM Management Exposure" "FAIL" "HIGH" \
                "HTTP/ASDM server is enabled with open or outside-facing listener:\n${broad_http}\n${outside_http}" \
                "Disable external ASDM listener or restrict strictly to dedicated management VLAN: 'no http 0 0 outside'." \
                "NIST SP 800-53: CM-7, AC-17, SC-7" "CIS Cisco ASA Benchmark: 1.3.1"
        else
            record_finding "ASA-AUD-03" "HTTP/ASDM Management Exposure" "WARN" "LOW" \
                "HTTP server is enabled for ASDM access, bound to internal/management subnets." \
                "If ASDM is not required, disable with 'no http server enable' to minimize surface." \
                "NIST SP 800-53: CM-7, AC-17" "CIS Cisco ASA Benchmark: 1.3.1"
        fi
    else
        record_finding "ASA-AUD-03" "HTTP/ASDM Management Exposure" "PASS" "LOW" \
            "HTTP/ASDM server is disabled globally." \
            "Maintain policy disabling unneeded web services." \
            "NIST SP 800-53: CM-7" "CIS Cisco ASA Benchmark: 1.3.1"
    fi
}

# 4. Security Audit Logging & Timestamps
audit_check_logging() {
    local logging_on
    local syslog_hosts
    local log_timestamp

    logging_on=$(grep -nE "^[[:space:]]*logging[[:space:]]+enable" <<< "$CONFIG_CONTENT" || true)
    syslog_hosts=$(grep -nE "^[[:space:]]*logging[[:space:]]+host[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    log_timestamp=$(grep -nE "^[[:space:]]*logging[[:space:]]+timestamp" <<< "$CONFIG_CONTENT" || true)

    if [[ -z "$logging_on" ]]; then
        record_finding "ASA-AUD-04" "Security Event Logging & SIEM Integration" "FAIL" "HIGH" \
            "Global logging is disabled or missing ('logging enable' not found)." \
            "Enable global logging: 'logging enable', configure remote syslog collector, and enable timestamps." \
            "NIST SP 800-53: AU-2, AU-3, AU-6, AU-12" "CIS Cisco ASA Benchmark: 2.1.1"
    elif [[ -z "$syslog_hosts" ]]; then
        record_finding "ASA-AUD-04" "Security Event Logging & SIEM Integration" "WARN" "MEDIUM" \
            "Logging is enabled locally, but no remote SIEM syslog host ('logging host <if> <ip>') is defined." \
            "Direct security event logs to a centralized tamper-resistant SIEM syslog server." \
            "NIST SP 800-53: AU-6, AU-9, AU-12" "CIS Cisco ASA Benchmark: 2.1.2"
    else
        if [[ -n "$log_timestamp" ]]; then
            record_finding "ASA-AUD-04" "Security Event Logging & SIEM Integration" "PASS" "MEDIUM" \
                "Logging is enabled, forwarded to remote syslog collectors, and configured with timestamps." \
                "Ensure NTP synchronization is maintained across all syslog collectors." \
                "NIST SP 800-53: AU-2, AU-8, AU-12" "CIS Cisco ASA Benchmark: 2.1.3"
        else
            record_finding "ASA-AUD-04" "Security Event Logging & SIEM Integration" "WARN" "LOW" \
                "Remote syslog host configured, but 'logging timestamp' is missing." \
                "Add 'logging timestamp' for precise forensic timeline reconstruction." \
                "NIST SP 800-53: AU-8" "CIS Cisco ASA Benchmark: 2.1.4"
        fi
    fi
}

# 5. SNMP Monitoring & Community Strings
audit_check_snmp() {
    local default_snmp
    local snmp_v3
    local snmp_present

    default_snmp=$(grep -nEi "^[[:space:]]*snmp-server[[:space:]]+community[[:space:]]+(public|private)" <<< "$CONFIG_CONTENT" || true)
    snmp_present=$(grep -nE "^[[:space:]]*snmp-server[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    snmp_v3=$(grep -nE "^[[:space:]]*snmp-server[[:space:]]+user[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -n "$default_snmp" ]]; then
        record_finding "ASA-AUD-05" "SNMP Monitoring & Community Security" "FAIL" "HIGH" \
            "Default, well-known SNMP community strings ('public' or 'private') detected:\n${default_snmp}" \
            "Remove default communities with 'no snmp-server community <name>'. Migrate to SNMPv3 with authPriv." \
            "NIST SP 800-53: IA-5, SC-8" "CIS Cisco ASA Benchmark: 1.4.1"
    elif [[ -n "$snmp_present" ]] && [[ -z "$snmp_v3" ]]; then
        record_finding "ASA-AUD-05" "SNMP Monitoring & Community Security" "WARN" "MEDIUM" \
            "SNMP is configured using legacy v1/v2c community strings without encrypted SNMPv3 users." \
            "Upgrade to SNMPv3 with SHA authentication and AES encryption (authPriv)." \
            "NIST SP 800-53: IA-5, SC-8" "CIS Cisco ASA Benchmark: 1.4.2"
    else
        record_finding "ASA-AUD-05" "SNMP Monitoring & Community Security" "PASS" "LOW" \
            "No insecure or default SNMP community strings detected." \
            "Maintain SNMPv3 authPriv policies." \
            "NIST SP 800-53: IA-5, SC-8" "CIS Cisco ASA Benchmark: 1.4.1"
    fi
}

# 6. Legacy Cryptographic Protocols & Ciphers
audit_check_crypto() {
    local weak_crypto
    local weak_dh
    local weak_ssl

    weak_crypto=$(grep -nEi "^[[:space:]]*(crypto[[:space:]]+.*(des|3des|md5)|ssl[[:space:]]+encryption[[:space:]]+.*(rc4|des|3des))" <<< "$CONFIG_CONTENT" || true)
    weak_dh=$(grep -nEi "^[[:space:]]*crypto[[:space:]]+ikev[12][[:space:]]+policy.*group[[:space:]]+(1|2|5)[[:space:]]*$" <<< "$CONFIG_CONTENT" || true)
    weak_ssl=$(grep -nEi "^[[:space:]]*ssl[[:space:]]+server-version[[:space:]]+(sslv3|tlsv1[[:space:]]*$|tlsv1\.0|tlsv1\.1)" <<< "$CONFIG_CONTENT" || true)

    local crypto_issues=()
    if [[ -n "$weak_crypto" ]]; then
        crypto_issues+=("Deprecated ciphers (DES/3DES/MD5/RC4) found:\n${weak_crypto}")
    fi
    if [[ -n "$weak_dh" ]]; then
        crypto_issues+=("Weak Diffie-Hellman groups (< 14) configured:\n${weak_dh}")
    fi
    if [[ -n "$weak_ssl" ]]; then
        crypto_issues+=("Legacy SSLv3/TLS 1.0/TLS 1.1 enabled:\n${weak_ssl}")
    fi

    if [[ ${#crypto_issues[@]} -gt 0 ]]; then
        local joined
        joined=$(printf "%s\n" "${crypto_issues[@]}")
        record_finding "ASA-AUD-06" "Cryptographic Algorithms & TLS Protocols" "FAIL" "HIGH" \
            "${joined}" \
            "Enforce AES-GCM (AES-256), SHA-256/384, Diffie-Hellman Group 14+, and TLS 1.2/1.3 minimum." \
            "NIST SP 800-53: SC-13, SC-28" "CIS Cisco ASA Benchmark: 3.1.1"
    else
        record_finding "ASA-AUD-06" "Cryptographic Algorithms & TLS Protocols" "PASS" "HIGH" \
            "No legacy DES, 3DES, RC4, MD5, or weak DH groups detected in crypto policies." \
            "Maintain CNSA/NIST compliant cipher suites." \
            "NIST SP 800-53: SC-13, SC-28" "CIS Cisco ASA Benchmark: 3.1.1"
    fi
}

# 7. AAA & Centralized Authentication
audit_check_aaa() {
    local aaa_auth
    local aaa_servers

    aaa_auth=$(grep -nE "^[[:space:]]*aaa[[:space:]]+authentication[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    aaa_servers=$(grep -nE "^[[:space:]]*aaa-server[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -z "$aaa_auth" ]] && [[ -z "$aaa_servers" ]]; then
        record_finding "ASA-AUD-07" "AAA Framework & Centralized Identity" "WARN" "HIGH" \
            "No centralized AAA authentication or server groups (RADIUS/TACACS+) configured." \
            "Configure 'aaa-server' groups pointing to enterprise identity providers (e.g. Cisco ISE) with local fallback." \
            "NIST SP 800-53: IA-2, IA-5, AC-2" "CIS Cisco ASA Benchmark: 1.5.1"
    elif [[ -z "$aaa_auth" ]] && [[ -n "$aaa_servers" ]]; then
        record_finding "ASA-AUD-07" "AAA Framework & Centralized Identity" "WARN" "MEDIUM" \
            "AAA server group defined, but no active 'aaa authentication' policy applied to administrative interfaces." \
            "Bind authentication: 'aaa authentication ssh console <GROUP> LOCAL'." \
            "NIST SP 800-53: IA-2, AC-2" "CIS Cisco ASA Benchmark: 1.5.1"
    else
        record_finding "ASA-AUD-07" "AAA Framework & Centralized Identity" "PASS" "MEDIUM" \
            "Centralized AAA authentication policy and server groups defined with fallback." \
            "Verify failover behavior when RADIUS/TACACS+ servers are unreachable." \
            "NIST SP 800-53: IA-2, AC-2" "CIS Cisco ASA Benchmark: 1.5.1"
    fi
}

# 8. Overly Permissive Access Rules (Permit Any Any)
audit_check_acls() {
    local any_any_rules
    local permit_ip_any

    any_any_rules=$(grep -nE "^[[:space:]]*access-list[[:space:]]+[^[:space:]]+[[:space:]]+(extended[[:space:]]+)?permit[[:space:]]+ip[[:space:]]+any[[:space:]]+any" <<< "$CONFIG_CONTENT" || true)
    permit_ip_any=$(grep -nE "^[[:space:]]*access-list[[:space:]]+[^[:space:]]+[[:space:]]+(extended[[:space:]]+)?permit[[:space:]]+(tcp|udp|ip)[[:space:]]+any[[:space:]]+" <<< "$CONFIG_CONTENT" || true)

    if [[ -n "$any_any_rules" ]]; then
        record_finding "ASA-AUD-08" "Overly Permissive ACL Rules" "FAIL" "HIGH" \
            "Unrestricted 'permit ip any any' access-list rules detected:\n${any_any_rules}" \
            "Remove open permit rules. Implement zero-trust microsegmentation using explicit network objects and destination ports." \
            "NIST SP 800-53: AC-3, AC-4, CM-7" "CIS Cisco ASA Benchmark: 4.1.1"
    elif [[ -n "$permit_ip_any" ]]; then
        record_finding "ASA-AUD-08" "Overly Permissive ACL Rules" "WARN" "MEDIUM" \
            "Rules permitting traffic from 'any' source to targeted internal destinations:\n${permit_ip_any}" \
            "Audit rules to ensure source addresses are restricted to expected partner or internal subnets." \
            "NIST SP 800-53: AC-3, AC-4" "CIS Cisco ASA Benchmark: 4.1.2"
    else
        record_finding "ASA-AUD-08" "Overly Permissive ACL Rules" "PASS" "HIGH" \
            "No unrestricted 'permit ip any any' access rules detected." \
            "Continue periodic rule auditing and retire unused access-list entries." \
            "NIST SP 800-53: AC-3, AC-4" "CIS Cisco ASA Benchmark: 4.1.1"
    fi
}

# 9. Password Storage and Credential Hardening
audit_check_passwords() {
    local unencrypted_enable
    local unencrypted_user

    unencrypted_enable=$(grep -nE "^[[:space:]]*enable[[:space:]]+password[[:space:]]+" <<< "$CONFIG_CONTENT" || true)
    unencrypted_user=$(grep -nE "^[[:space:]]*username[[:space:]]+[^[:space:]]+[[:space:]]+password[[:space:]]+[^\*[:space:]]+" <<< "$CONFIG_CONTENT" | grep -vE "(encrypted|pbkdf2)" || true)

    if [[ -n "$unencrypted_enable" ]] || [[ -n "$unencrypted_user" ]]; then
        local raw_matches=""
        if [[ -n "$unencrypted_enable" ]]; then raw_matches+="${unencrypted_enable}"$'\n'; fi
        if [[ -n "$unencrypted_user" ]]; then raw_matches+="${unencrypted_user}"; fi

        record_finding "ASA-AUD-09" "Credential Storage & Password Encryption" "FAIL" "CRITICAL" \
            "Plaintext or legacy weakly hashed passwords detected:\n${raw_matches}" \
            "Replace 'enable password' with salted 'enable secret 8 <HASH>' and enable 'password encryption aes'." \
            "NIST SP 800-53: IA-5" "CIS Cisco ASA Benchmark: 1.1.2"
    else
        record_finding "ASA-AUD-09" "Credential Storage & Password Encryption" "PASS" "HIGH" \
            "No unencrypted 'enable password' or plaintext username passwords detected." \
            "Ensure 'password encryption aes' is active for local master keying." \
            "NIST SP 800-53: IA-5" "CIS Cisco ASA Benchmark: 1.1.2"
    fi
}

# 10. Management Timeouts & Baseline Architecture
audit_check_timeouts_and_baseline() {
    local console_to
    local ssh_to
    local inspect_mpf
    local same_sec

    console_to=$(grep -nE "^[[:space:]]*console[[:space:]]+timeout" <<< "$CONFIG_CONTENT" || true)
    ssh_to=$(grep -nE "^[[:space:]]*ssh[[:space:]]+timeout" <<< "$CONFIG_CONTENT" || true)
    inspect_mpf=$(grep -nE "^[[:space:]]*policy-map[[:space:]]+global_policy" <<< "$CONFIG_CONTENT" || true)
    same_sec=$(grep -nE "^[[:space:]]*same-security-traffic[[:space:]]+permit" <<< "$CONFIG_CONTENT" || true)

    local baseline_notes=()
    if [[ -z "$console_to" ]]; then
        baseline_notes+=("Console idle timeout is not explicitly configured (recommend 'console timeout 15').")
    fi
    if [[ -z "$ssh_to" ]]; then
        baseline_notes+=("SSH idle timeout is not explicitly configured (recommend 'ssh timeout 15').")
    fi
    if [[ -n "$same_sec" ]]; then
        baseline_notes+=("Permissive same-security inter/intra-interface traffic is enabled.")
    fi
    if [[ -z "$inspect_mpf" ]]; then
        baseline_notes+=("Default Modular Policy Framework (MPF) inspection global_policy is missing or modified.")
    fi

    if [[ ${#baseline_notes[@]} -gt 0 ]]; then
        local joined
        joined=$(printf " - %s\n" "${baseline_notes[@]}")
        record_finding "ASA-AUD-10" "Session Timeouts & MPF Inspection Baseline" "WARN" "LOW" \
            "Configuration baseline deviations detected:\n${joined}" \
            "Configure explicit session timeouts and verify MPF stateful protocol inspection." \
            "NIST SP 800-53: AC-11, AC-12, SI-4, SC-7" "CIS Cisco ASA Benchmark: 1.2.3"
    else
        record_finding "ASA-AUD-10" "Session Timeouts & MPF Inspection Baseline" "PASS" "LOW" \
            "Explicit session timeouts configured; MPF inspection and security boundaries intact." \
            "Maintain baseline security policy settings." \
            "NIST SP 800-53: AC-11, AC-12, SI-4, SC-7" "CIS Cisco ASA Benchmark: 1.2.3"
    fi
}

# ==============================================================================
# EXECUTE AUDIT SUITE
# ==============================================================================

audit_check_telnet
audit_check_ssh
audit_check_http
audit_check_logging
audit_check_snmp
audit_check_crypto
audit_check_aaa
audit_check_acls
audit_check_passwords
audit_check_timeouts_and_baseline

# ==============================================================================
# REPORT GENERATION ENGINES
# ==============================================================================

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

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

REPORT_OUTPUT=""

if [[ "${OUTPUT_FORMAT}" == "json" ]]; then
    # JSON Generation Engine
    REPORT_OUTPUT="{\n"
    REPORT_OUTPUT+="  \"tool\": \"${SCRIPT_NAME}\",\n"
    REPORT_OUTPUT+="  \"version\": \"${VERSION}\",\n"
    REPORT_OUTPUT+="  \"timestamp_utc\": \"${TIMESTAMP}\",\n"
    REPORT_OUTPUT+="  \"target_file\": \"$(basename "${INPUT_FILE}")\",\n"
    REPORT_OUTPUT+="  \"overall_status\": \"${OVERALL_STATUS}\",\n"
    REPORT_OUTPUT+="  \"summary\": {\n"
    REPORT_OUTPUT+="    \"total_checks\": ${TOTAL_CHECKS},\n"
    REPORT_OUTPUT+="    \"passed\": ${PASS_COUNT},\n"
    REPORT_OUTPUT+="    \"warnings\": ${WARN_COUNT},\n"
    REPORT_OUTPUT+="    \"failures\": ${FAIL_COUNT},\n"
    REPORT_OUTPUT+="    \"info\": ${INFO_COUNT}\n"
    REPORT_OUTPUT+="  },\n"
    REPORT_OUTPUT+="  \"framework_alignments\": [\n"
    REPORT_OUTPUT+="    \"NIST SP 800-53 Rev. 5\",\n"
    REPORT_OUTPUT+="    \"CIS Cisco ASA Benchmark v4.1.0\"\n"
    REPORT_OUTPUT+="  ],\n"
    REPORT_OUTPUT+="  \"findings\": [\n"

    for ((i=0; i<TOTAL_CHECKS; i++)); do
        safe_f=$(echo "${REPORT_FINDINGS[i]}" | sed -E 's/"/\\"/g' | tr '\n' ' ')
        safe_r=$(echo "${REPORT_REMEDIATIONS[i]}" | sed -E 's/"/\\"/g' | tr '\n' ' ')
        comma=","
        if [[ $i -eq $((TOTAL_CHECKS - 1)) ]]; then comma=""; fi

        REPORT_OUTPUT+="    {\n"
        REPORT_OUTPUT+="      \"check_id\": \"${REPORT_CHECK_IDS[i]}\",\n"
        REPORT_OUTPUT+="      \"name\": \"${REPORT_CHECK_NAMES[i]}\",\n"
        REPORT_OUTPUT+="      \"status\": \"${REPORT_STATUSES[i]}\",\n"
        REPORT_OUTPUT+="      \"severity\": \"${REPORT_SEVERITIES[i]}\",\n"
        REPORT_OUTPUT+="      \"nist_control\": \"${REPORT_NIST_CONTROLS[i]}\",\n"
        REPORT_OUTPUT+="      \"cis_benchmark\": \"${REPORT_CIS_CONTROLS[i]}\",\n"
        REPORT_OUTPUT+="      \"finding\": \"${safe_f}\",\n"
        REPORT_OUTPUT+="      \"remediation\": \"${safe_r}\"\n"
        REPORT_OUTPUT+="    }${comma}\n"
    done
    REPORT_OUTPUT+="  ]\n}"

elif [[ "${OUTPUT_FORMAT}" == "csv" ]]; then
    # CSV Generation Engine
    REPORT_OUTPUT="Check ID,Name,Status,Severity,NIST Control,CIS Benchmark,Finding,Remediation\n"
    for ((i=0; i<TOTAL_CHECKS; i++)); do
        clean_f=$(echo "${REPORT_FINDINGS[i]}" | tr '\n' ' ' | sed 's/"/""/g')
        clean_r=$(echo "${REPORT_REMEDIATIONS[i]}" | tr '\n' ' ' | sed 's/"/""/g')
        REPORT_OUTPUT+="\"${REPORT_CHECK_IDS[i]}\",\"${REPORT_CHECK_NAMES[i]}\",\"${REPORT_STATUSES[i]}\",\"${REPORT_SEVERITIES[i]}\",\"${REPORT_NIST_CONTROLS[i]}\",\"${REPORT_CIS_CONTROLS[i]}\",\"${clean_f}\",\"${clean_r}\"\n"
    done

else
    # Standard Text Report
    REPORT_OUTPUT+="================================================================================\n"
    REPORT_OUTPUT+="CISCO ASA ENTERPRISE SECURITY HARDENING AUDIT REPORT\n"
    REPORT_OUTPUT+="================================================================================\n"
    REPORT_OUTPUT+="Timestamp       : ${TIMESTAMP}\n"
    REPORT_OUTPUT+="Target File     : ${INPUT_FILE}\n"
    REPORT_OUTPUT+="Audit Engine    : ${SCRIPT_NAME} v${VERSION}\n"
    REPORT_OUTPUT+="Frameworks      : NIST SP 800-53 Rev. 5, CIS Cisco ASA Benchmark v4.1.0\n"
    REPORT_OUTPUT+="================================================================================\n\n"

    for ((i=0; i<TOTAL_CHECKS; i++)); do
        REPORT_OUTPUT+="--------------------------------------------------------------------------------\n"
        REPORT_OUTPUT+="Check ID        : ${REPORT_CHECK_IDS[i]} - ${REPORT_CHECK_NAMES[i]}\n"
        REPORT_OUTPUT+="Status          : [ ${REPORT_STATUSES[i]} ] | Severity: ${REPORT_SEVERITIES[i]}\n"
        REPORT_OUTPUT+="NIST SP 800-53  : ${REPORT_NIST_CONTROLS[i]}\n"
        REPORT_OUTPUT+="CIS Benchmark   : ${REPORT_CIS_CONTROLS[i]}\n"
        REPORT_OUTPUT+="Finding         : ${REPORT_FINDINGS[i]}\n"
        REPORT_OUTPUT+="Remediation     : ${REPORT_REMEDIATIONS[i]}\n"
    done

    REPORT_OUTPUT+="\n================================================================================\n"
    REPORT_OUTPUT+="AUDIT SUMMARY & COMPLIANCE METRICS\n"
    REPORT_OUTPUT+="================================================================================\n"
    REPORT_OUTPUT+="Total Evaluated Checks : ${TOTAL_CHECKS}\n"
    REPORT_OUTPUT+="Passed Controls        : ${PASS_COUNT}\n"
    REPORT_OUTPUT+="Warnings (Review)      : ${WARN_COUNT}\n"
    REPORT_OUTPUT+="Failures (High/Crit)   : ${FAIL_COUNT}\n"
    REPORT_OUTPUT+="================================================================================\n"
    REPORT_OUTPUT+="OVERALL AUDIT OUTCOME  : [ ${OVERALL_STATUS} ]\n"
    REPORT_OUTPUT+="ASSESSMENT CONCLUSION  : ${STATUS_MSG}\n"
    REPORT_OUTPUT+="================================================================================\n"
fi

# Print to stdout or file
if [[ -n "${OUTPUT_FILE}" ]]; then
    OUTPUT_DIR=$(dirname "${OUTPUT_FILE}")
    if [[ ! -d "${OUTPUT_DIR}" ]]; then
        mkdir -p "${OUTPUT_DIR}"
    fi
    echo -e "${REPORT_OUTPUT}" > "${OUTPUT_FILE}"
    echo "Audit report saved successfully to: ${OUTPUT_FILE} (Format: ${OUTPUT_FORMAT})"
else
    echo -e "${REPORT_OUTPUT}"
fi

# Determine Exit Code
if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 2
fi

if [[ "$STRICT_MODE" = true && $WARN_COUNT -gt 0 ]]; then
    exit 2
fi

exit 0

