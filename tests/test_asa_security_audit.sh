#!/usr/bin/env bash
# ==============================================================================
# Script: tests/test_asa_security_audit.sh
# Purpose: Test Suite for Cisco ASA Security Audit Script (scripts/asa_security_audit.sh)
# Validates exit codes, check logic, error handling, and credential redaction.
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
AUDIT_SCRIPT="${REPO_ROOT}/scripts/asa_security_audit.sh"

PASSED_TESTS=0
FAILED_TESTS=0

# Helper assertion function
assert_equals() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"

    if [[ "$expected" == "$actual" ]]; then
        echo "  [PASS] ${test_name}"
        ((PASSED_TESTS++))
    else
        echo "  [FAIL] ${test_name} (Expected: '${expected}', Got: '${actual}')"
        ((FAILED_TESTS++))
    fi
}

assert_contains() {
    local test_name="$1"
    local needle="$2"
    local haystack="$3"

    if grep -qF "$needle" <<< "$haystack"; then
        echo "  [PASS] ${test_name}"
        ((PASSED_TESTS++))
    else
        echo "  [FAIL] ${test_name} (Substring '${needle}' not found)"
        ((FAILED_TESTS++))
    fi
}

assert_not_contains() {
    local test_name="$1"
    local needle="$2"
    local haystack="$3"

    if ! grep -qF "$needle" <<< "$haystack"; then
        echo "  [PASS] ${test_name}"
        ((PASSED_TESTS++))
    else
        echo "  [FAIL] ${test_name} (Prohibited substring '${needle}' was detected in output!)"
        ((FAILED_TESTS++))
    fi
}

echo "================================================================================"
echo "RUNNING CISCO ASA SECURITY AUDIT TEST SUITE"
echo "Target Script: ${AUDIT_SCRIPT}"
echo "================================================================================"

# ------------------------------------------------------------------------------
# Test 1: Hardened Configuration (asa-secure.cfg)
# ------------------------------------------------------------------------------
echo "--- Test Group 1: Hardened Sample Evaluation ---"
SECURE_OUTPUT=$(bash "${AUDIT_SCRIPT}" -i "${REPO_ROOT}/data/sample/asa-secure.cfg" 2>&1)
SECURE_EXIT=$?

assert_equals "Secure sample exit code should be 0" "0" "$SECURE_EXIT"
assert_contains "Secure sample has 0 failures" "Failures (High/Crit)   : 0" "$SECURE_OUTPUT"
assert_contains "Telnet check passes" "Check ID    : SEC-01 - Telnet Daemon & Access" "$SECURE_OUTPUT"

# ------------------------------------------------------------------------------
# Test 2: Insecure Configuration (asa-insecure.cfg)
# ------------------------------------------------------------------------------
echo "--- Test Group 2: Insecure Sample Evaluation ---"
INSECURE_OUTPUT=$(bash "${AUDIT_SCRIPT}" -i "${REPO_ROOT}/data/sample/asa-insecure.cfg" 2>&1 || true)
INSECURE_EXIT=$?

# In bash, when audit detects FAIL findings, exit code is 2
# But with '|| true' above, let's capture the true exit code cleanly:
bash "${AUDIT_SCRIPT}" -i "${REPO_ROOT}/data/sample/asa-insecure.cfg" > /dev/null 2>&1
INSECURE_REAL_EXIT=$?

assert_equals "Insecure sample exit code should be 2 (FAIL)" "2" "$INSECURE_REAL_EXIT"
assert_contains "Insecure sample identifies high failures" "OVERALL AUDIT OUTCOME  : [ FAIL ]" "$INSECURE_OUTPUT"
assert_contains "Telnet daemon failure detected" "SEC-01 - Telnet Daemon & Access" "$INSECURE_OUTPUT"
assert_contains "Unrestricted SSH detected" "SEC-02 - SSH Management Access" "$INSECURE_OUTPUT"
assert_contains "Permissive permit any rule flagged" "SEC-06 - Overly Permissive ACL Rules" "$INSECURE_OUTPUT"

# ------------------------------------------------------------------------------
# Test 3: Credential Masking and Secret Redaction
# ------------------------------------------------------------------------------
echo "--- Test Group 3: Sensitive Secret Redaction ---"
# Check that the plaintext passwords from asa-insecure.cfg do not leak into the report
assert_not_contains "Plaintext enable password must be redacted" "plaintextciscopassword123" "$INSECURE_OUTPUT"
assert_not_contains "Plaintext user password must be redacted" "unencryptedweakpass" "$INSECURE_OUTPUT"
assert_contains "Redaction placeholder present" "[REDACTED_SECRET]" "$INSECURE_OUTPUT"

# ------------------------------------------------------------------------------
# Test 4: CLI Error Traps & Edge Cases
# ------------------------------------------------------------------------------
echo "--- Test Group 4: Input Validation & CLI Robustness ---"

# Missing required --input argument
NO_ARG_OUTPUT=$(bash "${AUDIT_SCRIPT}" 2>&1 || true)
bash "${AUDIT_SCRIPT}" > /dev/null 2>&1
NO_ARG_EXIT=$?
assert_equals "Missing arguments exits with code 1" "1" "$NO_ARG_EXIT"

# Non-existent input file
MISSING_FILE_OUTPUT=$(bash "${AUDIT_SCRIPT}" -i "${REPO_ROOT}/nonexistent_file.cfg" 2>&1 || true)
bash "${AUDIT_SCRIPT}" -i "${REPO_ROOT}/nonexistent_file.cfg" > /dev/null 2>&1
MISSING_FILE_EXIT=$?
assert_equals "Missing file exits with code 1" "1" "$MISSING_FILE_EXIT"
assert_contains "Reports file does not exist" "does not exist" "$MISSING_FILE_OUTPUT"

# Empty input file
EMPTY_FILE="${REPO_ROOT}/empty_test_config.tmp"
touch "${EMPTY_FILE}"
EMPTY_OUTPUT=$(bash "${AUDIT_SCRIPT}" -i "${EMPTY_FILE}" 2>&1 || true)
bash "${AUDIT_SCRIPT}" -i "${EMPTY_FILE}" > /dev/null 2>&1
EMPTY_EXIT=$?
rm -f "${EMPTY_FILE}"
assert_equals "Empty file exits with code 1" "1" "$EMPTY_EXIT"
assert_contains "Reports file is empty" "is empty" "$EMPTY_OUTPUT"

# ------------------------------------------------------------------------------
# Test 5: File Report Export
# ------------------------------------------------------------------------------
echo "--- Test Group 5: Report File Generation ---"
TEMP_REPORT="${REPO_ROOT}/reports/sample/test-run-report.tmp"
bash "${AUDIT_SCRIPT}" -i "${REPO_ROOT}/data/sample/asa-secure.cfg" -o "${TEMP_REPORT}" > /dev/null 2>&1
if [[ -f "${TEMP_REPORT}" && -s "${TEMP_REPORT}" ]]; then
    echo "  [PASS] Output report successfully generated at target path"
    ((PASSED_TESTS++))
    rm -f "${TEMP_REPORT}"
else
    echo "  [FAIL] Report file was not created or was empty"
    ((FAILED_TESTS++))
fi

echo "================================================================================"
echo "BASH AUDIT TEST SUMMARY: ${PASSED_TESTS} passed, ${FAILED_TESTS} failed"
echo "================================================================================"

if [[ $FAILED_TESTS -gt 0 ]]; then
    exit 1
fi
exit 0

