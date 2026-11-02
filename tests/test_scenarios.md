# Test Scenarios and Automated Validation Matrix

This document defines the automated test scenarios executed across the framework's components, detailing prerequisites, inputs, execution commands, and expected assertions.

---

## 1. Python Pre-Migration Validation Test Scenarios (`tests/test_firewall_precheck.py`)

| Scenario ID | Test Name | Input Target | Injected Condition / Mutation | Expected Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **TC-PY-01** | Golden Manifest Baseline | `migration-valid.json` | None (Compliant schema, RFC IPs, declared objects). | `overall_status: PASS`, 0 Failures, Exit code `0`. |
| **TC-PY-02** | Missing Top-Level Structure | In-memory | `del data["interfaces"]` | `overall_status: FAIL`, `CHK-01` failure, Exit code `2`. |
| **TC-PY-03** | Invalid Device Metadata | In-memory | Blank target hostname, invalid management IP (`300.400.500.600`). | `CHK-02` failure, Exit code `2`. |
| **TC-PY-04** | Invalid Subnet CIDR | In-memory | `interfaces[0]["cidr"] = 35` | `CHK-03` failure, Exit code `2`. |
| **TC-PY-05** | Duplicate Interface IP | In-memory | Assign identical IP (`203.0.113.2`) to two interfaces. | `CHK-03` failure, Duplicate IP error, Exit code `2`. |
| **TC-PY-06** | Invalid Route Prefix | In-memory | `routes[0]["destination_prefix"] = "999.0.0.0/24"` | `CHK-04` failure, Exit code `2`. |
| **TC-PY-07** | Invalid Route Next-Hop | In-memory | Non-IP string `"invalid-next-hop-ip"`. | `CHK-04` failure, Exit code `2`. |
| **TC-PY-08** | Unreachable Route Next-Hop | In-memory | Next-hop (`172.16.50.1`) not within any interface subnet. | `CHK-04` status `WARN`, Overall `WARN` (exit code `0` non-strict). |
| **TC-PY-09** | Strict Mode Gate | In-memory | Next-hop unreachable executed with `--strict`. | Overall `FAIL`, Exit code `2`. |
| **TC-PY-10** | Duplicate Network Object | In-memory | Declare object name `obj-srv-web-dmz` twice. | `CHK-05` failure, Duplicate object error, Exit code `2`. |
| **TC-PY-11** | Inverted Address Range | In-memory | Range string `192.0.2.200-192.0.2.100` (Start > End). | `CHK-05` failure, Exit code `2`. |
| **TC-PY-12** | Ghost ACL Object Reference | In-memory | ACL rule references undeclared object `obj-ghost-server`. | `CHK-06` failure, Unresolved reference, Exit code `2`. |
| **TC-PY-13** | Hardware Port Exhaustion | In-memory | Target physical interfaces = 2; configured interfaces = 4. | `CHK-07` failure, Capacity exceeded, Exit code `2`. |
| **TC-PY-14** | CLI File Not Found | CLI | `-i nonexistent.json` | Stderr error, Exit code `1`. |
| **TC-PY-15** | CLI Malformed JSON | CLI | Non-JSON text `{ bad json ]` | JSONDecodeError handled gracefully, Exit code `1`. |
| **TC-PY-16** | Report File Export | CLI | `-i migration-valid.json -o <temp_file>` | Report JSON generated, readable, matches schema. |

---

## 2. Cisco ASA Security Audit Scenarios (`tests/test_asa_security_audit.sh`)

| Scenario ID | Test Target | Evaluation Scope | Assertion Criteria |
| :--- | :--- | :--- | :--- |
| **TC-SH-01** | `asa-secure.cfg` | Baseline hardened configuration. | 0 Failures, Exit code `0`. |
| **TC-SH-02** | `asa-insecure.cfg` | Legacy unhardened configuration. | Exit code `2`, Flags Telnet, SSH, HTTP, logging, and broad ACLs. |
| **TC-SH-03** | In-flight Redaction | Credential masking in reports. | Plaintext strings (`plaintextciscopassword123`, `unencryptedweakpass`) completely replaced by `[REDACTED_SECRET]`. |
| **TC-SH-04** | Missing Arguments | Invocation without `--input`. | Stderr usage instructions emitted, Exit code `1`. |
| **TC-SH-05** | Missing Input File | Path to non-existent configuration. | Trapped cleanly with error message, Exit code `1`. |
| **TC-SH-06** | Empty Configuration | 0-byte configuration file. | Trapped cleanly with empty file error, Exit code `1`. |
| **TC-SH-07** | Report Export Option | `-o <path>` | Creates output directory if missing, exports clean ASCII report. |

---

## 3. Ansible Rollback Safety Controls

| Scenario ID | Playbook Condition | Execution Parameters | Expected Interlock Behavior |
| :--- | :--- | :--- | :--- |
| **TC-ANS-01** | Missing Approval (Default) | `ansible-playbook ansible/rollback.yml` (`rollback_approved=false`) | Assertion failure at Stage 2.1: Execution halts with 0 changes. |
| **TC-ANS-02** | Missing Backup File | `-e rollback_approved=true -e backup_file_path=nonexistent.cfg` | Assertion failure at Stage 1.3: Halts with backup missing error. |
| **TC-ANS-03** | Missing Hostname | `-e rollback_approved=true -e firewall_hostname=""` | Assertion failure at Stage 1.1: Halts with missing variable error. |
| **TC-ANS-04** | Valid Lab Simulation | `-e rollback_approved=true -e simulation_mode=true` | Stages 1 through 5 succeed; records ledger entry in `rollback-audit.log`. |

