# Firewall Migration Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Bash: 4.4+](https://img.shields.io/badge/bash-4.4%2B-green.svg)](https://www.gnu.org/software/bash/)
[![NIST SP 800-53](https://img.shields.io/badge/NIST%20SP-800--53%20Rev.%205-red.svg)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-Cisco%20ASA%20v4.1.0-darkgreen.svg)](https://www.cisecurity.org/)

An enterprise-grade, offline-first engineering framework designed for validating firewall migrations, executing security hardening audits mapped to NIST SP 800-53 and CIS Benchmarks, implementing Zero Trust Network Architecture with Cisco ISE, and conducting safety-gated rollback automations.

Designed for network security engineers, cybersecurity professionals, and automation specialists executing high-risk infrastructure modernizations (including migrating legacy WatchGuard Firebox or older Cisco ASA deployments to refreshed platforms).

---

## Table of Contents
1. [Framework Overview & Five-Phase Lifecycle](#1-framework-overview--five-phase-lifecycle)
2. [Module Architecture & Deliverables](#2-module-architecture--deliverables)
3. [Repository Directory Structure](#3-repository-directory-structure)
4. [Prerequisites & Environment Setup](#4-prerequisites--environment-setup)
5. [Automated Tools Execution Guide](#5-automated-tools-execution-guide)
   - [A. Cisco ASA Security Hardening Audit Tool (`asa-hardening-audit.sh`)](#a-cisco-asa-security-hardening-audit-tool)
   - [B. Pre-Migration Policy & Risk Validator (`pre-migration-validator.py`)](#b-pre-migration-policy--risk-validator)
   - [C. Automated Rollback Workflow & Safety Checklist (`rollback-checklist.yml`)](#c-automated-rollback-workflow--safety-checklist)
6. [Zero Trust Identity & Cisco ISE EAP-TLS Integration](#6-zero-trust-identity--cisco-ise-eap-tls-integration)
7. [Reusable Security Configuration Templates](#7-reusable-security-configuration-templates)
8. [Automated Testing & Empirical Evidence](#8-automated-testing--empirical-evidence)
9. [Published Technical Articles](#9-published-technical-articles)
10. [Security Safeguards & Privacy Standards](#10-security-safeguards--privacy-standards)
11. [Supported vs. Unsupported Environments](#11-supported-vs-unsupported-environments)
12. [Known Limitations](#12-known-limitations)
13. [Engineering Troubleshooting Guide](#13-engineering-troubleshooting-guide)
14. [Engineering Disclaimer](#14-engineering-disclaimer)

---

## 1. Framework Overview & Five-Phase Lifecycle

Perimeter and datacenter firewall cutovers carry significant operational and security risks. Undetected syntax anomalies, unresolvable address objects, shadow access rules, and legacy unencrypted services can lead to service downtime or security exposures.

This framework standardizes the **Five-Phase Enterprise Firewall Migration Methodology** ([`docs/01-migration-methodology.md`](docs/01-migration-methodology.md)):

```
+---------------------------------------------------------------------------------------------------------+
|                                    FIVE-PHASE MIGRATION METHODOLOGY                                     |
+---------------------------------------------------------------------------------------------------------+
       |
       v
[ Phase 1: Network Discovery & Assessment ]
  -> Interfaces, 802.1Q trunks, dynamic routing (BGP/OSPF), NAT/PAT tables, IPsec VPN crypto proposals.
       |
       v
[ Phase 2: Policy Review & Migration Planning ]
  -> Duplicate rule pruning, shadow rule resolution, any-any mitigation, zero-trust microsegmentation.
       |
       v
[ Phase 3: Configuration & Pre-Migration Validation ]
  -> Automated CSV rule validation, semantic CIDR checking, offline static hardening audit against NIST/CIS.
       |
       v
[ Phase 4: Firewall Deployment, Migration & Verification ]
  -> Maintenance window cutover, physical link transfer, progressive 5-layer post-migration verification.
       |
       v
[ Phase 5: Post-Migration Monitoring & Rollback Readiness ]
  -> 72-hour burn-in telemetry, SIEM logging validation, and safety-gated rollback readiness.
```

---

## 2. Module Architecture & Deliverables

| Module | Core Deliverables | Technology | Scope & Functionality |
| :--- | :--- | :--- | :--- |
| **Module 1: Migration Methodology** | [`docs/01-migration-methodology.md`](docs/01-migration-methodology.md)<br>[`docs/03-watchguard-to-cisco-checklist.md`](docs/03-watchguard-to-cisco-checklist.md) | Markdown | 5-phase migration lifecycle; complete WatchGuard to Cisco ASA translation matrix. |
| **Module 2: Zero Trust & Identity** | [`docs/02-zero-trust-access-playbook.md`](docs/02-zero-trust-access-playbook.md)<br>[`docs/troubleshooting/ise-san-fix.md`](docs/troubleshooting/ise-san-fix.md) | Cisco ISE 3.x, 802.1X | EAP-TLS PKI validation; RADIUS vs TACACS+; resolving SAN DNS vs Subject CN failure. |
| **Module 3: Hardening Audit Tool** | [`scripts/asa-hardening-audit.sh`](scripts/asa-hardening-audit.sh) | POSIX Bash | Offline security audit; checks 10 domains; maps NIST SP 800-53 & CIS controls; outputs TXT/CSV/JSON. |
| **Module 4: Pre-Migration Validator**| [`scripts/pre-migration-validator.py`](scripts/pre-migration-validator.py) | Python 3 (std-lib) | Ingests CSV rule exports; detects duplicates, shadows, any-any, malformed CIDRs, high-risk ports. |
| **Module 5: Rollback Automation** | [`scripts/rollback-checklist.yml`](scripts/rollback-checklist.yml) | Ansible Playbook | Safety-interlocked restoration (`rollback_approved: false`); validates 5 health check domains. |
| **Module 6: Reusable Templates** | [`templates/asa-baseline.conf`](templates/asa-baseline.conf)<br>[`templates/bgp-prefix-list.template`](templates/bgp-prefix-list.template)<br>[`docs/04-site-template.md`](docs/04-site-template.md) | Cisco CLI / Jinja2 | Hardened ASA baseline; BGP bogon & prefix filtering; branch-site deployment checklists. |
| **Module 7: Technical Articles** | [`docs/articles/01-watchguard-to-cisco-migration.md`](docs/articles/01-watchguard-to-cisco-migration.md)<br>[`docs/articles/02-cisco-ise-eap-tls-troubleshooting.md`](docs/articles/02-cisco-ise-eap-tls-troubleshooting.md) | Markdown | Professional publications on WatchGuard-to-Cisco migration and Cisco ISE EAP-TLS troubleshooting. |

---

## 3. Repository Directory Structure

```
Firewall-Migration-framework/
│
├── README.md                               # Project summary, architecture, and complete operations guide
├── LICENSE                                 # MIT License
├── _config.yml                             # GitHub Pages Jekyll documentation site configuration
├── requirements.txt                        # Python dependencies (jsonschema, pyyaml)
├── ansible.cfg                             # Ansible controller configuration
│
├── docs/
│   ├── index.md                            # GitHub Pages documentation portal hub
│   ├── 01-migration-methodology.md         # Five-phase migration lifecycle & WatchGuard transition
│   ├── 02-zero-trust-access-playbook.md    # Cisco ISE, 802.1X, EAP-TLS, and RADIUS/TACACS+ playbook
│   ├── 03-watchguard-to-cisco-checklist.md # Granular WatchGuard to Cisco ASA translation checklist
│   ├── 04-site-template.md                 # Branch-site deployment blueprint & 5-layer verification checklist
│   ├── architecture.md                     # Deep system architecture & data contracts
│   ├── migration-runbook.md                # Maintenance window hour-by-hour operational runbook
│   ├── cisco-asa-hardening.md              # In-depth ASA hardening across all security domains
│   ├── cisco-ise-troubleshooting.md        # Structured Cisco ISE live logs & RADIUS triage guide
│   ├── eap-tls-troubleshooting.md          # 802.1X EAP-TLS PKI & certificate diagnostic manual
│   ├── rollback-procedure.md               # Detailed emergency rollback protocol & safety gates
│   ├── security-considerations.md          # Threat model, secret masking, and de-identification
│   ├── testing-and-limitations.md          # Test coverage, assumptions, and MVP vs Production
│   │
│   ├── troubleshooting/
│   │   └── ise-san-fix.md                  # Case study: Diagnosing EAP-TLS failure from SAN mismatch
│   │
│   └── articles/
│       ├── 01-watchguard-to-cisco-migration.md        # Technical article
│       └── 02-cisco-ise-eap-tls-troubleshooting.md    # Technical article
│
├── scripts/
│   ├── asa-hardening-audit.sh              # Bash Cisco ASA audit tool (NIST & CIS aligned)
│   ├── pre-migration-validator.py          # Python pre-migration CSV policy validator
│   ├── rollback-checklist.yml              # Ansible rollback workflow with safety controls
│   ├── asa_security_audit.sh               # Companion ASA audit script
│   └── firewall_precheck.py                # Companion JSON manifest pre-migration checker
│
├── templates/
│   ├── asa-baseline.conf                   # Production-grade hardened Cisco ASA baseline config
│   ├── bgp-prefix-list.template            # Enterprise BGP edge peering & prefix-list filter template
│   ├── asa/asa-base.cfg                    # Modular ASA base template
│   └── bgp/bgp-example.cfg                 # Modular BGP example template
│
├── tests/
│   ├── run_tests.sh                        # Master consolidated test runner script
│   ├── sample-firewall-rules.csv           # Test dataset of firewall rules (duplicates, shadows, any-any)
│   ├── sample-asa-config.txt               # Test Cisco ASA configuration file
│   ├── test-results.md                     # Comprehensive empirical test report & evidence
│   ├── test_firewall_precheck.py           # Python unit tests (18 unit tests)
│   ├── test_asa_security_audit.sh          # Bash shell tests (17 unit tests)
│   └── test_scenarios.md                   # Automated test scenario specifications
│
├── examples/
│   └── migration-risk-report.json          # Live generated pre-migration risk report
│
├── data/sample/
│   ├── asa-secure.cfg                      # Fictional hardened sample configuration
│   ├── asa-insecure.cfg                    # Fictional insecure legacy configuration
│   ├── migration-valid.json                # Fictional compliant migration manifest
│   ├── migration-invalid.json              # Fictional defective migration manifest
│   └── backup.cfg                          # Golden image backup configuration
│
└── reports/sample/
    ├── asa-audit-report.txt                # Sample text audit report
    ├── asa-hardening-report.json           # Sample JSON hardening report (NIST/CIS aligned)
    ├── migration-validation-report.json    # Sample JSON precheck validation report
    └── test-results.txt                    # Master test runner output logs
```

---

## 4. Prerequisites & Environment Setup

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+, RHEL 8+), macOS (12+), or Windows (Git Bash / WSL2).
- **Python**: Python 3.10+ (core validator utilizes standard libraries: `argparse`, `ipaddress`, `csv`, `json`, `pathlib`).
- **Bash**: GNU Bash 4.4+.
- **Ansible** (Optional for live execution): Ansible Core 2.14+.

### Installation
```bash
# Clone the repository
git clone https://github.com/Akintundekolapo22/Firewall-Migration-framework.git
cd Firewall-Migration-framework

# Install optional Python dependencies for extended schema/YAML parsing
python -m pip install -r requirements.txt
```

---

## 5. Automated Tools Execution Guide

### A. Cisco ASA Security Hardening Audit Tool
Audits exported Cisco ASA configurations against 10 security domains mapped to **NIST SP 800-53 Rev. 5** and **CIS Cisco ASA Benchmark v4.1.0**.

```bash
# Display help & options
bash scripts/asa-hardening-audit.sh --help

# Run audit with standard text console output
bash scripts/asa-hardening-audit.sh -i tests/sample-asa-config.txt

# Generate structured JSON report mapped to NIST controls
bash scripts/asa-hardening-audit.sh \
  -i tests/sample-asa-config.txt \
  -f json \
  -o reports/sample/asa-hardening-report.json

# Generate CSV format report
bash scripts/asa-hardening-audit.sh \
  -i tests/sample-asa-config.txt \
  -f csv \
  -o reports/sample/asa-hardening-report.csv
```

#### Audited Controls & NIST Mappings:
- **Telnet Daemon**: Deprecation of plaintext Telnet (`NIST CM-7, AC-17`)
- **SSH Management**: SSH v2 enforcement, restricted bastion subnets, 3DES deprecation (`NIST AC-3, SC-8`)
- **HTTP / ASDM Exposure**: Disabling external ASDM listeners (`NIST CM-7, AC-17, SC-7`)
- **Syslog Logging**: Forwarding to remote SIEM collectors with timestamps (`NIST AU-2, AU-6, AU-12`)
- **SNMP Security**: Deprecation of default `public`/`private` communities; SNMPv3 enforcement (`NIST IA-5, SC-8`)
- **Cryptographic Policies**: Removal of 3DES, DES, RC4, MD5, and weak DH groups < 14 (`NIST SC-13, SC-28`)
- **AAA Authentication**: Centralized RADIUS/TACACS+ with local console fallback (`NIST IA-2, IA-5`)
- **Permissive ACLs**: Detection of open `permit ip any any` rules (`NIST AC-3, AC-4, CM-7`)
- **Password Protection**: Salting enable secret (`enable secret 8`) and master AES keying (`NIST IA-5`)
- **Modular Policy Framework**: Default ICMP, TCP, UDP stateful application inspection (`NIST SI-4, SC-7`)

---

### B. Pre-Migration Policy & Risk Validator
Ingests firewall policy exports in **CSV format** and performs deep semantic analysis.

```bash
# Display help & CLI options
python scripts/pre-migration-validator.py --help

# Validate policy rules CSV and generate JSON risk report
python scripts/pre-migration-validator.py \
  --rules tests/sample-firewall-rules.csv \
  --output examples/migration-risk-report.json

# Validate policy rules CSV with CSV report output
python scripts/pre-migration-validator.py \
  --rules tests/sample-firewall-rules.csv \
  --output reports/sample/policy-risk-report.csv \
  --format csv

# Enforce strict evaluation (exits with code 2 on warnings)
python scripts/pre-migration-validator.py \
  --rules tests/sample-firewall-rules.csv \
  --strict
```

#### Analytical Capabilities:
- **Duplicate Rules**: Identifies identical 7-tuples (zone, source, destination, protocol, port, action).
- **Shadowed Rules**: Detects specific rules masked by preceding broader rules (redundant permits and dangerous action overrides).
- **Permissive Any-Any**: Flags unconstrained `permit ip any any` rules.
- **Syntax & Subnet Math**: Catches invalid CIDR notation (e.g. `/35`), broadcast IPs, and malformed strings.
- **Sensitive Port Exposures**: Identifies exposed management services (SSH 22, Telnet 23, HTTP 80, RDP 3389, SMB 445).
- **Rule Telemetry**: Flags dormant rules with 0 recorded hit counts.

---

### C. Automated Rollback Workflow & Safety Checklist
Ansible rollback automation engineered with **mandatory safety gates**.

```bash
# Verify playbook syntax
python -c "import yaml; yaml.safe_load(open('scripts/rollback-checklist.yml')); print('Syntax valid')"

# Execute simulated rollback with safety approval
ansible-playbook scripts/rollback-checklist.yml \
  -e "rollback_approved=true" \
  -e "simulation_mode=true" \
  -e "backup_file_path=data/sample/backup.cfg"

# Attempting execution WITHOUT approval halts immediately:
ansible-playbook scripts/rollback-checklist.yml
# => Fails: "SAFETY INTERLOCK ENGAGED: Rollback execution has NOT been approved."
```

#### 5-Layer Post-Recovery Checklist:
1. **Layer 3 Connectivity**: ICMP reachability to core gateway (`192.0.2.1`) and distribution switch (`192.0.2.2`).
2. **Routing Convergence**: Static default route verification and BGP neighbor adjacency.
3. **VPN Tunnel State**: IPsec IKEv2 security associations to remote peers.
4. **DNS Subsystem**: Resolving internal domain records via corporate DNS resolvers.
5. **SIEM Telemetry**: Streaming security syslog events to SIEM (`192.0.2.50`) on UDP 514.

---

## 6. Zero Trust Identity & Cisco ISE EAP-TLS Integration

The framework provides comprehensive documentation for identity-based network access control:
- **Zero Trust Access Playbook** ([`docs/02-zero-trust-access-playbook.md`](docs/02-zero-trust-access-playbook.md)): Architecture of Cisco ISE as PDP, 802.1X supplicants, RADIUS vs TACACS+, and EAP-TLS mutual authentication.
- **Case Study: Resolving EAP-TLS Failure Caused by SAN Mismatch** ([`docs/troubleshooting/ise-san-fix.md`](docs/troubleshooting/ise-san-fix.md)): Complete diagnostic case study diagnosing failure code `22056 Subject not found in identity store` caused by modern PKI templates populating `SAN:DNS` instead of deprecated `Subject: CN`.

---

## 7. Reusable Security Configuration Templates

- **Hardened Cisco ASA Baseline** ([`templates/asa-baseline.conf`](templates/asa-baseline.conf)): Complete, commented Cisco ASA configuration featuring OOB management-only isolation, SSH v2 DH group 14+, RADIUS AAA with local fallback, timestamped logging, least-privilege ACLs, and IKEv2 IPsec VPN.
- **Enterprise BGP Prefix-List Filter** ([`templates/bgp-prefix-list.template`](templates/bgp-prefix-list.template)): RFC 7454 compliant BGP routing configuration featuring ingress bogon filtering, outbound enterprise prefix-lists, AS-path prepending, and `maximum-prefix` route-leak safeguards.

---

## 8. Automated Testing & Empirical Evidence

Execute the entire test framework using the unified test runner:

```bash
bash tests/run_tests.sh
```

### Verified Test Results:
```
================================================================================
MASTER TEST RUN SUMMARY
================================================================================
Total Test Suites   : 6
Passed Suites       : 5
Failed Suites       : 0
Skipped Suites      : 1 (ansible-playbook CLI optional; verified via PyYAML)
Completion Time     : 2026-10-30 14:28:28Z
Overall Test Result : ALL CRITICAL TESTS PASSED
================================================================================
```

For full test scenarios and execution outputs, see [`tests/test-results.md`](tests/test-results.md).

---

## 9. Published Technical Articles

Two publication-ready articles:
1. **[Best Practices for Migrating Enterprise Firewalls from WatchGuard to Cisco ASA](docs/articles/01-watchguard-to-cisco-migration.md)**: Deep dive into architectural differences, zone trust models, identity NAT for VPNs, and migration checklists.
2. **[Troubleshooting Cisco ISE EAP-TLS Authentication Failures Caused by Certificate Identity Mismatch](docs/articles/02-cisco-ise-eap-tls-troubleshooting.md)**: Root-cause analysis of Subject CN deprecation, ISE Certificate Authentication Profiles, and resolving failure code 22056.

---

## 10. Security Safeguards & Privacy Standards

This repository strictly complies with international privacy and de-identification RFCs:
- **RFC 5737**: IP addresses use reserved documentation blocks exclusively:
  - `192.0.2.0/24` (TEST-NET-1): Internal LAN, management, SIEM, Cisco ISE.
  - `198.51.100.0/24` (TEST-NET-2): DMZ servers and public applications.
  - `203.0.113.0/24` (TEST-NET-3): WAN uplinks, ISP gateways, BGP transit.
- **RFC 2606 / RFC 6761**: Hostnames use the `.example` reserved TLD (e.g., `corp.example`).
- **RFC 6996**: Autonomous system numbers use private ASNs (`64512 - 65534`).
- **In-Flight Secret Redaction**: The Bash audit tool automatically masks plaintext passwords, hashes, and pre-shared keys prior to output generation.

---

## 11. Supported vs. Unsupported Environments

| Dimension | Supported | Unsupported / Out of Scope |
| :--- | :--- | :--- |
| **Operating Systems** | Linux (Ubuntu, RHEL, Debian), macOS, Windows (Git Bash / WSL2). | Native Windows Command Prompt without POSIX layer. |
| **Firewall Platforms** | Cisco ASA 5500-X, Firepower 1000/2100 running ASA image (ASA 9.1 - 9.18+). | Direct Cisco FMC API orchestration (planned for v3). |
| **Operational Mode** | Offline static configuration analysis; local simulation. | Live device port scanning or active vulnerability probing. |

---

## 12. Known Limitations

1. **Heuristic Static Analysis**: The Bash auditor utilizes regex stream parsing. Non-standard multi-line object groupings may require supplementary manual review.
2. **Dynamic Policy Scope**: Static configuration audits cannot evaluate dynamic policies injected at runtime by Cisco ISE via Downloadable ACLs (dACLs) or Security Group Tags (SGTs).
3. **Physical Hardware Recovery**: The Ansible rollback playbook's physical restoration stage requires direct network reachability to target appliances and the `cisco.asa` collection.

---

## 13. Engineering Troubleshooting Guide

| Issue | Root Cause | Remediation |
| :--- | :--- | :--- |
| `scripts/asa-hardening-audit.sh: command not found` | Script lacks execution permissions on POSIX hosts. | Run `chmod +x scripts/asa-hardening-audit.sh` or invoke with `bash`. |
| `pre-migration-validator.py: ModuleNotFoundError` | Python 2 invoked instead of Python 3. | Execute via `python3 scripts/pre-migration-validator.py`. |
| `Ansible assertion failed: rollback_approved` | Default safety interlock engaged. | Supply `-e rollback_approved=true` explicitly during authorized changes. |
| `EAP-TLS Handshake Failed (Code 22056)` | Certificate Subject CN is empty; identity is in SAN. | Update ISE Certificate Authentication Profile to extract from `SAN:DNS`. |

---

## 14. Engineering Disclaimer

> **IMPORTANT**: This framework provides offline validation, static security auditing, and automated rollback workflows for enterprise firewall migration projects. It does not replace formal change governance, lab staging, or live device testing. Before executing changes on production firewalls, always validate configurations against physical staging equipment in an isolated lab environment.
