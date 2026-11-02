# Testing Framework, Environmental Scope & Known Limitations

## 1. Testing Strategy and Automated Test Matrix

The framework employs a layered, multi-engine testing strategy:

| Layer | Target Component | Engine / Tool | Scope |
| :--- | :--- | :--- | :--- |
| **Unit & Logic** | `scripts/firewall_precheck.py` | Python `unittest` | IP address math, CIDRs, route parsing, duplicate detection, schema integrity. |
| **Static & Shell** | `scripts/asa_security_audit.sh` | Bash test script (`tests/test_asa_security_audit.sh`) | Argument handling, missing file traps, secret masking, exit code matrix. |
| **Syntax & Safety** | `ansible/rollback.yml` | PyYAML / Ansible Assert | Variable schema check, rollback approval safety gate, backup presence. |
| **Integration** | End-to-End Orchestration | Master Runner (`tests/run_tests.sh`) | Consolidated execution of all test suites, generating unified test reports. |

---

## 2. Distinction Between MVP and Production-Grade Enterprise Platform

| Feature Area | Current Minimum Viable Framework (MVP) | Full Enterprise Production Target |
| :--- | :--- | :--- |
| **Configuration Ingestion** | Flat ASCII Cisco ASA configuration text parsing and declarative JSON manifests. | Direct Netmiko/NAPALM/RESTCONF extraction from live firewalls with automatic context discovery. |
| **Semantic Analysis** | Offline validation of IP addresses, CIDR masks, unreachable next-hops, and ACL object references. | Full symbolic execution (e.g. Batfish / Forward Networks) modeling end-to-end packet reachability across multiple hops. |
| **Rollback Execution** | Safety-gated playbook with local audit logging and simulated lab execution path. | Production-grade state machine with automated rollback rollback loops, BGP drain, and zero-loss dynamic state recovery. |
| **Policy Engines** | Standard static heuristic rules for Cisco ASA 9.x. | Dynamic multi-vendor policy translation (Cisco ASA to Palo Alto PAN-OS / Fortinet FortiOS / CheckPoint). |

---

## 3. Supported and Unsupported Environments

### 3.1 Supported Environments
- **Operating Systems**: POSIX compliant systems (Linux, macOS, WSL2, Git Bash on Windows).
- **Python**: Python 3.9+ (Python 3.10 through 3.14 tested; standard library focus).
- **Target Configurations**: Cisco ASA running-configs from ASA version 9.1 through 9.18+.
- **Data Formats**: UTF-8 encoded JSON migration manifests and UNIX/DOS line-terminated Cisco configuration files.

### 3.2 Unsupported / Out-of-Scope Capabilities
- **Direct Live Device Scanning**: Framework does not perform port scanning, banner grabbing, or unauthenticated probing against production firewalls.
- **Dynamic NAT State Migration**: Real-time stateful translation tables (`xlate`) cannot be migrated between hardware platforms offline.
- **Proprietary Hardware Emulation**: The framework does not emulate ASIC-level packet forwarding.

---

## 4. Known Limitations

1. **Static Analysis Heuristics**: The Bash audit tool relies on regular expression matching. While highly effective for standard Cisco ASA formatting, non-standard indentation or heavily modified prompt lines may require manual verification.
2. **Dynamic ACL Injection**: Downloadable ACLs (dACLs) delivered dynamically by Cisco ISE at endpoint connection time are not visible in offline static `running-config` dumps.
3. **Hardware Platform Dependencies**: The Ansible rollback playbook's physical execution stage requires the `cisco.asa` collection and functional network_cli transport, which requires lab or physical hardware connectivity to validate live deployment.

