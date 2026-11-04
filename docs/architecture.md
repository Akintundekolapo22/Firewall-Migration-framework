# Framework Architecture and Data Flow

## 1. Architectural Overview

The **Firewall Migration Framework** is an open-source, practitioner-oriented cybersecurity implementation framework designed to support secure enterprise network modernization through structured migration methodologies, configuration security assessments, automated firewall policy validation, and documented rollback procedures. It operates offline-first with safety-gated validation workflows to address implementation-stage security and operational challenges during enterprise firewall replacements while guaranteeing that baseline security standards and operational rollback guardrails are rigorously enforced.

```
                          +-------------------------------------------------------+
                          |            Firewall Migration & Audit Suite           |
                          +-------------------------------------------------------+
                                                     |
         +-------------------------------------------+-------------------------------------------+
         |                                           |                                           |
         v                                           v                                           v
+------------------------+               +------------------------+               +------------------------+
| scripts/               |               | scripts/               |               | ansible/               |
| asa_security_audit.sh  |               | firewall_precheck.py   |               | rollback.yml           |
+------------------------+               +------------------------+               +------------------------+
         |                                           |                                           |
         | Static Config Evaluation                  | Semantic Data Verification                | Guarded Recovery
         v                                           v                                           v
[ Cisco ASA Flat Config ]                [ JSON Migration Spec ]                 [ Golden Baseline Backup ]
  - Telnet / SSH Controls                  - RFC IPv4 / CIDR Validity              - Pre-Change Verification
  - ASDM HTTP Exposure                     - Overlapping Interface IPs             - Explicit Approval Gate
  - Logging / Timestamp                    - Next-Hop Reachability                 - Audit Ledger Recording
  - Overly Permissive ACLs                 - Undefined ACL Objects                 - Lab Simulation Stage
  - Plaintext Credentials                  - Port / Capacity Parity                - Post-Restore Verification
         |                                           |                                           |
         v                                           v                                           v
[ reports/asa-audit.txt ]                [ reports/precheck.json ]               [ reports/rollback.log ]
```

---

## 2. Component Details

### A. Static Security Hardening Auditor (`scripts/asa_security_audit.sh`)
- **Execution Model**: Deterministic Bash script utilizing POSIX stream filters (`grep`, `sed`, `awk`).
- **Network Footprint**: Zero network footprint. Runs offline against exported ASCII configuration files (`show running-config`).
- **Data Protection**: Automatic in-flight redaction engine filters password hashes, enable passwords, preshared keys, and SNMP strings from terminal output and report logs.
- **Scoring Engine**: Evaluates 10 baseline security domains across `PASS`, `WARN`, `FAIL`, and `INFO`.

### B. Semantic Pre-Migration Validator (`scripts/firewall_precheck.py`)
- **Execution Model**: Object-oriented Python 3 tool utilizing standard library primitives (`ipaddress`, `json`, `argparse`, `pathlib`).
- **Contract Schema**: Validates declarative migration manifests against standard schema specifications.
- **Topology Analysis**:
  - Validates network / broadcast address compliance.
  - Verifies next-hop routers share Layer 3 subnets with designated egress interfaces.
  - Cross-references ACL object bindings against declared network object inventories.
- **Exit Matrix**: Emits Unix return codes (0 = Success, 1 = Schema/File Error, 2 = Logical Validation Failure).

### C. Safety-Gated Rollback Playbook (`ansible/rollback.yml`)
- **Execution Model**: Ansible orchestration playbook with mandatory safety assertions.
- **Interlock Controls**:
  - `rollback_approved`: Fails execution immediately if set to `false` (default).
  - `backup_file_path`: Verifies regular file presence, non-zero size, and readable permissions.
  - `simulation_mode`: Enables safe dry-run lab emulation without modifying production network state.
- **Audit Logging**: Appends timestamped execution records to `reports/sample/rollback-audit.log`.

---

## 3. Data Contracts & File Formats

### Migration Manifest Contract (`migration-valid.json`)
The validation engine ingests declarative JSON manifests structured as follows:

| Field | Type | Description |
| :--- | :--- | :--- |
| `schema_version` | String | Semantic version of migration schema (e.g. `1.0.0`). |
| `migration_id` | String | Unique change identifier / tracking ticket. |
| `source_firewall` | Object | Metadata including `hostname`, `vendor`, `model`, `management_ip`. |
| `target_firewall` | Object | Metadata including `hostname`, `total_physical_interfaces`. |
| `interfaces` | Array[Object] | Physical/sub-interface names, `ipv4_address`, `cidr`, `security_level`. |
| `routes` | Array[Object] | Routing entries with `destination_prefix`, `next_hop`, `interface`. |
| `network_objects` | Array[Object] | Host, subnet, or IP range objects referenced in policies. |
| `acls` | Array[Object] | Extended access-lists referencing declared objects. |

