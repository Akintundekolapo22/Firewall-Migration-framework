# Sample Data Catalog and Privacy Specification

All configuration files, IP subnets, credentials, hostnames, and migration manifests in this directory are fictional and strictly de-identified.

## Compliance with Documentation Standards
In accordance with **RFC 5737** (IPv4 Address Blocks Reserved for Documentation) and **RFC 2606 / RFC 6761** (Reserved Top Level DNS Names):
- `192.0.2.0/24` (TEST-NET-1) is used for internal/management infrastructure.
- `198.51.100.0/24` (TEST-NET-2) is used for DMZ servers and services.
- `203.0.113.0/24` (TEST-NET-3) is used for external ISP uplinks and public WAN ranges.
- Fictional domain suffix `.example` (e.g. `corp.example`) is used exclusively.
- All secrets, hashes, and authentication keys are synthetic placeholder strings.

## Manifest and Configuration Inventory

| File Name | Purpose | Expected Outcome |
| :--- | :--- | :--- |
| `asa-secure.cfg` | Hardened Cisco ASA 9.18 configuration with SSH v2, AAA, logging, and strict ACLs. | `asa_security_audit.sh` -> PASS / WARN (0 FAIL) |
| `asa-insecure.cfg` | Legacy Cisco ASA 9.1 configuration with Telnet, plaintext passwords, open HTTP, permit any. | `asa_security_audit.sh` -> FAIL (Exit Code 2) |
| `migration-valid.json` | Valid pre-migration JSON specification adhering to migration schema. | `firewall_precheck.py` -> PASS (Exit Code 0) |
| `migration-invalid.json` | Defective migration specification with invalid CIDRs, duplicate IPs, unresolvable ACL references. | `firewall_precheck.py` -> FAIL (Exit Code 2) |
| `backup.cfg` | Golden image configuration used for rollback dry-run tests. | `rollback.yml` -> Verified regular file |

