# Enterprise Firewall Migration and Security Hardening Framework
## Technical Documentation Hub

Welcome to the official documentation portal for the **Enterprise Firewall Migration and Security Hardening Framework**.

This open-source suite provides network security engineers, automation architects, and infrastructure administrators with standardized methodologies, automated validation tooling, security audit scripts, configuration templates, and troubleshooting playbooks.

---

### Core Framework Modules

#### Module 1: Enterprise Migration Methodology
- [Standardized 5-Phase Migration Methodology](01-migration-methodology.md)
- [WatchGuard to Cisco ASA Step-by-Step Checklist](03-watchguard-to-cisco-checklist.md)
- [Branch-Site Deployment & Migration Verification Template](04-site-template.md)
- [Enterprise Migration Operational Runbook](migration-runbook.md)

#### Module 2: Identity-Based Access Control & Zero Trust
- [Zero Trust Access Playbook (Cisco ISE, 802.1X, EAP-TLS)](02-zero-trust-access-playbook.md)
- [Case Study: Resolving EAP-TLS Authentication Failure via SAN Matching](troubleshooting/ise-san-fix.md)
- [Cisco ISE AAA & RADIUS Troubleshooting Guide](cisco-ise-troubleshooting.md)
- [EAP-TLS PKI & Certificate Diagnostics](eap-tls-troubleshooting.md)

#### Module 3: Security Hardening & Automated Auditing
- [Cisco ASA Security Hardening Guide](cisco-asa-hardening.md)
- [Bash ASA Security Audit Script Reference](../scripts/asa-hardening-audit.sh)
- [Security Considerations & Secret Masking](security-considerations.md)

#### Module 4: Pre-Migration Policy Validation Tool
- [Python Pre-Migration Policy Validator](../scripts/pre-migration-validator.py)
- [Sample Firewall Rules CSV Dataset](../tests/sample-firewall-rules.csv)
- [Sample Migration Risk & Readiness Report](../examples/migration-risk-report.json)

#### Module 5: Migration Rollback Automation
- [Ansible Rollback Workflow & Safety Controls](../scripts/rollback-checklist.yml)
- [Detailed Emergency Rollback Procedure](rollback-procedure.md)

#### Module 6: Published Technical Articles
- [Article 1: Best Practices for Migrating Enterprise Firewalls from WatchGuard to Cisco ASA](articles/01-watchguard-to-cisco-migration.md)
- [Article 2: Troubleshooting Cisco ISE EAP-TLS Authentication Failures Caused by Certificate Identity Mismatch](articles/02-cisco-ise-eap-tls-troubleshooting.md)

#### Module 7: Testing, Assurance & Evidence
- [Empirical Test Results & Execution Evidence](../tests/test-results.md)
- [System Architecture Specification](architecture.md)
- [Testing Scope & Environmental Limitations](testing-and-limitations.md)

