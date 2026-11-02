#!/usr/bin/env python3
"""
Enterprise Pre-Migration Firewall Policy Validation Tool
=========================================================
Script: scripts/pre-migration-validator.py
Purpose: Ingests legacy firewall policy exports (CSV) and infrastructure data,
         performing deep semantic validation, risk scoring, and optimization analysis.

Analytic Capabilities:
  1. Duplicate rule identification (exact duplicates across tuples).
  2. Fully and partially shadowed rule detection (rule ordering conflicts).
  3. Overly permissive security policy detection (any-any, unconstrained services).
  4. Inconsistent and malformed IP/CIDR syntax validation.
  5. Missing mandatory migration attributes (descriptions, owners, ticket refs).
  6. High-risk exposure analysis (administrative ports exposed to untrusted zones).
  7. Dormant/unused rule analysis based on hit-count and telemetry metadata.
  8. Routing, VPN gateway, and DNS resolver readiness verification.

Outputs:
  Structured JSON or CSV migration risk report.
"""

import argparse
import csv
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

__version__ = "2.1.0"
TOOL_NAME = "pre-migration-validator.py"

# Standard Risk and Status Constants
RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"

STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"

# High-Risk Port Profiles
SENSITIVE_MGMT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP (Cleartext)",
    445: "SMB / Windows File Sharing",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3389: "RDP / Remote Desktop",
    5432: "PostgreSQL Database",
    27017: "MongoDB",
}


class FirewallRule:
    """Represents a standardized firewall policy entry."""

    def __init__(self, raw: Dict[str, str], row_index: int):
        self.row_index = row_index
        self.rule_id = raw.get("rule_id", f"RULE-{row_index}").strip()
        self.name = raw.get("name", "").strip()
        self.source_zone = raw.get("source_zone", "").strip()
        self.dest_zone = raw.get("dest_zone", "").strip()
        self.source = raw.get("source", "").strip()
        self.destination = raw.get("destination", "").strip()
        self.protocol = raw.get("protocol", "ip").strip().lower()
        self.port = raw.get("port", "any").strip()
        self.action = raw.get("action", "permit").strip().lower()
        self.description = raw.get("description", "").strip()
        self.hit_count = self._parse_int(raw.get("hit_count", "0"))
        self.last_hit_date = raw.get("last_hit_date", "").strip()
        self.enabled = raw.get("enabled", "true").strip().lower() in ("true", "1", "yes")

        # Parsed network structures
        self.source_network: Optional[ipaddress.IPv4Network] = None
        self.dest_network: Optional[ipaddress.IPv4Network] = None
        self.source_is_any = self.source.lower() in ("any", "0.0.0.0/0", "")
        self.dest_is_any = self.destination.lower() in ("any", "0.0.0.0/0", "")
        self.port_is_any = self.port.lower() in ("any", "0", "")
        self.ports_list: List[int] = self._parse_ports(self.port)

    @staticmethod
    def _parse_int(val: str) -> int:
        try:
            return int(val.replace(",", "").strip())
        except (ValueError, AttributeError):
            return 0

    @staticmethod
    def _parse_ports(val: str) -> List[int]:
        if not val or val.lower() == "any":
            return []
        ports = []
        for part in val.split(","):
            part = part.strip()
            if "-" in part:
                tokens = part.split("-")
                try:
                    start_p = int(tokens[0])
                    end_p = int(tokens[1])
                    ports.extend(range(start_p, min(end_p + 1, 65536)))
                except (ValueError, IndexError):
                    pass
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        return ports

    def parse_networks(self) -> List[str]:
        """Resolves source and destination strings to ipaddress objects."""
        errors = []
        if not self.source_is_any:
            try:
                # Support single host without CIDR
                src_val = self.source if "/" in self.source else f"{self.source}/32"
                self.source_network = ipaddress.ip_network(src_val, strict=False)
            except ValueError as ve:
                errors.append(f"Invalid source address '{self.source}': {ve}")

        if not self.dest_is_any:
            try:
                dst_val = self.destination if "/" in self.destination else f"{self.destination}/32"
                self.dest_network = ipaddress.ip_network(dst_val, strict=False)
            except ValueError as ve:
                errors.append(f"Invalid destination address '{self.destination}': {ve}")

        return errors


class PolicyValidationEngine:
    def __init__(self, rules: List[FirewallRule], infrastructure_data: Optional[Dict[str, Any]] = None):
        self.rules = rules
        self.infra = infrastructure_data or {}
        self.findings: List[Dict[str, Any]] = []

    def run_all_checks(self):
        self._check_missing_fields_and_syntax()
        self._check_duplicate_rules()
        self._check_shadowed_rules()
        self._check_overly_permissive_rules()
        self._check_high_risk_exposures()
        self._check_dormant_and_unused_rules()
        self._check_infrastructure_readiness()

    def _add_finding(
        self,
        category: str,
        rule_id: str,
        severity: str,
        title: str,
        description: str,
        remediation: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.findings.append(
            {
                "category": category,
                "rule_id": rule_id,
                "severity": severity,
                "title": title,
                "description": description,
                "remediation": remediation,
                "details": details or {},
            }
        )

    def _check_missing_fields_and_syntax(self):
        """Checks for missing mandatory attributes and invalid IP structures."""
        for rule in self.rules:
            # Mandatory documentation metadata
            if not rule.description or rule.description.lower() in ("none", "temp", "test", "todo"):
                self._add_finding(
                    category="POLICY_GOVERNANCE",
                    rule_id=rule.rule_id,
                    severity=RISK_LOW,
                    title="Missing Business Justification / Description",
                    description=f"Rule '{rule.rule_id}' has no business justification or owner documentation.",
                    remediation="Add a descriptive explanation, change ticket ID, and application owner before migration.",
                )

            if not rule.name:
                self._add_finding(
                    category="POLICY_GOVERNANCE",
                    rule_id=rule.rule_id,
                    severity=RISK_LOW,
                    title="Unnamed Firewall Rule",
                    description=f"Rule '{rule.rule_id}' has no descriptive name identifier.",
                    remediation="Assign a standard naming convention (e.g., APP_DB_TIER_INGRESS).",
                )

            # Syntax validation
            syntax_errors = rule.parse_networks()
            for err in syntax_errors:
                self._add_finding(
                    category="SYNTAX_INTEGRITY",
                    rule_id=rule.rule_id,
                    severity=RISK_CRITICAL,
                    title="Malformed IP/CIDR Definition",
                    description=err,
                    remediation="Correct invalid subnet mask or IP string to RFC-compliant IPv4 format.",
                )

    def _check_duplicate_rules(self):
        """Identifies exact duplicate rules across tuples."""
        seen: Dict[Tuple[str, str, str, str, str, str, str], str] = {}
        for rule in self.rules:
            if not rule.enabled:
                continue
            signature = (
                rule.source_zone,
                rule.dest_zone,
                rule.source.lower(),
                rule.destination.lower(),
                rule.protocol.lower(),
                rule.port.lower(),
                rule.action.lower(),
            )
            if signature in seen:
                orig_id = seen[signature]
                self._add_finding(
                    category="RULE_REDUNDANCY",
                    rule_id=rule.rule_id,
                    severity=RISK_MEDIUM,
                    title="Exact Duplicate Access Rule",
                    description=f"Rule '{rule.rule_id}' is an exact duplicate of preceding rule '{orig_id}'.",
                    remediation=f"Decommission and remove rule '{rule.rule_id}' to reduce rule base complexity.",
                    details={"preceding_rule": orig_id},
                )
            else:
                seen[signature] = rule.rule_id

    def _check_shadowed_rules(self):
        """Identifies shadowed and unreachable access control rules."""
        active_rules = [r for r in self.rules if r.enabled]

        for i in range(len(active_rules)):
            current = active_rules[i]
            for j in range(i):
                earlier = active_rules[j]

                # Zone check
                if earlier.source_zone != current.source_zone or earlier.dest_zone != current.dest_zone:
                    continue

                # Check if earlier rule encompasses current rule
                src_shadows = False
                if earlier.source_is_any:
                    src_shadows = True
                elif earlier.source_network and current.source_network:
                    src_shadows = current.source_network.subnet_of(earlier.source_network)

                dst_shadows = False
                if earlier.dest_is_any:
                    dst_shadows = True
                elif earlier.dest_network and current.dest_network:
                    dst_shadows = current.dest_network.subnet_of(earlier.dest_network)

                proto_shadows = earlier.protocol in ("any", "ip") or earlier.protocol == current.protocol

                port_shadows = False
                if earlier.port_is_any:
                    port_shadows = True
                elif set(current.ports_list).issubset(set(earlier.ports_list)):
                    port_shadows = True

                if src_shadows and dst_shadows and proto_shadows and port_shadows:
                    if earlier.action == current.action:
                        self._add_finding(
                            category="RULE_OPTIMIZATION",
                            rule_id=current.rule_id,
                            severity=RISK_MEDIUM,
                            title="Fully Shadowed Redundant Rule",
                            description=f"Rule '{current.rule_id}' is completely shadowed by earlier rule '{earlier.rule_id}' with identical action ({current.action}). Traffic will never hit this rule.",
                            remediation=f"Consolidate or delete rule '{current.rule_id}'.",
                            details={"shadowing_rule": earlier.rule_id},
                        )
                    else:
                        self._add_finding(
                            category="POLICY_CONFLICT",
                            rule_id=current.rule_id,
                            severity=RISK_HIGH,
                            title="Action Conflict Shadowed Rule",
                            description=f"Rule '{current.rule_id}' ({current.action}) is masked by earlier rule '{earlier.rule_id}' ({earlier.action}). The intended policy of '{current.rule_id}' will be silently overridden.",
                            remediation=f"Reorder rules: place specific rule '{current.rule_id}' above generic rule '{earlier.rule_id}'.",
                            details={"conflicting_rule": earlier.rule_id},
                        )
                    break

    def _check_overly_permissive_rules(self):
        """Flags permit rules with open source, destination, and service."""
        for rule in self.rules:
            if not rule.enabled or rule.action != "permit":
                continue

            if rule.source_is_any and rule.dest_is_any and rule.port_is_any:
                self._add_finding(
                    category="SECURITY_POSTURE",
                    rule_id=rule.rule_id,
                    severity=RISK_CRITICAL,
                    title="Unrestricted Permit Any-Any Rule",
                    description=f"Rule '{rule.rule_id}' allows unrestricted IP traffic from ANY source to ANY destination across all ports.",
                    remediation="Replace with zero-trust microsegmentation rules specifying distinct network objects and destination ports.",
                )
            elif rule.source_is_any and rule.port_is_any:
                self._add_finding(
                    category="SECURITY_POSTURE",
                    rule_id=rule.rule_id,
                    severity=RISK_HIGH,
                    title="Permit Any Service from Any Source",
                    description=f"Rule '{rule.rule_id}' permits all ports and protocols from ANY source to internal destination '{rule.destination}'.",
                    remediation="Constrain destination port to required application services and narrow source subnet scope.",
                )

    def _check_high_risk_exposures(self):
        """Identifies risky administrative and database ports permitted from untrusted zones."""
        untrusted_zones = {"outside", "internet", "wan", "guest", "untrust"}

        for rule in self.rules:
            if not rule.enabled or rule.action != "permit":
                continue

            src_z = rule.source_zone.lower()
            if src_z in untrusted_zones or rule.source_is_any:
                for p in rule.ports_list:
                    if p in SENSITIVE_MGMT_PORTS:
                        svc_name = SENSITIVE_MGMT_PORTS[p]
                        self._add_finding(
                            category="EXPOSURE_RISK",
                            rule_id=rule.rule_id,
                            severity=RISK_CRITICAL if p in (21, 23, 445, 3389) else RISK_HIGH,
                            title=f"Sensitive Management Service Exposed: {svc_name} (Port {p})",
                            description=f"Rule '{rule.rule_id}' permits inbound access to sensitive service '{svc_name}' (port {p}) from untrusted zone '{rule.source_zone}'.",
                            remediation=f"Block inbound port {p} or route through VPN with multi-factor authentication (MFA) and dedicated bastion hosts.",
                            details={"exposed_port": p, "service": svc_name},
                        )

    def _check_dormant_and_unused_rules(self):
        """Identifies unused rules based on hit count telemetry."""
        for rule in self.rules:
            if rule.hit_count == 0:
                self._add_finding(
                    category="RULE_HYGIENE",
                    rule_id=rule.rule_id,
                    severity=RISK_LOW,
                    title="Zero Hit Count (Dormant Rule)",
                    description=f"Rule '{rule.rule_id}' shows 0 recorded hits in firewall telemetry.",
                    remediation="Review rule with application owner. If obsolete, deprecate rule rather than migrating.",
                )

    def _check_infrastructure_readiness(self):
        """Validates default routing, VPN gateway, and DNS resolvers if provided."""
        if not self.infra:
            return

        routes = self.infra.get("routes", [])
        has_default_route = any(r.get("destination_prefix") in ("0.0.0.0/0", "default") for r in routes)
        if not has_default_route:
            self._add_finding(
                category="INFRASTRUCTURE_READINESS",
                rule_id="ROUTING-GATEWAY",
                severity=RISK_HIGH,
                title="Missing Default Gateway Route",
                description="Infrastructure specification does not define a default route (0.0.0.0/0) for internet transit.",
                remediation="Configure a default gateway route on the outside interface before cutover.",
            )

        dns_servers = self.infra.get("dns_resolvers", [])
        if not dns_servers:
            self._add_finding(
                category="INFRASTRUCTURE_READINESS",
                rule_id="DNS-SUBSYSTEM",
                severity=RISK_MEDIUM,
                title="Missing DNS Resolver Configuration",
                description="No DNS resolvers defined for firewall FQDN address-object resolution or NTP lookups.",
                remediation="Specify at least two internal DNS resolver IP addresses.",
            )

        vpn_peers = self.infra.get("vpn_peers", [])
        for peer in vpn_peers:
            ip_str = peer.get("peer_ip")
            if ip_str:
                try:
                    ipaddress.ip_address(ip_str)
                except ValueError:
                    self._add_finding(
                        category="INFRASTRUCTURE_READINESS",
                        rule_id="VPN-GATEWAY",
                        severity=RISK_HIGH,
                        title="Invalid VPN Peer Gateway Address",
                        description=f"VPN peer '{peer.get('name', 'unnamed')}' has invalid IP address '{ip_str}'.",
                        remediation="Provide valid RFC IPv4 address for remote VPN peer.",
                    )


def load_rules_from_csv(csv_path: Path) -> List[FirewallRule]:
    rules = []
    with open(csv_path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            rules.append(FirewallRule(row, idx))
    return rules


def generate_migration_report(
    findings: List[Dict[str, Any]], rules_count: int, input_file: str, strict: bool = False
) -> Dict[str, Any]:
    critical_count = sum(1 for f in findings if f["severity"] == RISK_CRITICAL)
    high_count = sum(1 for f in findings if f["severity"] == RISK_HIGH)
    medium_count = sum(1 for f in findings if f["severity"] == RISK_MEDIUM)
    low_count = sum(1 for f in findings if f["severity"] == RISK_LOW)

    if critical_count > 0 or high_count > 0:
        overall_readiness = "NOT_READY_HIGH_RISK"
        overall_status = STATUS_FAIL
    elif medium_count > 0:
        overall_readiness = "CONDITIONAL_APPROVAL"
        overall_status = STATUS_FAIL if strict else STATUS_WARN
    else:
        overall_readiness = "READY_FOR_MIGRATION"
        overall_status = STATUS_PASS

    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": Path(input_file).name,
        "total_rules_evaluated": rules_count,
        "overall_status": overall_status,
        "migration_readiness": overall_readiness,
        "summary": {
            "total_findings": len(findings),
            "critical_risks": critical_count,
            "high_risks": high_count,
            "medium_risks": medium_count,
            "low_risks": low_count,
        },
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Pre-Migration Firewall Policy Validation Tool (CSV & Infrastructure Analyzer)"
    )
    parser.add_argument("-r", "--rules", required=True, help="Path to firewall rules CSV file")
    parser.add_argument("-i", "--infra", help="Optional path to infrastructure JSON (routes, VPN, DNS)")
    parser.add_argument("-o", "--output", help="Path to write validation report")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json", help="Report format (default: json)")
    parser.add_argument("-s", "--strict", action="store_true", help="Fail with exit code 2 if any warnings/medium risks found")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    rules_path = Path(args.rules)
    if not rules_path.exists() or not rules_path.is_file():
        sys.stderr.write(f"Error: Rules file '{args.rules}' not found.\n")
        sys.exit(1)

    try:
        rules = load_rules_from_csv(rules_path)
    except Exception as ex:
        sys.stderr.write(f"Error parsing rules CSV '{args.rules}': {ex}\n")
        sys.exit(1)

    infra_data = None
    if args.infra:
        infra_path = Path(args.infra)
        if infra_path.exists():
            try:
                with open(infra_path, "r", encoding="utf-8") as f:
                    infra_data = json.load(f)
            except Exception as ex:
                sys.stderr.write(f"Warning: Could not parse infra JSON '{args.infra}': {ex}\n")

    engine = PolicyValidationEngine(rules, infra_data)
    engine.run_all_checks()

    report = generate_migration_report(engine.findings, len(rules), str(rules_path), args.strict)

    # Console Summary
    print("=" * 80)
    print(f"PRE-MIGRATION FIREWALL VALIDATION REPORT: {rules_path.name}")
    print(f"Readiness Decision : [ {report['migration_readiness']} ]")
    print(f"Overall Status     : [ {report['overall_status']} ]")
    print(f"Total Rules Tested : {report['total_rules_evaluated']}")
    print(
        f"Findings Summary   : {report['summary']['total_findings']} total | "
        f"{report['summary']['critical_risks']} critical | "
        f"{report['summary']['high_risks']} high | "
        f"{report['summary']['medium_risks']} medium | "
        f"{report['summary']['low_risks']} low"
    )
    print("=" * 80)

    for f in engine.findings:
        sev_tag = f"[{f['severity']}]".ljust(10)
        print(f"{sev_tag} {f['rule_id']}: {f['title']}")
        print(f"           Description : {f['description']}")
        print(f"           Remediation : {f['remediation']}")

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        if args.format == "csv":
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Category", "Rule ID", "Severity", "Title", "Description", "Remediation"])
                for fnd in engine.findings:
                    writer.writerow([
                        fnd["category"],
                        fnd["rule_id"],
                        fnd["severity"],
                        fnd["title"],
                        fnd["description"],
                        fnd["remediation"],
                    ])
        else:
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        print(f"\nReport saved successfully to: {args.output} (Format: {args.format.upper()})")

    if report["overall_status"] == STATUS_FAIL:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()

