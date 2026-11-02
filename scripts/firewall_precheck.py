#!/usr/bin/env python3
"""
Enterprise Firewall Pre-Migration Validation Tool
==================================================
Performs offline pre-migration structural, logical, and semantic integrity checks
on firewall migration definitions before deployment to target infrastructure.

Standard Library Preferred:
  argparse, json, ipaddress, pathlib, sys, datetime, typing
"""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

__version__ = "1.2.0"
TOOL_NAME = "firewall_precheck.py"

# Standard Severity Constants
SEV_INFO = "INFO"
SEV_LOW = "LOW"
SEV_MEDIUM = "MEDIUM"
SEV_HIGH = "HIGH"
SEV_CRITICAL = "CRITICAL"

# Status Constants
STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"


class ValidationCheck:
    def __init__(
        self,
        check_id: str,
        name: str,
        status: str,
        severity: str,
        message: str,
        details: Optional[Any] = None,
        remediation: Optional[str] = None,
    ):
        self.check_id = check_id
        self.name = name
        self.status = status
        self.severity = severity
        self.message = message
        self.details = details or {}
        self.remediation = remediation or ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
        }


class FirewallPrecheckValidator:
    """Validates migration manifests adhering to the enterprise firewall migration schema."""

    REQUIRED_TOP_FIELDS = [
        "schema_version",
        "migration_id",
        "source_firewall",
        "target_firewall",
        "interfaces",
        "routes",
        "network_objects",
        "acls",
    ]

    def __init__(self, data: Dict[str, Any], input_path: str, strict: bool = False):
        self.data = data
        self.input_path = input_path
        self.strict = strict
        self.checks: List[ValidationCheck] = []
        self.declared_objects: Set[str] = set()
        self.interface_subnets: List[ipaddress.IPv4Network] = []

    def run_all_checks(self) -> Dict[str, Any]:
        self.validate_schema_structure()
        if not self._has_fatal_structure():
            self.validate_device_identities()
            self.validate_interfaces()
            self.validate_routes()
            self.validate_network_objects()
            self.validate_acl_references()
            self.validate_source_target_consistency()

        return self.generate_report()

    def _has_fatal_structure(self) -> bool:
        return any(c.check_id == "CHK-01" and c.status == STATUS_FAIL for c in self.checks)

    def validate_schema_structure(self):
        """Validates presence and primitive types of required top-level keys."""
        missing = [f for f in self.REQUIRED_TOP_FIELDS if f not in self.data]
        if missing:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-01",
                    name="Top-Level Schema Structure",
                    status=STATUS_FAIL,
                    severity=SEV_CRITICAL,
                    message=f"Missing required top-level migration fields: {', '.join(missing)}",
                    details={"missing_fields": missing},
                    remediation="Add missing required keys to the migration manifest root.",
                )
            )
            return

        # Type checks
        type_errors = []
        if not isinstance(self.data.get("interfaces"), list):
            type_errors.append("'interfaces' must be a list")
        if not isinstance(self.data.get("routes"), list):
            type_errors.append("'routes' must be a list")
        if not isinstance(self.data.get("network_objects"), list):
            type_errors.append("'network_objects' must be a list")
        if not isinstance(self.data.get("acls"), list):
            type_errors.append("'acls' must be a list")

        if type_errors:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-01",
                    name="Top-Level Schema Structure",
                    status=STATUS_FAIL,
                    severity=SEV_CRITICAL,
                    message=f"Structural type errors in manifest: {'; '.join(type_errors)}",
                    details={"errors": type_errors},
                    remediation="Ensure configuration sections adhere to array/object types.",
                )
            )
        else:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-01",
                    name="Top-Level Schema Structure",
                    status=STATUS_PASS,
                    severity=SEV_INFO,
                    message="All required top-level fields are present with correct data types.",
                    details={"fields": self.REQUIRED_TOP_FIELDS},
                )
            )

    def validate_device_identities(self):
        """Validates source and target firewall metadata."""
        src = self.data.get("source_firewall", {})
        tgt = self.data.get("target_firewall", {})

        issues = []
        if not isinstance(src, dict) or not src.get("hostname"):
            issues.append("Source firewall missing valid hostname")
        if not isinstance(tgt, dict) or not tgt.get("hostname"):
            issues.append("Target firewall missing valid hostname")

        # Management IP validation
        for label, dev in [("source", src), ("target", tgt)]:
            mgmt_ip = dev.get("management_ip") if isinstance(dev, dict) else None
            if mgmt_ip:
                try:
                    ipaddress.ip_address(mgmt_ip)
                except ValueError:
                    issues.append(f"{label} management_ip '{mgmt_ip}' is not a valid IPv4/IPv6 address")

        if issues:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-02",
                    name="Firewall Device Metadata",
                    status=STATUS_FAIL,
                    severity=SEV_HIGH,
                    message=f"Device identity errors: {'; '.join(issues)}",
                    details={"issues": issues},
                    remediation="Specify compliant hostnames and valid management IP addresses for source and target.",
                )
            )
        else:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-02",
                    name="Firewall Device Metadata",
                    status=STATUS_PASS,
                    severity=SEV_LOW,
                    message=f"Source ({src.get('hostname')}) and Target ({tgt.get('hostname')}) metadata validated.",
                    details={"source": src.get("hostname"), "target": tgt.get("hostname")},
                )
            )

    def validate_interfaces(self):
        """Validates interface addresses, CIDRs, duplicates, and zone parameters."""
        interfaces = self.data.get("interfaces", [])
        seen_ips: Dict[str, str] = {}
        interface_errors = []
        self.interface_subnets.clear()

        for idx, iface in enumerate(interfaces):
            name = iface.get("name", f"unnamed-iface-{idx}")
            ip_str = iface.get("ipv4_address")
            cidr_str = iface.get("cidr")

            if not ip_str or not cidr_str:
                interface_errors.append(f"Interface '{name}' missing ipv4_address or cidr")
                continue

            full_cidr = f"{ip_str}/{cidr_str}"
            try:
                # Use strict=False so host bits don't fail parsing the interface address
                if_obj = ipaddress.ip_interface(full_cidr)
                network = if_obj.network
                self.interface_subnets.append(network)

                # Check duplicate IP
                if ip_str in seen_ips:
                    interface_errors.append(
                        f"Duplicate IP address '{ip_str}' assigned to both '{name}' and '{seen_ips[ip_str]}'"
                    )
                else:
                    seen_ips[ip_str] = name

                # Validate network broadcast or network address assignment
                if if_obj.ip == network.network_address:
                    interface_errors.append(f"Interface '{name}' IP is the network address for {network}")
                elif if_obj.ip == network.broadcast_address:
                    interface_errors.append(f"Interface '{name}' IP is the broadcast address for {network}")

            except ValueError as ve:
                interface_errors.append(f"Invalid IP/CIDR '{full_cidr}' on interface '{name}': {ve}")

        if interface_errors:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-03",
                    name="Interface Addressing and CIDR",
                    status=STATUS_FAIL,
                    severity=SEV_CRITICAL,
                    message=f"Interface validation failures: {'; '.join(interface_errors)}",
                    details={"errors": interface_errors},
                    remediation="Correct invalid CIDRs, eliminate duplicate addresses, and assign valid host IPs.",
                )
            )
        else:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-03",
                    name="Interface Addressing and CIDR",
                    status=STATUS_PASS,
                    severity=SEV_INFO,
                    message=f"All {len(interfaces)} interfaces have valid unique IPv4 addresses and CIDR subnets.",
                    details={"interface_count": len(interfaces), "allocated_ips": list(seen_ips.keys())},
                )
            )

    def validate_routes(self):
        """Validates routing table entries, next-hop reachable subnets, and conflicting destinations."""
        routes = self.data.get("routes", [])
        seen_destinations: Dict[str, str] = {}
        route_errors = []
        route_warnings = []

        for idx, r in enumerate(routes):
            prefix = r.get("destination_prefix")
            next_hop = r.get("next_hop")
            interface = r.get("interface", f"route-{idx}")

            if not prefix or not next_hop:
                route_errors.append(f"Route entry #{idx} missing destination_prefix or next_hop")
                continue

            # Validate prefix CIDR
            try:
                dest_net = ipaddress.ip_network(prefix, strict=True)
            except ValueError as ve:
                route_errors.append(f"Invalid route destination prefix '{prefix}': {ve}")
                continue

            # Validate next hop IP
            try:
                nh_ip = ipaddress.ip_address(next_hop)
            except ValueError as ve:
                route_errors.append(f"Invalid next-hop IP '{next_hop}' for prefix {prefix}: {ve}")
                continue

            # Check duplicate identical prefixes
            dest_key = dest_net.exploded
            if dest_key in seen_destinations:
                route_warnings.append(
                    f"Duplicate route destination '{prefix}' detected (Equal-Cost Multi-Path or duplicate entry with '{seen_destinations[dest_key]}')"
                )
            else:
                seen_destinations[dest_key] = interface

            # Validate next-hop is directly connected to one of the firewall interface subnets
            # (unless it's null/discard route or default)
            is_directly_reachable = False
            for iface_net in self.interface_subnets:
                if nh_ip in iface_net:
                    is_directly_reachable = True
                    break

            if not is_directly_reachable and not nh_ip.is_loopback:
                route_warnings.append(
                    f"Next-hop '{next_hop}' for prefix {prefix} does not fall within any configured interface subnet"
                )

        if route_errors:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-04",
                    name="Route Destinations and Next-Hops",
                    status=STATUS_FAIL,
                    severity=SEV_HIGH,
                    message=f"Routing table errors: {'; '.join(route_errors)}",
                    details={"errors": route_errors, "warnings": route_warnings},
                    remediation="Provide valid RFC destination prefixes and valid next-hop IP addresses.",
                )
            )
        elif route_warnings:
            status = STATUS_FAIL if self.strict else STATUS_WARN
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-04",
                    name="Route Destinations and Next-Hops",
                    status=status,
                    severity=SEV_MEDIUM,
                    message=f"Routing potential anomalies: {'; '.join(route_warnings)}",
                    details={"warnings": route_warnings},
                    remediation="Verify ECMP intentions and verify next-hop routers share a direct Layer 3 subnet.",
                )
            )
        else:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-04",
                    name="Route Destinations and Next-Hops",
                    status=STATUS_PASS,
                    severity=SEV_INFO,
                    message=f"All {len(routes)} routes validated successfully with reachable next-hops.",
                    details={"route_count": len(routes)},
                )
            )

    def validate_network_objects(self):
        """Validates network object schemas, address definitions, and duplicates."""
        objects = self.data.get("network_objects", [])
        self.declared_objects.clear()
        obj_errors = []

        for idx, obj in enumerate(objects):
            name = obj.get("name")
            obj_type = obj.get("type")
            value = obj.get("value")

            if not name or not obj_type or not value:
                obj_errors.append(f"Object #{idx} is missing name, type, or value")
                continue

            if name in self.declared_objects:
                obj_errors.append(f"Duplicate network object name '{name}' declared")
            self.declared_objects.add(name)

            # Validate according to type
            if obj_type == "host":
                try:
                    ipaddress.ip_address(value)
                except ValueError as ve:
                    obj_errors.append(f"Object '{name}' declared as host with invalid IP '{value}': {ve}")
            elif obj_type == "network":
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError as ve:
                    obj_errors.append(f"Object '{name}' declared as network with invalid CIDR '{value}': {ve}")
            elif obj_type == "range":
                parts = value.split("-")
                if len(parts) != 2:
                    obj_errors.append(f"Object '{name}' range value must be format 'START_IP-END_IP': {value}")
                else:
                    try:
                        start_ip = ipaddress.ip_address(parts[0].strip())
                        end_ip = ipaddress.ip_address(parts[1].strip())
                        if start_ip > end_ip:
                            obj_errors.append(f"Object '{name}' range start IP is greater than end IP: {value}")
                    except ValueError as ve:
                        obj_errors.append(f"Object '{name}' invalid IP in range: {ve}")
            else:
                obj_errors.append(f"Object '{name}' has unsupported type '{obj_type}'. Expected host/network/range.")

        if obj_errors:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-05",
                    name="Network Object Definitions",
                    status=STATUS_FAIL,
                    severity=SEV_HIGH,
                    message=f"Network object errors: {'; '.join(obj_errors)}",
                    details={"errors": obj_errors},
                    remediation="Correct invalid object formats and eliminate duplicate definitions.",
                )
            )
        else:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-05",
                    name="Network Object Definitions",
                    status=STATUS_PASS,
                    severity=SEV_INFO,
                    message=f"Validated {len(objects)} network objects without syntax or semantic errors.",
                    details={"declared_count": len(self.declared_objects)},
                )
            )

    def validate_acl_references(self):
        """Validates that all ACL source/destination object references exist in network_objects."""
        acls = self.data.get("acls", [])
        acl_errors = []
        rule_count = 0

        # Special keywords that are allowed without explicit object declarations
        builtin_keywords = {"any", "any4", "any6", "interface"}

        for acl in acls:
            acl_name = acl.get("name", "unnamed_acl")
            rules = acl.get("rules", [])
            for r_idx, rule in enumerate(rules):
                rule_count += 1
                src_ref = rule.get("source_object")
                dst_ref = rule.get("destination_object")

                # If source_object is specified and not a builtin keyword
                if src_ref and src_ref.lower() not in builtin_keywords:
                    if src_ref not in self.declared_objects:
                        acl_errors.append(
                            f"ACL '{acl_name}' rule #{r_idx+1}: Undefined source object reference '{src_ref}'"
                        )

                # If destination_object is specified and not a builtin keyword
                if dst_ref and dst_ref.lower() not in builtin_keywords:
                    if dst_ref not in self.declared_objects:
                        acl_errors.append(
                            f"ACL '{acl_name}' rule #{r_idx+1}: Undefined destination object reference '{dst_ref}'"
                        )

        if acl_errors:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-06",
                    name="ACL Object Reference Resolution",
                    status=STATUS_FAIL,
                    severity=SEV_CRITICAL,
                    message=f"Unresolved object references in ACL policies: {'; '.join(acl_errors)}",
                    details={"errors": acl_errors},
                    remediation="Define all referenced network objects in 'network_objects' or verify object names.",
                )
            )
        else:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-06",
                    name="ACL Object Reference Resolution",
                    status=STATUS_PASS,
                    severity=SEV_INFO,
                    message=f"All object references across {len(acls)} ACLs ({rule_count} rules) resolve cleanly.",
                    details={"acl_count": len(acls), "rule_count": rule_count},
                )
            )

    def validate_source_target_consistency(self):
        """Cross-checks topology parity between source and target firewall definitions."""
        src = self.data.get("source_firewall", {})
        tgt = self.data.get("target_firewall", {})
        interfaces = self.data.get("interfaces", [])

        warnings = []
        if src.get("model") == tgt.get("model") and src.get("os_version") == tgt.get("os_version"):
            warnings.append("Source and target platforms are identical (like-for-like replacement or cloning)")

        # Check if interface count matches target physical port specifications if supplied
        target_ports = tgt.get("total_physical_interfaces")
        if target_ports and len(interfaces) > target_ports:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-07",
                    name="Source vs Target Hardware Consistency",
                    status=STATUS_FAIL,
                    severity=SEV_HIGH,
                    message=f"Configured interfaces ({len(interfaces)}) exceed target physical port capacity ({target_ports})",
                    details={"configured_interfaces": len(interfaces), "target_capacity": target_ports},
                    remediation="Consolidate interfaces onto sub-interfaces (802.1Q VLANs) or select higher-density target hardware.",
                )
            )
            return

        if warnings:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-07",
                    name="Source vs Target Hardware Consistency",
                    status=STATUS_PASS,
                    severity=SEV_LOW,
                    message="Configuration parameters are consistent between source and target specifications.",
                    details={"notes": warnings},
                )
            )
        else:
            self.checks.append(
                ValidationCheck(
                    check_id="CHK-07",
                    name="Source vs Target Hardware Consistency",
                    status=STATUS_PASS,
                    severity=SEV_LOW,
                    message="Platform topology and interface mapping cross-checked successfully.",
                )
            )

    def generate_report(self) -> Dict[str, Any]:
        pass_count = sum(1 for c in self.checks if c.status == STATUS_PASS)
        warn_count = sum(1 for c in self.checks if c.status == STATUS_WARN)
        fail_count = sum(1 for c in self.checks if c.status == STATUS_FAIL)

        if fail_count > 0:
            overall_status = STATUS_FAIL
        elif warn_count > 0:
            overall_status = STATUS_FAIL if self.strict else STATUS_WARN
        else:
            overall_status = STATUS_PASS

        remediations = [
            f"[{c.check_id}] {c.remediation}" for c in self.checks if c.status != STATUS_PASS and c.remediation
        ]

        safe_input_name = Path(self.input_path).name

        report = {
            "tool": TOOL_NAME,
            "version": __version__,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "input_file": safe_input_name,
            "strict_mode": self.strict,
            "overall_status": overall_status,
            "summary": {
                "total_checks": len(self.checks),
                "passed": pass_count,
                "warnings": warn_count,
                "failures": fail_count,
            },
            "individual_checks": [c.to_dict() for c in self.checks],
            "remediation_recommendations": remediations,
        }
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Firewall Pre-Migration Validation Tool - Offline Structural & Semantic Checker"
    )
    parser.add_argument("-i", "--input", required=True, help="Path to migration JSON manifest")
    parser.add_argument("-o", "--output", help="Path to output JSON validation report")
    parser.add_argument(
        "-s", "--strict", action="store_true", help="Fail with exit code 2 if any warnings are detected"
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        sys.stderr.write(f"Error: Input file '{args.input}' not found.\n")
        sys.exit(1)

    if not input_path.is_file():
        sys.stderr.write(f"Error: Path '{args.input}' is not a regular file.\n")
        sys.exit(1)

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as jde:
        sys.stderr.write(f"Error: Malformed JSON in '{args.input}': {jde}\n")
        sys.exit(1)
    except Exception as ex:
        sys.stderr.write(f"Error: Could not read '{args.input}': {ex}\n")
        sys.exit(1)

    validator = FirewallPrecheckValidator(data, input_path=str(input_path), strict=args.strict)
    report = validator.run_all_checks()

    # Print summary to console
    print("=" * 80)
    print(f"FIREWALL PRE-MIGRATION VALIDATION REPORT: {input_path.name}")
    print(f"Overall Outcome: [ {report['overall_status']} ]")
    print(
        f"Checks: {report['summary']['total_checks']} total | {report['summary']['passed']} passed | "
        f"{report['summary']['warnings']} warnings | {report['summary']['failures']} failures"
    )
    print("=" * 80)

    for c in report["individual_checks"]:
        stat_prefix = f"[{c['status']}]".ljust(8)
        print(f"{stat_prefix} {c['check_id']} - {c['name']}")
        print(f"         {c['message']}")
        if c["remediation"]:
            print(f"         Remediation: {c['remediation']}")

    if args.output:
        try:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"\nDetailed JSON report exported to: {args.output}")
        except Exception as ex:
            sys.stderr.write(f"Error writing report to '{args.output}': {ex}\n")
            sys.exit(1)

    if report["overall_status"] == STATUS_FAIL:
        sys.exit(2)
    elif report["overall_status"] == STATUS_WARN and args.strict:
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()

