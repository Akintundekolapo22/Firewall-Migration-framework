#!/usr/bin/env python3
"""
Unit Test Suite for Firewall Pre-Migration Validation Tool (scripts/firewall_precheck.py)
Tests structural schema validation, IP calculation, route verification,
ACL object references, edge cases, and CLI exit codes.
"""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

# Import the validator classes directly from scripts/firewall_precheck.py
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from firewall_precheck import (
    FirewallPrecheckValidator,
    STATUS_PASS,
    STATUS_WARN,
    STATUS_FAIL,
    __version__,
)


class TestFirewallPrecheckValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        valid_path = REPO_ROOT / "data" / "sample" / "migration-valid.json"
        with open(valid_path, "r", encoding="utf-8") as f:
            cls.valid_data = json.load(f)

    def setUp(self):
        # Create a deep copy for each test to prevent mutation
        self.data = copy.deepcopy(self.valid_data)

    def test_valid_manifest_passes(self):
        validator = FirewallPrecheckValidator(self.data, input_path="test_valid.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_PASS)
        self.assertEqual(report["summary"]["failures"], 0)
        self.assertGreater(report["summary"]["passed"], 5)

    def test_missing_required_top_level_field(self):
        del self.data["interfaces"]
        validator = FirewallPrecheckValidator(self.data, input_path="test_missing_field.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)
        self.assertTrue(any(c["check_id"] == "CHK-01" and c["status"] == STATUS_FAIL for c in report["individual_checks"]))

    def test_invalid_device_identity(self):
        self.data["source_firewall"]["hostname"] = ""
        self.data["target_firewall"]["management_ip"] = "300.400.500.600"
        validator = FirewallPrecheckValidator(self.data, input_path="test_device.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)
        self.assertTrue(any(c["check_id"] == "CHK-02" and c["status"] == STATUS_FAIL for c in report["individual_checks"]))

    def test_invalid_interface_cidr(self):
        self.data["interfaces"][0]["cidr"] = 35
        validator = FirewallPrecheckValidator(self.data, input_path="test_cidr.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)
        self.assertTrue(any(c["check_id"] == "CHK-03" and c["status"] == STATUS_FAIL for c in report["individual_checks"]))

    def test_duplicate_interface_ip(self):
        # Assign duplicate IP across two interfaces
        self.data["interfaces"][1]["ipv4_address"] = self.data["interfaces"][0]["ipv4_address"]
        validator = FirewallPrecheckValidator(self.data, input_path="test_dup_ip.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)
        chk = next(c for c in report["individual_checks"] if c["check_id"] == "CHK-03")
        self.assertEqual(chk["status"], STATUS_FAIL)
        self.assertIn("Duplicate IP", chk["message"])

    def test_invalid_route_destination(self):
        self.data["routes"][0]["destination_prefix"] = "999.0.0.0/24"
        validator = FirewallPrecheckValidator(self.data, input_path="test_route.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)
        self.assertTrue(any(c["check_id"] == "CHK-04" and c["status"] == STATUS_FAIL for c in report["individual_checks"]))

    def test_invalid_route_next_hop(self):
        self.data["routes"][0]["next_hop"] = "invalid-next-hop-ip"
        validator = FirewallPrecheckValidator(self.data, input_path="test_nh.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)
        self.assertTrue(any(c["check_id"] == "CHK-04" and c["status"] == STATUS_FAIL for c in report["individual_checks"]))

    def test_unreachable_next_hop_emits_warning(self):
        # Set next-hop to an IP not in any interface subnet
        self.data["routes"][0]["next_hop"] = "172.16.50.1"
        validator = FirewallPrecheckValidator(self.data, input_path="test_unreach_nh.json", strict=False)
        report = validator.run_all_checks()
        chk = next(c for c in report["individual_checks"] if c["check_id"] == "CHK-04")
        self.assertEqual(chk["status"], STATUS_WARN)
        self.assertEqual(report["overall_status"], STATUS_WARN)

    def test_strict_mode_treats_warning_as_failure(self):
        self.data["routes"][0]["next_hop"] = "172.16.50.1"
        validator = FirewallPrecheckValidator(self.data, input_path="test_strict.json", strict=True)
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)

    def test_network_object_duplicate(self):
        self.data["network_objects"].append(
            {"name": "obj-srv-web-dmz", "type": "host", "value": "198.51.100.99"}
        )
        validator = FirewallPrecheckValidator(self.data, input_path="test_dup_obj.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)
        chk = next(c for c in report["individual_checks"] if c["check_id"] == "CHK-05")
        self.assertIn("Duplicate network object", chk["message"])

    def test_network_object_inverted_range(self):
        self.data["network_objects"].append(
            {"name": "obj-bad-range", "type": "range", "value": "192.0.2.200-192.0.2.100"}
        )
        validator = FirewallPrecheckValidator(self.data, input_path="test_range.json")
        report = validator.run_all_checks()
        chk = next(c for c in report["individual_checks"] if c["check_id"] == "CHK-05")
        self.assertEqual(chk["status"], STATUS_FAIL)
        self.assertIn("greater than end IP", chk["message"])

    def test_undefined_acl_object_reference(self):
        self.data["acls"][0]["rules"].append(
            {
                "action": "permit",
                "protocol": "tcp",
                "source_object": "obj-ghost-server",
                "destination_object": "obj-srv-web-dmz",
            }
        )
        validator = FirewallPrecheckValidator(self.data, input_path="test_ghost_obj.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)
        chk = next(c for c in report["individual_checks"] if c["check_id"] == "CHK-06")
        self.assertIn("Undefined source object reference 'obj-ghost-server'", chk["message"])

    def test_hardware_capacity_exceeded(self):
        # Target has total_physical_interfaces = 2, but we configure 4 interfaces
        self.data["target_firewall"]["total_physical_interfaces"] = 2
        validator = FirewallPrecheckValidator(self.data, input_path="test_capacity.json")
        report = validator.run_all_checks()
        self.assertEqual(report["overall_status"], STATUS_FAIL)
        chk = next(c for c in report["individual_checks"] if c["check_id"] == "CHK-07")
        self.assertIn("exceed target physical port capacity", chk["message"])


class TestFirewallPrecheckCLI(unittest.TestCase):
    """Tests CLI invocation, arguments, and return codes."""

    def test_cli_valid_file_exit_code_zero(self):
        valid_path = REPO_ROOT / "data" / "sample" / "migration-valid.json"
        cmd = [sys.executable, str(REPO_ROOT / "scripts" / "firewall_precheck.py"), "-i", str(valid_path)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Overall Outcome: [ PASS ]", res.stdout)

    def test_cli_invalid_file_exit_code_two(self):
        invalid_path = REPO_ROOT / "data" / "sample" / "migration-invalid.json"
        cmd = [sys.executable, str(REPO_ROOT / "scripts" / "firewall_precheck.py"), "-i", str(invalid_path)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)
        self.assertIn("Overall Outcome: [ FAIL ]", res.stdout)

    def test_cli_missing_file_exit_code_one(self):
        cmd = [sys.executable, str(REPO_ROOT / "scripts" / "firewall_precheck.py"), "-i", "nonexistent.json"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)

    def test_cli_malformed_json_exit_code_one(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            tf.write("{ this is invalid json ]")
            temp_name = tf.name

        try:
            cmd = [sys.executable, str(REPO_ROOT / "scripts" / "firewall_precheck.py"), "-i", temp_name]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)
            self.assertIn("Malformed JSON", res.stderr)
        finally:
            Path(temp_name).unlink(missing_ok=True)

    def test_cli_output_report_generation(self):
        valid_path = REPO_ROOT / "data" / "sample" / "migration-valid.json"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            report_name = tf.name

        try:
            cmd = [
                sys.executable,
                str(REPO_ROOT / "scripts" / "firewall_precheck.py"),
                "-i",
                str(valid_path),
                "-o",
                report_name,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertTrue(Path(report_name).exists())
            with open(report_name, "r", encoding="utf-8") as f:
                rep_data = json.load(f)
            self.assertEqual(rep_data["overall_status"], "PASS")
        finally:
            Path(report_name).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

