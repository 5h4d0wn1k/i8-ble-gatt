#!/usr/bin/env python3
"""Deterministic offline tests for I8 - BLE GATT assessment (byte-level)."""

import csv
import json
import os
import sys
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO, "firmware"))

from ble_gatt_assess import (
    assess, build_profile_from_att, load_csv, load_json, load_gatt,
    parse_att_pdu, parse_adv_packet, profile_from_dict, resolve_uuid,
    _is_sensitive_name, run_demo,
)


class TestUUIDResolution(unittest.TestCase):
    def test_short_form(self):
        self.assertEqual(resolve_uuid("0x180f"), "Battery Service")

    def test_full_form(self):
        self.assertEqual(
            resolve_uuid("0000180f-0000-1000-8000-00805f9b34fb"),
            "Battery Service")

    def test_full_form_characteristic(self):
        self.assertEqual(
            resolve_uuid("00002a00-0000-1000-8000-00805f9b34fb"),
            "Device Name")

    def test_unknown(self):
        self.assertEqual(resolve_uuid("0xdead"), "Unknown")


class TestSensitiveNames(unittest.TestCase):
    def test_password(self):
        self.assertTrue(_is_sensitive_name("User Password"))

    def test_token(self):
        self.assertTrue(_is_sensitive_name("Auth Token"))

    def test_battery_battery_level(self):
        self.assertFalse(_is_sensitive_name("Battery Level"))

    def test_device_name(self):
        self.assertFalse(_is_sensitive_name("Device Name"))


SAMPLE_JSON = {
    "device_name": "ExampleSensor",
    "address": "AA:BB:CC:DD:EE:FF",
    "services": [
        {
            "uuid": "0000180f-0000-1000-8000-00805f9b34fb",
            "name": "Battery Service",
            "characteristics": [
                {
                    "uuid": "00002a19-0000-1000-8000-00805f9b34fb",
                    "name": "Battery Level",
                    "properties": ["read"],
                    "descriptors": [],
                },
            ],
        },
    ],
}


class TestLoaders(unittest.TestCase):
    def test_load_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump(SAMPLE_JSON, fh)
            path = fh.name
        try:
            profile = load_json(path)
            self.assertEqual(profile.device_name, "ExampleSensor")
            self.assertEqual(len(profile.services), 1)
            self.assertEqual(profile.services[0].name, "Battery Service")
            self.assertEqual(
                profile.services[0].characteristics[0].properties, ["read"])
        finally:
            os.unlink(path)

    def test_load_csv(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", newline="",
                                         delete=False) as fh:
            writer = csv.DictWriter(fh, fieldnames=[
                "service_uuid", "service_name", "char_uuid", "char_name",
                "char_properties", "descriptors"])
            writer.writeheader()
            writer.writerow({
                "service_uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                "service_name": "Battery Service",
                "char_uuid": "00002a19-0000-1000-8000-00805f9b34fb",
                "char_name": "Battery Level",
                "char_properties": "read, notify",
                "descriptors": "",
            })
            path = fh.name
        try:
            profile = load_csv(path)
            self.assertEqual(len(profile.services), 1)
            self.assertEqual(
                profile.services[0].characteristics[0].properties,
                ["read", "notify"])
        finally:
            os.unlink(path)

    def test_load_gatt_auto_detect(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump(SAMPLE_JSON, fh)
            path = fh.name
        try:
            profile = load_gatt(path)
            self.assertEqual(len(profile.services), 1)
        finally:
            os.unlink(path)

    def test_profile_from_dict(self):
        profile = profile_from_dict(SAMPLE_JSON)
        self.assertEqual(profile.services[0].characteristics[0].name,
                         "Battery Level")


class TestAssessment(unittest.TestCase):
    def setUp(self):
        self.profile = profile_from_dict({
            "device_name": "DemoFitnessTracker",
            "address": "AA:BB:CC:DD:EE:FF",
            "services": [{
                "uuid": "0000180d-0000-1000-8000-00805f9b34fb",
                "name": "Heart Rate",
                "characteristics": [{
                    "uuid": "00002a37-0000-1000-8000-00805f9b34fb",
                    "name": "Heart Rate Measurement",
                    "properties": ["notify", "broadcast"],
                }],
            }, {
                "uuid": "0000ffe0-0000-1000-8000-00805f9b34fb",
                "name": "Custom Service",
                "characteristics": [
                    {"uuid": "0000ffe1-0000-1000-8000-00805f9b34fb",
                     "name": "Custom Secret",
                     "properties": ["read", "write-without-response"]},
                    {"uuid": "0000ffe2-0000-1000-8000-00805f9b34fb",
                     "name": "User Password",
                     "properties": ["read", "write"]},
                ],
            }],
        })

    def test_broadcast_enabled_high(self):
        finds = assess(self.profile)
        hits = [f for f in finds if f.category == "Broadcast Enabled"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "HIGH")

    def test_write_without_response_medium(self):
        finds = assess(self.profile)
        hits = [f for f in finds
                if f.category == "Write Without Response"
                and "ffe1" in f.char_uuid]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "MEDIUM")

    def test_write_to_sensitive_high(self):
        finds = assess(self.profile)
        hits = [f for f in finds
                if f.category == "Write to Sensitive Characteristic"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "HIGH")

    def test_sensitive_name_detected(self):
        finds = assess(self.profile)
        hits = [f for f in finds if f.category == "Sensitive Name"]
        self.assertGreaterEqual(len(hits), 1)

    def test_findings_sorted_by_risk(self):
        finds = assess(self.profile)
        scores = [f.risk_score for f in finds]
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestAttPdu(unittest.TestCase):
    def test_exchange_mtu_request(self):
        pdu = parse_att_pdu(bytes.fromhex("02f800"))
        self.assertEqual(pdu["opcode"], 0x02)
        self.assertEqual(pdu["opcode_name"], "Exchange MTU Request")
        self.assertEqual(pdu["client_rx_mtu"], 248)
        self.assertTrue(pdu["expects_response"])
        self.assertFalse(pdu["is_command"])

    def test_write_request(self):
        pdu = parse_att_pdu(bytes.fromhex("122300616300"))
        self.assertEqual(pdu["opcode_name"], "Write Request")
        self.assertEqual(pdu["handle"], 0x23)
        self.assertEqual(pdu["value"], "616300")
        self.assertTrue(pdu["expects_response"])

    def test_notification_no_response(self):
        pdu = parse_att_pdu(bytes.fromhex("1b24002a00"))
        self.assertEqual(pdu["opcode_name"], "Handle Value Notification")
        self.assertEqual(pdu["handle"], 0x24)
        self.assertEqual(pdu["value"], "2a00")
        self.assertFalse(pdu["expects_response"])
        self.assertTrue(pdu["is_command"])

    def test_error_response_fields(self):
        pdu = parse_att_pdu(bytes.fromhex("010823000a"))
        self.assertEqual(pdu["req_opcode"], 0x08)
        self.assertEqual(pdu["att_handle"], 0x23)
        self.assertEqual(pdu["error"], 0x0a)
        self.assertEqual(pdu["error_name"], "Attribute Not Found")

    def test_group_type_response(self):
        pdu = parse_att_pdu(bytes.fromhex("110601000b000f18"))
        self.assertEqual(pdu["opcode_name"], "Read By Group Type Response")
        self.assertEqual(len(pdu["items"]), 1)
        self.assertEqual(pdu["items"][0]["handle"], 1)
        self.assertEqual(pdu["items"][0]["group_end"], 11)
        self.assertEqual(pdu["items"][0]["uuid_short"], "0x180f")
        self.assertEqual(pdu["items"][0]["uuid_name"], "Battery Service")

    def test_read_by_type_response(self):
        pdu = parse_att_pdu(bytes.fromhex("09070200020300192a"))
        self.assertEqual(pdu["opcode_name"], "Read By Type Response")
        self.assertEqual(pdu["items"][0]["handle"], 2)
        self.assertEqual(pdu["items"][0]["data"], "020300192a")

    def test_read_request_handle(self):
        pdu = parse_att_pdu(bytes.fromhex("0a2300"))
        self.assertEqual(pdu["opcode_name"], "Read Request")
        self.assertEqual(pdu["handle"], 0x23)

    def test_partial_pdu_safe(self):
        pdu = parse_att_pdu(bytes.fromhex("01"))
        self.assertTrue(pdu.get("partial"))
        self.assertEqual(pdu["opcode_name"], "Error Response")

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            parse_att_pdu(b"")


class TestAdvPacket(unittest.TestCase):
    def test_parses_name_and_flags(self):
        adv = parse_adv_packet(
            bytes.fromhex("00112233445566020106090944656d6f54657374"))
        self.assertEqual(adv["pdu_type_name"], "ADV_IND")
        self.assertEqual(adv["adv_addr_hex"], "112233445566")
        self.assertEqual(adv["local_name"], "DemoTest")
        self.assertEqual(len(adv["ad_fields"]), 2)
        self.assertEqual(adv["ad_fields"][0]["type_name"], "Flags")

    def test_flag_byte_present(self):
        adv = parse_adv_packet(
            bytes.fromhex("00112233445566020106090944656d6f54657374"))
        self.assertEqual(adv["ad_fields"][0]["data"], "06")

    def test_no_name_when_not_present(self):
        adv = parse_adv_packet(bytes.fromhex("00112233445566020106"))
        self.assertNotIn("local_name", adv)
        self.assertEqual(len(adv["ad_fields"]), 1)


class TestWireReconstruction(unittest.TestCase):
    def test_discovery_builds_profile(self):
        profile = build_profile_from_att([
            bytes.fromhex("110601000b000f18"),
            bytes.fromhex("09070200020300192a"),
        ])
        self.assertEqual(len(profile.services), 1)
        svc = profile.services[0]
        self.assertEqual(svc.name, "Battery Service")
        self.assertEqual(len(svc.characteristics), 1)
        ch = svc.characteristics[0]
        self.assertEqual(ch.name, "Battery Level")
        self.assertEqual(ch.properties, ["read"])

    def test_wire_profile_assessable(self):
        profile = build_profile_from_att([
            bytes.fromhex("110601000b000f18"),
            bytes.fromhex("09070200020300192a"),
        ])
        finds = assess(profile)
        self.assertTrue(any(f.category == "Open Read" for f in finds))


class TestDemo(unittest.TestCase):
    def test_demo_exits_zero_with_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = run_demo(tmp, print_report=False)
            self.assertEqual(rc, 0)
            path = os.path.join(tmp, "i8_demo_report.json")
            self.assertTrue(os.path.exists(path))
            with open(path) as fh:
                data = json.load(fh)
            self.assertGreaterEqual(data["service_count"], 1)
            self.assertGreaterEqual(len(data["findings"]), 1)
            self.assertEqual(data["demo_exit"], 0)
            self.assertEqual(len(data["att_parses"]), 4)
            self.assertEqual(data["wire_discovered_characteristics"], 1)


if __name__ == "__main__":
    unittest.main()