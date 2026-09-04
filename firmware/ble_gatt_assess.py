#!/usr/bin/env python3
"""I8 - BLE GATT Security Assessment

Bluetooth Low Energy GATT service/characteristic enumeration and security
weakness assessment.  Works offline with JSON/CSV input or live via bleak.

Uses only the Python standard library for core analysis.  Optional bleak
import is guarded behind try/except with a clear fallback message.
"""

import csv
import json
import math
import os
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from bleak import BleakScanner  # type: ignore
    HAVE_BLEAK = True
except ImportError:
    HAVE_BLEAK = False

# ---------------------------------------------------------------------------
# Known BLE UUID table (16-bit short forms expanded to full 128-bit)
# ---------------------------------------------------------------------------

_UUID_SHORT_MAP: Dict[str, str] = {
    "0x1800": "Generic Access",
    "0x1801": "Generic Attribute",
    "0x1802": "Immediate Alert",
    "0x1803": "Link Loss",
    "0x1804": "TX Power",
    "0x1805": "Current Time",
    "0x1806": "Reference Time Update",
    "0x1807": "Next DST Change",
    "0x1808": "Glucose",
    "0x1809": "Health Thermometer",
    "0x180a": "Device Information",
    "0x180c": "Network Availability",
    "0x180d": "Heart Rate",
    "0x180e": "Phone Alert Status",
    "0x180f": "Battery Service",
    "0x1810": "Blood Pressure",
    "0x1811": "Alert Notification",
    "0x1812": "Human Interface Device",
    "0x1813": "Scan Parameters",
    "0x1814": "Running Speed and Cadence",
    "0x1816": "Cycling Speed and Cadence",
    "0x1818": "Cycling Power",
    "0x181a": "Environmental Sensing",
    "0x181c": "User Data",
    "0x181d": "Weight Scale",
    "0x181e": "Bond Management",
    "0x181f": "Continuous Glucose Monitoring",
    "0x1820": "Internet Protocol Support",
    "0x1821": "Indoor Positioning",
    "0x1822": "Pulse Oximeter",
    "0x1823": "HTTP Proxy",
    "0x1824": "Transport Discovery",
    "0x1825": "Object Transfer",
    "0x1826": "Fitness Machine",
    "0x1827": "Mesh Provisioning",
    "0x1828": "Mesh Proxy",
    # Characteristics
    "0x2a00": "Device Name",
    "0x2a01": "Appearance",
    "0x2a02": "Peripheral Privacy Flag",
    "0x2a03": "Reconnection Address",
    "0x2a04": "Peripheral Preferred Connection Parameters",
    "0x2a05": "Service Changed",
    "0x2a19": "Battery Level",
    "0x2a29": "Manufacturer Name String",
    "0x2a24": "Model Number String",
    "0x2a25": "Serial Number String",
    "0x2a26": "Firmware Revision String",
    "0x2a27": "Hardware Revision String",
    "0x2a28": "Software Revision String",
    "0x2a23": "System ID",
    "0x2a2a": "IEEE 11073-20601 Regulatory",
    "0x2a37": "Heart Rate Measurement",
    "0x2a38": "Body Sensor Location",
    "0x2a39": "Heart Rate Control Point",
    "0x2a4d": "Report",
    "0x2a4e": "Protocol Mode",
    "0x2a50": "PnP ID",
}

# Expanded form: "0000XXXX-0000-1000-8000-00805f9b34fb" -> name
EXPANDED_MAP: Dict[str, str] = {}
for _short, _name in _UUID_SHORT_MAP.items():
    _hex_val = _short.replace("0x", "").lower()
    _full = "0000%s-0000-1000-8000-00805f9b34fb" % _hex_val
    EXPANDED_MAP[_full] = _name
    EXPANDED_MAP[_hex_val] = _name
    EXPANDED_MAP[_short.lower()] = _name


def resolve_uuid(uuid_str: str) -> str:
    """Return a human-readable name for a UUID, or the raw string if unknown."""
    lower = uuid_str.strip().lower()
    if lower in EXPANDED_MAP:
        return EXPANDED_MAP[lower]
    # Try 16-bit short form from last significant bytes
    if len(lower) >= 8 and lower.startswith("0000"):
        short = "0x" + lower[4:8]
        if short in _UUID_SHORT_MAP:
            return _UUID_SHORT_MAP[short]
    return "Unknown"


# ---------------------------------------------------------------------------
# Sensitive name keywords
# ---------------------------------------------------------------------------

_SENSITIVE_KEYWORDS = [
    "password", "passwd", "pass", "pwd",
    "token", "auth", "key", "secret",
    "credential", "pin", "otp",
    "private", "encrypt", "decrypt",
    "session", "cookie",
]


def _is_sensitive_name(name: str) -> bool:
    """Check whether a characteristic name suggests sensitive data."""
    lower = name.lower()
    return any(kw in lower for kw in _SENSITIVE_KEYWORDS)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Characteristic:
    uuid: str
    name: str
    properties: List[str] = field(default_factory=list)
    descriptors: List[str] = field(default_factory=list)


@dataclass
class Service:
    uuid: str
    name: str
    characteristics: List[Characteristic] = field(default_factory=list)


@dataclass
class GATTProfile:
    device_name: str = "Unknown"
    address: str = "00:00:00:00:00:00"
    services: List[Service] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    service_uuid: str = ""
    char_uuid: str = ""
    risk_score: int = 0


def _score_findings(findings: List[Finding]) -> List[Finding]:
    """Assign numeric risk scores based on severity."""
    base = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 5}
    for f in findings:
        f.risk_score = base.get(f.severity, 0)
    findings.sort(key=lambda f: (-f.risk_score, SEVERITY_ORDER.get(f.severity, 99)))
    return findings


# ---------------------------------------------------------------------------
# GATT loaders
# ---------------------------------------------------------------------------

def _char_from_dict(d: Dict[str, Any]) -> Characteristic:
    """Build a Characteristic from a dictionary."""
    return Characteristic(
        uuid=d.get("uuid", ""),
        name=d.get("name", ""),
        properties=[p.lower() for p in d.get("properties", [])],
        descriptors=d.get("descriptors", []),
    )


def load_json(path: str) -> GATTProfile:
    """Load a GATT profile from a JSON file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    profile = GATTProfile(
        device_name=data.get("device_name", "Unknown"),
        address=data.get("address", "00:00:00:00:00:00"),
    )
    for svc in data.get("services", []):
        chars = [_char_from_dict(c) for c in svc.get("characteristics", [])]
        profile.services.append(Service(
            uuid=svc.get("uuid", ""),
            name=svc.get("name", ""),
            characteristics=chars,
        ))
    return profile


def load_csv(path: str) -> GATTProfile:
    """Load a GATT profile from a CSV file.

    Expected columns:
        service_uuid, service_name, char_uuid, char_name,
        char_properties, descriptors
    """
    profile = GATTProfile()
    svc_map: Dict[str, Service] = {}
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            svc_uuid = row.get("service_uuid", "")
            if svc_uuid not in svc_map:
                svc_map[svc_uuid] = Service(
                    uuid=svc_uuid,
                    name=row.get("service_name", ""),
                )
            props_raw = row.get("char_properties", "")
            props = [p.strip().lower() for p in props_raw.split(",") if p.strip()]
            desc_raw = row.get("descriptors", "")
            descs = [d.strip() for d in desc_raw.split(",") if d.strip()]
            svc_map[svc_uuid].characteristics.append(Characteristic(
                uuid=row.get("char_uuid", ""),
                name=row.get("char_name", ""),
                properties=props,
                descriptors=descs,
            ))
    profile.services = list(svc_map.values())
    return profile


def load_gatt(path: str) -> GATTProfile:
    """Auto-detect format and load a GATT profile."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return load_json(path)
    elif ext == ".csv":
        return load_csv(path)
    # Try JSON first, then CSV
    try:
        return load_json(path)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return load_csv(path)


# ---------------------------------------------------------------------------
# Live BLE scanner (requires bleak)
# ---------------------------------------------------------------------------

async def _scan_live(address: Optional[str] = None, timeout: float = 10.0) -> GATTProfile:
    """Scan for a BLE device and enumerate its GATT services via bleak."""
    if not HAVE_BLEAK:
        raise RuntimeError(
            "bleak is required for live scanning.\n"
            "Install with: pip install bleak"
        )
    from bleak import BleakClient  # type: ignore

    print("[*] Scanning for BLE devices (timeout %.0fs)..." % timeout)
    devices = await BleakScanner.discover(timeout=timeout)

    target = None
    if address:
        for d in devices:
            if d.address.upper() == address.upper():
                target = d
                break
        if target is None:
            # Try name match
            for d in devices:
                if d.name and address.lower() in (d.name or "").lower():
                    target = d
                    break
        if target is None:
            raise RuntimeError("Device %s not found in scan results." % address)
    else:
        if not devices:
            raise RuntimeError("No BLE devices found.")
        target = devices[0]

    print("[*] Connecting to %s (%s)..." % (target.name or "?", target.address))
    profile = GATTProfile(
        device_name=target.name or "Unknown",
        address=target.address,
    )

    async with BleakClient(target) as client:
        for svc in client.services:
            service_obj = Service(uuid=str(svc.uuid), name=resolve_uuid(str(svc.uuid)))
            for char in svc.characteristics:
                props = []
                if "read" in char.properties:
                    props.append("read")
                if "write" in char.properties:
                    props.append("write")
                if "write-without-response" in char.properties:
                    props.append("write-without-response")
                if "notify" in char.properties:
                    props.append("notify")
                if "indicate" in char.properties:
                    props.append("indicate")
                if "broadcast" in char.properties:
                    props.append("broadcast")
                descriptors = [str(d.uuid) for d in char.descriptors]
                service_obj.characteristics.append(Characteristic(
                    uuid=str(char.uuid),
                    name=resolve_uuid(str(char.uuid)),
                    properties=props,
                    descriptors=descriptors,
                ))
            profile.services.append(service_obj)

    return profile


# ---------------------------------------------------------------------------
# Security assessment engine
# ---------------------------------------------------------------------------

def assess(profile: GATTProfile) -> List[Finding]:
    """Run the full security assessment and return a list of findings."""
    findings: List[Finding] = []

    for svc in profile.services:
        svc_resolved = svc.name or resolve_uuid(svc.uuid)
        for ch in svc.characteristics:
            ch_resolved = ch.name or resolve_uuid(ch.uuid)
            props_set = set(p.lower() for p in ch.properties)

            # 1. Write-without-response
            if "write-without-response" in props_set:
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Write Without Response",
                    message=(
                        "Characteristic \"%s\" (%s): write-without-response "
                        "enabled — data can be written without acknowledgment, "
                        "allowing spoofing or replay." % (ch_resolved, _short_uuid(ch.uuid))
                    ),
                    service_uuid=svc.uuid,
                    char_uuid=ch.uuid,
                ))

            # 2. Broadcast enabled
            if "broadcast" in props_set:
                findings.append(Finding(
                    severity="HIGH",
                    category="Broadcast Enabled",
                    message=(
                        "Characteristic \"%s\" (%s): broadcast enabled — "
                        "data may be sniffed by any nearby BLE receiver."
                        % (ch_resolved, _short_uuid(ch.uuid))
                    ),
                    service_uuid=svc.uuid,
                    char_uuid=ch.uuid,
                ))

            # 3. Sensitive name
            if _is_sensitive_name(ch.name):
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Sensitive Name",
                    message=(
                        "Characteristic \"%s\" (%s): sensitive name detected — "
                        "may expose credentials or secrets."
                        % (ch_resolved, _short_uuid(ch.uuid))
                    ),
                    service_uuid=svc.uuid,
                    char_uuid=ch.uuid,
                ))

            # 4. Open read (readable without authentication indication)
            if "read" in props_set and "notify" not in props_set and "indicate" not in props_set:
                # Check if it looks like it should be protected
                sensitive = _is_sensitive_name(ch.name)
                if sensitive:
                    findings.append(Finding(
                        severity="HIGH",
                        category="Unprotected Read",
                        message=(
                            "Characteristic \"%s\" (%s): sensitive data readable "
                            "without apparent authentication."
                            % (ch_resolved, _short_uuid(ch.uuid))
                        ),
                        service_uuid=svc.uuid,
                        char_uuid=ch.uuid,
                    ))
                else:
                    findings.append(Finding(
                        severity="LOW",
                        category="Open Read",
                        message=(
                            "Characteristic \"%s\" (%s): no authentication "
                            "required for read access."
                            % (ch_resolved, _short_uuid(ch.uuid))
                        ),
                        service_uuid=svc.uuid,
                        char_uuid=ch.uuid,
                    ))

            # 5. Write on sensitive-looking characteristic
            if "write" in props_set and _is_sensitive_name(ch.name):
                findings.append(Finding(
                    severity="HIGH",
                    category="Write to Sensitive Characteristic",
                    message=(
                        "Characteristic \"%s\" (%s): write-enabled on a "
                        "sensitive characteristic — potential for credential injection."
                        % (ch_resolved, _short_uuid(ch.uuid))
                    ),
                    service_uuid=svc.uuid,
                    char_uuid=ch.uuid,
                ))

            # 6. Notify/indicate without read (potential info leak via subscription)
            if ("notify" in props_set or "indicate" in props_set) and _is_sensitive_name(ch.name):
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Sensitive Notification",
                    message=(
                        "Characteristic \"%s\" (%s): notifies/indicates sensitive "
                        "data — subscribe to receive passively."
                        % (ch_resolved, _short_uuid(ch.uuid))
                    ),
                    service_uuid=svc.uuid,
                    char_uuid=ch.uuid,
                ))

    return _score_findings(findings)


def _short_uuid(uuid_str: str) -> str:
    """Return a compact display form of a UUID."""
    lower = uuid_str.strip().lower()
    if lower in EXPANDED_MAP:
        # Show 16-bit short form
        if len(lower) >= 8 and lower.startswith("0000"):
            return "0x" + lower[4:8].upper()
    return uuid_str[:16] + ("..." if len(uuid_str) > 16 else "")


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(profile: GATTProfile, findings: List[Finding]) -> str:
    """Build the human-readable assessment report string."""
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("  I8 - BLE GATT Security Assessment")
    lines.append("=" * 60)
    lines.append("")

    # Device summary
    total_chars = sum(len(s.characteristics) for s in profile.services)
    lines.append("Device: %s (%s)" % (profile.device_name, profile.address))
    lines.append("Services: %d  |  Characteristics: %d" % (len(profile.services), total_chars))
    lines.append("")

    # UUID resolution table
    lines.append("--- UUID Resolution ---")
    for svc in profile.services:
        name = svc.name or resolve_uuid(svc.uuid)
        lines.append("  %-10s -> %s" % (_short_uuid(svc.uuid), name))
        for ch in svc.characteristics:
            ch_name = ch.name or resolve_uuid(ch.uuid)
            if ch_name != name:
                lines.append("    %-8s -> %s" % (_short_uuid(ch.uuid), ch_name))
    lines.append("")

    # Characteristic properties detail
    lines.append("--- Characteristic Properties ---")
    for svc in profile.services:
        for ch in svc.characteristics:
            ch_name = ch.name or resolve_uuid(ch.uuid)
            lines.append("  %-24s (%s)  props=[%s]" % (
                ch_name, _short_uuid(ch.uuid), ", ".join(ch.properties)))
    lines.append("")

    # Security findings
    lines.append("--- Security Findings ---")
    if not findings:
        lines.append("  No security findings.")
    for f in findings:
        tag = "[%s]" % f.severity.ljust(6)
        lines.append(" %s %s" % (tag, f.message))
    lines.append("")

    # Risk summary
    lines.append("--- Risk Summary ---")
    counts = Counter(f.severity for f in findings)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(sev, 0) > 0:
            lines.append("  %-9s %d" % (sev + ":", counts[sev]))
    lines.append("  %-9s %d" % ("TOTAL:", len(findings)))
    lines.append("")

    # Risk score
    total_score = sum(f.risk_score for f in findings)
    if total_score > 0:
        max_possible = len(findings) * 100 if findings else 1
        pct = (total_score / max_possible) * 100
        lines.append("Overall Risk Score: %d / %d (%.0f%%)" % (total_score, max_possible, pct))
    lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def export_csv(findings: List[Finding], path: str) -> None:
    """Export findings to a CSV file."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["severity", "category", "risk_score",
                         "service_uuid", "char_uuid", "message"])
        for f in findings:
            writer.writerow([f.severity, f.category, f.risk_score,
                             f.service_uuid, f.char_uuid, f.message])


# ---------------------------------------------------------------------------
# Bundled sample data for offline demo
# ---------------------------------------------------------------------------

DEMO_GATT: Dict[str, Any] = {
    "device_name": "DemoFitnessTracker",
    "address": "AA:BB:CC:DD:EE:FF",
    "services": [
        {
            "uuid": "00001800-0000-1000-8000-00805f9b34fb",
            "name": "Generic Access",
            "characteristics": [
                {
                    "uuid": "00002a00-0000-1000-8000-00805f9b34fb",
                    "name": "Device Name",
                    "properties": ["read"],
                    "descriptors": [],
                },
                {
                    "uuid": "00002a01-0000-1000-8000-00805f9b34fb",
                    "name": "Appearance",
                    "properties": ["read"],
                    "descriptors": [],
                },
            ],
        },
        {
            "uuid": "0000180a-0000-1000-8000-00805f9b34fb",
            "name": "Device Information",
            "characteristics": [
                {
                    "uuid": "00002a29-0000-1000-8000-00805f9b34fb",
                    "name": "Manufacturer Name String",
                    "properties": ["read"],
                    "descriptors": [],
                },
                {
                    "uuid": "00002a24-0000-1000-8000-00805f9b34fb",
                    "name": "Model Number String",
                    "properties": ["read"],
                    "descriptors": [],
                },
                {
                    "uuid": "00002a25-0000-1000-8000-00805f9b34fb",
                    "name": "Serial Number String",
                    "properties": ["read"],
                    "descriptors": [],
                },
                {
                    "uuid": "00002a26-0000-1000-8000-00805f9b34fb",
                    "name": "Firmware Revision String",
                    "properties": ["read"],
                    "descriptors": [],
                },
            ],
        },
        {
            "uuid": "0000180f-0000-1000-8000-00805f9b34fb",
            "name": "Battery Service",
            "characteristics": [
                {
                    "uuid": "00002a19-0000-1000-8000-00805f9b34fb",
                    "name": "Battery Level",
                    "properties": ["read", "notify"],
                    "descriptors": [],
                },
            ],
        },
        {
            "uuid": "0000180d-0000-1000-8000-00805f9b34fb",
            "name": "Heart Rate",
            "characteristics": [
                {
                    "uuid": "00002a37-0000-1000-8000-00805f9b34fb",
                    "name": "Heart Rate Measurement",
                    "properties": ["notify", "broadcast"],
                    "descriptors": [],
                },
                {
                    "uuid": "00002a38-0000-1000-8000-00805f9b34fb",
                    "name": "Body Sensor Location",
                    "properties": ["read"],
                    "descriptors": [],
                },
            ],
        },
        {
            "uuid": "0000181c-0000-1000-8000-00805f9b34fb",
            "name": "User Data",
            "characteristics": [
                {
                    "uuid": "00002a2a-0000-1000-8000-00805f9b34fb",
                    "name": "IEEE Regulatory",
                    "properties": ["read"],
                    "descriptors": [],
                },
            ],
        },
        {
            "uuid": "0000ffe0-0000-1000-8000-00805f9b34fb",
            "name": "Custom Service",
            "characteristics": [
                {
                    "uuid": "0000ffe1-0000-1000-8000-00805f9b34fb",
                    "name": "Custom Secret",
                    "properties": ["read", "write-without-response"],
                    "descriptors": [],
                },
                {
                    "uuid": "0000ffe2-0000-1000-8000-00805f9b34fb",
                    "name": "User Password",
                    "properties": ["read", "write"],
                    "descriptors": [],
                },
                {
                    "uuid": "0000ffe3-0000-1000-8000-00805f9b34fb",
                    "name": "Auth Token",
                    "properties": ["read", "notify"],
                    "descriptors": [],
                },
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def _async_main() -> int:
    """Async main used when live BLE scanning is requested."""
    import argparse
    parser = argparse.ArgumentParser(
        description="I8 - BLE GATT Security Assessment Toolkit",
    )
    parser.add_argument("input_file", nargs="?", default=None,
                        help="Path to JSON or CSV GATT dump")
    parser.add_argument("--live", nargs="?", const="", default=None,
                        help="Live BLE scan (optionally pass target address)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Scan timeout in seconds (default: 10)")
    parser.add_argument("--csv", default=None,
                        help="Export findings to CSV file")
    args = parser.parse_args()

    print("=== I8 - BLE GATT Security Assessment ===")

    if args.live is not None:
        addr = args.live if args.live else None
        print("[mode] live BLE scan")
        if not HAVE_BLEAK:
            print("[!] bleak is not installed. Run: pip install bleak")
            print("[!] Falling back to demo mode.")
            profile = GATTProfile()
            for svc in DEMO_GATT["services"]:
                chars = [_char_from_dict(c) for c in svc.get("characteristics", [])]
                profile.services.append(Service(
                    uuid=svc["uuid"], name=svc["name"], characteristics=chars,
                ))
            profile.device_name = DEMO_GATT["device_name"]
            profile.address = DEMO_GATT["address"]
        else:
            profile = await _scan_live(address=addr, timeout=args.timeout)
    elif args.input_file:
        print("[mode] file (%s)" % args.input_file)
        profile = load_gatt(args.input_file)
    else:
        print("[mode] demo (bundled sample data)")
        profile = GATTProfile()
        for svc in DEMO_GATT["services"]:
            chars = [_char_from_dict(c) for c in svc.get("characteristics", [])]
            profile.services.append(Service(
                uuid=svc["uuid"], name=svc["name"], characteristics=chars,
            ))
        profile.device_name = DEMO_GATT["device_name"]
        profile.address = DEMO_GATT["address"]

    print("")
    findings = assess(profile)
    report = generate_report(profile, findings)
    print(report)

    if args.csv:
        export_csv(findings, args.csv)
        print("Findings exported to %s" % args.csv)

    return 0


def main() -> int:
    """Synchronous entry point that handles async BLE scanning if needed."""
    # Quick check: if --live is in args, we need async
    if "--live" in sys.argv:
        import asyncio
        return asyncio.run(_async_main())
    else:
        # Parse args synchronously for file/demo modes
        import argparse
        parser = argparse.ArgumentParser(
            description="I8 - BLE GATT Security Assessment Toolkit",
        )
        parser.add_argument("input_file", nargs="?", default=None,
                            help="Path to JSON or CSV GATT dump")
        parser.add_argument("--live", nargs="?", const="", default=None,
                            help="Live BLE scan (requires bleak)")
        parser.add_argument("--timeout", type=float, default=10.0,
                            help="Scan timeout in seconds (default: 10)")
        parser.add_argument("--csv", default=None,
                            help="Export findings to CSV file")
        args = parser.parse_args()

        print("=== I8 - BLE GATT Security Assessment ===")

        if args.input_file:
            print("[mode] file (%s)" % args.input_file)
            profile = load_gatt(args.input_file)
        else:
            print("[mode] demo (bundled sample data)")
            profile = GATTProfile()
            for svc in DEMO_GATT["services"]:
                chars = [_char_from_dict(c) for c in svc.get("characteristics", [])]
                profile.services.append(Service(
                    uuid=svc["uuid"], name=svc["name"], characteristics=chars,
                ))
            profile.device_name = DEMO_GATT["device_name"]
            profile.address = DEMO_GATT["address"]

        print("")
        findings = assess(profile)
        report = generate_report(profile, findings)
        print(report)

        if args.csv:
            export_csv(findings, args.csv)
            print("Findings exported to %s" % args.csv)

        return 0


if __name__ == "__main__":
    sys.exit(main())
