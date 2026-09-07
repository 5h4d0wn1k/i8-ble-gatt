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
# Wire-level protocol: ATT (Attribute Protocol) PDU parsing
# ---------------------------------------------------------------------------

ATT_OPCODES: Dict[int, Dict[str, Any]] = {
    0x01: {"name": "Error Response", "rcv": "req"},
    0x02: {"name": "Exchange MTU Request", "rcv": "req"},
    0x03: {"name": "Exchange MTU Response", "rcv": "rsp"},
    0x04: {"name": "Find Information Request", "rcv": "req"},
    0x05: {"name": "Find Information Response", "rcv": "rsp"},
    0x06: {"name": "Find By Type Value Request", "rcv": "req"},
    0x07: {"name": "Find By Type Value Response", "rcv": "rsp"},
    0x08: {"name": "Read By Type Request", "rcv": "req"},
    0x09: {"name": "Read By Type Response", "rcv": "rsp"},
    0x0a: {"name": "Read Request", "rcv": "req"},
    0x0b: {"name": "Read Response", "rcv": "rsp"},
    0x0c: {"name": "Read Blob Request", "rcv": "req"},
    0x0d: {"name": "Read Blob Response", "rcv": "rsp"},
    0x0e: {"name": "Read Multiple Request", "rcv": "req"},
    0x0f: {"name": "Read Multiple Response", "rcv": "rsp"},
    0x10: {"name": "Read By Group Type Request", "rcv": "req"},
    0x11: {"name": "Read By Group Type Response", "rcv": "rsp"},
    0x12: {"name": "Write Request", "rcv": "req"},
    0x13: {"name": "Write Response", "rcv": "rsp"},
    0x14: {"name": "Write Command", "rcv": "cmd"},
    0x15: {"name": "Signed Write Command", "rcv": "cmd"},
    0x16: {"name": "Prepare Write Request", "rcv": "req"},
    0x17: {"name": "Prepare Write Response", "rcv": "rsp"},
    0x18: {"name": "Execute Write Request", "rcv": "req"},
    0x19: {"name": "Execute Write Response", "rcv": "rsp"},
    0x1b: {"name": "Handle Value Notification", "rcv": "cmd"},
    0x1d: {"name": "Handle Value Indication", "rcv": "req"},
    0x1e: {"name": "Handle Value Confirmation", "rcv": "rsp"},
}

ATT_ERRORS: Dict[int, str] = {
    0x01: "Invalid Handle",
    0x02: "Read Not Permitted",
    0x03: "Write Not Permitted",
    0x04: "Invalid PDU",
    0x05: "Insufficient Authentication",
    0x06: "Request Not Supported",
    0x07: "Invalid Offset",
    0x08: "Insufficient Authorization",
    0x09: "Prepare Queue Full",
    0x0a: "Attribute Not Found",
    0x0b: "Attribute Not Long",
    0x0c: "Insufficient Encryption Key Size",
    0x0d: "Invalid Attribute Value Length",
    0x0e: "Unlikely Error",
    0x0f: "Insufficient Encryption",
    0x10: "Unsupported Group Type",
    0x11: "Insufficient Resources",
}

GAP_AD_TYPES: Dict[int, str] = {
    0x01: "Flags",
    0x02: "Incomplete List of 16-bit Service UUIDs",
    0x03: "Complete List of 16-bit Service UUIDs",
    0x04: "Incomplete List of 32-bit Service UUIDs",
    0x05: "Complete List of 32-bit Service UUIDs",
    0x06: "Incomplete List of 128-bit Service UUIDs",
    0x07: "Complete List of 128-bit Service UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0a: "TX Power Level",
    0x16: "Service Data",
    0xff: "Manufacturer Specific Data",
}

ADV_PDU_NAMES: Dict[int, str] = {
    0x00: "ADV_IND",
    0x01: "ADV_DIRECT_IND",
    0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ",
    0x04: "SCAN_RSP",
    0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND",
}


def _le16(b, off):
    return b[off] | (b[off + 1] << 8)


def _uuid_short_label(b: bytes) -> str:
    """Render a raw LE 2-byte UUID as '0xXXXX'."""
    if len(b) == 2:
        return "0x%04x" % _le16(b, 0)
    return b.hex()


def parse_att_pdu(raw: bytes) -> Dict[str, Any]:
    """Parse a raw ATT protocol data unit into its fields.

    Returns a JSON-safe dict (values are hex strings / ints / lists). Always
    exposes the opcode, its human-readable name, payload length and whether the
    PDU expects a response / is a no-response command.
    """
    if not raw:
        raise ValueError("empty ATT PDU")
    op = raw[0]
    meta = ATT_OPCODES.get(op, {})
    rcv = meta.get("rcv", "rsp")
    out: Dict[str, Any] = {
        "opcode": op,
        "opcode_name": meta.get("name", "0x%02x" % op),
        "length": len(raw),
        "expects_response": rcv == "req",
        "is_command": rcv == "cmd",
    }
    try:
        if op == 0x01:  # Error response
            out.update(
                req_opcode=raw[1],
                att_handle=_le16(raw, 2),
                error=raw[4],
                error_name=ATT_ERRORS.get(raw[4], "0x%02x" % raw[4]),
            )
        elif op == 0x02:
            out["client_rx_mtu"] = _le16(raw, 1)
        elif op == 0x03:
            out["server_rx_mtu"] = _le16(raw, 1)
        elif op in (0x04,):
            out.update(start_handle=_le16(raw, 1), end_handle=_le16(raw, 3))
        elif op == 0x05:  # Find information response
            fmt = raw[1]
            step = 4 if fmt == 1 else 18
            uuids = []
            for i in range(2, len(raw) - 1, step):
                uuids.append(_uuid_short_label(raw[i:i + 2]))
            out.update(format=fmt, uuids=uuids)
        elif op == 0x06:
            out.update(
                start_handle=_le16(raw, 1),
                end_handle=_le16(raw, 3),
                type=raw[5:7].hex(),
                value=raw[7:].hex(),
            )
        elif op == 0x07:
            items = []
            for i in range(1, len(raw) - 3, 4):
                items.append({"handle": _le16(raw, i),
                              "group_end": _le16(raw, i + 2)})
            out["items"] = items
        elif op == 0x08:
            out.update(
                start_handle=_le16(raw, 1),
                end_handle=_le16(raw, 3),
                type=raw[5:].hex(),
            )
        elif op == 0x09:  # Read by type response
            length = raw[1]
            step = max(2, length)
            items = []
            for i in range(2, len(raw) - 1, step):
                items.append({"handle": _le16(raw, i),
                              "data": raw[i + 2:i + step].hex()})
            out.update(pair_length=length, items=items)
        elif op == 0x0a:
            out["handle"] = _le16(raw, 1)
        elif op == 0x0b:
            out["value"] = raw[1:].hex()
        elif op == 0x0c:
            out.update(handle=_le16(raw, 1), offset=_le16(raw, 3))
        elif op == 0x0d:
            out["value"] = raw[1:].hex()
        elif op == 0x0e:
            out["handles"] = [_le16(raw, i) for i in range(1, len(raw) - 1, 2)]
        elif op == 0x0f:
            out["values"] = raw[1:].hex()
        elif op == 0x10:  # Read by group type request (service discovery)
            out.update(
                start_handle=_le16(raw, 1),
                end_handle=_le16(raw, 3),
                group_type=raw[5:].hex(),
            )
        elif op == 0x11:  # Read by group type response (services)
            length = raw[1]
            step = max(2, length)
            items = []
            for i in range(2, len(raw) - 1, step):
                uuid_bytes = raw[i + 4:i + step]
                short = _uuid_short_label(uuid_bytes)
                items.append({
                    "handle": _le16(raw, i),
                    "group_end": _le16(raw, i + 2),
                    "uuid_short": short,
                    "uuid_name": resolve_uuid(short),
                })
            out.update(pair_length=length, items=items)
        elif op == 0x12:  # Write request
            out.update(handle=_le16(raw, 1), value=raw[3:].hex())
        elif op == 0x13:
            out.update(handle=_le16(raw, 1))
        elif op in (0x14,):  # Write command
            out.update(handle=_le16(raw, 1), value=raw[3:].hex())
        elif op == 0x15:  # Signed write command
            out.update(handle=_le16(raw, 1), signature=raw[3:11].hex(),
                       value=raw[11:].hex())
        elif op in (0x16, 0x17):
            out.update(handle=_le16(raw, 1), offset=_le16(raw, 3),
                       value=raw[5:].hex())
        elif op == 0x18:
            out["operation"] = raw[1]
        elif op == 0x19:
            out["flags"] = raw[1]
        elif op in (0x1b, 0x1d):  # Notification / indication
            out.update(handle=_le16(raw, 1), value=raw[3:].hex())
        elif op == 0x1e:
            out["handle"] = _le16(raw, 1)
    except IndexError:
        out["partial"] = True
    return out


def render_att_pdu(pdu: Dict[str, Any]) -> str:
    """Human-readable one-liner for a parsed ATT PDU."""
    parts = ["0x%02x %s (len %d)" % (pdu["opcode"], pdu["opcode_name"],
                                     pdu["length"])]
    for key in ("handle", "value", "client_rx_mtu", "server_rx_mtu",
                "start_handle", "end_handle", "type", "group_type",
                "req_opcode", "error_name"):
        if key in pdu:
            parts.append("%s=%s" % (key, pdu[key]))
    if pdu.get("expects_response"):
        parts.append("(expects response)")
    if pdu.get("is_command"):
        parts.append("(no response)")
    return " ".join(parts)


def parse_adv_packet(raw: bytes) -> Dict[str, Any]:
    """Parse a raw BLE advertisement (GAP) packet.

    Layout: PDU header byte, 6-byte advertiser address, then AD structures of
    (length, type, data). JSON-safe output.
    """
    if len(raw) < 7:
        raise ValueError("advertisement packet too short")
    header = raw[0]
    pdu_type = header & 0x0f
    out: Dict[str, Any] = {
        "pdu_type": pdu_type,
        "pdu_type_name": ADV_PDU_NAMES.get(pdu_type, "0x%02x" % pdu_type),
        "tx_address_random": bool((header >> 6) & 1),
        "rx_address_random": bool((header >> 7) & 1),
        "adv_addr_hex": raw[1:7].hex(),
        "ad_fields": [],
    }
    local_name = None
    i = 7
    while i < len(raw):
        ln = raw[i]
        if ln == 0:
            break
        if i + 1 + ln > len(raw):
            break
        typ = raw[i + 1]
        data = raw[i + 2:i + 1 + ln]
        out["ad_fields"].append({
            "type": typ,
            "type_name": GAP_AD_TYPES.get(typ, "0x%02x" % typ),
            "data": data.hex(),
        })
        if typ in (0x08, 0x09):
            try:
                text = data.decode("utf-8")
                local_name = text
            except UnicodeDecodeError:
                pass
        i += 1 + ln
    if local_name is not None:
        out["local_name"] = local_name
    return out


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


def profile_from_dict(data: Dict[str, Any]) -> GATTProfile:
    """Build a GATTProfile from a JSON-like dict."""
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


def _full_uuid16(short: int) -> str:
    """Expand a 16-bit UUID to the standard 128-bit base form."""
    return "0000%04x-0000-1000-8000-00805f9b34fb" % short


def _props_from_flags(b: int) -> List[str]:
    """Decode a characteristic properties byte into the standard names."""
    props = []
    if b & 0x01:
        props.append("broadcast")
    if b & 0x02:
        props.append("read")
    if b & 0x04:
        props.append("write-without-response")
    if b & 0x08:
        props.append("write")
    if b & 0x10:
        props.append("notify")
    if b & 0x20:
        props.append("indicate")
    if b & 0x40:
        props.append("authenticated-signed-writes")
    if b & 0x80:
        props.append("extended-properties")
    return props


def build_profile_from_att(pdus: List[bytes]) -> GATTProfile:
    """Reconstruct a GATTProfile from raw ATT discovery responses.

    Consumes Read By Group Type responses (services) and Read By Type responses
    (characteristic declarations) in order, mirroring how a client would
    discover primary services and their characteristics over the wire.
    """
    profile = GATTProfile(device_name="WireDiscovery", address="00:00:00:00:00:00")
    current_service: Optional[Service] = None
    for raw in pdus:
        pdu = parse_att_pdu(raw)
        op = pdu["opcode"]
        if op == 0x11:
            for it in pdu.get("items", []):
                short = int(it["uuid_short"], 16)
                svc = Service(uuid=_full_uuid16(short),
                              name=resolve_uuid(it["uuid_short"]))
                profile.services.append(svc)
                current_service = svc
        elif op == 0x09:
            if current_service is None:
                continue
            for it in pdu.get("items", []):
                data = bytes.fromhex(it["data"])
                if len(data) < 4:  # props(1) + value handle(2) + uuid(>=2)
                    continue
                props_byte = data[0]
                uuid_bytes = data[3:]
                if len(uuid_bytes) == 2:
                    short = _le16(uuid_bytes, 0)
                    full = _full_uuid16(short)
                else:
                    full = "-".join([
                        uuid_bytes.hex()[:8],
                        uuid_bytes.hex()[8:12],
                        uuid_bytes.hex()[12:16],
                        uuid_bytes.hex()[16:20],
                        uuid_bytes.hex()[20:32],
                    ])
                current_service.characteristics.append(Characteristic(
                    uuid=full,
                    name=resolve_uuid(full),
                    properties=_props_from_flags(props_byte),
                ))
    return profile


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

# Raw ATT PDUs for the demo (hex): MTU exchange, write request, notification,
# error response.
DEMO_ATT_PDUS: List[str] = [
    "02f800",              # Exchange MTU Request, client rx MTU 248
    "122300616300",        # Write Request to handle 0x0023, value "ac\x00"
    "1b24002a00",          # Handle Value Notification, handle 0x0024, b"\x2a"
    "010823000a",          # Error Response: Attribute Not Found (0x0a)
]

# Raw ATT discovery trace used to reconstruct a wire profile:
#  - Read By Group Type Response: service handle 1, group end 11, UUID 0x180f
#  - Read By Type Response: handle 2, properties Read, value handle 3,
#                           UUID 0x2a19 (Battery Level)
DEMO_ATT_DISCOVERY: List[str] = [
    "110601000b000f18",
    "09070200020300192a",
]

# Raw BLE advertisement: ADV_IND, adv addr aabbccddeeff (masked), the Flags AD
# structure and a Complete Local Name AD structure ("DemoTest").
DEMO_ADV: str = "00112233445566020106090944656d6f54657374"

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

# ---------------------------------------------------------------------------
# JSON report writer
# ---------------------------------------------------------------------------

def _report_dict(profile: GATTProfile, findings: List[Finding]) -> Dict[str, Any]:
    total_chars = sum(len(s.characteristics) for s in profile.services)
    total_score = sum(f.risk_score for f in findings)
    max_possible = len(findings) * 100 if findings else 1
    return {
        "tool": "i8-ble-gatt",
        "device_name": profile.device_name,
        "address": profile.address,
        "service_count": len(profile.services),
        "characteristic_count": total_chars,
        "services": [
            {
                "uuid": s.uuid,
                "name": s.name,
                "characteristics": [
                    {"uuid": c.uuid, "name": c.name,
                     "properties": c.properties, "descriptors": c.descriptors}
                    for c in s.characteristics
                ],
            } for s in profile.services
        ],
        "findings": [
            {"severity": f.severity, "category": f.category,
             "risk_score": f.risk_score, "service_uuid": f.service_uuid,
             "char_uuid": f.char_uuid, "message": f.message}
            for f in findings
        ],
        "risk_score_total": total_score,
        "risk_score_percent": round(float(total_score) / max_possible * 100, 1),
    }


def _write_json_report(profile: GATTProfile, findings: List[Finding],
                       report_dir: str, filename: str) -> str:
    os.makedirs(report_dir, exist_ok=True)
    path = os.path.join(report_dir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_report_dict(profile, findings), fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# Offline demo
# ---------------------------------------------------------------------------

def run_demo(report_dir: str = "reports", print_report: bool = True) -> int:
    """Offline demo: bundled GATT assessment, wire-level ATT/ADV parses and a
    wire-discovery reconstruction. Writes reports/i8_demo_report.json and
    returns 0."""
    os.makedirs(report_dir, exist_ok=True)
    profile = profile_from_dict(DEMO_GATT)
    findings = assess(profile)

    if print_report:
        print("=== I8 - BLE GATT Security Assessment ===")
        print("[mode] demo (bundled sample data + wire-level ATT/ADV)")
        print("")
        print(generate_report(profile, findings))

    print("")
    print("-- Wire-level ATT PDU parses --")
    att_parses = []
    for h in DEMO_ATT_PDUS:
        pdu = parse_att_pdu(bytes.fromhex(h))
        att_parses.append(pdu)
        print("  0x%02x %-30s %s" % (pdu["opcode"], render_att_pdu(pdu), h))

    adv = parse_adv_packet(bytes.fromhex(DEMO_ADV))
    print("")
    print("- advertisement: %s, addr=%s, name=%s" % (
        adv["pdu_type_name"], adv["adv_addr_hex"],
        adv.get("local_name", "?")))

    wire_profile = build_profile_from_att([bytes.fromhex(x)
                                           for x in DEMO_ATT_DISCOVERY])
    wire_findings = assess(wire_profile)
    print("- wire discovery: %d service(s), %d characteristic(s)" % (
        len(wire_profile.services),
        sum(len(s.characteristics) for s in wire_profile.services)))
    for svc in wire_profile.services:
        for ch in svc.characteristics:
            print("  %s / %s  props=[%s]" % (
                svc.name, ch.name, ", ".join(ch.properties)))

    data = _report_dict(profile, findings)
    data["att_parses"] = [
        {"pdu": h, "opcode": p["opcode"], "opcode_name": p["opcode_name"]}
        for h, p in zip(DEMO_ATT_PDUS, att_parses)
    ]
    data["advertisement"] = adv
    data["wire_discovered_services"] = len(wire_profile.services)
    data["wire_discovered_characteristics"] = sum(
        len(s.characteristics) for s in wire_profile.services)
    data["wire_findings"] = [
        {"severity": f.severity, "category": f.category, "message": f.message}
        for f in wire_findings
    ]
    data["att_round_trip"] = all(
        parse_att_pdu(bytes.fromhex(h))["opcode"] == p["opcode"]
        for h, p in zip(DEMO_ATT_PDUS, att_parses))
    data["demo_exit"] = 0

    json_path = os.path.join(report_dir, "i8_demo_report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    if print_report:
        print("")
        print("[+] Report: %s" % json_path)
        print("[+] Demo complete - exit 0")
    return 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_parser() -> "argparse.ArgumentParser":
    """Shared argument parser for sync and async paths."""
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
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo (bundled GATT + wire-level "
                             "ATT/ADV parses), write reports/i8_demo_report.json, exit 0")
    parser.add_argument("--att", default=None, metavar="HEX",
                        help="Parse a raw ATT protocol data unit from hex")
    parser.add_argument("--adv", default=None, metavar="HEX",
                        help="Parse a raw BLE advertisement (GAP) packet from hex")
    parser.add_argument("--json", action="store_true",
                        help="Write JSON report to --report-dir")
    parser.add_argument("--report-dir", default="reports",
                        help="Directory for JSON reports (default: reports)")
    return parser


def _run_assessment(profile: GATTProfile, args: Any) -> int:
    findings = assess(profile)
    print("")
    print(generate_report(profile, findings))
    if args.csv:
        export_csv(findings, args.csv)
        print("Findings exported to %s" % args.csv)
    if args.json:
        path = _write_json_report(profile, findings, args.report_dir,
                                  "i8_gatt_report.json")
        print("Report written to %s" % path)
    return 0


async def _async_main(args: Any) -> int:
    """Async path used when a live BLE scan is requested."""
    print("=== I8 - BLE GATT Security Assessment ===")
    addr = args.live or None
    print("[mode] live BLE scan")
    if not HAVE_BLEAK:
        print("[!] bleak is not installed. Run: pip install bleak")
        print("[!] Falling back to demo mode.")
        profile = profile_from_dict(DEMO_GATT)
    else:
        profile = await _scan_live(address=addr, timeout=args.timeout)
    return _run_assessment(profile, args)


def _file_or_demo(args: Any) -> int:
    print("=== I8 - BLE GATT Security Assessment ===")
    if args.input_file:
        print("[mode] file (%s)" % args.input_file)
        profile = load_gatt(args.input_file)
    else:
        print("[mode] demo (bundled sample data)")
        profile = profile_from_dict(DEMO_GATT)
    return _run_assessment(profile, args)


def main() -> int:
    """Synchronous entry point that handles async BLE scanning if needed."""
    import argparse
    parser = build_parser()
    args = parser.parse_args()

    if args.att is not None:
        try:
            raw = bytes.fromhex(args.att)
        except ValueError:
            print("error: invalid hex for --att")
            return 2
        pdu = parse_att_pdu(raw)
        print(render_att_pdu(pdu))
        return 0

    if args.adv is not None:
        try:
            raw = bytes.fromhex(args.adv)
        except ValueError:
            print("error: invalid hex for --adv")
            return 2
        adv = parse_adv_packet(raw)
        print(json.dumps(adv, indent=2))
        return 0

    if args.demo:
        return run_demo(args.report_dir, print_report=not args.json)

    if args.live is not None:
        import asyncio
        return asyncio.run(_async_main(args))

    return _file_or_demo(args)


if __name__ == "__main__":
    sys.exit(main())
