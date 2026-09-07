# I8 — BLE GATT Assessment

Bluetooth Low Energy GATT service/characteristic enumeration and security weakness assessment toolkit.

## What the engine genuinely does

- **Wire-level ATT PDU parser** — raw `parse_att_pdu()` handles the actual
  Attribute Protocol opcodes at the byte level (MTU exchange, find/read-by-type
  request/response, read/write, notification/indication, error response with
  decoded error codes), producing JSON-safe field dicts.
- **GAP advertisement parser** — `parse_adv_packet()` decodes a raw advertising
  PDU header, advertiser address, and each AD structure (Flags, local name,
  service UUIDs, TX power, service/manufacturer data).
- **Wire discovery reconstruction** — `build_profile_from_att()` rebuilds a
  GATT profile from raw "Read By Group Type" + "Read By Type" responses, exactly
  like a client would discover primary services/characteristics over the air.
- **GATT parsing** — load service/characteristic trees from JSON or CSV.
- **UUID lookup** — maps 60+ standard BLE profile UUIDs (Battery, Heart Rate,
  Device Info, etc.) to human-readable names.
- **Weakness detection** — flags write-without-response, unprotected/broadcast
  reads, writes on sensitive-named characteristics, and sensitive
  notifications, with severity-weighted risk scoring.
- **Sensitive name scanning** — detects characteristic names suggesting secrets
  (password, token, key, secret).
- **JSON reports** — severity-sorted findings written to `reports/` (gitignored).
- **Optional live BLE scanning** via `bleak`, gracefully degrading offline.

## Installation

```bash
# No external dependencies required for offline/simulation mode
# Requires Python 3.6+

# Optional: install bleak for live BLE scanning
pip install bleak
```

## Usage

```bash
# Offline demo: bundled GATT + wire-level ATT/ADV parses + JSON report, exit 0
python3 firmware/ble_gatt_assess.py --demo

# Analyze a JSON/CSV file of GATT services (JSON report optional)
python3 firmware/ble_gatt_assess.py gatt_dump.json --json

# Analyze a CSV file and export findings
python3 firmware/ble_gatt_assess.py gatt_dump.csv --csv findings.csv

# Parse a single raw ATT PDU (hex)
python3 firmware/ble_gatt_assess.py --att 122300616300

# Parse a raw BLE advertisement packet (hex)
python3 firmware/ble_gatt_assess.py --adv 00112233445566020106090944656d6f54657374

# Live BLE scan (requires bleak + BLE adapter)
python3 firmware/ble_gatt_assess.py --live AA:BB:CC:DD:EE:FF

# Tests
python3 -m unittest discover -s tests
```

### CLI

```
usage: ble_gatt_assess.py [-h] [input_file] [--live [ADDR]] [--timeout SEC]
                          [--csv FILE] [--demo] [--att HEX] [--adv HEX]
                          [--json] [--report-dir DIR]

Exit codes: 0 success, 2 invalid --att/--adv hex.
```

### Input Format (JSON)

```json
{
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
          "descriptors": []
        }
      ]
    }
  ]
}
```

### Input Format (CSV)

```csv
service_uuid,service_name,char_uuid,char_name,char_properties,descriptors
0000180f-0000-1000-8000-00805f9b34fb,Battery Service,00002a19-0000-1000-8000-00805f9b34fb,Battery Level,read,
```

## Example Output

```
=== I8 - BLE GATT Security Assessment ===
[mode] demo (bundled sample data)

Device: DemoFitnessTracker (AA:BB:CC:DD:EE:FF)
Services: 6  |  Characteristics: 18

--- UUID Resolution ---
  0x1800  -> Generic Access
  0x1801  -> Generic Attribute
  0x180a  -> Device Information
  0x180f  -> Battery Service
  0x180d  -> Heart Rate
  0xffe0  -> Custom (unknown)

--- Security Findings ---
 [HIGH]  Characteristic "Heart Rate Measurement" (0x2a37): broadcast enabled — data may be sniffed
 [MEDIUM] Characteristic "Custom Secret" (0xffe1): write-without-response — no acknowledgment, spoofable
 [MEDIUM] Characteristic "User Password" (0xffe2): sensitive name detected (password) — may expose credentials
 [LOW]    Characteristic "Battery Level" (0x2a19): no authentication required — open read

--- Risk Summary ---
  HIGH:   1
  MEDIUM: 2
  LOW:    1
  INFO:   0
  TOTAL:  4 findings

Report written to stdout.
```

## Live Lab Test Plan

1. **Offline baseline**: `python3 firmware/ble_gatt_assess.py --demo` — confirm
   the bundled GATT profile reports findings with severity/risk scores, the
   wire-level ATT PDUs parse (MTU exchange 248, write request, notification,
   `Attribute Not Found` error), the advertisement decodes `DemoTest` with the
   Flags AD, and the wire discovery reconstructs Battery Service / Battery
   Level (read) — exit 0, JSON report written to `reports/`.
2. **Byte-level**: `python3 firmware/ble_gatt_assess.py --att 010823000a` →
   `Error Response req_opcode=8 error_name=Attribute Not Found`. Parse your
   own captured ATT PDUs from a lab bench you own.
3. **File mode**: feed a JSON/CSV dump of a lab device you own, confirm each
   standard UUID resolves and findings are stable across runs.
4. **Discover/assess regression**: re-run `python3 -m unittest discover -s
   tests` — all deterministic tests pass.
5. **Regulatory**: adjust enable BLE adapter and perform live scans only on
   your own device per the authorization requirements below.

## Metrics

| Metric                     | Value |
|----------------------------|-------|
| Standard-library core      | Yes   |
| Optional dependency        | bleak (live scan only) |
| Deterministic offline tests| 32    |
| ATT opcodes covered        | 0x01-0x19, 0x1b, 0x1d-0x1e |
| GAP AD types mapped        | 10    |
| Standard UUIDs mapped      | 60+   |
| Offline demo exit          | 0     |
| Report output              | `reports/*.json` (gitignored) |
| Wire reconstruction        | ATT discovery responses → GATTProfile |
| Live scanning              | opt-in, requires `pip install bleak` |

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the device owner before scanning or assessing BLE devices
- Unauthorized interception of Bluetooth communications is illegal under federal and state laws
- This tool should ONLY be used on devices you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: BLE data collection may capture personal data subject to privacy regulations

### Acceptable Use
- Testing security of your own BLE devices
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Scanning or connecting to BLE devices you do not own
- Intercepting BLE communications without consent
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
