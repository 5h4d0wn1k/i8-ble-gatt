# I8 — BLE GATT Assessment

Bluetooth Low Energy GATT service/characteristic enumeration and security weakness assessment toolkit.

## Overview

This project analyzes BLE GATT (Generic Attribute Profile) services and characteristics for security weaknesses:
- Parses GATT service data from JSON or CSV input files
- Identifies security weaknesses in characteristic properties and permissions
- Maps known UUIDs to human-readable service/characteristic names
- Produces scored risk reports and optional CSV findings export
- Includes a bundled sample dataset for offline demo and testing
- Optional live BLE scanning via `bleak` (gracefully degrades without it)

## Features

- **GATT Parsing**: Load service/characteristic trees from JSON or CSV
- **UUID Lookup**: Maps 50+ standard BLE profile UUIDs (Battery, Heart Rate, Device Info, etc.)
- **Weakness Detection**: Flags write-without-response, no authentication, open broadcast, Just Works pairing
- **Sensitive Name Scanning**: Detects characteristics with names suggesting secrets (password, token, key, secret)
- **Risk Scoring**: Ranks findings by severity with weighted scoring
- **Report Generation**: Human-readable terminal report and optional CSV export
- **Simulation Mode**: Full analysis without BLE hardware using bundled sample data

## Installation

```bash
# No external dependencies required for offline/simulation mode
# Requires Python 3.6+

# Optional: install bleak for live BLE scanning
pip install bleak
```

## Usage

```bash
# Run demo self-test with bundled sample data
python3 firmware/ble_gatt_assess.py

# Analyze a JSON file of GATT services
python3 firmware/ble_gatt_assess.py gatt_dump.json

# Analyze a CSV file and export findings
python3 firmware/ble_gatt_assess.py gatt_dump.csv --csv findings.csv

# Live BLE scan (requires bleak + BLE adapter)
python3 firmware/ble_gatt_assess.py --live AA:BB:CC:DD:EE:FF
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
