> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# I8 — BLE GATT Assessment

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub Stars](https://img.shields.io/github/stars/5h4d0wn1k/i8-ble-gatt)
![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/i8-ble-gatt)
![GitHub Issues](https://img.shields.io/github/issues/5h4d0wn1k/i8-ble-gatt)

> **BLE GATT security assessment toolkit** — wire-level ATT PDU parsing,
> advertisement decoding, GATT service/characteristic enumeration, weakness and
> sensitive-name detection, and severity-ranked JSON reports for Bluetooth Low
> Energy security research.

## Why

BLE peripherals expose their capabilities through the GATT profile, and
misconfigured services — write-without-response, broadcast reads, credential
flavors of characteristic names — are a common source of real IoT flaws. I8
assesses that attack surface the way a pentester would: raw `parse_att_pdu()`
handles every ATT opcode at the byte level (MTU exchange, find/read-by-type,
read/write, notifications, error responses), `parse_adv_packet()` decodes
advertisement PDUs, and the profile builder reconstructs a full GATT service
tree from over-the-air discovery responses. Offline by default, it's a safe,
repeatable way to learn BLE security assessment against your own devices or
captured PDUs.

## Features

- **Wire-level ATT parser** — decodes opcodes `0x01–0x19`, `0x1b`, `0x1d–0x1e`
  into JSON-safe field dicts.
- **GAP advertisement parser** — AD structures: flags, name, UUIDs, TX power,
  service/manufacturer data.
- **GATT profile builder** — reconstructs services/characteristics from
  "Read By Group Type" + "Read By Type" responses.
- **JSON/CSV input** — load service trees from files or paste raw captures.
- **UUID resolution** — 60+ standard BLE profile UUIDs mapped to names.
- **Weakness detection** — write-without-response, open/broadcast reads,
  sensitive notifications, and sensitive-name scanning with weighted risk.
- **Reports** — severity-sorted findings to `reports/` (gitignored).
- **Optional live scanning** — `--live ADDR` via `bleak` (opt-in install).

## Quickstart

```bash
# Offline demo: bundled GATT + wire-level parses + report, exit 0
python3 firmware/ble_gatt_assess.py --demo

# Analyze a JSON/CSV dump of services
python3 firmware/ble_gatt_assess.py gatt_dump.json --json
python3 firmware/ble_gatt_assess.py gatt_dump.csv --csv findings.csv

# Parse raw ATT / advertisement PDUs (hex)
python3 firmware/ble_gatt_assess.py --att 122300616300
python3 firmware/ble_gatt_assess.py --adv 00112233445566020106090944656d6f54657374

# Live scan of a device you own (requires: pip install bleak)
python3 firmware/ble_gatt_assess.py --live AA:BB:CC:DD:EE:FF

python3 -m unittest discover -s tests
```

Exit codes: `0` success, `2` invalid `--att`/`--adv` hex.

## Project structure

```
firmware/ble_gatt_assess.py   # assessment engine + CLI
firmware/__init__.py
tests/                        # deterministic offline tests
ETHICS.md                     # ethics/authorized-use policy (read first)
SCOPE.md                      # defined assessment scope
```

## Documentation

- [ETHICS.md](ETHICS.md) — ethical-use policy, read first
- [SCOPE.md](SCOPE.md) — authorized-scope definition
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [SECURITY.md](SECURITY.md) — vulnerability reporting

## Contributing

New ATT opcodes, AD types, UUID coverage, and weak-characteristic signatures are
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).