# Tests Utilities

## VF8 DoIP UDP Server

File: `tests/doip_vf8_udp_server.py`

This is a server-only DoIP test endpoint for the VF8 dataset. It loads:

- All ECU modules from `src/VF8Data.cpp` (`kVF8Ecus`)
- All reference systems and DTCs from `src/VF8Data.cpp` (`kVF8ReferenceScan`)

It uses external protocol libraries when available:

- `doipclient` for DoIP UDP request validation and response packing
- `udsoncan` for UDS-style DTC enrichment (`id_iso`, status byte)

Install dependencies:

```bash
python3 -m pip install -r tests/requirements.txt
```

### Run

```bash
python3 tests/doip_vf8_udp_server.py --host 0.0.0.0 --port 13400
```

### Use with the application

Point the app to:

- Gateway/Broadcast IP: your server host (for local testing: `127.0.0.1`)
- Port: `13400`
- Tester address: `0x0E80`
- Functional address: `0xE400` (or `--functional-addr` value)

The app can then perform discovery, routing activation, ECU enumeration,
ReadDataByIdentifier, and DTC reads against this server.

### Core DoIP support

- Vehicle Identification Request/Response (`0x0001/0x0004`)
- Vehicle Identification by EID (`0x0002/0x0004`)
- Vehicle Identification by VIN (`0x0003/0x0004`)
- Entity Status Request/Response (`0x4001/0x4002`)
- Diagnostic Power Mode Request/Response (`0x4003/0x4004`)
- Routing Activation Request/Response (`0x0005/0x0006`)
- Diagnostic Message + positive/negative ack (`0x8001/0x8002/0x8003`)

### UDS behavior for app testing

- `0x3E` TesterPresent
- `0x10` DiagnosticSessionControl
- `0x22` ReadDataByIdentifier for common identification DIDs
- `0x19` ReadDTCInformation (`0x01`, `0x02`, `0x0A`, `0x04`, `0x06`, `0x14`)
- `0x14` ClearDiagnosticInformation (clears module DTCs in runtime state)

### Extended data access (JSON over UDP)

Custom payload type request: `0xF100`

Custom payload type response: `0xF101`

Example request JSON payloads:

```json
{"action":"list_modules"}
{"action":"get_module","code":"BMS"}
{"action":"get_module","address":"0x1003"}
{"action":"get_dtcs","code":"BMS"}
{"action":"get_dtcs","code":"BMS","status":"Current"}
{"action":"search_dtc","dtc":"U110887"}
{"action":"stats"}
```

### Notes

- This utility keeps mutable DTC state in memory for the running process.
- Restarting the server resets DTCs to the source reference scan data.
