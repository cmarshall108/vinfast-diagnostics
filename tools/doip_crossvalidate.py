#!/usr/bin/env python3
"""
doip_crossvalidate.py - Validate the DoIP simulator (and, by extension, the
framing our C++ client relies on) against the independent, established
`doipclient` library (jacobschaer/python-doipclient, ISO 13400-2:2019).

If a third-party stack interoperates with our simulator, our wire format is
spec-correct.

  Terminal 1:  python3 tools/doip_simulator.py --host 127.0.0.1
  Terminal 2:  python3 tools/doip_crossvalidate.py

Requires: pip install doipclient
"""
import sys

from doipclient import DoIPClient
from doipclient.messages import VehicleIdentificationResponse

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
GATEWAY_LA = 0x1001

npass = nfail = 0


def check(name, ok, detail=""):
    global npass, nfail
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
    if ok:
        npass += 1
    else:
        nfail += 1


def main():
    print(f"Cross-validating simulator at {HOST}:13400 with doipclient\n")

    # 1. UDP Vehicle Identification (broadcast) via the third-party stack.
    # get_entity returns ((ip, port), VehicleIdentificationResponse).
    addr, ident = DoIPClient.get_entity(HOST)
    ok = isinstance(ident, VehicleIdentificationResponse)
    raw_vin = ident.vin if ok else b""
    vin = raw_vin.decode("ascii", "replace") if isinstance(raw_vin, bytes) else str(raw_vin)
    check("get_entity (vehicle identification)", ok, f"VIN={vin!r}")
    check("logical address parsed",
          ok and ident.logical_address == GATEWAY_LA,
          f"0x{ident.logical_address:04X}" if ok else "")

    # 2. TCP connect + routing activation happen in the constructor.
    client = DoIPClient(HOST, GATEWAY_LA)
    check("connect + routing activation (constructor)", True)

    # 3. UDP Entity Status.
    try:
        st = client.request_entity_status()
        check("request_entity_status", st is not None,
              f"max_open={getattr(st, 'max_concurrent_sockets', '?')}")
    except Exception as e:  # noqa: BLE001
        check("request_entity_status", False, str(e))

    # 4. UDP Diagnostic Power Mode.
    try:
        pm = client.request_diagnostic_power_mode()
        check("request_diagnostic_power_mode", pm is not None,
              f"mode={getattr(pm, 'diagnostic_power_mode', '?')}")
    except Exception as e:  # noqa: BLE001
        check("request_diagnostic_power_mode", False, str(e))

    # 5. UDS ReadDataByIdentifier (0x22 F190 -> VIN) over a diagnostic message.
    try:
        client.send_diagnostic(bytes([0x22, 0xF1, 0x90]))
        resp = client.receive_diagnostic(timeout=3)
        ok = resp is not None and resp[0] == 0x62
        check("send/receive UDS 0x22 F190", ok, resp.hex() if resp else "no reply")
    except Exception as e:  # noqa: BLE001
        check("send/receive UDS 0x22 F190", False, str(e))

    # 6. UDS TesterPresent (0x3E) -> positive 0x7E.
    try:
        client.send_diagnostic(bytes([0x3E, 0x00]))
        resp = client.receive_diagnostic(timeout=3)
        check("send/receive UDS 0x3E (TesterPresent)",
              resp is not None and resp[0] == 0x7E, resp.hex() if resp else "no reply")
    except Exception as e:  # noqa: BLE001
        check("send/receive UDS 0x3E (TesterPresent)", False, str(e))

    client.close()
    print(f"\nResult: {npass} passed, {nfail} failed")
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
