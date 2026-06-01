#!/usr/bin/env python3
"""
doip_simulator.py - Minimal local DoIP (ISO 13400-2) entity for testing the
vinfast_scanner client WITHOUT a real vehicle.

It deliberately exercises every feature added to src/DoIPClient.cpp:
  * UDP Vehicle Identification: broadcast (0x0001), by-EID (0x0002), by-VIN (0x0003)
  * UDP Entity Status (0x4001/0x4002) and Diagnostic Power Mode (0x4003/0x4004)
  * TCP Routing Activation (0x0005/0x0006), optionally requiring an OEM field
  * TCP Diagnostic Message (0x8001) with positive ack (0x8002)
  * Multiple simulated ECUs + a functional group address (enumeration)
  * UDS "response pending" (NRC 0x78) bursts (deadline-refresh test)
  * Generic Header Negative Acknowledge (0x0000) on demand
  * Optional non-printable bytes in the VIN (sanitization test)

Usage:
  python3 tools/doip_simulator.py [--host 0.0.0.0] [--port 13400]
                                  [--require-oem] [--dirty-vin]

Point the app at it:
  Broadcast IP / Gateway IP : 127.0.0.1
  Port                      : 13400
  Tester address            : 0E80
  Functional address        : E400   (Enumerate ECUs button)
  Gateway/target address    : 1001 / 1003
"""

import argparse
import socket
import struct
import threading
import time

PROTO_VER = 0x02

# Payload types
PT_VID_REQ        = 0x0001
PT_VID_REQ_EID    = 0x0002
PT_VID_REQ_VIN    = 0x0003
PT_VID_RESP       = 0x0004
PT_ROUTING_REQ    = 0x0005
PT_ROUTING_RESP   = 0x0006
PT_ALIVE_REQ      = 0x0007
PT_ALIVE_RESP     = 0x0008
PT_GENERIC_NACK   = 0x0000
PT_ENTITY_STATUS_REQ  = 0x4001
PT_ENTITY_STATUS_RESP = 0x4002
PT_POWER_REQ      = 0x4003
PT_POWER_RESP     = 0x4004
PT_DIAG           = 0x8001
PT_DIAG_ACK_POS   = 0x8002
PT_DIAG_ACK_NEG   = 0x8003

GATEWAY_LA   = 0x1001
FUNCTIONAL   = 0xE400
EID          = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
GID          = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])

# Simulated ECUs: logical address -> friendly name
ECUS = {
    0x1001: "Gateway",
    0x1003: "BMS",
    0x1010: "VCU",
}

# DIDs each ECU answers to (DID -> response data bytes after the echoed DID)
DIDS = {
    0xF190: b"RP8AB1AB1PE000123",          # VIN
    0xF18C: b"ECU-SN-0001",                 # ECU serial number
    0xF195: bytes([0x01, 0x02]),            # SW version
}


def make_vin(dirty: bool) -> bytes:
    vin = b"RP8AB1AB1PE000123"  # 17 chars
    if dirty:
        # Inject NUL + control bytes to verify client-side sanitization.
        vin = b"RP8AB1AB1PE0001\x00\x07"
    return vin[:17].ljust(17, b" ")


def hdr(ptype: int, payload: bytes) -> bytes:
    return struct.pack(">BBHI", PROTO_VER, (~PROTO_VER) & 0xFF, ptype, len(payload)) + payload


def vid_response(dirty_vin: bool) -> bytes:
    payload = (
        make_vin(dirty_vin)
        + struct.pack(">H", GATEWAY_LA)
        + EID
        + GID
        + bytes([0x00])  # further action required = none
    )
    return hdr(PT_VID_RESP, payload)


# ----------------------------------------------------------------------------
# UDP server: discovery, entity status, power mode
# ----------------------------------------------------------------------------
def udp_server(host, port, dirty_vin):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((host, port))
    print(f"[udp] listening on {host}:{port}")
    while True:
        data, addr = s.recvfrom(2048)
        if len(data) < 8:
            continue
        _, _, ptype, plen = struct.unpack(">BBHI", data[:8])
        if ptype in (PT_VID_REQ, PT_VID_REQ_EID, PT_VID_REQ_VIN):
            kind = {PT_VID_REQ: "broadcast", PT_VID_REQ_EID: "by-EID",
                    PT_VID_REQ_VIN: "by-VIN"}[ptype]
            print(f"[udp] VehicleIdentRequest ({kind}) from {addr}")
            s.sendto(vid_response(dirty_vin), addr)
        elif ptype == PT_ENTITY_STATUS_REQ:
            print(f"[udp] EntityStatusRequest from {addr}")
            # nodeType=0 gateway, maxSockets=4, openSockets=1, maxData=0x10000
            payload = bytes([0x00, 0x04, 0x01]) + struct.pack(">I", 0x10000)
            s.sendto(hdr(PT_ENTITY_STATUS_RESP, payload), addr)
        elif ptype == PT_POWER_REQ:
            print(f"[udp] DiagnosticPowerModeRequest from {addr}")
            s.sendto(hdr(PT_POWER_RESP, bytes([0x01])), addr)  # 0x01 = ready


# ----------------------------------------------------------------------------
# TCP server: routing activation + diagnostic messages
# ----------------------------------------------------------------------------
def diag_ack_positive(tester, ecu):
    # SA = ECU, TA = tester, ackCode 0x00
    return hdr(PT_DIAG_ACK_POS, struct.pack(">HHB", ecu, tester, 0x00))


def diag_message(ecu, tester, uds):
    return hdr(PT_DIAG, struct.pack(">HH", ecu, tester) + uds)


def uds_response_for(ecu, uds, flash=None):
    """Return the UDS response bytes for a given ECU, or None for no-reply.

    The VCU (0x1010) implements a stateful ISO 14229 reprogramming sequence
    (0x10/0x27/0x31/0x34/0x36/0x37/0x11) so the self-test can validate a full
    flash run end to end. `flash` is a per-connection dict holding that state.
    """
    if not uds:
        return None
    sid = uds[0]

    # VCU stateful reprogramming services take precedence for the flash SIDs.
    if ecu == 0x1010 and flash is not None:
        r = vcu_flash_response(uds, flash)
        if r is not None:
            return r

    if sid == 0x3E:  # TesterPresent -> positive 0x7E
        return bytes([0x7E, 0x00])
    if sid == 0x22 and len(uds) >= 3:  # ReadDataByIdentifier
        did = (uds[1] << 8) | uds[2]
        # VCU running-software state DID: 0x01 application, 0x00 bootloader.
        if ecu == 0x1010 and did == 0xF1A0 and flash is not None:
            return bytes([0x62, uds[1], uds[2], 0x01 if flash.get("app") else 0x00])
        if did in DIDS:
            return bytes([0x62, uds[1], uds[2]]) + DIDS[did]
        return bytes([0x7F, 0x22, 0x31])  # requestOutOfRange -> not present
    # Unknown service: serviceNotSupported
    return bytes([0x7F, sid, 0x11])


def vcu_flash_response(uds, flash):
    """ISO 14229 flash state machine for the VCU (0x1010). Returns the UDS
    response bytes for a flash SID, or None to fall through to the generic
    handler (e.g. for 0x22 / 0x3E). Enforces session/security ordering and the
    TransferData block-sequence-counter so the client side can be validated."""
    sid = uds[0]

    if sid == 0x10 and len(uds) >= 2:            # DiagnosticSessionControl
        sub = uds[1]
        flash["session"] = sub
        if sub == 0x02:                          # entering programming session
            flash["unlocked"] = False
            flash["download"] = False
        # 0x50 <sub> + P2/P2* timing (4 bytes)
        return bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])

    if sid == 0x27 and len(uds) >= 2:            # SecurityAccess
        sub = uds[1]
        if sub % 2 == 1:                         # requestSeed (odd sub-function)
            if flash.get("session") != 0x02:
                return bytes([0x7F, 0x27, 0x22])  # conditionsNotCorrect
            flash["seed"] = bytes([0x11, 0x22, 0x33, 0x44])
            return bytes([0x67, sub]) + flash["seed"]
        # sendKey (even sub-function): agreed test transform key = seed XOR 0xFF.
        seed = flash.get("seed", b"")
        expect = bytes(b ^ 0xFF for b in seed)
        if bytes(uds[2:]) != expect:
            return bytes([0x7F, 0x27, 0x35])      # invalidKey
        flash["unlocked"] = True
        return bytes([0x67, sub])

    if sid == 0x31 and len(uds) >= 4:            # RoutineControl (erase memory)
        if not flash.get("unlocked"):
            return bytes([0x7F, 0x31, 0x33])      # securityAccessDenied
        # 0x71 <sub> <RID hi lo> <routineStatusRecord 0x00 = finished OK>
        return bytes([0x71, uds[1], uds[2], uds[3], 0x00])

    if sid == 0x34:                              # RequestDownload
        if not flash.get("unlocked"):
            return bytes([0x7F, 0x34, 0x33])      # securityAccessDenied
        flash["download"] = True
        flash["expected_bsc"] = 0x01
        flash["received"] = 0
        # 0x74 <LFID: hi nibble = maxBlockLength width 2> <maxBlockLength 0x0402>
        return bytes([0x74, 0x20, 0x04, 0x02])    # 1026 -> 1024 usable payload

    if sid == 0x36 and len(uds) >= 2:            # TransferData
        if not flash.get("download"):
            return bytes([0x7F, 0x36, 0x24])      # requestSequenceError
        bsc = uds[1]
        expected = flash.get("expected_bsc", 0x01)
        if bsc != expected:
            return bytes([0x7F, 0x36, 0x73])      # wrongBlockSequenceCounter
        flash["received"] += len(uds) - 2
        flash["expected_bsc"] = (expected + 1) & 0xFF   # wraps 0xFF -> 0x00
        return bytes([0x76, bsc])

    if sid == 0x37:                              # RequestTransferExit
        if not flash.get("download"):
            return bytes([0x7F, 0x37, 0x24])      # requestSequenceError
        flash["download"] = False
        flash["flashed"] = True
        return bytes([0x77])                      # optional checksum omitted

    if sid == 0x11 and len(uds) >= 2:            # ECUReset
        # A completed flash validates the application image; after the reset the
        # ECU "boots" the application (running-software DID 0xF1A0 -> 0x01).
        if flash.get("flashed"):
            flash["app"] = True
        flash["session"] = 0x01
        flash["unlocked"] = False
        return bytes([0x51, uds[1]])

    return None



def handle_conn(conn, addr, require_oem, nack_state):
    print(f"[tcp] connection from {addr}")
    conn.settimeout(30)
    tester = 0x0E80
    buf = b""
    flash = {}   # per-connection VCU reprogramming state
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 8:
                _, _, ptype, plen = struct.unpack(">BBHI", buf[:8])
                if len(buf) < 8 + plen:
                    break
                payload = buf[8:8 + plen]
                buf = buf[8 + plen:]
                _dispatch(conn, ptype, payload, require_oem, nack_state, flash)
    except (socket.timeout, ConnectionError):
        pass
    finally:
        print(f"[tcp] connection closed {addr}")
        conn.close()


def _dispatch(conn, ptype, payload, require_oem, nack_state, flash):
    if ptype == PT_ROUTING_REQ:
        tester = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 0x0E80
        has_oem = len(payload) >= 11  # 2+1+4 reserved + 4 OEM
        print(f"[tcp] RoutingActivation tester=0x{tester:04X} oem={'yes' if has_oem else 'no'}")
        if require_oem and not has_oem:
            # Respond with a generic header NACK to test that path.
            print("[tcp] -> Generic Header NACK (OEM field required)")
            conn.sendall(hdr(PT_GENERIC_NACK, bytes([0x04])))
            return
        # 0x0006: tester LA(2) + entity LA(2) + responseCode(1) + reserved(4)
        resp = struct.pack(">HHB", tester, GATEWAY_LA, 0x10) + b"\x00\x00\x00\x00"
        conn.sendall(hdr(PT_ROUTING_RESP, resp))
    elif ptype == PT_ALIVE_RESP:
        pass  # client answered an alive-check; nothing to do
    elif ptype == PT_DIAG:
        if len(payload) < 4:
            return
        source = struct.unpack(">H", payload[:2])[0]
        target = struct.unpack(">H", payload[2:4])[0]
        uds = payload[4:]
        tester = source
        if target == FUNCTIONAL:
            # Functional group: every ECU acks + answers from its own address.
            print(f"[tcp] functional request to 0x{target:04X} ({uds.hex()})")
            for ecu in ECUS:
                conn.sendall(diag_ack_positive(tester, ecu))
            for ecu in ECUS:
                r = uds_response_for(ecu, uds)
                if r is not None:
                    conn.sendall(diag_message(ecu, tester, r))
            return
        if target not in ECUS:
            print(f"[tcp] unknown target 0x{target:04X} -> negative ack")
            conn.sendall(hdr(PT_DIAG_ACK_NEG, struct.pack(">HHB", target, tester, 0x03)))
            return
        print(f"[tcp] diag to 0x{target:04X} ({uds.hex()})")
        conn.sendall(diag_ack_positive(tester, target))
        # BMS demonstrates UDS response-pending (NRC 0x78) bursts for DID reads.
        if target == 0x1003 and uds[:1] == b"\x22":
            for _ in range(3):
                conn.sendall(diag_message(target, tester, bytes([0x7F, 0x22, 0x78])))
                time.sleep(0.2)
        r = uds_response_for(target, uds, flash)
        if r is not None:
            conn.sendall(diag_message(target, tester, r))
    else:
        # Unknown payload type -> Generic Header NACK (unknown payload type).
        print(f"[tcp] unknown payload type 0x{ptype:04X} -> Generic NACK")
        conn.sendall(hdr(PT_GENERIC_NACK, bytes([0x01])))


def tcp_server(host, port, require_oem):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(4)
    print(f"[tcp] listening on {host}:{port}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_conn, args=(conn, addr, require_oem, {}),
                         daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description="Local DoIP simulator for vinfast_scanner")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=13400)
    ap.add_argument("--require-oem", action="store_true",
                    help="Reject routing activation without a 4-byte OEM field")
    ap.add_argument("--dirty-vin", action="store_true",
                    help="Return a VIN with control bytes (sanitization test)")
    args = ap.parse_args()

    print("DoIP simulator")
    print(f"  ECUs: " + ", ".join(f"0x{a:04X} {n}" for a, n in ECUS.items()))
    print(f"  Functional group: 0x{FUNCTIONAL:04X}")
    print(f"  require-oem={args.require_oem} dirty-vin={args.dirty_vin}")

    threading.Thread(target=udp_server, args=(args.host, args.port, args.dirty_vin),
                     daemon=True).start()
    try:
        tcp_server(args.host, args.port, args.require_oem)
    except KeyboardInterrupt:
        print("\nshutting down")


if __name__ == "__main__":
    main()
