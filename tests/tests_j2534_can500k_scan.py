#!/usr/bin/env python3
"""
tests_j2534_can500k_scan.py - Load Toyota's Mini-VCI J2534 driver (mvci32.dll)
and scan CAN buses for any ECU responses, sweeping every standard CAN bit rate.

This is a self-contained, dependency-free probe used to confirm how a vehicle
(e.g. a VinFast VF8 - whose diagnostics, like the VF6, run on ISO 15765-4 CAN
@ 500k) communicates on the OBD-II port, using the same Toyota Mini-VCI cable
the C++ app drives.

Vehicle wiring (VF8): the diagnostic bus is on the standard SAE J1962 OBD-II
high-speed CAN pins - pin 6 = D-CAN H (CAN High), pin 14 = D-CAN L (CAN Low).
The Mini-VCI's OBD plug maps to these directly, so no adapter/pin-swap is
needed; this is the bus this probe talks to.

By default it sweeps ALL standard automotive CAN bit rates (1M, 500k, 250k,
125k, 100k, 83.333k, 50k, 33.333k), fastest first, and for each rate does two
things over the raw ISO 11898-1 CAN data-link layer (J2534 `CAN` protocol)
rather than the ISO 15765-4 transport layer:
  1. Passive sniff - opens a raw CAN channel and listens for any live bus
     traffic (a modern EV constantly broadcasts, so this alone proves the bus
     is CAN @ that rate).
  2. Active OBD/UDS probe - sends hand-built ISO 11898-1 single CAN frames
     (manual ISO-TP single-frame PCI, no device-managed flow control) carrying
     a functional OBD-II "Mode 01 PID 00" request (and a UDS "tester present"),
     then reads raw CAN frames back, collecting every responder.

Note: this probe sends ISO-TP flow-control frames itself, so multi-frame
(ISO-TP) responses ARE reassembled - a single-frame reply is reported whole,
and a multi-frame reply (e.g. a DTC list) is streamed via a flow-control frame
and reassembled into the complete UDS payload.

IMPORTANT: mvci32.dll is a 32-bit DLL. You MUST run this with a 32-bit Python
interpreter on Windows; a 64-bit process cannot load it (WinError 193).

Usage (Windows, 32-bit Python):
    py -3-32 tests/tests_j2534_can500k_scan.py                       # sweep all bauds
    py -3-32 tests/tests_j2534_can500k_scan.py --baud 500000         # one baud only
    py -3-32 tests/tests_j2534_can500k_scan.py --baud 500000 --baud 250000
    py -3-32 tests/tests_j2534_can500k_scan.py --dll "C:\\Program Files (x86)\\XHorse Electronics\\MVCI Driver for TOYOTA TIS\\mvci32.dll"
"""

import argparse
import ctypes
import os
import sys
import time
from ctypes import (
    c_char, c_char_p, c_long, c_ubyte, c_ulong, POINTER, Structure, byref,
)

# --- SAE J2534 v04.04 constants --------------------------------------------
CAN = 5
ISO15765 = 6

CAN_29BIT_ID = 0x00000100
ISO15765_FRAME_PAD = 0x00000040

# RxStatus bits
TX_MSG_TYPE = 0x00000001          # loopback echo of our own transmit
ISO15765_FIRST_FRAME = 0x00000002  # ISO-TP first-frame indication

# Filter types
PASS_FILTER = 0x00000001
FLOW_CONTROL_FILTER = 0x00000003

# Return codes
STATUS_NOERROR = 0x00
ERR_TIMEOUT = 0x09
ERR_BUFFER_EMPTY = 0x10

MSG_DATA_SIZE = 4128

# Common default install locations for the XHorse "MVCI Driver for TOYOTA TIS".
DEFAULT_DLL_CANDIDATES = [
    r"C:\Program Files (x86)\XHorse Electronics\MVCI Driver for TOYOTA TIS\mvci32.dll",
    r"C:\Program Files\XHorse Electronics\MVCI Driver for TOYOTA TIS\mvci32.dll",
    r"C:\Program Files (x86)\Toyota Diagnostics\MVCI\mvci32.dll",
    r"C:\Program Files\Toyota Diagnostics\MVCI\mvci32.dll",
]


class PASSTHRU_MSG(Structure):
    _pack_ = 1
    _fields_ = [
        ("ProtocolID", c_ulong),
        ("RxStatus", c_ulong),
        ("TxFlags", c_ulong),
        ("Timestamp", c_ulong),
        ("DataSize", c_ulong),
        ("ExtraDataIndex", c_ulong),
        ("Data", c_ubyte * MSG_DATA_SIZE),
    ]


def _bind(dll):
    """Resolve and prototype the J2534 PassThru exports we need."""
    fns = {}

    def proto(name, restype, argtypes, required=True):
        try:
            fn = getattr(dll, name)
        except AttributeError:
            if required:
                raise RuntimeError(f"mvci32.dll is missing required export '{name}'")
            return None
        fn.restype = restype
        fn.argtypes = argtypes
        fns[name] = fn
        return fn

    proto("PassThruOpen", c_long, [c_char_p, POINTER(c_ulong)])
    proto("PassThruClose", c_long, [c_ulong])
    proto("PassThruConnect", c_long,
          [c_ulong, c_ulong, c_ulong, c_ulong, POINTER(c_ulong)])
    proto("PassThruDisconnect", c_long, [c_ulong])
    proto("PassThruReadMsgs", c_long,
          [c_ulong, POINTER(PASSTHRU_MSG), POINTER(c_ulong), c_ulong])
    proto("PassThruWriteMsgs", c_long,
          [c_ulong, POINTER(PASSTHRU_MSG), POINTER(c_ulong), c_ulong])
    proto("PassThruStartMsgFilter", c_long,
          [c_ulong, c_ulong, POINTER(PASSTHRU_MSG), POINTER(PASSTHRU_MSG),
           POINTER(PASSTHRU_MSG), POINTER(c_ulong)])
    proto("PassThruStopMsgFilter", c_long, [c_ulong, c_ulong])
    proto("PassThruReadVersion", c_long,
          [c_ulong, c_char_p, c_char_p, c_char_p], required=False)
    proto("PassThruGetLastError", c_long, [c_char_p], required=False)
    return fns


def _last_error(fns):
    fn = fns.get("PassThruGetLastError")
    if not fn:
        return "unknown J2534 error"
    buf = ctypes.create_string_buffer(128)
    if fn(buf) == STATUS_NOERROR and buf.value:
        return buf.value.decode(errors="replace")
    return "unknown J2534 error"


def _put_id(msg, can_id):
    """Write a 4-byte big-endian CAN id into the front of a PASSTHRU_MSG."""
    msg.Data[0] = (can_id >> 24) & 0xFF
    msg.Data[1] = (can_id >> 16) & 0xFF
    msg.Data[2] = (can_id >> 8) & 0xFF
    msg.Data[3] = can_id & 0xFF


def _hex(data, n):
    return " ".join(f"{data[i]:02X}" for i in range(n))


def _hex_bytes(data):
    """Hex-format a bytes/bytearray of reassembled UDS payload."""
    return " ".join(f"{b:02X}" for b in data) if data else "(empty)"


def resolve_dll(explicit):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for cand in DEFAULT_DLL_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    return None


def passive_sniff(fns, device_id, baud, listen_s):
    """Open raw CAN @ baud and report any live bus frames."""
    print(f"\n[1] Passive raw-CAN sniff @ {baud} bps for {listen_s:.1f}s ...")
    channel_id = c_ulong(0)
    rc = fns["PassThruConnect"](device_id, CAN, 0, baud, byref(channel_id))
    if rc != STATUS_NOERROR:
        print(f"    link failed: VCI could not open raw CAN ({_last_error(fns)})")
        return 0

    # Pass-all filter so reads return every frame on the bus.
    mask = PASSTHRU_MSG(ProtocolID=CAN, DataSize=4)
    patt = PASSTHRU_MSG(ProtocolID=CAN, DataSize=4)
    fid = c_ulong(0)
    fns["PassThruStartMsgFilter"](channel_id, PASS_FILTER,
                                  byref(mask), byref(patt), None, byref(fid))

    seen = {}
    deadline = time.time() + listen_s
    while time.time() < deadline:
        rx = PASSTHRU_MSG()
        num = c_ulong(1)
        rc = fns["PassThruReadMsgs"](channel_id, byref(rx), byref(num), 200)
        if rc != STATUS_NOERROR or num.value == 0:
            continue
        if rx.RxStatus & TX_MSG_TYPE or rx.DataSize < 4:
            continue
        can_id = (rx.Data[0] << 24) | (rx.Data[1] << 16) | (rx.Data[2] << 8) | rx.Data[3]
        if can_id not in seen:
            payload = _hex(rx.Data, min(rx.DataSize, 12))
            seen[can_id] = payload
            print(f"    live frame  id=0x{can_id:X}  data={payload}")

    fns["PassThruStopMsgFilter"](channel_id, fid)
    fns["PassThruDisconnect"](channel_id)
    if seen:
        print(f"    -> {len(seen)} distinct CAN id(s) seen: bus IS active @ {baud}")
    else:
        print("    -> no bus activity (wrong baud, or VCI not connected to a live bus)")
    return len(seen)


def active_probe(fns, device_id, baud, req_id, resp_id, ext, requests):
    """Open raw ISO 11898-1 CAN @ baud and collect responders to hand-built
    single CAN frames (manual ISO-TP single-frame PCI). When an ECU answers
    with a multi-frame (ISO-TP) reply we send a flow-control frame ourselves
    and reassemble the consecutive frames so the full payload is recovered.
    """
    width = "29-bit" if ext else "11-bit"
    print(f"\n[2] Active ISO 11898-1 raw-CAN probe @ {baud} bps, {width}, "
          f"req=0x{req_id:X} resp=0x{resp_id:X} ...")
    flags = CAN_29BIT_ID if ext else 0
    channel_id = c_ulong(0)
    rc = fns["PassThruConnect"](device_id, CAN, flags, baud, byref(channel_id))
    if rc != STATUS_NOERROR:
        print(f"    link failed: VCI could not open raw CAN ({_last_error(fns)})")
        return 0

    txf = CAN_29BIT_ID if ext else 0

    def send_flow_control(flow_id):
        """Send an ISO-TP flow-control frame (CTS, BS=0, STmin=0) to flow_id so
        a responding ECU will stream its consecutive frames to us."""
        fc = PASSTHRU_MSG(ProtocolID=CAN, TxFlags=txf)
        _put_id(fc, flow_id)
        fc.Data[4] = 0x30        # FlowStatus = ContinueToSend
        fc.Data[5] = 0x00        # BlockSize = 0 (send all)
        fc.Data[6] = 0x00        # STmin = 0 (no separation delay)
        for i in range(7, 12):   # pad to a full 8-byte CAN frame
            fc.Data[i] = 0x00
        fc.DataSize = 12
        n = c_ulong(1)
        fns["PassThruWriteMsgs"](channel_id, byref(fc), byref(n), 200)

    # Pass-all filter so reads return every raw CAN frame (we match responders
    # ourselves rather than relying on an ISO-TP flow-control filter).
    mask = PASSTHRU_MSG(ProtocolID=CAN, DataSize=4)
    patt = PASSTHRU_MSG(ProtocolID=CAN, DataSize=4)
    fid = c_ulong(0)
    rc = fns["PassThruStartMsgFilter"](channel_id, PASS_FILTER,
                                       byref(mask), byref(patt), None, byref(fid))
    if rc != STATUS_NOERROR:
        print(f"    warning: pass filter failed ({_last_error(fns)}); "
              "reads may return nothing")

    found = 0
    for name, payload in requests:
        # ISO 11898-1 classic single CAN frame: 4-byte BE id, then an ISO-TP
        # single-frame header (PCI = payload length in the low nibble) followed
        # by the UDS/OBD bytes, padded to a full 8-byte CAN frame.
        tx = PASSTHRU_MSG(ProtocolID=CAN, TxFlags=txf)
        _put_id(tx, req_id)
        tx.Data[4] = len(payload) & 0x0F          # single-frame PCI
        for i, b in enumerate(payload):
            tx.Data[5 + i] = b
        for i in range(5 + len(payload), 12):     # pad remaining bytes to 0x00
            tx.Data[i] = 0x00
        tx.DataSize = 12                            # 4 id + 8 data (full frame)

        num = c_ulong(1)
        rc = fns["PassThruWriteMsgs"](channel_id, byref(tx), byref(num), 1000)
        if rc != STATUS_NOERROR:
            print(f"    {name}: transmit failed ({_last_error(fns)})")
            continue

        got_any = False
        deadline = time.time() + 1.0
        while time.time() < deadline:
            rx = PASSTHRU_MSG()
            n = c_ulong(1)
            rc = fns["PassThruReadMsgs"](channel_id, byref(rx), byref(n), 200)
            if rc != STATUS_NOERROR or n.value == 0:
                continue
            if rx.RxStatus & TX_MSG_TYPE:          # our own loopback echo
                continue
            if rx.DataSize < 5:                    # need id + at least 1 data byte
                continue
            src = (rx.Data[0] << 24) | (rx.Data[1] << 16) | (rx.Data[2] << 8) | rx.Data[3]
            # Ignore frames that are clearly not a diagnostic reply to us. A
            # genuine response's first PCI nibble is single (0x0n) or first
            # frame (0x1n); other broadcast traffic is skipped.
            pci_type = (rx.Data[4] >> 4) & 0x0F
            if pci_type not in (0x0, 0x1):
                continue

            if pci_type == 0x0:
                # Single-frame: the whole UDS payload fits in this CAN frame.
                length = rx.Data[4] & 0x0F
                uds = bytes(rx.Data[5:5 + length])
                print(f"    {name}: RESPONSE from 0x{src:X} (single) -> "
                      f"{_hex_bytes(uds)}")
            else:
                # First-frame of a multi-frame ISO-TP message. Total UDS length
                # is a 12-bit field; the first 6 payload bytes are in this frame.
                total = ((rx.Data[4] & 0x0F) << 8) | rx.Data[5]
                uds = bytearray(rx.Data[6:12])
                # Reply with a flow-control frame so the ECU streams the rest.
                # Functional/physical convention: the ECU listens on its own
                # request id, which for OBD/UDS is the response id minus 8.
                flow_id = src - 8 if src >= 8 else req_id
                send_flow_control(flow_id)
                expected_sn = 1
                cf_deadline = time.time() + 1.0
                while len(uds) < total and time.time() < cf_deadline:
                    cf = PASSTHRU_MSG()
                    cn = c_ulong(1)
                    rc = fns["PassThruReadMsgs"](channel_id, byref(cf), byref(cn), 200)
                    if rc != STATUS_NOERROR or cn.value == 0:
                        continue
                    if cf.RxStatus & TX_MSG_TYPE or cf.DataSize < 5:
                        continue
                    csrc = (cf.Data[0] << 24) | (cf.Data[1] << 16) | \
                           (cf.Data[2] << 8) | cf.Data[3]
                    if csrc != src:
                        continue
                    if (cf.Data[4] >> 4) & 0x0F != 0x2:   # consecutive frame
                        continue
                    if (cf.Data[4] & 0x0F) != (expected_sn & 0x0F):
                        continue                          # out-of-order / gap
                    uds += bytes(cf.Data[5:cf.DataSize - 0])[:total - len(uds)]
                    expected_sn += 1
                uds = bytes(uds[:total])
                status = "complete" if len(uds) >= total else \
                    f"partial {len(uds)}/{total}"
                print(f"    {name}: RESPONSE from 0x{src:X} (multi-frame, "
                      f"{status}) -> {_hex_bytes(uds)}")

            found += 1
            got_any = True
            break
        if not got_any:
            print(f"    {name}: no response")

    fns["PassThruStopMsgFilter"](channel_id, fid)
    fns["PassThruDisconnect"](channel_id)
    return found


def main():
    ap = argparse.ArgumentParser(
        description="Load Toyota's Mini-VCI mvci32.dll and scan CAN for responses "
                    "across all standard baud rates.")
    ap.add_argument("--dll", help="Full path to mvci32.dll "
                    "(default: auto-detect under Program Files Toyota/XHorse).")
    ap.add_argument("--baud", type=int, action="append", metavar="BPS",
                    help="CAN bit rate to scan. Repeat to scan several, e.g. "
                    "--baud 500000 --baud 250000. Default: scan ALL standard "
                    "CAN bauds (1M, 500k, 250k, 125k, 100k, 83.333k, 50k, 33.333k).")
    ap.add_argument("--req", type=lambda x: int(x, 0), default=0x7DF,
                    help="ISO 15765 functional request id (default 0x7DF).")
    ap.add_argument("--resp", type=lambda x: int(x, 0), default=0x7E8,
                    help="Expected response id (informational; raw ISO 11898-1 "
                    "matching is done on PCI, default 0x7E8).")
    ap.add_argument("--ext", action="store_true", help="Use 29-bit CAN identifiers.")
    ap.add_argument("--listen", type=float, default=3.0,
                    help="Passive sniff duration in seconds (default 3.0).")
    args = ap.parse_args()

    # Default sweep: every standard automotive CAN bit rate, fastest first so
    # the most likely (500k diagnostic bus) is found early.
    ALL_BAUDS = [1000000, 500000, 250000, 125000, 100000, 83333, 50000, 33333]
    bauds = args.baud if args.baud else ALL_BAUDS
    if sys.platform != "win32":
        print("ERROR: J2534 / mvci32.dll is Windows-only. Run this on Windows "
              "with a 32-bit Python interpreter.")
        return 2
    if ctypes.sizeof(ctypes.c_void_p) != 4:
        print("ERROR: mvci32.dll is 32-bit; a 64-bit Python process cannot load it.\n"
              "       Re-run with 32-bit Python, e.g.:  py -3-32 "
              + os.path.basename(__file__))
        return 2

    dll_path = resolve_dll(args.dll)
    if not dll_path:
        print("ERROR: could not find mvci32.dll. Pass it explicitly with --dll, e.g.:\n"
              '       --dll "C:\\Program Files (x86)\\XHorse Electronics\\'
              'MVCI Driver for TOYOTA TIS\\mvci32.dll"')
        return 2

    print(f"Loading Toyota Mini-VCI driver: {dll_path}")
    try:
        dll = ctypes.WinDLL(dll_path)
    except OSError as e:
        print(f"ERROR: failed to load mvci32.dll: {e}")
        return 2

    try:
        fns = _bind(dll)
    except RuntimeError as e:
        print(f"ERROR: {e}")
        return 2

    device_id = c_ulong(0)
    rc = fns["PassThruOpen"](None, byref(device_id))
    if rc != STATUS_NOERROR:
        print(f"ERROR: PassThruOpen failed ({_last_error(fns)}); is the Mini-VCI plugged in?")
        return 1
    print(f"PassThruOpen OK (device id {device_id.value}).")

    rv = fns.get("PassThruReadVersion")
    if rv:
        fw = ctypes.create_string_buffer(80)
        dl = ctypes.create_string_buffer(80)
        api = ctypes.create_string_buffer(80)
        if rv(device_id, fw, dl, api) == STATUS_NOERROR:
            print(f"  Firmware: {fw.value.decode(errors='replace')}  "
                  f"DLL: {dl.value.decode(errors='replace')}  "
                  f"J2534: {api.value.decode(errors='replace')}")

    try:
        # Functional OBD-II Mode 01 PID 00 (supported PIDs) + UDS tester-present
        # + DTC reads (both the generic OBD-II and the manufacturer UDS forms
        # the VF8 stack uses).
        requests = [
            ("OBD Mode01 PID00", [0x01, 0x00]),
            ("UDS TesterPresent", [0x3E, 0x00]),
            ("UDS DiagSessionDefault", [0x10, 0x01]),
            # OBD-II Mode 03 "Show stored DTCs" (single-byte request, SID 0x03).
            ("OBD Mode03 StoredDTCs", [0x03]),
            # UDS ReadDTCInformation (SID 0x19) sub-function 0x02
            # reportDTCByStatusMask, status mask 0xFF = match all DTC statuses.
            ("UDS ReadDTC 19 02 FF", [0x19, 0x02, 0xFF]),
        ]

        results = []  # (baud, passive_hits, active_resp)
        for baud in bauds:
            print("\n" + "=" * 60)
            print(f"  Scanning CAN @ {baud} bps")
            print("=" * 60)
            hits = passive_sniff(fns, device_id, baud, args.listen)
            resp = active_probe(fns, device_id, baud, args.req, args.resp,
                                args.ext, requests)
            results.append((baud, hits, resp))

        print("\n=== Summary (all bauds) ===")
        any_hit = False
        for baud, hits, resp in results:
            mark = "  <-- responsive" if (hits or resp) else ""
            any_hit = any_hit or bool(hits or resp)
            print(f"  {baud:>7} bps : passive {hits:>2} id(s), "
                  f"active {resp} response(s){mark}")
        if any_hit:
            live = ", ".join(str(b) for b, h, r in results if (h or r))
            print(f"  RESULT : vehicle communicates over CAN at: {live} bps.")
        else:
            print("  RESULT : no responses on any baud. Try --ext (29-bit), "
                  "check the cable/ignition, or confirm the bus is on the OBD pins.")
    finally:
        fns["PassThruClose"](device_id)
        print("\nPassThruClose OK. Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
