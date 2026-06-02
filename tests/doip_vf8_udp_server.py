#!/usr/bin/env python3
"""
Extensive VF8 DoIP UDP server for test environments.

What it does:
- Implements core DoIP UDP discovery/status/power endpoints.
- Loads all ECU modules and reference DTCs directly from src/VF8Data.cpp.
- Exposes module metadata + trouble codes through a JSON-over-UDP API.

JSON-over-UDP protocol (custom):
- Request payload type:  0xF100
- Response payload type: 0xF101

Supported request actions:
- {"action":"list_modules"}
- {"action":"get_module", "code":"BMS"}
- {"action":"get_module", "address":"0x1003"}
- {"action":"get_dtcs", "code":"BMS"}
- {"action":"get_dtcs", "code":"BMS", "status":"Current"}
- {"action":"search_dtc", "dtc":"U110887"}
- {"action":"stats"}

Notes:
- This server is intentionally UDP-focused. It does not implement DoIP TCP
  routing activation or UDS transport.
- DoIP payloads use protocol version 0x02.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import struct
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from doipclient.messages import (
        DiagnosticPowerModeRequest,
        DiagnosticPowerModeResponse,
        DoipEntityStatusRequest,
        EntityStatusResponse,
        VehicleIdentificationRequest,
        VehicleIdentificationRequestWithEID,
        VehicleIdentificationRequestWithVIN,
        VehicleIdentificationResponse,
    )

    HAVE_DOIPCLIENT = True
except Exception:  # noqa: BLE001
    HAVE_DOIPCLIENT = False

try:
    from udsoncan import Dtc

    HAVE_UDSONCAN = True
except Exception:  # noqa: BLE001
    HAVE_UDSONCAN = False

PROTO_VER = 0x02

# ISO 13400-2 payload types (UDP side)
PT_GENERIC_NACK = 0x0000
PT_VID_REQ = 0x0001
PT_VID_REQ_EID = 0x0002
PT_VID_REQ_VIN = 0x0003
PT_VID_RESP = 0x0004
PT_ENTITY_STATUS_REQ = 0x4001
PT_ENTITY_STATUS_RESP = 0x4002
PT_POWER_REQ = 0x4003
PT_POWER_RESP = 0x4004
PT_ROUTING_REQ = 0x0005
PT_ROUTING_RESP = 0x0006
PT_ALIVE_REQ = 0x0007
PT_ALIVE_RESP = 0x0008
PT_DIAG = 0x8001
PT_DIAG_ACK_POS = 0x8002
PT_DIAG_ACK_NEG = 0x8003

# Custom JSON-over-UDP payloads for richer test access.
PT_JSON_REQ = 0xF100
PT_JSON_RESP = 0xF101

DEFAULT_EID = bytes([0x56, 0x46, 0x38, 0x00, 0x00, 0x01])  # "VF8\0\0\1"
DEFAULT_GID = bytes([0x56, 0x46, 0x47, 0x57, 0x00, 0x01])  # "VFGW\0\1"
DEFAULT_VIN = b"RLLV1AEB0RH004878"
DEFAULT_FUNCTIONAL_ADDR = 0xE400


@dataclass
class Ecu:
    code: str
    name: str
    placeholder_addr: int
    hw_part: str
    sw_part: str
    alt_addr: int = 0


@dataclass
class RefDtc:
    dtc: str
    status: str
    desc: str


@dataclass
class RefSystem:
    code: str
    name: str
    dtcs: List[RefDtc]


def doip_header(payload_type: int, payload: bytes) -> bytes:
    inv = (~PROTO_VER) & 0xFF
    return struct.pack(">BBHI", PROTO_VER, inv, payload_type, len(payload)) + payload


def parse_int_token(token: str) -> int:
    token = token.strip()
    if token.lower().startswith("0x"):
        return int(token, 16)
    return int(token, 10)


def extract_initializer(text: str, symbol: str) -> str:
    marker = f"{symbol} ="
    i = text.find(marker)
    if i < 0:
        raise ValueError(f"symbol not found: {symbol}")

    j = text.find("{", i)
    if j < 0:
        raise ValueError(f"initializer start not found for: {symbol}")

    depth = 0
    k = j
    while k < len(text):
        ch = text[k]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[j : k + 1]
        k += 1

    raise ValueError(f"initializer end not found for: {symbol}")


def parse_ecus(vf8_text: str) -> List[Ecu]:
    block = extract_initializer(vf8_text, "kVF8Ecus")
    pat = re.compile(
        r'\{\s*"([^"]+)"\s*,\s*"([^"]*)"\s*,\s*'
        r'(0x[0-9A-Fa-f]+|\d+)\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"'
        r'(?:\s*,\s*(0x[0-9A-Fa-f]+|\d+))?\s*\}'
    )

    out: List[Ecu] = []
    for m in pat.finditer(block):
        code, name, addr, hw, sw, alt = m.groups()
        out.append(
            Ecu(
                code=code,
                name=name,
                placeholder_addr=parse_int_token(addr),
                hw_part=hw,
                sw_part=sw,
                alt_addr=parse_int_token(alt) if alt else 0,
            )
        )

    if not out:
        raise ValueError("failed to parse kVF8Ecus from VF8Data.cpp")
    return out


def parse_reference_scan(vf8_text: str) -> List[RefSystem]:
    block = extract_initializer(vf8_text, "kVF8ReferenceScan")
    lines = block.splitlines()

    sys_open = re.compile(r'^\s*\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*\{\s*$')
    dtc_pat = re.compile(r'\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\}')

    systems: List[RefSystem] = []
    current_code = ""
    current_name = ""
    current_dtcs: List[RefDtc] = []
    in_system = False

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("//"):
            continue

        if not in_system:
            m = sys_open.match(raw)
            if m:
                current_code, current_name = m.group(1), m.group(2)
                current_dtcs = []
                in_system = True
            continue

        for dm in dtc_pat.finditer(raw):
            current_dtcs.append(RefDtc(dtc=dm.group(1), status=dm.group(2), desc=dm.group(3)))

        if line.startswith("}},") or line == "}}":
            systems.append(RefSystem(code=current_code, name=current_name, dtcs=current_dtcs))
            in_system = False
            current_code = ""
            current_name = ""
            current_dtcs = []

    if in_system:
        systems.append(RefSystem(code=current_code, name=current_name, dtcs=current_dtcs))

    if not systems:
        raise ValueError("failed to parse kVF8ReferenceScan from VF8Data.cpp")
    return systems


def normalize_address(value: str) -> int:
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value)


def autel_code_to_uds_id(autel_code: str) -> Optional[int]:
    """Convert Autel DTC strings like U110887 into 24-bit UDS DTC ids."""
    code = autel_code.strip().upper()
    if len(code) < 7:
        return None

    letter = code[0]
    base = code[1:5]
    ftb = code[5:7]

    if letter not in "PCBU":
        return None
    if not re.fullmatch(r"[0-9A-F]{4}", base):
        return None
    if not re.fullmatch(r"[0-9A-F]{2}", ftb):
        return None

    family_bits = {"P": 0, "C": 1, "B": 2, "U": 3}[letter]
    d0 = int(base[0], 16)
    if d0 > 3:
        return None

    d1 = int(base[1], 16)
    d2 = int(base[2], 16)
    d3 = int(base[3], 16)
    b0 = (family_bits << 6) | (d0 << 4) | d1
    b1 = (d2 << 4) | d3
    b2 = int(ftb, 16)
    return (b0 << 16) | (b1 << 8) | b2


def uds_status_for_label(status: str):
    if not HAVE_UDSONCAN:
        return None

    s = status.strip().lower()
    if s == "current":
        return Dtc.Status(test_failed=True, pending=True, confirmed=True)
    if s == "history":
        return Dtc.Status(test_failed_since_last_clear=True, confirmed=True)
    return Dtc.Status()


def uds_status_byte_for_label(status: str) -> int:
    """Map reference labels to a plausible UDS status byte."""
    s = status.strip().lower()
    if HAVE_UDSONCAN:
        st = uds_status_for_label(status)
        if st is not None:
            return int(st.get_byte_as_int())

    # Fallback without udsoncan: conservative status bits.
    # Current -> testFailed + pending + confirmed (0x0D)
    # History -> confirmed only (0x08)
    return 0x0D if s == "current" else 0x08


def uds_dtc_bytes_from_autel_code(code: str) -> Optional[Tuple[int, int, int]]:
    dtc_id = autel_code_to_uds_id(code)
    if dtc_id is None:
        return None
    return ((dtc_id >> 16) & 0xFF, (dtc_id >> 8) & 0xFF, dtc_id & 0xFF)


class Vf8DoipUdpServer:
    def __init__(
        self,
        host: str,
        port: int,
        vf8_path: Path,
        functional_addr: int = DEFAULT_FUNCTIONAL_ADDR,
        vin: bytes = DEFAULT_VIN,
        eid: bytes = DEFAULT_EID,
        gid: bytes = DEFAULT_GID,
        verbose: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.verbose = verbose

        text = vf8_path.read_text(encoding="utf-8")
        self.ecus = parse_ecus(text)
        self.ref_systems = parse_reference_scan(text)

        self.ecu_by_code: Dict[str, Ecu] = {e.code: e for e in self.ecus}
        self.ecu_by_addr: Dict[int, Ecu] = {e.placeholder_addr: e for e in self.ecus}
        self.ref_by_code: Dict[str, RefSystem] = {s.code: s for s in self.ref_systems}

        self.gateway_addr = self.ecu_by_code.get("XGW", self.ecus[0]).placeholder_addr
        self.functional_addr = functional_addr

        self.vin = (vin[:17]).ljust(17, b" ")
        self.eid = (eid[:6]).ljust(6, b"\x00")
        self.gid = (gid[:6]).ljust(6, b"\x00")

        # Mutable DTC store keyed by ECU code for read/clear operations.
        self._dtc_runtime: Dict[str, List[RefDtc]] = {
            e.code: [RefDtc(dtc=d.dtc, status=d.status, desc=d.desc)
                     for d in self.ref_by_code.get(e.code, RefSystem("", "", [])).dtcs]
            for e in self.ecus
        }
        self._dtc_lock = threading.Lock()

    def log(self, msg: str) -> None:
        if self.verbose:
            now = time.strftime("%H:%M:%S")
            print(f"[{now}] {msg}")

    def build_vid_response(self) -> bytes:
        if HAVE_DOIPCLIENT:
            msg = VehicleIdentificationResponse(
                vin=self.vin,
                logical_address=self.gateway_addr,
                eid=self.eid,
                gid=self.gid,
                further_action_required=0,
                vin_gid_sync_status=None,
            )
            return doip_header(msg.payload_type, msg.pack())

        payload = self.vin + struct.pack(">H", self.gateway_addr) + self.eid + self.gid + b"\x00"
        return doip_header(PT_VID_RESP, payload)

    def build_entity_status_response(self) -> bytes:
        # nodeType=0 (gateway), maxSockets=16, openSockets=0, maxData=65535
        if HAVE_DOIPCLIENT:
            msg = EntityStatusResponse(
                node_type=0,
                max_concurrent_sockets=16,
                currently_open_sockets=0,
                max_data_size=0x0000FFFF,
            )
            return doip_header(msg.payload_type, msg.pack())

        payload = bytes([0x00, 0x10, 0x00]) + struct.pack(">I", 0x0000FFFF)
        return doip_header(PT_ENTITY_STATUS_RESP, payload)

    def build_power_response(self) -> bytes:
        # 0x01 = ready
        if HAVE_DOIPCLIENT:
            msg = DiagnosticPowerModeResponse(
                DiagnosticPowerModeResponse.DiagnosticPowerMode.Ready
            )
            return doip_header(msg.payload_type, msg.pack())

        return doip_header(PT_POWER_RESP, b"\x01")

    def build_generic_nack(self, code: int = 0x01) -> bytes:
        return doip_header(PT_GENERIC_NACK, bytes([code & 0xFF]))

    def serialize_dtcs(self, dtcs: List[RefDtc]) -> List[Dict[str, object]]:
        enriched: List[Dict[str, object]] = []
        for d in dtcs:
            obj: Dict[str, object] = asdict(d)
            uds_id = autel_code_to_uds_id(d.dtc)
            if uds_id is not None:
                obj["udsDtcIdHex"] = f"0x{uds_id:06X}"
                if HAVE_UDSONCAN:
                    dtc_obj = Dtc(uds_id)
                    obj["udsIso"] = dtc_obj.id_iso()
                    st = uds_status_for_label(d.status)
                    if st is not None:
                        obj["udsStatusByte"] = st.get_byte_as_int()
            enriched.append(obj)
        return enriched

    def module_record(self, ecu: Ecu, include_dtcs: bool = True) -> Dict[str, object]:
        ref = self.ref_by_code.get(ecu.code)
        dtcs = ref.dtcs if ref else []

        current_count = sum(1 for d in dtcs if d.status.lower() == "current")
        history_count = sum(1 for d in dtcs if d.status.lower() == "history")

        rec: Dict[str, object] = {
            "code": ecu.code,
            "name": ecu.name,
            "logicalAddress": f"0x{ecu.placeholder_addr:04X}",
            "logicalAddressDecimal": ecu.placeholder_addr,
            "altLogicalAddress": f"0x{ecu.alt_addr:04X}" if ecu.alt_addr else None,
            "altLogicalAddressDecimal": ecu.alt_addr if ecu.alt_addr else None,
            "hardwarePartNumber": ecu.hw_part or None,
            "softwarePartNumber": ecu.sw_part or None,
            "diagnosticCoverage": {
                "presentInReferenceScan": ref is not None,
                "currentDtcCount": current_count,
                "historyDtcCount": history_count,
                "totalDtcCount": len(dtcs),
            },
            "protocol": {
                "transport": "DoIP (ISO 13400)",
                "application": "UDS (ISO 14229)",
                "addressingHint": "placeholderAddr values are test placeholders",
            },
        }

        if include_dtcs:
            rec["dtcs"] = self.serialize_dtcs(dtcs)
        return rec

    def handle_json_request(self, payload: bytes) -> bytes:
        try:
            req = json.loads(payload.decode("utf-8"))
        except Exception as exc:  # pylint: disable=broad-except
            rsp = {"ok": False, "error": f"invalid JSON payload: {exc}"}
            return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

        action = str(req.get("action", "")).strip()

        if action == "list_modules":
            modules = [self.module_record(e, include_dtcs=False) for e in self.ecus]
            rsp = {
                "ok": True,
                "action": action,
                "count": len(modules),
                "modules": modules,
            }
            return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

        if action == "get_module":
            code = req.get("code")
            address = req.get("address")

            ecu: Optional[Ecu] = None
            if isinstance(code, str) and code:
                ecu = self.ecu_by_code.get(code)
            elif isinstance(address, str) and address:
                ecu = self.ecu_by_addr.get(normalize_address(address))
            elif isinstance(address, int):
                ecu = self.ecu_by_addr.get(address)

            if ecu is None:
                rsp = {"ok": False, "action": action, "error": "module not found"}
            else:
                rsp = {"ok": True, "action": action, "module": self.module_record(ecu, include_dtcs=True)}
            return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

        if action == "get_dtcs":
            code = req.get("code")
            status_filter = str(req.get("status", "")).strip().lower()
            if not isinstance(code, str) or not code:
                rsp = {"ok": False, "action": action, "error": "missing code"}
                return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

            ref = self.ref_by_code.get(code)
            if ref is None:
                rsp = {
                    "ok": True,
                    "action": action,
                    "code": code,
                    "name": self.ecu_by_code.get(code).name if code in self.ecu_by_code else None,
                    "count": 0,
                    "dtcs": [],
                }
                return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

            dtcs = ref.dtcs
            if status_filter in {"current", "history"}:
                dtcs = [d for d in dtcs if d.status.lower() == status_filter]

            rsp = {
                "ok": True,
                "action": action,
                "code": code,
                "name": ref.name,
                "statusFilter": status_filter or None,
                "count": len(dtcs),
                "dtcs": self.serialize_dtcs(dtcs),
            }
            return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

        if action == "search_dtc":
            dtc = str(req.get("dtc", "")).strip().upper()
            if not dtc:
                rsp = {"ok": False, "action": action, "error": "missing dtc"}
                return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

            hits: List[Dict[str, object]] = []
            for sys in self.ref_systems:
                for d in sys.dtcs:
                    if d.dtc.upper() == dtc:
                        hits.append(
                            {
                                "moduleCode": sys.code,
                                "moduleName": sys.name,
                                "status": d.status,
                                "desc": d.desc,
                            }
                        )
            rsp = {"ok": True, "action": action, "dtc": dtc, "count": len(hits), "matches": hits}
            return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

        if action == "stats":
            total_dtcs = sum(len(s.dtcs) for s in self.ref_systems)
            current_dtcs = sum(1 for s in self.ref_systems for d in s.dtcs if d.status.lower() == "current")
            history_dtcs = sum(1 for s in self.ref_systems for d in s.dtcs if d.status.lower() == "history")

            rsp = {
                "ok": True,
                "action": action,
                "moduleCount": len(self.ecus),
                "referenceSystemCount": len(self.ref_systems),
                "dtcTotal": total_dtcs,
                "dtcCurrent": current_dtcs,
                "dtcHistory": history_dtcs,
                "gatewayLogicalAddress": f"0x{self.gateway_addr:04X}",
            }
            return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

        rsp = {"ok": False, "error": "unsupported action", "action": action}
        return doip_header(PT_JSON_RESP, json.dumps(rsp).encode("utf-8"))

    def _module_dtcs(self, ecu: Ecu) -> List[RefDtc]:
        with self._dtc_lock:
            return [RefDtc(dtc=d.dtc, status=d.status, desc=d.desc) for d in self._dtc_runtime.get(ecu.code, [])]

    def _clear_module_dtcs(self, ecu: Ecu) -> None:
        with self._dtc_lock:
            self._dtc_runtime[ecu.code] = []

    def _did_value(self, ecu: Ecu, did: int) -> Optional[bytes]:
        if did == 0xF190:
            return self.vin.rstrip(b" ")
        if did == 0xF187:
            return (ecu.hw_part or "").encode("ascii", errors="ignore")
        if did == 0xF188:
            return (ecu.sw_part or "").encode("ascii", errors="ignore")
        if did == 0xF189:
            return (ecu.sw_part or "").encode("ascii", errors="ignore")
        if did == 0xF18C:
            return f"{ecu.code}-SN-001".encode("ascii", errors="ignore")
        if did == 0xF18A:
            return b"VINFAST"
        if did == 0xF191:
            return (ecu.hw_part or "").encode("ascii", errors="ignore")
        if did == 0xF193:
            return (ecu.hw_part or "").encode("ascii", errors="ignore")
        if did == 0xF195:
            return (ecu.sw_part or "").encode("ascii", errors="ignore")
        if did == 0xF197:
            return ecu.name.encode("ascii", errors="ignore")
        return None

    def _uds_read_dtc_info(self, ecu: Ecu, uds: bytes) -> bytes:
        if len(uds) < 2:
            return bytes([0x7F, 0x19, 0x13])
        sub = uds[1]
        dtcs = self._module_dtcs(ecu)

        def records(mask: int) -> List[Tuple[Tuple[int, int, int], int]]:
            out: List[Tuple[Tuple[int, int, int], int]] = []
            for d in dtcs:
                b = uds_dtc_bytes_from_autel_code(d.dtc)
                if b is None:
                    continue
                st = uds_status_byte_for_label(d.status)
                if mask == 0x00 or (st & mask) != 0:
                    out.append((b, st))
            return out

        # ReportNumberOfDTCByStatusMask
        if sub == 0x01:
            if len(uds) < 3:
                return bytes([0x7F, 0x19, 0x13])
            mask = uds[2]
            recs = records(mask)
            cnt = len(recs)
            return bytes([0x59, 0x01, 0xFF, 0x01, (cnt >> 8) & 0xFF, cnt & 0xFF])

        # ReportDTCByStatusMask
        if sub == 0x02:
            if len(uds) < 3:
                return bytes([0x7F, 0x19, 0x13])
            mask = uds[2]
            out = bytearray([0x59, 0x02, 0xFF])
            for (b0, b1, b2), st in records(mask):
                out.extend([b0, b1, b2, st])
            return bytes(out)

        # ReportSupportedDTC
        if sub == 0x0A:
            out = bytearray([0x59, 0x0A, 0xFF])
            for (b0, b1, b2), st in records(0x00):
                out.extend([b0, b1, b2, st])
            return bytes(out)

        # ReportDTCSnapshotRecordByDTCNumber
        if sub == 0x04:
            if len(uds) < 6:
                return bytes([0x7F, 0x19, 0x13])
            # 0x59 0x04 <DTC(3)> <status> <recordNo> <DIDcount>
            b0, b1, b2, rec_no = uds[2], uds[3], uds[4], uds[5]
            found_status = 0x00
            for (x0, x1, x2), st in records(0x00):
                if (x0, x1, x2) == (b0, b1, b2):
                    found_status = st
                    break
            return bytes([0x59, 0x04, b0, b1, b2, found_status, rec_no, 0x00])

        # ReportDTCExtDataRecordByDTCNumber
        if sub == 0x06:
            if len(uds) < 6:
                return bytes([0x7F, 0x19, 0x13])
            b0, b1, b2, rec_no = uds[2], uds[3], uds[4], uds[5]
            found_status = 0x00
            for (x0, x1, x2), st in records(0x00):
                if (x0, x1, x2) == (b0, b1, b2):
                    found_status = st
                    break
            return bytes([0x59, 0x06, b0, b1, b2, found_status, rec_no, 0x00])

        # ReportDTCFaultDetectionCounter
        if sub == 0x14:
            out = bytearray([0x59, 0x14])
            for (b0, b1, b2), st in records(0x00):
                # Use status-derived synthetic counter for stable UI behavior.
                fdc = 0x28 if (st & 0x01) else 0x08
                out.extend([b0, b1, b2, fdc])
            return bytes(out)

        return bytes([0x7F, 0x19, 0x12])

    def _uds_response_for(self, ecu: Ecu, uds: bytes) -> Optional[bytes]:
        if not uds:
            return None

        sid = uds[0]
        if sid == 0x3E:
            return bytes([0x7E, 0x00])

        if sid == 0x10 and len(uds) >= 2:
            sub = uds[1]
            return bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])

        if sid == 0x22 and len(uds) >= 3:
            did = (uds[1] << 8) | uds[2]
            val = self._did_value(ecu, did)
            if val is None:
                return bytes([0x7F, 0x22, 0x31])
            return bytes([0x62, uds[1], uds[2]]) + val

        if sid == 0x19:
            return self._uds_read_dtc_info(ecu, uds)

        if sid == 0x14:
            self._clear_module_dtcs(ecu)
            return bytes([0x54])

        return bytes([0x7F, sid, 0x11])

    def _diag_ack_positive(self, tester_addr: int, ecu_addr: int) -> bytes:
        return doip_header(PT_DIAG_ACK_POS, struct.pack(">HHB", ecu_addr, tester_addr, 0x00))

    def _diag_message(self, ecu_addr: int, tester_addr: int, uds: bytes) -> bytes:
        return doip_header(PT_DIAG, struct.pack(">HH", ecu_addr, tester_addr) + uds)

    def _diag_ack_negative(self, target_addr: int, tester_addr: int, code: int = 0x03) -> bytes:
        return doip_header(PT_DIAG_ACK_NEG, struct.pack(">HHB", target_addr, tester_addr, code & 0xFF))

    def _dispatch_tcp(self, conn: socket.socket, ptype: int, payload: bytes) -> None:
        if ptype == PT_ROUTING_REQ:
            tester = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 0x0E80
            # tester LA(2) + gateway LA(2) + responseCode(1) + reserved(4)
            rsp = struct.pack(">HHB", tester, self.gateway_addr, 0x10) + b"\x00\x00\x00\x00"
            conn.sendall(doip_header(PT_ROUTING_RESP, rsp))
            return

        if ptype == PT_ALIVE_RESP:
            return

        if ptype != PT_DIAG:
            conn.sendall(self.build_generic_nack(0x01))
            return

        if len(payload) < 4:
            return

        tester_addr = struct.unpack(">H", payload[:2])[0]
        target_addr = struct.unpack(">H", payload[2:4])[0]
        uds = payload[4:]

        if target_addr == self.functional_addr:
            # Functional addressing: acknowledge and answer from every ECU.
            for ecu in self.ecus:
                conn.sendall(self._diag_ack_positive(tester_addr, ecu.placeholder_addr))
            for ecu in self.ecus:
                r = self._uds_response_for(ecu, uds)
                if r is not None:
                    conn.sendall(self._diag_message(ecu.placeholder_addr, tester_addr, r))
            return

        ecu = self.ecu_by_addr.get(target_addr)
        if ecu is None:
            conn.sendall(self._diag_ack_negative(target_addr, tester_addr, 0x03))
            return

        conn.sendall(self._diag_ack_positive(tester_addr, target_addr))
        r = self._uds_response_for(ecu, uds)
        if r is not None:
            conn.sendall(self._diag_message(target_addr, tester_addr, r))

    def _tcp_connection(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        self.log(f"tcp connect from {addr}")
        conn.settimeout(30)
        buf = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 8:
                    ver, inv, ptype, plen = struct.unpack(">BBHI", buf[:8])
                    if ver != PROTO_VER or inv != ((~PROTO_VER) & 0xFF):
                        conn.sendall(self.build_generic_nack(0x00))
                        return
                    if len(buf) < 8 + plen:
                        break
                    payload = buf[8 : 8 + plen]
                    buf = buf[8 + plen :]
                    self._dispatch_tcp(conn, ptype, payload)
        except (ConnectionError, OSError):
            pass
        finally:
            conn.close()
            self.log(f"tcp closed {addr}")

    def serve_tcp_forever(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(16)
        print(f"  tcp: {self.host}:{self.port}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self._tcp_connection, args=(conn, addr), daemon=True).start()

    def serve_forever(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((self.host, self.port))

        print("VF8 DoIP UDP test server")
        print(f"  listen: {self.host}:{self.port}")
        print(f"  VIN: {self.vin.decode('ascii', errors='replace')}")
        print(f"  EID: {self.eid.hex()}  GID: {self.gid.hex()}")
        print(f"  gateway logical address: 0x{self.gateway_addr:04X}")
        print(f"  functional address: 0x{self.functional_addr:04X}")
        print(f"  modules loaded: {len(self.ecus)}")
        print(f"  reference systems loaded: {len(self.ref_systems)}")
        print(f"  doipclient integration: {'enabled' if HAVE_DOIPCLIENT else 'fallback encoder'}")
        print(f"  udsoncan enrichment: {'enabled' if HAVE_UDSONCAN else 'disabled'}")
        print("  custom payloads: request=0xF100 response=0xF101")

        threading.Thread(target=self.serve_tcp_forever, daemon=True).start()

        while True:
            data, addr = sock.recvfrom(65535)
            if len(data) < 8:
                continue

            ver, inv, ptype, plen = struct.unpack(">BBHI", data[:8])
            if ver != PROTO_VER or inv != ((~PROTO_VER) & 0xFF):
                self.log(f"drop invalid proto header from {addr}")
                continue
            if len(data) < 8 + plen:
                self.log(f"drop short payload from {addr} ptype=0x{ptype:04X}")
                continue

            payload = data[8 : 8 + plen]
            self.log(f"rx {addr} ptype=0x{ptype:04X} len={plen}")

            if ptype in (PT_VID_REQ, PT_VID_REQ_EID, PT_VID_REQ_VIN):
                if HAVE_DOIPCLIENT:
                    try:
                        if ptype == PT_VID_REQ:
                            VehicleIdentificationRequest.unpack(payload)
                        elif ptype == PT_VID_REQ_EID:
                            VehicleIdentificationRequestWithEID.unpack(payload)
                        else:
                            VehicleIdentificationRequestWithVIN.unpack(payload)
                    except Exception as exc:  # noqa: BLE001
                        self.log(f"bad VID request from {addr}: {exc}")
                        sock.sendto(self.build_generic_nack(0x04), addr)
                        continue
                sock.sendto(self.build_vid_response(), addr)
                continue

            if ptype == PT_ENTITY_STATUS_REQ:
                if HAVE_DOIPCLIENT:
                    try:
                        DoipEntityStatusRequest.unpack(payload)
                    except Exception as exc:  # noqa: BLE001
                        self.log(f"bad entity-status request from {addr}: {exc}")
                        sock.sendto(self.build_generic_nack(0x04), addr)
                        continue
                sock.sendto(self.build_entity_status_response(), addr)
                continue

            if ptype == PT_POWER_REQ:
                if HAVE_DOIPCLIENT:
                    try:
                        DiagnosticPowerModeRequest.unpack(payload)
                    except Exception as exc:  # noqa: BLE001
                        self.log(f"bad power-mode request from {addr}: {exc}")
                        sock.sendto(self.build_generic_nack(0x04), addr)
                        continue
                sock.sendto(self.build_power_response(), addr)
                continue

            if ptype == PT_JSON_REQ:
                sock.sendto(self.handle_json_request(payload), addr)
                continue

            sock.sendto(self.build_generic_nack(0x01), addr)


def parse_hex_bytes(value: str, required_len: int) -> bytes:
    compact = value.replace(":", "").replace(" ", "").strip()
    data = bytes.fromhex(compact)
    if len(data) != required_len:
        raise ValueError(f"expected {required_len} bytes, got {len(data)}")
    return data


def main() -> None:
    ap = argparse.ArgumentParser(description="Extensive VF8 DoIP UDP test server")
    ap.add_argument("--host", default="0.0.0.0", help="listen host")
    ap.add_argument("--port", type=int, default=13400, help="listen UDP port")
    ap.add_argument(
        "--vf8-data",
        default="src/VF8Data.cpp",
        help="path to VF8Data.cpp (default: src/VF8Data.cpp)",
    )
    ap.add_argument(
        "--functional-addr",
        default=f"0x{DEFAULT_FUNCTIONAL_ADDR:04X}",
        help="functional logical address for group diagnostics (default: 0xE400)",
    )
    ap.add_argument("--vin", default=DEFAULT_VIN.decode("ascii"), help="17-char VIN used in VID response")
    ap.add_argument("--eid", default=DEFAULT_EID.hex(), help="6-byte hex EID (example: deadbeef0001)")
    ap.add_argument("--gid", default=DEFAULT_GID.hex(), help="6-byte hex GID (example: 001122334455)")
    ap.add_argument("--verbose", action="store_true", help="enable verbose request logging")

    args = ap.parse_args()

    vf8_path = Path(args.vf8_data)
    if not vf8_path.exists():
        raise SystemExit(f"VF8 data file not found: {vf8_path}")

    try:
        eid = parse_hex_bytes(args.eid, 6)
        gid = parse_hex_bytes(args.gid, 6)
    except ValueError as exc:
        raise SystemExit(f"invalid EID/GID: {exc}") from exc

    try:
        functional_addr = normalize_address(str(args.functional_addr))
    except ValueError as exc:
        raise SystemExit(f"invalid --functional-addr: {exc}") from exc

    server = Vf8DoipUdpServer(
        host=args.host,
        port=args.port,
        vf8_path=vf8_path,
        functional_addr=functional_addr,
        vin=args.vin.encode("ascii", errors="ignore"),
        eid=eid,
        gid=gid,
        verbose=args.verbose,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")


if __name__ == "__main__":
    main()
