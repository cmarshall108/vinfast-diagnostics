#include "UDSClient.hpp"
#include "Logger.hpp"
#include "VF8Data.hpp"

#include <algorithm>
#include <cstdio>
#include <unordered_map>

// Human-readable name for a UDS service ID (the first request byte).
static const char* udsServiceName(uint8_t sid) {
    switch (sid) {
        case 0x10: return "DiagnosticSessionControl";
        case 0x11: return "ECUReset";
        case 0x14: return "ClearDiagnosticInformation";
        case 0x19: return "ReadDTCInformation";
        case 0x22: return "ReadDataByIdentifier";
        case 0x23: return "ReadMemoryByAddress";
        case 0x27: return "SecurityAccess";
        case 0x28: return "CommunicationControl";
        case 0x2E: return "WriteDataByIdentifier";
        case 0x2F: return "InputOutputControlByIdentifier";
        case 0x2A: return "ReadDataByPeriodicIdentifier";
        case 0x2C: return "DynamicallyDefineDataIdentifier";
        case 0x31: return "RoutineControl";
        case 0x34: return "RequestDownload";
        case 0x36: return "TransferData";
        case 0x37: return "RequestTransferExit";
        case 0x3E: return "TesterPresent";
        case 0x85: return "ControlDTCSetting";
        default:   return "Unknown service";
    }
}

static std::string addr16(uint16_t a) {
    return byteHex((a >> 8) & 0xFF) + byteHex(a & 0xFF);
}

// -----------------------------------------------------------------------
// Core request/response wrapper with negative-response handling.
// -----------------------------------------------------------------------
bool UDSClient::request(uint16_t target, const std::vector<uint8_t>& req,
                        std::vector<uint8_t>& resp, std::string& err) {
    uint8_t sid = req.empty() ? 0x00 : req[0];
    Logger::instance().log(LogLevel::Tx,
        "UDS -> 0x" + addr16(target) + "  " + udsServiceName(sid) +
        " (SID 0x" + byteHex(sid) + "), req[" + std::to_string(req.size()) +
        "]: " + toHex(req.data(), req.size()));

    if (!doip_.sendDiagnostic(tester_, target, req, resp, 5000, err)) {
        Logger::instance().log(LogLevel::Error,
            "UDS <- 0x" + addr16(target) + "  " + udsServiceName(sid) +
            " transport error: " + err);
        return false;
    }
    if (resp.empty()) {
        err = "Empty UDS response";
        Logger::instance().log(LogLevel::Error,
            "UDS <- 0x" + addr16(target) + "  empty response");
        return false;
    }

    if (resp[0] == 0x7F) {                       // negative response
        uint8_t nrc = resp.size() >= 3 ? resp[2] : 0x00;
        err = "UDS negative response (NRC 0x" + byteHex(nrc) + "): " + nrcText(nrc);
        Logger::instance().log(LogLevel::Warn,
            "UDS <- 0x" + addr16(target) + "  NEGATIVE for " + udsServiceName(sid) +
            ": NRC 0x" + byteHex(nrc) + " (" + nrcText(nrc) + ")");
        return false;
    }
    if (resp[0] != (uint8_t)(req[0] + 0x40)) {   // SID + 0x40 = positive
        err = "Unexpected UDS positive response SID 0x" + byteHex(resp[0]);
        Logger::instance().log(LogLevel::Warn,
            "UDS <- 0x" + addr16(target) + "  unexpected SID 0x" + byteHex(resp[0]) +
            " (expected 0x" + byteHex((uint8_t)(req[0] + 0x40)) + ")");
        return false;
    }
    Logger::instance().log(LogLevel::Rx,
        "UDS <- 0x" + addr16(target) + "  POSITIVE " + udsServiceName(sid) +
        ", resp[" + std::to_string(resp.size()) + "]: " +
        toHex(resp.data(), resp.size()));
    return true;
}

bool UDSClient::diagnosticSessionControl(uint16_t target, UdsSession session,
                                         std::string& err) {
    std::vector<uint8_t> req = {0x10, (uint8_t)session};
    std::vector<uint8_t> resp;
    // Positive: 0x50 <session> <P2_hi P2_lo P2*_hi P2*_lo> (timing params).
    return request(target, req, resp, err);
}

std::optional<std::vector<uint8_t>>
UDSClient::requestSeed(uint16_t target, uint8_t level, std::string& err) {
    // Odd sub-function = requestSeed (e.g. 0x01, 0x03, 0x05 ...).
    std::vector<uint8_t> req = {0x27, level};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return std::nullopt;
    // Positive: 0x67 <level> <seed...>. An all-zero seed means already unlocked.
    if (resp.size() < 2) { err = "Seed response too short"; return std::nullopt; }
    return std::vector<uint8_t>(resp.begin() + 2, resp.end());
}

bool UDSClient::sendKey(uint16_t target, uint8_t level,
                        const std::vector<uint8_t>& key, std::string& err) {
    // Even sub-function = sendKey (requestSeed level + 1).
    std::vector<uint8_t> req = {0x27, (uint8_t)(level + 1)};
    req.insert(req.end(), key.begin(), key.end());
    std::vector<uint8_t> resp;
    return request(target, req, resp, err);
}

std::optional<std::vector<uint8_t>>
UDSClient::readDataByIdentifier(uint16_t target, uint16_t did, std::string& err) {
    std::vector<uint8_t> req = {0x22, (uint8_t)((did >> 8) & 0xFF),
                                (uint8_t)(did & 0xFF)};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return std::nullopt;
    // Positive: 0x62 DID_hi DID_lo <data...>
    if (resp.size() < 3) { err = "RDBI response too short"; return std::nullopt; }
    return std::vector<uint8_t>(resp.begin() + 3, resp.end());
}

std::string UDSClient::readEcuIdentification(uint16_t target, bool& anyOk) {
    // Standard ISO 14229 identification DIDs. Values that are printable ASCII
    // are shown as text, otherwise as hex.
    struct { uint16_t did; const char* label; } ids[] = {
        {0xF190, "VIN"},
        {0xF187, "Spare Part Number"},
        {0xF188, "SW Version"},
        {0xF189, "SW Version (alt)"},
        {0xF191, "HW Part Number"},
        {0xF193, "HW Version"},
        {0xF195, "SW Version Number"},
        {0xF18C, "ECU Serial Number"},
        {0xF18A, "System Supplier ID"},
        {0xF197, "System Name"},
    };
    anyOk = false;
    std::string out;
    for (auto& it : ids) {
        std::string err;
        auto data = readDataByIdentifier(target, it.did, err);
        if (!data) continue;
        anyOk = true;
        // Decide text vs hex.
        bool printable = !data->empty();
        for (uint8_t b : *data)
            if (b != 0 && (b < 0x20 || b > 0x7E)) { printable = false; break; }
        std::string val;
        if (printable) {
            for (uint8_t b : *data) if (b) val.push_back((char)b);
        } else {
            val = toHex(data->data(), data->size());
        }
        char did[8];
        std::snprintf(did, sizeof did, "%04X", it.did);
        out += std::string(it.label) + " (" + did + "): " + val + "\n";
    }
    if (!anyOk) out = "(no identification DIDs answered)";
    return out;
}

std::vector<UDSClient::IdentField>
UDSClient::sweepIdentificationDids(uint16_t target, int& answered, int timeoutMs) {
    // Well-known ISO 14229 identification DIDs in the 0xF1xx block. Unlisted
    // DIDs that still answer are reported with a generic label.
    static const std::unordered_map<uint16_t, const char*> kKnown = {
        {0xF180, "Boot Software ID"},
        {0xF181, "Application Software ID"},
        {0xF182, "Application Data ID"},
        {0xF183, "Boot Software Fingerprint"},
        {0xF184, "Application Software Fingerprint"},
        {0xF185, "Application Data Fingerprint"},
        {0xF186, "Active Diagnostic Session"},
        {0xF187, "Spare Part Number"},
        {0xF188, "ECU SW Number"},
        {0xF189, "ECU SW Version"},
        {0xF18A, "System Supplier ID"},
        {0xF18B, "ECU Manufacturing Date"},
        {0xF18C, "ECU Serial Number"},
        {0xF18D, "Supported Functional Units"},
        {0xF190, "VIN"},
        {0xF191, "HW Part Number"},
        {0xF192, "System Supplier HW Number"},
        {0xF193, "System Supplier HW Version"},
        {0xF194, "System Supplier SW Number"},
        {0xF195, "System Supplier SW Version"},
        {0xF196, "Exhaust Regulation / Type Approval"},
        {0xF197, "System Name / Engineering Name"},
        {0xF198, "Repair Shop Code / Tester Serial"},
        {0xF199, "Programming Date"},
        {0xF19D, "ECU Installation Date"},
        {0xF19E, "ODX File Identifier"},
        {0xF1A0, "Vehicle Manufacturer Spare Part Number"},
        {0xF1A1, "Vehicle Manufacturer ECU SW Number"},
    };

    answered = 0;
    std::vector<IdentField> fields;
    // Sweep the whole standard identification block. probeDID uses read-only
    // 0x22 and classifies absent DIDs quickly, so this stays responsive.
    for (uint16_t did = 0xF180; did <= 0xF1FF; ++did) {
        std::vector<uint8_t> resp;
        std::string err;
        int r = probeDID(target, did, resp, err, timeoutMs);
        if (r != 1) continue;                    // only keep positive reads (data present)
        if (resp.size() < 3) continue;           // need 0x62 <DID_hi> <DID_lo> [data]
        std::vector<uint8_t> data(resp.begin() + 3, resp.end());

        IdentField f;
        f.did = did;
        auto it = kKnown.find(did);
        if (it != kKnown.end()) f.label = it->second;
        else {
            char buf[16];
            std::snprintf(buf, sizeof buf, "DID %04X", did);
            f.label = buf;
        }
        f.printable = !data.empty();
        for (uint8_t b : data)
            if (b != 0 && (b < 0x20 || b > 0x7E)) { f.printable = false; break; }
        if (f.printable) {
            for (uint8_t b : data) if (b) f.value.push_back((char)b);
        } else {
            f.value = toHex(data.data(), data.size());
        }
        fields.push_back(std::move(f));
        ++answered;
    }

    Logger::instance().log(LogLevel::Info,
        "DID sweep 0x" + addr16(target) + ": " + std::to_string(answered) +
        " identification DID(s) answered");
    return fields;
}

bool UDSClient::readDTCByStatusMask(uint16_t target, uint8_t mask,
                                    std::vector<Dtc>& out, std::string& err) {
    std::vector<uint8_t> req = {0x19, 0x02, mask};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x59 0x02 <statusAvailabilityMask> [DTC(3) status(1)]...
    if (resp.size() < 3) { err = "DTC response too short"; return false; }
    Logger::instance().log(LogLevel::Info,
        "DTC report 0x" + addr16(target) + ": statusAvailabilityMask=0x" +
        byteHex(resp[2]) + ", " + std::to_string((resp.size() - 3) / 4) +
        " record(s)");
    for (size_t i = 3; i + 4 <= resp.size(); i += 4) {
        Dtc d;
        d.code   = ((uint32_t)resp[i] << 16) | ((uint32_t)resp[i + 1] << 8) | resp[i + 2];
        d.status = resp[i + 3];
        d.text   = decodeDtc(d.code);
        Logger::instance().log(LogLevel::Info,
            "  DTC " + byteHex(resp[i]) + byteHex(resp[i + 1]) + byteHex(resp[i + 2]) +
            " status=0x" + byteHex(d.status) + " [" + decodeDtcStatus(d.status) +
            "]  " + d.text);
        out.push_back(d);
    }
    return true;
}

bool UDSClient::readNumberOfDTCByStatusMask(uint16_t target, uint8_t mask,
                                            uint16_t& count, uint8_t& formatId,
                                            std::string& err) {
    std::vector<uint8_t> req = {0x19, 0x01, mask};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x59 0x01 <statusAvailabilityMask> <DTCFormatId> <count_hi count_lo>
    if (resp.size() < 6) { err = "Number-of-DTC response too short"; return false; }
    formatId = resp[3];
    count    = (uint16_t)((resp[4] << 8) | resp[5]);
    Logger::instance().log(LogLevel::Info,
        "DTC count 0x" + addr16(target) + ": " + std::to_string(count) +
        " (format 0x" + byteHex(formatId) + ", availMask 0x" + byteHex(resp[2]) + ")");
    return true;
}

bool UDSClient::readSupportedDTC(uint16_t target, std::vector<Dtc>& out,
                                 std::string& err) {
    std::vector<uint8_t> req = {0x19, 0x0A};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x59 0x0A <statusAvailabilityMask> [DTC(3) status(1)]...
    if (resp.size() < 3) { err = "Supported-DTC response too short"; return false; }
    Logger::instance().log(LogLevel::Info,
        "Supported DTC list 0x" + addr16(target) + ": " +
        std::to_string((resp.size() - 3) / 4) + " entries");
    for (size_t i = 3; i + 4 <= resp.size(); i += 4) {
        Dtc d;
        d.code   = ((uint32_t)resp[i] << 16) | ((uint32_t)resp[i + 1] << 8) | resp[i + 2];
        d.status = resp[i + 3];
        d.text   = decodeDtc(d.code);
        out.push_back(d);
    }
    return true;
}

bool UDSClient::readDTCSnapshot(uint16_t target, uint32_t dtc, uint8_t recordNumber,
                                std::vector<uint8_t>& raw, std::string& err) {
    std::vector<uint8_t> req = {0x19, 0x04,
                                (uint8_t)((dtc >> 16) & 0xFF),
                                (uint8_t)((dtc >> 8) & 0xFF),
                                (uint8_t)(dtc & 0xFF),
                                recordNumber};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x59 0x04 <DTC(3)> <statusOfDTC> [recordNumber DIDcount ...]
    if (resp.size() < 6) { err = "Snapshot response too short"; return false; }
    raw.assign(resp.begin() + 2, resp.end());   // everything after 0x59 0x04
    Logger::instance().log(LogLevel::Info,
        "DTC snapshot 0x" + addr16(target) + " for " +
        byteHex((dtc >> 16) & 0xFF) + byteHex((dtc >> 8) & 0xFF) + byteHex(dtc & 0xFF) +
        ": " + std::to_string(raw.size()) + " payload bytes");
    return true;
}

bool UDSClient::clearDiagnosticInformation(uint16_t target, uint32_t group,
                                           std::string& err) {
    std::vector<uint8_t> req = {0x14,
                                (uint8_t)((group >> 16) & 0xFF),
                                (uint8_t)((group >> 8) & 0xFF),
                                (uint8_t)(group & 0xFF)};
    std::vector<uint8_t> resp;
    return request(target, req, resp, err);
}

bool UDSClient::ecuReset(uint16_t target, EcuResetType type, std::string& err) {
    std::vector<uint8_t> req = {0x11, (uint8_t)type};
    std::vector<uint8_t> resp;
    // Positive: 0x51 <resetType> [powerDownTime for type 0x04]. The ECU then
    // reboots, so a follow-up TesterPresent will briefly fail - that is normal.
    if (!request(target, req, resp, err)) return false;
    Logger::instance().log(LogLevel::Info,
        "ECUReset 0x" + addr16(target) + " type 0x" + byteHex((uint8_t)type) +
        " accepted - ECU rebooting");
    return true;
}

bool UDSClient::controlDTCSetting(uint16_t target, bool on, std::string& err) {
    // Sub-function 0x01 = ON (resume DTC logging), 0x02 = OFF (suspend).
    std::vector<uint8_t> req = {0x85, (uint8_t)(on ? 0x01 : 0x02)};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    Logger::instance().log(LogLevel::Info,
        "ControlDTCSetting 0x" + addr16(target) + " -> " +
        (on ? "ON (logging resumed)" : "OFF (logging suspended)"));
    return true;
}

bool UDSClient::testerPresent(uint16_t target, std::string& err,
                              bool suppressPositiveResponse) {
    // Sub-function 0x00; bit 0x80 suppresses the positive response.
    uint8_t sub = suppressPositiveResponse ? 0x80 : 0x00;
    std::vector<uint8_t> req = {0x3E, sub};
    if (suppressPositiveResponse) {
        // Fire-and-forget keep-alive: the ECU sends nothing back.
        std::vector<uint8_t> resp;
        return doip_.sendDiagnostic(tester_, target, req, resp, 800, err) || true;
    }
    std::vector<uint8_t> resp;
    return request(target, req, resp, err);
}

bool UDSClient::probe(uint16_t target, std::string& err) {
    // A negative response (0x7F) still proves the address is reachable and
    // routable, so treat "any UDS reply" as success.
    std::vector<uint8_t> req = {0x3E, 0x00};
    std::vector<uint8_t> resp;
    if (doip_.sendDiagnostic(tester_, target, req, resp, 1500, err))
        return !resp.empty();
    return false;  // err set by DoIP layer (timeout / nack)
}

bool UDSClient::enumerateEcus(uint16_t functionalAddr, std::vector<uint16_t>& found,
                              std::string& err, int collectMs) {
    // TesterPresent without suppression: every ECU in the functional group is
    // expected to answer (positive 0x7E or a negative response - either way it
    // reveals the responder's logical address).
    std::vector<uint8_t> req = {0x3E, 0x00};
    Logger::instance().log(LogLevel::Tx,
        "UDS functional enumerate -> 0x" + addr16(functionalAddr) +
        "  TesterPresent (collecting " + std::to_string(collectMs) + "ms)");

    std::vector<doip::DiagResponse> responses;
    if (!doip_.sendDiagnosticMulti(tester_, functionalAddr, req, responses,
                                   collectMs, err))
        return false;

    found.clear();
    for (const auto& r : responses) found.push_back(r.source);
    std::sort(found.begin(), found.end());

    std::string list;
    for (uint16_t a : found) list += (list.empty() ? "" : ", ") + ("0x" + addr16(a));
    Logger::instance().log(LogLevel::Info,
        "Functional enumeration found " + std::to_string(found.size()) +
        " ECU(s): " + (list.empty() ? "(none)" : list));
    return true;
}

// -----------------------------------------------------------------------
// Safe service-discovery primitives
// -----------------------------------------------------------------------

// True when a negative-response code means "the ID is recognized but the
// request is currently not allowed" (so the identifier EXISTS). Codes that
// mean the ID is simply not implemented return false.
static bool nrcMeansExists(uint8_t nrc) {
    switch (nrc) {
        case 0x13: // incorrectMessageLengthOrInvalidFormat
        case 0x21: // busyRepeatRequest
        case 0x22: // conditionsNotCorrect
        case 0x24: // requestSequenceError
        case 0x33: // securityAccessDenied
        case 0x35: // invalidKey
        case 0x70: // uploadDownloadNotAccepted
        case 0x7E: // subFunctionNotSupportedInActiveSession
        case 0x7F: // serviceNotSupportedInActiveSession
            return true;
        case 0x11: // serviceNotSupported
        case 0x12: // subFunctionNotSupported
        case 0x31: // requestOutOfRange  -> ID not present
        default:
            return false;
    }
}

int UDSClient::rawRequest(uint16_t target, const std::vector<uint8_t>& req,
                          std::vector<uint8_t>& resp, uint8_t& nrc,
                          std::string& err, int timeoutMs) {
    nrc = 0;
    uint8_t sid = req.empty() ? 0x00 : req[0];
    Logger::instance().log(LogLevel::Tx,
        "UDS -> 0x" + addr16(target) + "  " + udsServiceName(sid) +
        " req[" + std::to_string(req.size()) + "]: " + toHex(req.data(), req.size()));
    if (!doip_.sendDiagnostic(tester_, target, req, resp, timeoutMs, err))
        return -1;
    if (resp.empty()) { err = "Empty UDS response"; return -1; }
    if (resp[0] == 0x7F) {
        nrc = resp.size() >= 3 ? resp[2] : 0x00;
        Logger::instance().log(LogLevel::Rx,
            "UDS <- 0x" + addr16(target) + "  NRC 0x" + byteHex(nrc) +
            " (" + nrcText(nrc) + ")");
        return 0;
    }
    Logger::instance().log(LogLevel::Rx,
        "UDS <- 0x" + addr16(target) + "  POSITIVE resp[" +
        std::to_string(resp.size()) + "]: " + toHex(resp.data(), resp.size()));
    return 1;
}

// Map a rawRequest outcome to existence classification (1 exists+positive,
// 0 exists+negative, -1 absent / no response).
static int classify(int raw, uint8_t nrc) {
    if (raw == 1) return 1;
    if (raw == 0) return nrcMeansExists(nrc) ? 0 : -1;
    return -1;
}

int UDSClient::probeDID(uint16_t target, uint16_t did,
                        std::vector<uint8_t>& resp, std::string& err, int timeoutMs) {
    std::vector<uint8_t> req = {0x22, (uint8_t)((did >> 8) & 0xFF), (uint8_t)(did & 0xFF)};
    uint8_t nrc = 0;
    return classify(rawRequest(target, req, resp, nrc, err, timeoutMs), nrc);
}

int UDSClient::probeRoutine(uint16_t target, uint16_t rid,
                            std::vector<uint8_t>& resp, std::string& err, int timeoutMs) {
    // 0x31 0x03 = requestRoutineResults: read-only, does NOT start a routine.
    std::vector<uint8_t> req = {0x31, 0x03,
                                (uint8_t)((rid >> 8) & 0xFF), (uint8_t)(rid & 0xFF)};
    uint8_t nrc = 0;
    return classify(rawRequest(target, req, resp, nrc, err, timeoutMs), nrc);
}

int UDSClient::probeIOControl(uint16_t target, uint16_t did,
                              std::vector<uint8_t>& resp, std::string& err, int timeoutMs) {
    // 0x2F <DID> 0x00 = returnControlToECU: restorative, never seizes control.
    std::vector<uint8_t> req = {0x2F, (uint8_t)((did >> 8) & 0xFF),
                                (uint8_t)(did & 0xFF), 0x00};
    uint8_t nrc = 0;
    return classify(rawRequest(target, req, resp, nrc, err, timeoutMs), nrc);
}

bool UDSClient::ioReturnControlToECU(uint16_t target, uint16_t did, std::string& err) {
    std::vector<uint8_t> req = {0x2F, (uint8_t)((did >> 8) & 0xFF),
                                (uint8_t)(did & 0xFF), 0x00};
    std::vector<uint8_t> resp;
    return request(target, req, resp, err);
}

// -----------------------------------------------------------------------
// Additional standard ISO 14229 services
// -----------------------------------------------------------------------
bool UDSClient::writeDataByIdentifier(uint16_t target, uint16_t did,
                                      const std::vector<uint8_t>& data,
                                      std::string& err) {
    std::vector<uint8_t> req = {0x2E, (uint8_t)((did >> 8) & 0xFF),
                                (uint8_t)(did & 0xFF)};
    req.insert(req.end(), data.begin(), data.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    Logger::instance().log(LogLevel::Info,
        "WriteDataByIdentifier 0x" + addr16(target) + " DID 0x" +
        byteHex((did >> 8) & 0xFF) + byteHex(did & 0xFF) + " <- " +
        std::to_string(data.size()) + " byte(s) accepted");
    return true;
}

bool UDSClient::readMemoryByAddress(uint16_t target, uint32_t address, uint32_t size,
                                    uint8_t addrBytes, uint8_t sizeBytes,
                                    std::vector<uint8_t>& out, std::string& err) {
    if (addrBytes < 1 || addrBytes > 4 || sizeBytes < 1 || sizeBytes > 4) {
        err = "addrBytes/sizeBytes must be 1-4"; return false;
    }
    // addressAndLengthFormatIdentifier: high nibble = size width, low = addr width.
    uint8_t alfid = (uint8_t)((sizeBytes << 4) | addrBytes);
    std::vector<uint8_t> req = {0x23, alfid};
    for (int i = addrBytes - 1; i >= 0; --i) req.push_back((uint8_t)((address >> (8 * i)) & 0xFF));
    for (int i = sizeBytes - 1; i >= 0; --i) req.push_back((uint8_t)((size >> (8 * i)) & 0xFF));
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x63 <data...>
    out.assign(resp.begin() + 1, resp.end());
    Logger::instance().log(LogLevel::Info,
        "ReadMemoryByAddress 0x" + addr16(target) + ": " +
        std::to_string(out.size()) + " byte(s) returned");
    return true;
}

bool UDSClient::routineControl(uint16_t target, RoutineCtrl sub, uint16_t routineId,
                               const std::vector<uint8_t>& params,
                               std::vector<uint8_t>& out, std::string& err) {
    std::vector<uint8_t> req = {0x31, (uint8_t)sub,
                                (uint8_t)((routineId >> 8) & 0xFF),
                                (uint8_t)(routineId & 0xFF)};
    req.insert(req.end(), params.begin(), params.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x71 <sub> <RID hi lo> [routineStatusRecord...]
    if (resp.size() > 4) out.assign(resp.begin() + 4, resp.end());
    else out.clear();
    const char* s = sub == RoutineCtrl::Start ? "start" :
                    sub == RoutineCtrl::Stop ? "stop" : "results";
    Logger::instance().log(LogLevel::Info,
        "RoutineControl 0x" + addr16(target) + " " + s + " RID 0x" +
        byteHex((routineId >> 8) & 0xFF) + byteHex(routineId & 0xFF) +
        " accepted (" + std::to_string(out.size()) + " status byte(s))");
    return true;
}

bool UDSClient::communicationControl(uint16_t target, CommCtrl control,
                                     uint8_t commType, std::string& err) {
    std::vector<uint8_t> req = {0x28, (uint8_t)control, commType};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    Logger::instance().log(LogLevel::Info,
        "CommunicationControl 0x" + addr16(target) + " control 0x" +
        byteHex((uint8_t)control) + " commType 0x" + byteHex(commType) + " accepted");
    return true;
}

bool UDSClient::readDataByPeriodicIdentifier(uint16_t target, PeriodicMode mode,
                                             const std::vector<uint8_t>& pdids,
                                             std::string& err) {
    if (mode != PeriodicMode::StopSending && pdids.empty()) {
        err = "ReadDataByPeriodicIdentifier needs at least one PDID"; return false;
    }
    // Request: 0x2A <transmissionMode> <periodicDataIdentifier...>
    std::vector<uint8_t> req = {0x2A, (uint8_t)mode};
    req.insert(req.end(), pdids.begin(), pdids.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x6A (scheduling acknowledged; recurring data pushed separately).
    Logger::instance().log(LogLevel::Info,
        "ReadDataByPeriodicIdentifier 0x" + addr16(target) + " mode 0x" +
        byteHex((uint8_t)mode) + " (" + std::to_string(pdids.size()) +
        " PDID) scheduled");
    return true;
}

bool UDSClient::defineDynamicDataIdentifier(uint16_t target, uint16_t dddid,
                                            const std::vector<DddSource>& sources,
                                            std::string& err) {
    if (sources.empty()) { err = "defineDynamicDataIdentifier needs >=1 source"; return false; }
    // Request: 0x2C 0x01 <DDDID_hi DDDID_lo>
    //          [ sourceDID_hi sourceDID_lo position size ]...
    std::vector<uint8_t> req = {0x2C, 0x01,
                                (uint8_t)((dddid >> 8) & 0xFF), (uint8_t)(dddid & 0xFF)};
    for (const auto& s : sources) {
        if (s.position < 1 || s.size < 1) { err = "DddSource position/size must be >=1"; return false; }
        req.push_back((uint8_t)((s.sourceDid >> 8) & 0xFF));
        req.push_back((uint8_t)(s.sourceDid & 0xFF));
        req.push_back(s.position);
        req.push_back(s.size);
    }
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x6C 0x01 <DDDID_hi DDDID_lo>
    Logger::instance().log(LogLevel::Info,
        "DynamicallyDefineDataIdentifier 0x" + addr16(target) + " DDDID 0x" +
        addr16(dddid) + " defined from " + std::to_string(sources.size()) + " source(s)");
    return true;
}

bool UDSClient::clearDynamicDataIdentifier(uint16_t target, uint16_t dddid,
                                           std::string& err) {
    // Request: 0x2C 0x03 [DDDID_hi DDDID_lo]. Omitting the DID clears all.
    std::vector<uint8_t> req = {0x2C, 0x03};
    if (dddid != 0x0000) {
        req.push_back((uint8_t)((dddid >> 8) & 0xFF));
        req.push_back((uint8_t)(dddid & 0xFF));
    }
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    Logger::instance().log(LogLevel::Info,
        "DynamicallyDefineDataIdentifier 0x" + addr16(target) + " cleared " +
        (dddid == 0x0000 ? std::string("ALL dynamic DIDs") : "DDDID 0x" + addr16(dddid)));
    return true;
}

bool UDSClient::requestDownload(uint16_t target, uint32_t memoryAddress, uint32_t size,
                                uint8_t addrBytes, uint8_t sizeBytes, uint8_t dataFormatId,
                                uint32_t& maxBlockLength, std::string& err) {
    if (addrBytes < 1 || addrBytes > 4 || sizeBytes < 1 || sizeBytes > 4) {
        err = "addrBytes/sizeBytes must be 1-4"; return false;
    }
    // addressAndLengthFormatIdentifier: high nibble = size width, low = addr width.
    uint8_t alfid = (uint8_t)((sizeBytes << 4) | addrBytes);
    std::vector<uint8_t> req = {0x34, dataFormatId, alfid};
    for (int i = addrBytes - 1; i >= 0; --i) req.push_back((uint8_t)((memoryAddress >> (8 * i)) & 0xFF));
    for (int i = sizeBytes - 1; i >= 0; --i) req.push_back((uint8_t)((size >> (8 * i)) & 0xFF));
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x74 <lengthFormatIdentifier> <maxNumberOfBlockLength...>
    // The high nibble of the LFID gives the byte-width of maxNumberOfBlockLength.
    if (resp.size() < 3) { err = "RequestDownload response too short"; return false; }
    uint8_t lenWidth = (resp[1] >> 4) & 0x0F;
    if (lenWidth < 1 || lenWidth > 4 || resp.size() < (size_t)(2 + lenWidth)) {
        err = "RequestDownload maxBlockLength width invalid"; return false;
    }
    uint32_t mbl = 0;
    for (uint8_t i = 0; i < lenWidth; ++i) mbl = (mbl << 8) | resp[2 + i];
    maxBlockLength = mbl;
    Logger::instance().log(LogLevel::Info,
        "RequestDownload 0x" + addr16(target) + ": " + std::to_string(size) +
        " byte(s) accepted, maxBlockLength=" + std::to_string(mbl));
    return true;
}

bool UDSClient::transferData(uint16_t target, uint8_t blockSequenceCounter,
                             const std::vector<uint8_t>& data, std::string& err) {
    std::vector<uint8_t> req = {0x36, blockSequenceCounter};
    req.insert(req.end(), data.begin(), data.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x76 <blockSequenceCounter> [transferResponseParameterRecord]
    if (resp.size() >= 2 && resp[1] != blockSequenceCounter) {
        err = "TransferData block-counter mismatch (sent 0x" +
              byteHex(blockSequenceCounter) + ", echoed 0x" + byteHex(resp[1]) + ")";
        return false;
    }
    Logger::instance().log(LogLevel::Info,
        "TransferData 0x" + addr16(target) + " block 0x" + byteHex(blockSequenceCounter) +
        " (" + std::to_string(data.size()) + " byte(s)) accepted");
    return true;
}

bool UDSClient::requestTransferExit(uint16_t target, const std::vector<uint8_t>& params,
                                    std::vector<uint8_t>& out, std::string& err) {
    std::vector<uint8_t> req = {0x37};
    req.insert(req.end(), params.begin(), params.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x77 [transferResponseParameterRecord...]
    out.assign(resp.begin() + 1, resp.end());
    Logger::instance().log(LogLevel::Info,
        "RequestTransferExit 0x" + addr16(target) + " accepted (" +
        std::to_string(out.size()) + " response byte(s))");
    return true;
}

bool UDSClient::downloadBlock(uint16_t target, uint32_t memoryAddress,
                              const std::vector<uint8_t>& image,
                              uint8_t addrBytes, uint8_t sizeBytes, uint8_t dataFormatId,
                              const std::function<void(size_t, size_t)>& progress,
                              std::string& err) {
    if (image.empty()) { err = "Download image is empty"; return false; }

    uint32_t maxBlockLength = 0;
    if (!requestDownload(target, memoryAddress, (uint32_t)image.size(),
                         addrBytes, sizeBytes, dataFormatId, maxBlockLength, err))
        return false;

    // maxNumberOfBlockLength includes the 0x36 SID + block-sequence-counter, so
    // the usable payload per TransferData block is two bytes less.
    if (maxBlockLength <= 2) {
        err = "ECU-reported maxBlockLength too small (" +
              std::to_string(maxBlockLength) + ")";
        return false;
    }
    size_t chunk = (size_t)(maxBlockLength - 2);

    size_t offset = 0;
    uint8_t bsc = 0x01;   // block sequence counter starts at 1
    while (offset < image.size()) {
        size_t n = (std::min)(chunk, image.size() - offset);
        std::vector<uint8_t> block(image.begin() + offset, image.begin() + offset + n);
        if (!transferData(target, bsc, block, err)) return false;
        offset += n;
        bsc = (uint8_t)(bsc + 1);   // wraps 0xFF -> 0x00 per ISO 14229
        if (progress) progress(offset, image.size());
    }

    std::vector<uint8_t> exitResp;
    if (!requestTransferExit(target, {}, exitResp, err)) return false;
    Logger::instance().log(LogLevel::Info,
        "Block download to 0x" + addr16(target) + " complete: " +
        std::to_string(image.size()) + " byte(s) in " +
        std::to_string((image.size() + chunk - 1) / chunk) + " block(s)");
    return true;
}

bool UDSClient::readDTCExtendedData(uint16_t target, uint32_t dtc,
                                    uint8_t recordNumber,
                                    std::vector<uint8_t>& raw, std::string& err) {
    std::vector<uint8_t> req = {0x19, 0x06,
                                (uint8_t)((dtc >> 16) & 0xFF),
                                (uint8_t)((dtc >> 8) & 0xFF),
                                (uint8_t)(dtc & 0xFF),
                                recordNumber};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x59 0x06 <DTC(3)> <statusOfDTC> [recordNumber data ...]
    if (resp.size() < 6) { err = "Extended-data response too short"; return false; }
    raw.assign(resp.begin() + 2, resp.end());
    Logger::instance().log(LogLevel::Info,
        "DTC extended data 0x" + addr16(target) + " for " +
        byteHex((dtc >> 16) & 0xFF) + byteHex((dtc >> 8) & 0xFF) + byteHex(dtc & 0xFF) +
        ": " + std::to_string(raw.size()) + " payload bytes");
    return true;
}

bool UDSClient::readDTCFaultDetectionCounter(uint16_t target,
                                             std::vector<Dtc>& out, std::string& err) {
    std::vector<uint8_t> req = {0x19, 0x14};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x59 0x14 [DTC(3) faultDetectionCounter(1)]...
    if (resp.size() < 2) { err = "Fault-detection-counter response too short"; return false; }
    for (size_t i = 2; i + 4 <= resp.size(); i += 4) {
        Dtc d;
        d.code   = ((uint32_t)resp[i] << 16) | ((uint32_t)resp[i + 1] << 8) | resp[i + 2];
        d.status = resp[i + 3];   // here the 4th byte is the fault-detection counter
        d.text   = decodeDtc(d.code);
        Logger::instance().log(LogLevel::Info,
            "  DTC " + d.text + " faultDetectionCounter=" + std::to_string((int8_t)d.status));
        out.push_back(d);
    }
    return true;
}

bool UDSClient::obdRequest(uint16_t target, const std::vector<uint8_t>& modePid,
                           std::vector<uint8_t>& out, std::string& err) {
    uint8_t nrc = 0;
    std::vector<uint8_t> resp;
    int r = rawRequest(target, modePid, resp, nrc, err);
    if (r < 0) return false;
    if (r == 0) { err = "OBD negative response (NRC 0x" + byteHex(nrc) + ")"; return false; }
    // Positive OBD reply echoes (mode + 0x40); strip it (and the echoed PID is
    // left in place for the caller to interpret).
    out.assign(resp.begin() + 1, resp.end());
    Logger::instance().log(LogLevel::Info,
        "OBD-II 0x" + addr16(target) + " mode 0x" +
        byteHex(modePid.empty() ? 0 : modePid[0]) + ": " +
        std::to_string(out.size()) + " byte(s)");
    return true;
}

bool UDSClient::inputOutputControl(uint16_t target, uint16_t did,
                                   IoControlOption option,
                                   const std::vector<uint8_t>& controlState,
                                   const std::vector<uint8_t>& controlEnableMask,
                                   std::vector<uint8_t>& out, std::string& err) {
    // Request: 0x2F <DID hi lo> <controlOptionRecord> [controlEnableMaskRecord]
    // The controlOptionRecord is the option byte followed (for short-term
    // adjustment) by the desired control state bytes.
    std::vector<uint8_t> req = {0x2F, (uint8_t)((did >> 8) & 0xFF),
                                (uint8_t)(did & 0xFF), (uint8_t)option};
    if (option == IoControlOption::ShortTermAdjustment)
        req.insert(req.end(), controlState.begin(), controlState.end());
    req.insert(req.end(), controlEnableMask.begin(), controlEnableMask.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x6F <DID hi lo> <controlStatusRecord...>
    if (resp.size() > 3) out.assign(resp.begin() + 3, resp.end());
    else out.clear();
    static const char* kOpt[] = {"returnControl", "resetToDefault",
                                 "freezeState", "shortTermAdjust"};
    Logger::instance().log(LogLevel::Info,
        "InputOutputControl 0x" + addr16(target) + " DID 0x" + addr16(did) + " " +
        kOpt[(uint8_t)option & 0x03] + " accepted (" +
        std::to_string(out.size()) + " status byte(s))");
    return true;
}

bool UDSClient::readScalingDataByIdentifier(uint16_t target, uint16_t did,
                                            std::vector<uint8_t>& out, std::string& err) {
    std::vector<uint8_t> req = {0x24, (uint8_t)((did >> 8) & 0xFF),
                                (uint8_t)(did & 0xFF)};
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x64 <DID hi lo> <scalingByte + scalingByteExtension...>
    if (resp.size() < 3) { err = "ReadScalingData response too short"; return false; }
    out.assign(resp.begin() + 3, resp.end());
    Logger::instance().log(LogLevel::Info,
        "ReadScalingDataByIdentifier 0x" + addr16(target) + " DID 0x" + addr16(did) +
        ": " + std::to_string(out.size()) + " scaling byte(s)");
    return true;
}

bool UDSClient::writeMemoryByAddress(uint16_t target, uint32_t address,
                                     const std::vector<uint8_t>& data,
                                     uint8_t addrBytes, uint8_t sizeBytes,
                                     std::string& err) {
    if (addrBytes < 1 || addrBytes > 4 || sizeBytes < 1 || sizeBytes > 4) {
        err = "addrBytes/sizeBytes must be 1-4"; return false;
    }
    if (data.empty()) { err = "WriteMemoryByAddress needs data"; return false; }
    uint32_t size = (uint32_t)data.size();
    uint8_t alfid = (uint8_t)((sizeBytes << 4) | addrBytes);
    std::vector<uint8_t> req = {0x3D, alfid};
    for (int i = addrBytes - 1; i >= 0; --i) req.push_back((uint8_t)((address >> (8 * i)) & 0xFF));
    for (int i = sizeBytes - 1; i >= 0; --i) req.push_back((uint8_t)((size >> (8 * i)) & 0xFF));
    req.insert(req.end(), data.begin(), data.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    Logger::instance().log(LogLevel::Info,
        "WriteMemoryByAddress 0x" + addr16(target) + " <- " +
        std::to_string(data.size()) + " byte(s) accepted");
    return true;
}

bool UDSClient::requestUpload(uint16_t target, uint32_t memoryAddress, uint32_t size,
                              uint8_t addrBytes, uint8_t sizeBytes, uint8_t dataFormatId,
                              uint32_t& maxBlockLength, std::string& err) {
    if (addrBytes < 1 || addrBytes > 4 || sizeBytes < 1 || sizeBytes > 4) {
        err = "addrBytes/sizeBytes must be 1-4"; return false;
    }
    uint8_t alfid = (uint8_t)((sizeBytes << 4) | addrBytes);
    std::vector<uint8_t> req = {0x35, dataFormatId, alfid};
    for (int i = addrBytes - 1; i >= 0; --i) req.push_back((uint8_t)((memoryAddress >> (8 * i)) & 0xFF));
    for (int i = sizeBytes - 1; i >= 0; --i) req.push_back((uint8_t)((size >> (8 * i)) & 0xFF));
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x75 <lengthFormatIdentifier> <maxNumberOfBlockLength...>
    if (resp.size() < 3) { err = "RequestUpload response too short"; return false; }
    uint8_t lenWidth = (resp[1] >> 4) & 0x0F;
    if (lenWidth < 1 || lenWidth > 4 || resp.size() < (size_t)(2 + lenWidth)) {
        err = "RequestUpload maxBlockLength width invalid"; return false;
    }
    uint32_t mbl = 0;
    for (uint8_t i = 0; i < lenWidth; ++i) mbl = (mbl << 8) | resp[2 + i];
    maxBlockLength = mbl;
    Logger::instance().log(LogLevel::Info,
        "RequestUpload 0x" + addr16(target) + ": " + std::to_string(size) +
        " byte(s) accepted, maxBlockLength=" + std::to_string(mbl));
    return true;
}

bool UDSClient::uploadBlock(uint16_t target, uint32_t memoryAddress, uint32_t size,
                            uint8_t addrBytes, uint8_t sizeBytes, uint8_t dataFormatId,
                            std::vector<uint8_t>& image,
                            const std::function<void(size_t, size_t)>& progress,
                            std::string& err) {
    if (size == 0) { err = "Upload size is zero"; return false; }
    uint32_t maxBlockLength = 0;
    if (!requestUpload(target, memoryAddress, size, addrBytes, sizeBytes,
                       dataFormatId, maxBlockLength, err))
        return false;

    // For an upload the ECU pushes data in its TransferData (0x36) responses;
    // the tester requests each block with an incrementing sequence counter.
    image.clear();
    image.reserve(size);
    uint8_t bsc = 0x01;
    while (image.size() < size) {
        std::vector<uint8_t> req = {0x36, bsc};
        std::vector<uint8_t> resp;
        if (!request(target, req, resp, err)) return false;
        if (resp.size() < 2 || resp[1] != bsc) {
            err = "TransferData (upload) block-counter mismatch"; return false;
        }
        image.insert(image.end(), resp.begin() + 2, resp.end());
        bsc = (uint8_t)(bsc + 1);
        if (progress) progress(image.size(), size);
        if (resp.size() <= 2) break;   // ECU returned no payload -> stop
    }

    std::vector<uint8_t> exitResp;
    if (!requestTransferExit(target, {}, exitResp, err)) return false;
    Logger::instance().log(LogLevel::Info,
        "Block upload from 0x" + addr16(target) + " complete: " +
        std::to_string(image.size()) + " byte(s) received");
    return true;
}

bool UDSClient::linkControl(uint16_t target, LinkControlType sub,
                            const std::vector<uint8_t>& param, std::string& err) {
    std::vector<uint8_t> req = {0x87, (uint8_t)sub};
    if (sub != LinkControlType::TransitionMode)
        req.insert(req.end(), param.begin(), param.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    Logger::instance().log(LogLevel::Info,
        "LinkControl 0x" + addr16(target) + " sub 0x" + byteHex((uint8_t)sub) + " accepted");
    return true;
}

bool UDSClient::accessTimingParameter(uint16_t target, TimingParamAccess sub,
                                      const std::vector<uint8_t>& request_,
                                      std::vector<uint8_t>& out, std::string& err) {
    std::vector<uint8_t> req = {0x83, (uint8_t)sub};
    if (sub == TimingParamAccess::SetToGivenValues)
        req.insert(req.end(), request_.begin(), request_.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0xC3 <sub> [timingParameterResponseRecord...]
    if (resp.size() > 2) out.assign(resp.begin() + 2, resp.end());
    else out.clear();
    Logger::instance().log(LogLevel::Info,
        "AccessTimingParameter 0x" + addr16(target) + " sub 0x" + byteHex((uint8_t)sub) +
        " accepted (" + std::to_string(out.size()) + " byte(s))");
    return true;
}

bool UDSClient::authentication(uint16_t target, uint8_t subFunction,
                               const std::vector<uint8_t>& data,
                               std::vector<uint8_t>& out, std::string& err) {
    std::vector<uint8_t> req = {0x29, subFunction};
    req.insert(req.end(), data.begin(), data.end());
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    // Positive: 0x69 <sub> <authReturnParameter> [data...]
    if (resp.size() > 2) out.assign(resp.begin() + 2, resp.end());
    else out.clear();
    Logger::instance().log(LogLevel::Info,
        "Authentication 0x" + addr16(target) + " sub 0x" + byteHex(subFunction) +
        " accepted (" + std::to_string(out.size()) + " byte(s))");
    return true;
}

bool UDSClient::requestFileTransfer(uint16_t target, FileTransferMode mode,
                                    const std::string& filePath, uint8_t dataFormatId,
                                    uint64_t fileSizeUncompressed,
                                    uint64_t fileSizeCompressed,
                                    std::vector<uint8_t>& out, std::string& err) {
    // Request: 0x38 <modeOfOperation> <filePathLen(2)> <filePath...>
    //          [dataFormatId] [fileSizeParamLen] [uncompressed][compressed]
    std::vector<uint8_t> req = {0x38, (uint8_t)mode};
    uint16_t pathLen = (uint16_t)filePath.size();
    req.push_back((uint8_t)((pathLen >> 8) & 0xFF));
    req.push_back((uint8_t)(pathLen & 0xFF));
    req.insert(req.end(), filePath.begin(), filePath.end());

    const bool needsSize = (mode == FileTransferMode::AddFile ||
                            mode == FileTransferMode::ReplaceFile ||
                            mode == FileTransferMode::ResumeFile);
    if (mode != FileTransferMode::DeleteFile && mode != FileTransferMode::ReadDir)
        req.push_back(dataFormatId);
    if (needsSize) {
        // Pick the minimum width that holds the larger of the two sizes.
        uint64_t big = (std::max)(fileSizeUncompressed, fileSizeCompressed);
        uint8_t width = 1;
        while (width < 8 && (big >> (8 * width)) != 0) ++width;
        req.push_back(width);
        for (int i = width - 1; i >= 0; --i) req.push_back((uint8_t)((fileSizeUncompressed >> (8 * i)) & 0xFF));
        for (int i = width - 1; i >= 0; --i) req.push_back((uint8_t)((fileSizeCompressed   >> (8 * i)) & 0xFF));
    }
    std::vector<uint8_t> resp;
    if (!request(target, req, resp, err)) return false;
    out.assign(resp.begin() + 1, resp.end());
    Logger::instance().log(LogLevel::Info,
        "RequestFileTransfer 0x" + addr16(target) + " mode 0x" + byteHex((uint8_t)mode) +
        " '" + filePath + "' accepted (" + std::to_string(out.size()) + " byte(s))");
    return true;
}

void UDSClient::restoreSafeState(uint16_t target,

                                 const std::vector<uint16_t>& touchedIoDids,
                                 std::string& summary) {
    Logger::instance().log(LogLevel::Info,
        "Restoring safe state on 0x" + addr16(target) + " ...");
    std::string e;
    int returned = 0;
    for (uint16_t did : touchedIoDids) {
        if (ioReturnControlToECU(target, did, e)) ++returned;
    }
    // Re-enable DTC logging (in case discovery suspended it).
    bool dtcOn = controlDTCSetting(target, true, e);
    // Drop back to the default session so no extended state lingers.
    bool sess = diagnosticSessionControl(target, UdsSession::Default, e);
    // A final TesterPresent confirms the link is still alive.
    std::string te;
    testerPresent(target, te, /*suppress=*/false);

    summary = "Returned control of " + std::to_string(returned) + "/" +
              std::to_string(touchedIoDids.size()) + " I/O DID(s); DTC logging " +
              (dtcOn ? "ON" : "(unchanged)") + "; session " +
              (sess ? "Default" : "(unchanged)");
    Logger::instance().log(LogLevel::Info, "Safe-state restore: " + summary);
}

// -----------------------------------------------------------------------
// Decoding helpers
// -----------------------------------------------------------------------
std::string decodeDtc(uint32_t code) {
    // 3-byte UDS DTC. The high two bits of byte0 select the letter group,
    // remaining bits give the 4 hex digits; byte2 is the failure-type byte.
    static const char letters[4] = {'P', 'C', 'B', 'U'};
    uint8_t b0 = (code >> 16) & 0xFF;
    uint8_t b1 = (code >> 8) & 0xFF;
    uint8_t b2 = code & 0xFF;
    char letter = letters[(b0 >> 6) & 0x03];
    int  d1 = (b0 >> 4) & 0x03;
    int  d2 = b0 & 0x0F;
    char buf[16];
    std::snprintf(buf, sizeof buf, "%c%01X%01X%02X-%02X", letter, d1, d2, b1, b2);
    return buf;
}

std::string decodeDtcStatus(uint8_t s) {
    // ISO 14229-1 status-of-DTC bit definitions.
    struct { uint8_t bit; const char* name; } bits[] = {
        {0x01, "testFailed"},
        {0x02, "testFailedThisCycle"},
        {0x04, "pendingDTC"},
        {0x08, "confirmedDTC"},
        {0x10, "testNotCompletedSinceClear"},
        {0x20, "testFailedSinceClear"},
        {0x40, "testNotCompletedThisCycle"},
        {0x80, "warningIndicatorRequested"},
    };
    std::string out;
    for (auto& b : bits) {
        if (s & b.bit) { if (!out.empty()) out += ", "; out += b.name; }
    }
    if (out.empty()) out = "none";
    return "0x" + byteHex(s) + " (" + out + ")";
}

std::string dtcDescription(uint32_t code) {
    // Prefer VinFast VF8 data: explicit Autel text, else a standardized
    // SAE J2012 base description combined with the ISO 14229 failure-type byte.
    std::string key = decodeDtc(code);
    key.erase(std::remove(key.begin(), key.end(), '-'), key.end());
    return vf8DtcDescribe(key);
}

std::string nrcText(uint8_t nrc) {
    switch (nrc) {
        case 0x10: return "generalReject";
        case 0x11: return "serviceNotSupported";
        case 0x12: return "subFunctionNotSupported";
        case 0x13: return "incorrectMessageLengthOrInvalidFormat";
        case 0x14: return "responseTooLong";
        case 0x21: return "busyRepeatRequest";
        case 0x22: return "conditionsNotCorrect";
        case 0x24: return "requestSequenceError";
        case 0x31: return "requestOutOfRange";
        case 0x33: return "securityAccessDenied";
        case 0x35: return "invalidKey";
        case 0x70: return "uploadDownloadNotAccepted";
        case 0x78: return "requestCorrectlyReceived-ResponsePending";
        case 0x7E: return "subFunctionNotSupportedInActiveSession";
        case 0x7F: return "serviceNotSupportedInActiveSession";
        default:   return "unknown";
    }
}
