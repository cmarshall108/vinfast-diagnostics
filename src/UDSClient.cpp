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
