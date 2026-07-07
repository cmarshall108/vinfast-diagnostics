//
// OpenXcTransport.cpp - OpenXC USB/Bluetooth primary transport with optional CAN backup.
//
// Primary OpenXC transport implementation.  All diagnostic traffic is routed through
// an OpenXC Vehicle Interface over serial; the optional CAN (J2534) client is
// used only as a fallback when the OpenXC link is unavailable or a request
// fails.
//
#include "OpenXcTransport.hpp"
#include "Logger.hpp"

extern "C" {
#include <uds/uds.h>  // OBD2_FUNCTIONAL_BROADCAST_ID
}

#include <algorithm>
#include <chrono>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <thread>

namespace openxc {

namespace {

static std::string bytesToHex(const std::vector<uint8_t>& b) {
    if (b.empty()) return "";
    std::ostringstream ss;
    for (uint8_t byte : b)
        ss << std::hex << std::uppercase
           << std::setfill('0') << std::setw(2)
           << static_cast<int>(byte);
    return ss.str();
}

static std::string byteHex(uint8_t b) {
    std::ostringstream ss;
    ss << std::hex << std::uppercase
       << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

static std::string trimCopy(const std::string& s) {
    size_t begin = 0;
    while (begin < s.size() && std::isspace(static_cast<unsigned char>(s[begin]))) ++begin;
    size_t end = s.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1]))) --end;
    return s.substr(begin, end - begin);
}

static std::string lowerCopy(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) out.push_back(static_cast<char>(std::tolower(c)));
    return out;
}

static bool isAutoDeviceToken(const std::string& s) {
    std::string t = lowerCopy(trimCopy(s));
    return t.empty() || t == "auto" || t == "usb" || t == "openxc";
}

static bool looksLikeSerialPath(const std::string& s) {
    std::string t = trimCopy(s);
    std::string low = lowerCopy(t);
    if (low.rfind("/dev/", 0) == 0) return true;
    if (low.rfind("com", 0) == 0 && low.size() > 3) return true;
    if (low.rfind("\\\\.\\com", 0) == 0) return true;
    return false;
}

static void addUnique(std::vector<std::string>& list, const std::string& item) {
    std::string trimmed = trimCopy(item);
    if (trimmed.empty()) return;
    if (std::find(list.begin(), list.end(), trimmed) == list.end())
        list.push_back(std::move(trimmed));
}

} // namespace

Transport::Transport()  = default;
Transport::~Transport() { disconnect(); }

bool Transport::connect(const std::string& deviceOrMac, std::string& err) {
    disconnect();

    const std::string requested = trimCopy(deviceOrMac);
    const bool autoRequested = isAutoDeviceToken(requested);
    const bool explicitSerial = looksLikeSerialPath(requested);

    std::vector<std::string> candidates;
    if (explicitSerial) addUnique(candidates, requested);
    if (!explicitSerial) {
        for (const auto& path : openxc::Client::enumerateUsbSerialPorts())
            addUnique(candidates, path);
    }
    if (!autoRequested && !explicitSerial)
        addUnique(candidates, requested);

    if (candidates.empty()) {
        err = autoRequested
            ? "No OpenXC USB serial ports found; enter a serial path or Bluetooth MAC"
            : "No OpenXC device specified";
        connected_ = false;
        return false;
    }

    std::string allErr;
    for (const auto& candidate : candidates) {
        std::string tryErr;
        Logger::instance().info("Trying OpenXC device: " + candidate);

        if (!openxcClient_.connect(candidate, tryErr)) {
            allErr += (allErr.empty() ? "" : " | ") + candidate + ": " + tryErr;
            openxcClient_.disconnect();
            continue;
        }

        if (!initializeLink(tryErr)) {
            allErr += (allErr.empty() ? "" : " | ") + candidate + ": " + tryErr;
            openxcClient_.disconnect();
            continue;
        }

        connected_ = true;
        const std::string& path = openxcClient_.connectedPath();
        Logger::instance().info("OpenXC transport connected: " +
                                (path.empty() ? candidate : path));
        return true;
    }

    if (!autoRequested && explicitSerial) {
        // A typed serial path should stay exact; users can enter "auto" to scan all USB ports.
        openxcClient_.disconnect();
    }

    connected_ = false;
    err = allErr.empty() ? "No OpenXC device responded" : allErr;
    return false;
}

void Transport::disconnect() {
    openxcClient_.disconnect();
    connected_ = false;
}

bool Transport::isConnected() const {
    return connected_ && openxcClient_.isConnected();
}

// ---------------------------------------------------------------------------
// OpenXC VI bus initialization
//
// The 2024 VF8 (and many other vehicles) will not answer diagnostic requests
// until the VI is configured correctly.  The sequence below:
//   1) reads the firmware version (proves the serial link is alive),
//   2) disables the predefined OBD-II request set so it does not collide with
//      our UDS traffic,
//   3) bypasses the acceptance filter on the selected bus so the VI forwards
//      every frame, including non-standard IDs the VF8 gateway may use.
// ---------------------------------------------------------------------------
bool Transport::initializeLink(std::string& err) {
    std::string line;
    bool gotVersion = false;

    // 1) Link handshake. The Bluetooth RFCOMM data channel and the VI's command
    //    parser may need a moment after the port opens, so retry a few times
    //    before giving up.
    bool linked = false;
    std::string lastErr;
    for (int attempt = 0; attempt < 3 && !linked; ++attempt) {
        if (openxcClient_.sendCommand(R"({"command":"platform"})", line, 1000, err)) {
            linked = true;
            break;
        }
        lastErr = "platform query failed: " + err;
        if (openxcClient_.sendCommand(R"({"command":"version"})", line, 1000, err)) {
            linked = true;
            gotVersion = true;
            break;
        }
        lastErr += "; version query failed: " + err;
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
    if (!linked) {
        err = "OpenXC link check failed: " + lastErr;
        return false;
    }
    Logger::instance().info("OpenXC VI: " + line);

    if (!gotVersion && openxcClient_.sendCommand(R"({"command":"version"})", line, 500, err)) {
        Logger::instance().info("OpenXC VI: " + line);
    } else if (!gotVersion) {
        Logger::instance().warn("OpenXC version query skipped: " + err);
        err.clear();
    }

    // 2) Disable predefined OBD-II requests to free the bus for UDS.
    {
        std::string cmd = R"({"command":"predefined_obd2","enabled":false})";
        if (!openxcClient_.sendCommand(cmd, line, 1000, err)) {
            Logger::instance().warn("OpenXC predefined_obd2 disable failed: " + err);
            // Non-fatal: older firmware may not implement this command.
            err.clear();
        } else {
            Logger::instance().info("OpenXC predefined OBD-II disabled");
        }
    }

    // 3) Bypass acceptance filters on the selected bus.
    {
        std::ostringstream cmd;
        cmd << R"({"command":"af_bypass","bus":)" << bus_ << R"(,"bypass":true})";
        if (!openxcClient_.sendCommand(cmd.str(), line, 1000, err)) {
            Logger::instance().warn("OpenXC af_bypass failed: " + err);
            // Non-fatal: older firmware may not implement this command.
            err.clear();
        } else {
            Logger::instance().info("OpenXC acceptance filter bypass enabled on bus " +
                                    std::to_string(bus_));
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// CAN arbitration ID mapping
//
// UDS logical addresses (16-bit, e.g. 0x1001) are not CAN IDs.  Most OEM
// gateways map the low byte of the logical address to a physical CAN ID.
// The default base 0x700 with +8 response offset yields the standard pairs:
//   0x00E0 -> 0x7E0 / 0x7E8 (primary ECU / gateway)
//   0x0001 -> 0x701 / 0x709
// Functional broadcasts always use 0x7DF.
// ---------------------------------------------------------------------------
uint32_t Transport::mapLogicalToCanId(uint16_t logicalAddr, bool functional) const {
    if (functional)
        return static_cast<uint32_t>(OBD2_FUNCTIONAL_BROADCAST_ID);
    uint32_t id = canIdBase_ + (logicalAddr & 0xFFu);
    if (id > 0x7FFu) id = 0x7FFu;
    return id;
}

uint32_t Transport::responseIdForRequest(uint32_t requestId, bool functional) const {
    if (functional) return 0u;
    uint32_t id = requestId + canRespOffset_;
    return id <= 0x7FFu ? id : 0u;
}

uint16_t Transport::mapCanResponseToLogical(uint32_t responseId) const {
    if (responseId < canIdBase_ + canRespOffset_) return static_cast<uint16_t>(responseId & 0x7FFu);
    uint32_t low = responseId - canIdBase_ - canRespOffset_;
    return static_cast<uint16_t>(low & 0xFFu);
}

bool Transport::retargetCanBackup(uint16_t target, bool functional, std::string& err) {
    if (!canBackup_ || !canBackup_->isConnected()) {
        err = "CAN backup not connected";
        return false;
    }

    uint32_t reqId = mapLogicalToCanId(target, functional);
    uint32_t respId = responseIdForRequest(reqId, functional);
    if (functional) {
        // Functional UDS requests use the broadcast request ID. Use the common
        // physical gateway response as the flow-control anchor so the VCI has a
        // concrete ISO-TP response ID while waiting for the first answer.
        respId = (canIdBase_ + 0xE0u + canRespOffset_) & 0x7FFu;
    }
    if (respId == 0u || respId > 0x7FFu) {
        err = "Invalid CAN response ID for target";
        return false;
    }

    canBackup_->setAddressing(reqId, respId, err);
    return err.empty();
}

// ---------------------------------------------------------------------------
// Diagnostic send (public, with optional CAN fallback)
// ---------------------------------------------------------------------------
bool Transport::sendDiagnostic(uint16_t source, uint16_t target,
                               const std::vector<uint8_t>& uds,
                               std::vector<uint8_t>& response, int timeoutMs,
                               std::string& err, bool functional) {
    lastUsedCanBackup_ = false;

    if (sendDiagnosticOpenXc(source, target, uds, response, timeoutMs, err, functional))
        return true;

    if (canBackup_ && canBackup_->isConnected()) {
        std::string canErr;
        if (!retargetCanBackup(target, functional, canErr)) {
            err += (err.empty() ? "" : " | ");
            err += "CAN backup retarget failed: " + canErr;
            return false;
        }
        if (canBackup_->sendDiagnostic(source, target, uds, response,
                                       timeoutMs, canErr, functional)) {
            lastUsedCanBackup_ = true;
            Logger::instance().warn("OpenXC transport failed, used CAN backup");
            return true;
        }
        err += (err.empty() ? "" : " | ");
        err += "CAN backup also failed: " + canErr;
    }
    return false;
}

bool Transport::sendDiagnosticMulti(uint16_t source, uint16_t target,
                                    const std::vector<uint8_t>& uds,
                                    std::vector<DiagResponse>& responses,
                                    int collectMs, std::string& err) {
    responses.clear();

    uint32_t arbId = mapLogicalToCanId(target, true);
    std::vector<DiagnosticFrame> frames;
    if (openxcClient_.sendDiagnosticMulti(arbId, uds, frames,
                                          collectMs > 0 ? collectMs : 2000,
                                          bus_, err)) {
        responses.reserve(frames.size());
        for (auto& f : frames)
            responses.push_back({mapCanResponseToLogical(f.arbitrationId), std::move(f.uds)});
        return true;
    }

    if (canBackup_ && canBackup_->isConnected()) {
        std::vector<can::MultiResponse> canResp;
        std::string canErr;
        if (!retargetCanBackup(target, true, canErr)) {
            err += (err.empty() ? "" : " | ");
            err += "CAN backup retarget failed: " + canErr;
            return false;
        }
        if (canBackup_->sendDiagnosticMulti(source, target, uds, canResp,
                                            collectMs, canErr)) {
            responses.reserve(canResp.size());
            for (auto& r : canResp)
                responses.push_back({r.source, std::move(r.uds)});
            lastUsedCanBackup_ = true;
            return true;
        }
        err += (err.empty() ? "" : " | ");
        err += "CAN backup also failed: " + canErr;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Core OpenXC diagnostic exchange (no CAN fallback)
// ---------------------------------------------------------------------------
bool Transport::sendDiagnosticOpenXc(uint16_t source, uint16_t target,
                                     const std::vector<uint8_t>& uds,
                                     std::vector<uint8_t>& response, int timeoutMs,
                                     std::string& err, bool functional) {
    response.clear();
    if (!isConnected()) {
        err = "OpenXC transport not connected";
        return false;
    }
    if (uds.empty()) {
        err = "Empty UDS request";
        return false;
    }

    testerAddr_ = source;
    uint32_t arbId = mapLogicalToCanId(target, functional);
    uint32_t respId = responseIdForRequest(arbId, functional);

    {
        std::ostringstream dbg;
        dbg << "OpenXC TX bus=" << bus_ << " arb=0x" << std::hex << std::uppercase
            << arbId << " uds=" << bytesToHex(uds);
        if (!functional && respId != 0u)
            dbg << " (expect resp 0x" << std::hex << std::uppercase << respId << ")";
        Logger::instance().info(dbg.str());
    }

    if (!openxcClient_.sendDiagnostic(arbId, respId, uds, response,
                                       timeoutMs > 0 ? timeoutMs : 2000,
                                       bus_, err)) {
        return false;
    }

    Logger::instance().info("OpenXC RX uds=" + bytesToHex(response));
    return true;
}

} // namespace openxc
