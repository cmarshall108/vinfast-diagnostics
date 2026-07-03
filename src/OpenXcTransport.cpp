//
// OpenXcTransport.cpp - OpenXC Bluetooth primary transport with optional CAN backup.
//
// Primary OpenXC transport implementation.  All diagnostic traffic is routed through
// an OpenXC Vehicle Interface over RFCOMM; the optional CAN (J2534) client is
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
#include <sstream>
#include <iomanip>

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

} // namespace

Transport::Transport()  = default;
Transport::~Transport() { disconnect(); }

bool Transport::connect(const std::string& deviceOrMac, std::string& err) {
    disconnect();

    if (!openxcClient_.connect(deviceOrMac, err)) {
        connected_ = false;
        return false;
    }

    if (!initializeLink(err)) {
        openxcClient_.disconnect();
        connected_ = false;
        return false;
    }

    connected_ = true;
    const std::string& path = openxcClient_.connectedPath();
    Logger::instance().info("OpenXC transport connected: " +
                            (path.empty() ? deviceOrMac : path));
    return true;
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

    // 1) Version handshake.
    if (!openxcClient_.sendCommand(R"({"command":"version"})", line, 1500, err)) {
        err = "OpenXC version query failed: " + err;
        return false;
    }
    Logger::instance().info("OpenXC VI: " + line);

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

    // OpenXC VI returns one diagnostic response per request.
    std::vector<uint8_t> single;
    if (sendDiagnosticOpenXc(source, target, uds, single, collectMs, err, true)) {
        responses.push_back({target, std::move(single)});
        return true;
    }

    if (canBackup_ && canBackup_->isConnected()) {
        std::vector<can::MultiResponse> canResp;
        std::string canErr;
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
    uint32_t respId = functional ? 0u : (arbId + canRespOffset_);

    {
        std::ostringstream dbg;
        dbg << "OpenXC TX bus=" << bus_ << " arb=0x" << std::hex << std::uppercase
            << arbId << " uds=" << bytesToHex(uds);
        if (!functional && respId <= 0x7FFu)
            dbg << " (expect resp 0x" << std::hex << std::uppercase << respId << ")";
        Logger::instance().info(dbg.str());
    }

    if (!openxcClient_.sendDiagnostic(arbId, uds, response,
                                       timeoutMs > 0 ? timeoutMs : 2000,
                                       bus_, err)) {
        return false;
    }

    Logger::instance().info("OpenXC RX uds=" + bytesToHex(response));
    return true;
}

} // namespace openxc
