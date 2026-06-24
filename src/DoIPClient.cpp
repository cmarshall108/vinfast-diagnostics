#include "DoIPClient.hpp"
#include "CanClient.hpp"
#include "Logger.hpp"

extern "C" {
#include <uds/uds.h>  // OBD2_FUNCTIONAL_BROADCAST_ID and UDS constants
}

#include <array>
#include <sstream>
#include <iomanip>

namespace doip {

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

static std::string bytesToHex(const std::vector<uint8_t>& b) {
    if (b.empty()) return "";
    std::ostringstream ss;
    for (uint8_t byte : b)
        ss << std::hex << std::uppercase
           << std::setfill('0') << std::setw(2)
           << static_cast<int>(byte);
    return ss.str();
}

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

Client::Client()  = default;
Client::~Client() { disconnect(); }

socket_t Client::invalidSocketValue() { return -1; }

// ---------------------------------------------------------------------------
// Discovery stubs – not supported over OpenXC Bluetooth transport
// ---------------------------------------------------------------------------

bool Client::discover(const std::string&, uint16_t, int,
                      std::vector<Entity>&, std::string& err) {
    err = "DoIP discovery not available: using OpenXC Bluetooth transport";
    return false;
}

bool Client::discoverByVin(const std::string&, uint16_t, int,
                           const std::string&, std::vector<Entity>&,
                           std::string& err) {
    err = "Targeted DoIP discovery not available: using OpenXC Bluetooth transport";
    return false;
}

bool Client::discoverByEid(const std::string&, uint16_t, int,
                           const std::array<uint8_t, 6>&, std::vector<Entity>&,
                           std::string& err) {
    err = "Targeted DoIP discovery not available: using OpenXC Bluetooth transport";
    return false;
}

bool Client::entityStatus(const std::string&, uint16_t, int,
                          EntityStatus&, std::string& err) {
    err = "DoIP entity status not available: using OpenXC Bluetooth transport";
    return false;
}

bool Client::diagnosticPowerMode(const std::string&, uint16_t, int,
                                 uint8_t&, std::string& err) {
    err = "DoIP power mode not available: using OpenXC Bluetooth transport";
    return false;
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

bool Client::connectTcp(const std::string& ip, uint16_t /*port*/,
                        std::string& err,
                        int /*connectTimeoutMs*/, int /*rcvTimeoutMs*/) {
    // `ip` carries the Bluetooth MAC address or /dev/cu.* device path as
    // entered in the UI "Bluetooth MAC / Device" field.
    if (!openxcClient_.connect(ip, err)) {
        connected_ = false;
        return false;
    }
    connected_ = true;
    const std::string& endpoint = openxcClient_.connectedPath();
    Logger::instance().info("OpenXC Bluetooth transport connected: " +
                            (endpoint.empty() ? ip : endpoint));
    return true;
}

void Client::disconnect() {
    openxcClient_.disconnect();
    connected_ = false;
}

bool Client::routingActivation(uint16_t sourceAddr, uint8_t,
                               std::string&, const std::vector<uint8_t>&) {
    testerAddr_ = sourceAddr;
    return true;
}

// ---------------------------------------------------------------------------
// Diagnostic send (public, with optional CAN fallback)
// ---------------------------------------------------------------------------

bool Client::sendDiagnostic(uint16_t source, uint16_t target,
                            const std::vector<uint8_t>& uds,
                            std::vector<uint8_t>& response, int timeoutMs,
                            std::string& err, bool functional) {
    lastUsedCanBackup_ = false;

    if (sendDiagnosticDoIP(source, target, uds, response, timeoutMs, err, functional))
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

bool Client::sendDiagnosticMulti(uint16_t source, uint16_t target,
                                 const std::vector<uint8_t>& uds,
                                 std::vector<DiagResponse>& responses,
                                 int collectMs, std::string& err) {
    responses.clear();

    // OpenXC VI returns one diagnostic response per request.
    std::vector<uint8_t> single;
    if (sendDiagnosticDoIP(source, target, uds, single, collectMs, err, true)) {
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

bool Client::sendDiagnosticDoIP(uint16_t /*source*/, uint16_t target,
                                const std::vector<uint8_t>& uds,
                                std::vector<uint8_t>& response, int timeoutMs,
                                std::string& err, bool functional) {
    response.clear();
    if (!connected_ || !openxcClient_.isConnected()) {
        err = "OpenXC Bluetooth transport not connected";
        return false;
    }
    if (uds.empty()) {
        err = "Empty UDS request";
        return false;
    }

    // Map the UDS target logical address to a CAN arbitration ID.
    // Standard OBD-II/UDS addressing:
    //   functional  → 0x7DF (broadcast; OBD2_FUNCTIONAL_BROADCAST_ID from uds-c)
    //   physical    → target if it's a valid 11-bit CAN ID (≤ 0x7FF),
    //                 otherwise fall back to 0x7E0 (primary ECU)
    uint32_t arbId = functional
        ? static_cast<uint32_t>(OBD2_FUNCTIONAL_BROADCAST_ID)
        : (target <= 0x7FFu ? static_cast<uint32_t>(target) : 0x7E0u);

    {
        std::ostringstream dbg;
        dbg << "OpenXC TX arb=0x" << std::hex << std::uppercase << arbId
            << " uds=" << bytesToHex(uds);
        Logger::instance().info(dbg.str());
    }

    if (!openxcClient_.sendDiagnostic(arbId, uds, response,
                                       timeoutMs > 0 ? timeoutMs : 2000,
                                       /*bus=*/1, err)) {
        return false;
    }

    Logger::instance().info("OpenXC RX uds=" + bytesToHex(response));
    return true;
}

bool Client::sendDiagnosticMultiDoIP(uint16_t, uint16_t,
                                     const std::vector<uint8_t>&,
                                     std::vector<DiagResponse>&,
                                     int, std::string& err) {
    err = "sendDiagnosticMultiDoIP: not implemented for OpenXC transport";
    return false;
}

} // namespace doip
