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
    // Native raw-USB backend token ("usb" or "usb:VID:PID"): the stock VI has
    // no serial node, so this is handed straight to the libusb backend.
    const std::string reqLower = lowerCopy(requested);
    const bool usbToken = (reqLower == "usb" || reqLower.rfind("usb:", 0) == 0);

    std::vector<std::string> candidates;
    if (usbToken) addUnique(candidates, requested);
    if (explicitSerial) addUnique(candidates, requested);
    if (!explicitSerial && !usbToken) {
        for (const auto& path : openxc::Client::enumerateUsbSerialPorts())
            addUnique(candidates, path);
    }
    if (!autoRequested && !explicitSerial && !usbToken)
        addUnique(candidates, requested);
#ifdef OPENXC_HAVE_LIBUSB
    // Native raw-USB fallback: when the user asked for auto/USB, always try the
    // libusb backend last. It waits briefly for the VI to appear, so a device
    // that isn't enumerated yet (the VI sleeps and drops off USB) can still be
    // caught by plugging it in / waking it right after pressing Connect.
    if (autoRequested || usbToken)
        addUnique(candidates, "usb");
#endif

    if (candidates.empty()) {
        err = autoRequested
            ? "No OpenXC device found; plug in the VI over USB, or enter a "
              "serial path / Bluetooth MAC"
            : "No OpenXC device specified";
        connected_.store(false, std::memory_order_release);
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

        connected_.store(true, std::memory_order_release);
        const std::string& path = openxcClient_.connectedPath();
        Logger::instance().info("OpenXC transport connected: " +
                                (path.empty() ? candidate : path));
        return true;
    }

    if (!autoRequested && explicitSerial) {
        // A typed serial path should stay exact; users can enter "auto" to scan all USB ports.
        openxcClient_.disconnect();
    }

    connected_.store(false, std::memory_order_release);
    err = allErr.empty() ? "No OpenXC device responded" : allErr;
    return false;
}

void Transport::disconnect() {
    connected_.store(false, std::memory_order_release);
    openxcClient_.disconnect();
}

bool Transport::requestBootloader(std::string& err) {
    if (!isConnected()) {
        err = "OpenXC transport not connected";
        return false;
    }
    return openxcClient_.requestBootloader(err);
}

bool Transport::isConnected() const {
    return connected_.load(std::memory_order_acquire) && openxcClient_.isConnected();
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

    // 1) Link handshake. The VI needs a warm-up after the link opens before it
    //    answers commands: the native-USB Ford VI silently DROPS the first ~2
    //    commands (~2-3 s) right after connect, then answers reliably; the
    //    Bluetooth RFCOMM channel likewise needs a moment. So poll persistently
    //    for a real command_response instead of giving up after a few tries.
    //    A genuine reply echoes {"command_response":...}; we require that token
    //    so link-up is not falsely triggered by stray bytes.
    const bool isUsb = openxcClient_.connectedPath().rfind("usb", 0) == 0;
    const int warmupMs = isUsb ? 20000 : 4000;

    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + std::chrono::milliseconds(warmupMs);
    bool linked = false;
    std::string lastErr;
    auto tryCmd = [&](const char* cmd) {
        auto t0 = Clock::now();
        bool ok = openxcClient_.sendCommand(cmd, line, 900, err) &&
                  line.find("command_response") != std::string::npos;
        if (!ok) {
            lastErr = err.empty() ? "no handshake response" : err;
            // Avoid a hot spin if the command failed fast (e.g. VI dropped off).
            if (Clock::now() - t0 < std::chrono::milliseconds(150))
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        return ok;
    };
    while (Clock::now() < deadline && !linked) {
        if (tryCmd(R"({"command":"version"})"))  { linked = true; gotVersion = true; break; }
        if (tryCmd(R"({"command":"platform"})")) { linked = true; break; }
    }
    if (!linked) {
        err = "OpenXC link check failed (no handshake within " +
              std::to_string(warmupMs / 1000) + "s): " + lastErr;
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
// Addresses already in the 11-bit diagnostic band (0x600-0x7FF) are treated as
// raw CAN request IDs.  That covers:
//   • Legislated OBD physical 0x7E0 / functional 0x7DF
//   • VF8 Info-CAN DiagReq tunnels from the MHU matrix (0x681, 0x682, …)
//
// Smaller logical aliases (e.g. 0x00E0, legacy 0x1001 placeholders) still use
//   request = canIdBase_ + (addr & 0xFF)   default base 0x700 → 0x7E0 / 0x701
//
// Response IDs (J2534):
//   • Info DiagReq 0x680-0x6FF → req - 0x80  (DBC DiagResp pair)
//   • else                    → req + canRespOffset_  (OBD default +8)
// ---------------------------------------------------------------------------
bool Transport::isBroadcastRequestId(uint32_t requestId) {
    return requestId == static_cast<uint32_t>(OBD2_FUNCTIONAL_BROADCAST_ID) ||
           requestId == 0x6EFu ||  // DIAG_Req_All_CAN (Info DBC)
           requestId == 0x6FFu;    // DIAG_Req_All_Ecu (Info DBC)
}

uint32_t Transport::mapLogicalToCanId(uint16_t logicalAddr, bool functional) const {
    // Explicit functional path: honour known broadcast arbs / direct CAN IDs,
    // otherwise fall back to legislated 0x7DF.
    if (functional) {
        if (isBroadcastRequestId(logicalAddr) ||
            (logicalAddr >= 0x600u && logicalAddr <= 0x7FFu))
            return logicalAddr;
        return static_cast<uint32_t>(OBD2_FUNCTIONAL_BROADCAST_ID);
    }

    // Direct 11-bit diagnostic CAN ID (Info DiagReq, OBD physical, etc.).
    if (logicalAddr >= 0x600u && logicalAddr <= 0x7FFu)
        return logicalAddr;

    uint32_t id = canIdBase_ + (logicalAddr & 0xFFu);
    if (id > 0x7FFu) id = 0x7FFu;
    return id;
}

// OpenXC JSON diagnostic_response.id for a *physical* request is the request
// arbitration id (VI subtracts 0x8 from the CAN response arb). For functional
// / broadcast requests the VI publishes the real responding module arb — leave
// the match unconstrained (0). CAN-backup still needs the true ISO-TP response.
uint32_t Transport::openXcMatchIdForRequest(uint32_t requestId, bool functional) const {
    if (functional || isBroadcastRequestId(requestId)) return 0u;
    return requestId <= 0x7FFu ? requestId : 0u;
}

uint32_t Transport::canResponseIdForRequest(uint32_t requestId, bool functional) const {
    if (functional || isBroadcastRequestId(requestId)) return 0u;

    // Info-CAN MHU diagnostic tunnels (01_Info_CAN_Matrix): DiagResp = DiagReq - 0x80.
    if (requestId >= 0x680u && requestId <= 0x6FFu)
        return requestId - 0x80u;

    const int32_t sum = static_cast<int32_t>(requestId) + canRespOffset_;
    if (sum < 0 || sum > 0x7FF) return 0u;
    return static_cast<uint32_t>(sum);
}

uint16_t Transport::mapCanResponseToLogical(uint32_t responseId) const {
    // OpenXC multi/functional path may hand us either:
    //   • actual CAN response arb (e.g. 0x7E8 or Info 0x602), or
    //   • request-shaped id (e.g. 0x7E0 / 0x682) after VI rewrite.
    responseId &= 0x7FFu;

    // Info DiagResp band → prefer the matching DiagReq as the logical key.
    if (responseId >= 0x600u && responseId <= 0x67Fu)
        return static_cast<uint16_t>(responseId + 0x80u);

    // Already a diagnostic request-shaped id (Info DiagReq or OBD 0x7Ex).
    if (responseId >= 0x680u && responseId <= 0x7FFu)
        return static_cast<uint16_t>(responseId);

    // Legacy base+offset reverse map (OBD-style logical aliases).
    if (canRespOffset_ >= 0) {
        const uint32_t off = static_cast<uint32_t>(canRespOffset_);
        if (responseId >= canIdBase_ + off) {
            uint32_t low = responseId - canIdBase_ - off;
            if (low <= 0xFFu) return static_cast<uint16_t>(low);
        }
    }
    if (responseId >= canIdBase_) {
        uint32_t low = responseId - canIdBase_;
        if (low <= 0xFFu) return static_cast<uint16_t>(low);
    }
    return static_cast<uint16_t>(responseId);
}

bool Transport::retargetCanBackup(uint16_t target, bool functional, std::string& err) {
    if (!canBackup_ || !canBackup_->isConnected()) {
        err = "CAN backup not connected";
        return false;
    }

    uint32_t reqId = mapLogicalToCanId(target, functional);
    // J2534/ISO-TP needs the real CAN response arbitration id.
    uint32_t respId = canResponseIdForRequest(reqId, functional);
    if (functional || isBroadcastRequestId(reqId) || respId == 0u) {
        // Broadcast / unknown response: anchor flow-control on the common OBD
        // physical gateway response (0x7E8 under default mapping).
        const int32_t anchor = static_cast<int32_t>(canIdBase_ + 0xE0u) + canRespOffset_;
        if (anchor >= 0 && anchor <= 0x7FF)
            respId = static_cast<uint32_t>(anchor);
        else
            respId = 0x7E8u;
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
    lastUsedCanBackup_.store(false, std::memory_order_relaxed);

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
            lastUsedCanBackup_.store(true, std::memory_order_relaxed);
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
            lastUsedCanBackup_.store(true, std::memory_order_relaxed);
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
    // Stock OpenXC publishes physical diagnostic_response.id == request arb
    // (not the CAN response arb). Match that; functional leaves id open.
    uint32_t matchId = openXcMatchIdForRequest(arbId, functional);
    const uint32_t canRespId = canResponseIdForRequest(arbId, functional);

    {
        std::ostringstream dbg;
        dbg << "OpenXC TX bus=" << bus_ << " arb=0x" << std::hex << std::uppercase
            << arbId << " uds=" << bytesToHex(uds);
        if (!functional) {
            dbg << " (OpenXC match id 0x" << matchId;
            if (canRespId != 0u)
                dbg << ", CAN resp 0x" << canRespId;
            dbg << ")";
        } else {
            dbg << " (functional; accept any responder id)";
        }
        Logger::instance().info(dbg.str());
    }

    if (!openxcClient_.sendDiagnostic(arbId, matchId, uds, response,
                                       timeoutMs > 0 ? timeoutMs : 2000,
                                       bus_, err)) {
        // Help distinguish the two very different "no response" causes:
        //   • VI returned other messages but none matched -> the bus is live,
        //     the target address/bus is just wrong (placeholders!).
        //   • VI returned nothing at all -> no CAN activity: the vehicle is
        //     asleep, ignition off, or the VI isn't on the diagnostic bus.
        int seen = openxcClient_.lastRxCount();
        if (seen > 0) {
            Logger::instance().warn(
                "VI saw " + std::to_string(seen) + " CAN/data message(s) but none "
                "matched (wrong target/bus/mode). Sample: " +
                openxcClient_.lastRxSample());
        } else {
            // Silence these repetitive messages for now:
            //Logger::instance().info(
            //    "VI returned no data - no CAN activity on bus " + std::to_string(bus_) +
            //    " (vehicle asleep / ignition off / VI not on the diagnostic bus).");
        }
        return false;
    }

    Logger::instance().info("OpenXC RX uds=" + bytesToHex(response));
    return true;
}

} // namespace openxc
