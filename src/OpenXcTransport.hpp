#pragma once
//
// OpenXcTransport.hpp - Primary diagnostic transport for the VinFast scanner.
//
// Wraps openxc::Client (USB/Bluetooth serial to an OpenXC Vehicle Interface) and
// exposes a UDS-shaped API used by UDSClient.  The optional CAN (ISO 15765 /
// J2534) backup is still supported: when an OpenXC exchange fails and a CAN
// backup client has been registered and connected, the request is retried
// transparently over UDS-on-CAN.
//
// Logical UDS addresses are mapped to physical CAN arbitration IDs:
//   • 0x600-0x7FF  → used directly (Info-CAN DiagReq IDs, OBD 0x7E0, etc.)
//   • otherwise    → request = canIdBase + (addr & 0xFF)
//                     (default base 0x700 → 0x00E0 becomes 0x7E0)
// Response arb for J2534/raw CAN:
//   • Info DiagReq 0x680-0x6FF → resp = req - 0x80 (DBC pair rule)
//   • otherwise                → resp = req + canRespOffset (default +8)
// Functional / broadcast request arbs (0x7DF, 0x6EF, 0x6FF) leave the OpenXC
// match id open so any responder module arb is accepted.
//
#include "OpenXcClient.hpp"
#include "CanClient.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace openxc {

// One ECU reply collected during a functional (broadcast) request.
struct DiagResponse {
    uint16_t             source = 0;
    std::vector<uint8_t> uds;
};

class Transport {
public:
    Transport();
    ~Transport();

    Transport(const Transport&)            = delete;
    Transport& operator=(const Transport&) = delete;

    // Open the serial link to the OpenXC VI. `deviceOrMac` may be a USB serial
    // path ("/dev/ttyUSB0", "/dev/cu.usbmodem*", "COM3") or a Bluetooth MAC.
    bool connect(const std::string& deviceOrMac, std::string& err);
    bool isConnected() const;
    const std::string& connectedPath() const { return openxcClient_.connectedPath(); }
    void disconnect();

    // Sends a UDS request to `target` and returns the raw UDS response bytes.
    // `target` is mapped to a CAN arbitration ID before being handed to the
    // OpenXC VI.  timeoutMs is the response budget; each UDS "response pending"
    // (NRC 0x78) extends it.  When `functional` is true, `target` is treated as
    // a functional broadcast address.
    bool sendDiagnostic(uint16_t source, uint16_t target,
                        const std::vector<uint8_t>& uds,
                        std::vector<uint8_t>& response, int timeoutMs,
                        std::string& err, bool functional = false);

    // Sends one (typically functional) request and collects every diagnostic
    // response that arrives within collectMs, keyed by responder source address
    // and de-duplicated.
    bool sendDiagnosticMulti(uint16_t source, uint16_t target,
                             const std::vector<uint8_t>& uds,
                             std::vector<DiagResponse>& responses,
                             int collectMs, std::string& err);

    bool receiveCanFrame(RawCanFrame& frame, int timeoutMs, std::string& err) {
        return openxcClient_.receiveCanFrame(frame, timeoutMs, err);
    }

    // Enable raw CAN streaming only while the Live Data consumer is running.
    bool setPassthrough(bool enabled, std::string& err);

    // Request the custom Fordboard USB bootloader. A successful request is
    // followed by the expected USB disconnect as the device resets.
    bool requestBootloader(std::string& err);

    // Registers an optional CAN backup transport.  When set, a failed OpenXC
    // diagnostic exchange automatically falls back to it.  The pointer is
    // borrowed; the caller retains ownership.
    void setCanBackup(can::Client* backup) { canBackup_ = backup; }
    bool usingCanBackup() const { return lastUsedCanBackup_.load(std::memory_order_acquire); }

    // Select the OpenXC CAN bus used for diagnostic requests (1 or 2).
    // Default is 1.  Must be set before connect() to take effect.
    void setBus(int bus) { bus_ = (bus == 2 ? 2 : 1); }
    int  bus() const { return bus_; }

    // Configure how non-direct logical UDS addresses are translated to CAN IDs.
    // Addresses already in 0x600-0x7FF are passed through as raw request arbs.
    // `responseOffset` may be negative (e.g. -0x80). Applied as:
    //   requestId  = canIdBase_ + (addr & 0xFF)   when addr is not 0x600-0x7FF
    //   responseId = requestId + responseOffset   when not in Info DiagReq band
    // Info DiagReq 0x680-0x6FF always uses resp = req - 0x80 automatically.
    void setCanIdMapping(uint32_t baseRequestId, int32_t responseOffset) {
        canIdBase_ = baseRequestId & 0x7FFu;
        // Keep offset in a sane 11-bit-ish range (allow negative for −0x80).
        if (responseOffset > 0x7FF) responseOffset = 0x7FF;
        if (responseOffset < -0x7FF) responseOffset = -0x7FF;
        canRespOffset_ = responseOffset;
    }
    uint32_t canIdBase() const { return canIdBase_; }
    int32_t  canRespOffset() const { return canRespOffset_; }

    uint16_t testerAddress() const { return testerAddr_; }

private:
    bool sendDiagnosticOpenXc(uint16_t source, uint16_t target,
                              const std::vector<uint8_t>& uds,
                              std::vector<uint8_t>& response, int timeoutMs,
                              std::string& err, bool functional);

    // Run the OpenXC VI initialization sequence that prepares the selected
    // CAN bus for arbitrary diagnostic traffic.
    bool initializeLink(std::string& err);

    // Map a logical UDS address to the CAN request arbitration ID.
    uint32_t mapLogicalToCanId(uint16_t logicalAddr, bool functional) const;

    // Map a CAN / OpenXC response id back to the request-ID-shaped logical
    // key used by the UI when true logical addresses are unknown.
    uint16_t mapCanResponseToLogical(uint32_t responseId) const;

    // True for OBD/Info functional broadcast request arbitration IDs.
    static bool isBroadcastRequestId(uint32_t requestId);

    // OpenXC JSON id to match for a physical request (request arb id).
    // Broadcast / functional returns 0 (accept any responder).
    uint32_t openXcMatchIdForRequest(uint32_t requestId, bool functional) const;
    // True ISO-TP CAN response arbitration id for J2534.
    uint32_t canResponseIdForRequest(uint32_t requestId, bool functional) const;
    bool retargetCanBackup(uint16_t target, bool functional, std::string& err);

    openxc::Client openxcClient_;
    std::atomic<bool> connected_{false};
    uint16_t testerAddr_     = 0x0E80;
    can::Client* canBackup_  = nullptr;
    std::atomic<bool> lastUsedCanBackup_{false};
    int      bus_            = 1;
    uint32_t canIdBase_      = 0x700u;  // default OEM / OBD base
    int32_t  canRespOffset_  = 0x08;    // response = request + offset (OBD +8)
};

} // namespace openxc
