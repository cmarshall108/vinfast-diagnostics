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
// Logical UDS addresses (e.g. 0x1001 for the gateway) are mapped to physical
// CAN arbitration IDs using a configurable scheme.  The default is the common
// OEM scheme request = 0x700 + (addr & 0xFF), response = request + 8, which
// gives the standard 0x7E0/0x7E8 pair for address 0x00E0.
//
#include "OpenXcClient.hpp"
#include "CanClient.hpp"

#include <cstdint>
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

    // Registers an optional CAN backup transport.  When set, a failed OpenXC
    // diagnostic exchange automatically falls back to it.  The pointer is
    // borrowed; the caller retains ownership.
    void setCanBackup(can::Client* backup) { canBackup_ = backup; }
    bool usingCanBackup() const { return lastUsedCanBackup_; }

    // Select the OpenXC CAN bus used for diagnostic requests (1 or 2).
    // Default is 1.  Must be set before connect() to take effect.
    void setBus(int bus) { bus_ = (bus == 2 ? 2 : 1); }
    int  bus() const { return bus_; }

    // Configure how logical UDS addresses are translated to CAN arbitration IDs.
    // For a physical request to logical address `addr`:
    //   requestId  = canIdBase_ + (addr & 0xFF)
    //   responseId = requestId + canRespOffset_
    // Functional requests always use 0x7DF.
    void setCanIdMapping(uint32_t baseRequestId, uint32_t responseOffset) {
        canIdBase_ = baseRequestId & 0x7FFu;
        canRespOffset_ = responseOffset & 0x7FFu;
    }
    uint32_t canIdBase() const { return canIdBase_; }
    uint32_t canRespOffset() const { return canRespOffset_; }

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

    // OpenXC JSON id to match for a physical request (request arb id).
    // Functional returns 0 (accept any responder).
    uint32_t openXcMatchIdForRequest(uint32_t requestId, bool functional) const;
    // True ISO-TP CAN response arbitration id (request + offset) for J2534.
    uint32_t canResponseIdForRequest(uint32_t requestId, bool functional) const;
    bool retargetCanBackup(uint16_t target, bool functional, std::string& err);

    openxc::Client openxcClient_;
    bool     connected_      = false;
    uint16_t testerAddr_     = 0x0E80;
    can::Client* canBackup_  = nullptr;
    bool     lastUsedCanBackup_ = false;
    int      bus_            = 1;
    uint32_t canIdBase_      = 0x700u;  // default OEM base
    uint32_t canRespOffset_  = 0x08u;   // response = request + 8
};

} // namespace openxc
