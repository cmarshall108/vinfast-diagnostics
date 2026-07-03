#pragma once
//
// CanClient.hpp - UDS-over-CAN (ISO 14229 on ISO 15765-2) transport backed by
// Toyota's Mini-VCI, whose `mvci32.dll` is a SAE J2534 PassThru library.
//
// This is the CAN fallback used when the primary OpenXC Bluetooth transport is
// unavailable. The public surface deliberately mirrors openxc::Transport so the UDS
// layer can use it as a drop-in backup transport:
//
//     bool sendDiagnostic(source, target, uds, response, timeoutMs, err, functional)
//
// On Windows the implementation dynamically loads mvci32.dll and drives the
// standardized J2534 PassThru API (PassThruOpen / PassThruConnect(ISO15765) /
// PassThruStartMsgFilter(FLOW_CONTROL) / PassThruWriteMsgs / PassThruReadMsgs).
// The device handles ISO 15765-2 (ISO-TP) segmentation/flow-control internally,
// so a full UDS request is written in one message and the assembled response is
// returned. On non-Windows platforms the class compiles to a graceful stub
// that always reports the backup as unavailable.
//
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace can {

// CAN / ISO 15765 link configuration.
struct Config {
    // Filename (or full path) of the J2534 PassThru library. The default is
    // Toyota's Mini-VCI driver; other vendors ship a differently named DLL.
    std::string dllPath    = "mvci32.dll";
    uint32_t    baudrate   = 500000;   // CAN bit rate (500 kbit/s is typical)
    uint32_t    reqId      = 0x7E0;    // physical request CAN ID (tester -> ECU)
    uint32_t    respId     = 0x7E8;    // response CAN ID (ECU -> tester)
    bool        extendedId = false;    // true = 29-bit CAN identifiers
};

// One ECU's reply to a functional (broadcast) request. `source` is a 16-bit
// key distinguishing responders (derived from the VCI's unique response
// identifier) so callers can de-duplicate per ECU.
struct MultiResponse {
    uint16_t             source = 0;
    std::vector<uint8_t> uds;
};

// Outcome of probing one standard OBD-II communication protocol candidate while
// trying to discover how an unknown vehicle talks. Produced by
// Client::scanObdProtocols (one per candidate attempted).
struct ProtocolProbe {
    std::string protocol;          // human-readable candidate, e.g. "ISO 15765-4 CAN 500k 11-bit"
    bool        linkUp    = false; // the VCI accepted/opened the protocol channel
    bool        responded = false; // the vehicle answered (or live bus traffic seen)
    std::string detail;            // response hex / sniffed frame / status text
};

class Client {
public:
    Client();
    ~Client();

    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;

    // Loads mvci32.dll and brings up an ISO 15765 (UDS-over-CAN) logical link.
    // Returns false and sets `err` if the DLL/device is missing or the link
    // cannot be established (e.g. when running off Windows).
    bool connect(const Config& cfg, std::string& err);

    bool isConnected() const;
    void disconnect();

    // Re-targets subsequent requests at a different ECU by changing the
    // physical request / response CAN IDs on the open link.
    void setAddressing(uint32_t reqId, uint32_t respId, std::string& err);

    // Sends a complete UDS request and returns the assembled UDS response
    // (ISO-TP handled by the MVCI). Mirrors openxc::Transport::sendDiagnostic so it
    // can serve as a backup transport. `source`/`target` are accepted for
    // signature compatibility and logging; the CAN link addresses ECUs via the
    // configured request/response CAN IDs. `functional` relaxes the single
    // response expectation (collects the first answer that arrives).
    bool sendDiagnostic(uint16_t source, uint16_t target,
                        const std::vector<uint8_t>& uds,
                        std::vector<uint8_t>& response, int timeoutMs,
                        std::string& err, bool functional = false);

    // Sends a single functional request and collects EVERY UDS response that
    // arrives within collectMs (de-duplicated per responder). Mirrors
    // openxc::Transport::sendDiagnosticMulti so it can back up functional ECU
    // enumeration over CAN.
    bool sendDiagnosticMulti(uint16_t source, uint16_t target,
                             const std::vector<uint8_t>& uds,
                             std::vector<MultiResponse>& responses,
                             int collectMs, std::string& err);

    // True only on platforms where the mvci32.dll integration is compiled in
    // (Windows). Lets callers skip CAN setup with a clear message elsewhere.
    static bool platformSupported();

    // Discovers how an unknown vehicle communicates by sweeping every standard
    // OBD-II protocol the Mini-VCI can attempt: ISO 15765-4 CAN (11/29-bit at
    // 500k & 250k, active OBD probe), raw CAN (passive bus sniff at 500k &
    // 250k), SAE J1850 PWM & VPW, ISO 9141-2 and ISO 14230-4 KWP2000 (K-line).
    // Self-contained: opens and tears down its own device/channels, so it can
    // run independently of any active backup link. `progress` is called with a
    // 0..1 fraction, `report` once per candidate as results arrive, and the
    // sweep stops early when `cancel` becomes true. Windows-only; the stub
    // returns false with an explanatory `err`.
    bool scanObdProtocols(const std::string& dllPath,
                          const std::function<void(float)>& progress,
                          const std::function<void(const ProtocolProbe&)>& report,
                          const std::atomic<bool>& cancel,
                          std::string& err);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace can
