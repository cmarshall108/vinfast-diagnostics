#pragma once
//
// CanClient.hpp - UDS-over-CAN (ISO 14229 on ISO 15765-2) transport backed by
// an MVCI (ISO 22900-2 D-PDU API) pass-thru device exposing `mvci32.dll`.
//
// This is the CAN fallback used when the primary DoIP (Ethernet) transport is
// unavailable. The public surface deliberately mirrors doip::Client so the UDS
// layer can use it as a drop-in backup transport:
//
//     bool sendDiagnostic(source, target, uds, response, timeoutMs, err, functional)
//
// On Windows the implementation dynamically loads mvci32.dll and drives the
// standardized D-PDU API (PDUConstruct / PDUModuleConnect /
// PDUCreateComLogicalLink(ISO_15765) / PDUStartComPrimitive(SENDRECV) ...).
// The MVCI handles ISO 15765-2 (ISO-TP) segmentation/flow-control internally,
// so a full UDS request is sent in one primitive and the assembled response is
// returned. On non-Windows platforms the class compiles to a graceful stub
// that always reports the backup as unavailable.
//
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace can {

// CAN / ISO 15765 link configuration.
struct Config {
    // Filename (or full path) of the MVCI D-PDU API library. The default is the
    // common ISO 22900-2 name; vendors may ship a differently named DLL.
    std::string dllPath    = "mvci32.dll";
    uint32_t    baudrate   = 500000;   // CAN bit rate (500 kbit/s is typical)
    uint32_t    reqId      = 0x7E0;    // physical request CAN ID (tester -> ECU)
    uint32_t    respId     = 0x7E8;    // response CAN ID (ECU -> tester)
    bool        extendedId = false;    // true = 29-bit CAN identifiers
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
    // (ISO-TP handled by the MVCI). Mirrors doip::Client::sendDiagnostic so it
    // can serve as a backup transport. `source`/`target` are accepted for
    // signature compatibility and logging; the CAN link addresses ECUs via the
    // configured request/response CAN IDs. `functional` relaxes the single
    // response expectation (collects the first answer that arrives).
    bool sendDiagnostic(uint16_t source, uint16_t target,
                        const std::vector<uint8_t>& uds,
                        std::vector<uint8_t>& response, int timeoutMs,
                        std::string& err, bool functional = false);

    // True only on platforms where the mvci32.dll integration is compiled in
    // (Windows). Lets callers skip CAN setup with a clear message elsewhere.
    static bool platformSupported();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace can
