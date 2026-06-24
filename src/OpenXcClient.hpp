#pragma once
//
// OpenXcClient.hpp
//
// Connects to a paired OpenXC Vehicle Interface over its RFCOMM serial port
// (/dev/cu.OpenXC-VI-* on macOS) and exchanges UDS diagnostic requests /
// responses using the OpenXC JSON message format.
//
// Uses openxc/uds-c (github.com/openxc/uds-c) for DiagnosticRequest struct
// validation and openxc/isotp-c + openxc/bitfield-c as transitive deps.
//
// The public sendDiagnostic() API accepts/returns raw UDS PDU byte vectors so
// the existing DoIPClient wrapper and UDSClient do not need changes.
//
#include <cstdint>
#include <string>
#include <vector>

namespace openxc {

class Client {
public:
    Client();
    ~Client();

    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;

    // Open the RFCOMM serial connection to the OpenXC VI.
    //
    // deviceOrMac may be:
    //   • A full device path  – "/dev/cu.OpenXC-VI-04C461C369D0"
    //   • A Bluetooth MAC     – "04:C4:61:C3:69:D0"  (auto-resolved to
    //                           /dev/cu.OpenXC-VI-04C461C369D0)
    //
    // Returns true on success.  The connection persists across multiple
    // sendDiagnostic() calls (no per-request reconnect overhead).
    bool connect(const std::string& deviceOrMac, std::string& err);

    bool isConnected() const { return fd_ >= 0; }
    const std::string& connectedPath() const { return connectedPath_; }
    void disconnect();

    // Send a UDS request and receive the response over the OpenXC VI.
    //
    // arbId     – CAN arbitration ID (e.g. 0x7E0 for targeted, 0x7DF for
    //             functional broadcast)
    // udsReq    – Full UDS PDU: [mode, param0, param1, ...]
    //             e.g. {0x22, 0xF1, 0x90} for ReadDataByIdentifier 0xF190
    // udsResp   – Reconstructed UDS response PDU on success
    //             Positive: [mode+0x40, ...]
    //             Negative: [0x7F, mode, NRC]
    // timeoutMs – How long to wait for a diagnostic response line
    // bus       – OpenXC CAN bus index (1 = primary)
    //
    // Returns true when a response was received (check udsResp[0] for +/-).
    bool sendDiagnostic(uint32_t              arbId,
                        const std::vector<uint8_t>& udsReq,
                        std::vector<uint8_t>& udsResp,
                        int                   timeoutMs,
                        int                   bus,
                        std::string&          err);

private:
    // Resolve a MAC address or device path to the actual /dev/cu.* path.
    static std::string resolvePath(const std::string& deviceOrMac,
                                   std::string& err);

    // Write all bytes to fd_, handling EINTR.
    bool writeAll(const char* data, size_t n, std::string& err);

    // Read one newline-terminated line within timeoutMs ms.
    bool readLine(std::string& line, int timeoutMs, std::string& err);

    // Build the OpenXC JSON diagnostic_request string (without trailing '\n').
    static std::string buildRequest(uint32_t                     arbId,
                                    const std::vector<uint8_t>&  udsReq,
                                    int                          bus);

    // Parse an OpenXC JSON diagnostic_response line into a raw UDS PDU.
    // Returns true when a complete diagnostic response was found.
    // Returns false when the line is not a diagnostic response (vehicle data
    // message) — caller should skip and read the next line.
    static bool parseResponse(const std::string&    jsonLine,
                               uint8_t               requestMode,
                               std::vector<uint8_t>& udsResp,
                               std::string&          err);

    int fd_ = -1;
    std::string connectedPath_;
};

} // namespace openxc
