#pragma once
//
// OpenXcClient.hpp
//
// Connects to an OpenXC Vehicle Interface over a USB or Bluetooth serial port
// and exchanges UDS diagnostic requests / responses using the OpenXC JSON
// message format.
//
// Uses openxc/uds-c (github.com/openxc/uds-c) for DiagnosticRequest struct
// validation and openxc/isotp-c + openxc/bitfield-c as transitive deps.
//
// The public sendDiagnostic() API accepts/returns raw UDS PDU byte vectors so
// UDSClient does not need changes.
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

    // Open the serial connection to the OpenXC VI.
    //
    // deviceOrMac may be:
    //   • A full USB/serial device path – "/dev/ttyUSB0", "/dev/cu.usbmodem*",
    //     "COM3", etc.
    //   • A Bluetooth MAC – "04:C4:61:C3:69:D0" (auto-resolved to the
    //     RFCOMM serial device when supported by the platform)
    //
    // USB paths are used as-is; Bluetooth MACs are resolved via BtDiscovery.
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

    // Send an arbitrary OpenXC command (JSON, without trailing '\n') and read
    // the first response line within timeoutMs.  Returns true when a line was
    // read; false on timeout/error.  Useful for VI setup commands such as
    // af_bypass / predefined_obd2 before diagnostic traffic begins.
    bool sendCommand(const std::string& command, std::string& response,
                     int timeoutMs, std::string& err);

    // Return a list of candidate USB/serial device paths for the OpenXC VI.
    // The list is platform-specific:
    //   • macOS: /dev/cu.usbmodem*, /dev/cu.usbserial*, /dev/tty.usbmodem*, ...
    //   • Linux: /dev/ttyUSB*, /dev/ttyACM*
    //   • Windows: COM1 .. COM256 (filtered to those that exist)
    // Paths are sorted with common OpenXC/VI patterns first.
    static std::vector<std::string> enumerateUsbSerialPorts();

private:
    // Resolve a user-supplied identifier to the actual serial device path.
    // If the input already looks like a path or COM port it is returned as-is;
    // otherwise it is treated as a Bluetooth MAC/name and resolved via
    // BtDiscovery.
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
