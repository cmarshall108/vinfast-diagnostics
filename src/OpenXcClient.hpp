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
#include <mutex>
#include <string>
#include <vector>

namespace bt { class Connection; }

namespace openxc {

struct DiagnosticFrame {
    uint32_t             arbitrationId = 0;
    int                  bus = 0;
    std::vector<uint8_t> uds;
};

struct RawCanFrame {
    uint32_t             arbitrationId = 0;
    int                  bus = 0;
    std::vector<uint8_t> data;
};

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
    //   • A native raw-USB token – "usb" or "usb:1BC4:0001" (VID:PID). The
    //     stock Ford OpenXC VI exposes a vendor-specific USB interface (bulk
    //     endpoints, no serial port); when built with libusb the client talks
    //     to it directly instead of through a /dev serial node.
    //
    // USB paths are used as-is; Bluetooth MACs are resolved via BtDiscovery.
    // Returns true on success.  The connection persists across multiple
    // sendDiagnostic() calls (no per-request reconnect overhead).
    bool connect(const std::string& deviceOrMac, std::string& err);

    bool isConnected() const;
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
    // expectedId – OpenXC diagnostic_response "id" to accept. Stock VI firmware
    //             publishes the *request* arbitration id for physical replies
    //             (response_arb - 8), and the real module arb id for functional
    //             0x7DF replies. Pass arbId for physical; 0 to accept any.
    // timeoutMs – How long to wait for a diagnostic response line
    // bus       – OpenXC CAN bus index (1 = primary)
    //
    // Returns true when a response was received (check udsResp[0] for +/-).
    bool sendDiagnostic(uint32_t              arbId,
                        uint32_t              expectedId,
                        const std::vector<uint8_t>& udsReq,
                        std::vector<uint8_t>& udsResp,
                        int                   timeoutMs,
                        int                   bus,
                        std::string&          err);

    // Send one request and collect every matching diagnostic response within
    // collectMs. expected response IDs are intentionally not constrained here;
    // callers use arbitrationId on each frame to distinguish responders.
    bool sendDiagnosticMulti(uint32_t                    arbId,
                             const std::vector<uint8_t>& udsReq,
                             std::vector<DiagnosticFrame>& responses,
                             int                         collectMs,
                             int                         bus,
                             std::string&                err);

    // Wait for the next raw OpenXC CAN passthrough message. Non-CAN messages
    // are skipped until timeout; diagnostic exchanges remain serialized by
    // the same I/O mutex.
    bool receiveCanFrame(RawCanFrame& frame, int timeoutMs, std::string& err);

    // Send an arbitrary OpenXC command (JSON, without trailing delimiter) and
    // read the first response message within timeoutMs.  Returns true when a
    // message was read; false on timeout/error.  Useful for VI setup commands such as
    // af_bypass / predefined_obd2 before diagnostic traffic begins.
    bool sendCommand(const std::string& command, std::string& response,
                     int timeoutMs, std::string& err);

    // Requests the custom Fordboard bootloader on the next reset. The device
    // intentionally disconnects before it can acknowledge this command.
    bool requestBootloader(std::string& err);

    // Return a list of candidate USB/serial device paths for the OpenXC VI.
    // The list is platform-specific:
    //   • macOS: /dev/cu.usbmodem*, /dev/cu.usbserial*, /dev/tty.usbmodem*, ...
    //   • Linux: /dev/ttyUSB*, /dev/ttyACM*
    //   • Windows: COM1 .. COM256 (filtered to those that exist)
    // Paths are sorted with common OpenXC/VI patterns first.
    static std::vector<std::string> enumerateUsbSerialPorts();

    // Diagnostics for the most recent sendDiagnostic() exchange: how many
    // OpenXC messages the VI returned (even non-matching / vehicle-data ones)
    // and a short sample of the last one. Lets the transport distinguish "VI
    // saw CAN traffic but nothing matched the target" from "VI returned nothing
    // at all" (no live bus) when a request gets no response.
    int                lastRxCount()  const { return lastRxCount_; }
    const std::string& lastRxSample() const { return lastRxSample_; }

private:
    // Resolve a user-supplied identifier to the actual serial device path.
    // If the input already looks like a path or COM port it is returned as-is;
    // otherwise it is treated as a Bluetooth MAC/name and resolved via
    // BtDiscovery.
    static std::string resolvePath(const std::string& deviceOrMac,
                                   std::string& err);

    // Write all bytes to the serial handle.
    bool writeAll(const char* data, size_t n, std::string& err);

    // Read one OpenXC message within timeoutMs ms. Stock firmware uses NUL
    // delimiters; newline is accepted for traces and development tools.
    bool readLine(std::string& line, int timeoutMs, std::string& err);

    // Native raw-USB (libusb) backend for VIs that expose a vendor-specific
    // bulk interface instead of a serial port. `token` is "usb" or
    // "usb:VID:PID". No-op returning false when built without libusb.
    bool connectUsb(const std::string& token, std::string& err);
    // Read one NUL/newline-delimited message from the buffered USB bulk stream.
    bool readLineUsb(std::string& line, int timeoutMs, std::string& err);
    void drainUsbInput();
    // True when `token` names the native USB backend ("usb" / "usb:VID:PID").
    static bool isUsbToken(const std::string& token);

    // Build the OpenXC JSON diagnostic_request string without its delimiter.
    static std::string buildRequest(uint32_t                     arbId,
                                    const std::vector<uint8_t>&  udsReq,
                                    int                          bus);

    // Parse an OpenXC JSON diagnostic_response line into a raw UDS PDU.
    // Returns true when a complete diagnostic response was found.
    // Returns false when the line is not a diagnostic response (vehicle data
    // message) — caller should skip and read the next line.
    // expectedId is the OpenXC-published id (request arb for physical), not
    // necessarily the raw CAN response arbitration id.
    static bool parseResponse(const std::string& jsonLine,
                              const std::vector<uint8_t>& udsReq,
                              uint32_t expectedId,
                              int expectedBus,
                              DiagnosticFrame& frame,
                              std::string& err);

#ifdef _WIN32
    void* handle_ = nullptr;  // HANDLE without pulling windows.h into the header
#else
    int fd_ = -1;
#endif
    bt::Connection* btConnection_ = nullptr;
    // Native raw-USB (libusb) backend state. void* keeps libusb.h out of the
    // header; these stay null/false unless a "usb[:VID:PID]" connection is open.
    void*         usbHandle_ = nullptr;   // libusb_device_handle*
    void*         usbCtx_    = nullptr;   // libusb_context*
    bool          usbMode_   = false;
    bool          usbInterfaceClaimed_ = false;
    int           usbIface_  = 0;
    unsigned char usbEpIn_   = 0x82;      // bulk IN  (VI -> host JSON stream)
    unsigned char usbEpOut_  = 0x05;      // bulk OUT (host -> VI commands)
    std::string   usbRxBuf_;              // buffered bytes awaiting delimiter
    int           lastRxCount_ = 0;       // messages seen in last sendDiagnostic
    std::string   lastRxSample_;          // sample of the last message seen
    mutable std::mutex ioMutex_;           // serializes USB/serial request-response exchanges
    std::atomic<bool> isConnected_{false}; // lock-free connection indicator
    std::string connectedPath_;

    bool isConnectedUnlocked() const;
    void disconnectUnlocked();
};

} // namespace openxc
