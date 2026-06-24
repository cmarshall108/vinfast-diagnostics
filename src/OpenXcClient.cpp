#include "OpenXcClient.hpp"
#include "BtDiscovery.hpp"

// openxc/uds-c – DiagnosticRequest struct + UDS constants.
// isotp-c and bitfield-c are linked transitively.
extern "C" {
#include <uds/uds.h>
}

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>

namespace openxc {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Encode bytes as "0xAABBCC..."; returns "" for an empty span.
static std::string bytesToHexStr(const uint8_t* data, size_t len) {
    if (!data || len == 0) return "";
    std::ostringstream ss;
    ss << "0x";
    for (size_t i = 0; i < len; ++i)
        ss << std::hex << std::uppercase
           << std::setfill('0') << std::setw(2)
           << static_cast<int>(data[i]);
    return ss.str();
}

// Decode "0xAABBCC..." or "AABBCC..." into bytes.
static std::vector<uint8_t> hexStrToBytes(const std::string& hex) {
    const char* p = hex.c_str();
    if (hex.size() >= 2 && hex[0] == '0' &&
        (hex[1] == 'x' || hex[1] == 'X')) {
        p += 2;
    }
    std::vector<uint8_t> out;
    size_t len = std::strlen(p);
    for (size_t i = 0; i + 1 < len; i += 2) {
        char buf[3] = {p[i], p[i + 1], '\0'};
        out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tiny JSON field extractors (no external JSON library required)
// ---------------------------------------------------------------------------

static bool jsonGetBool(const std::string& json,
                        const std::string& key, bool& out) {
    auto pos = json.find('"' + key + '"');
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + key.size() + 2);
    if (pos == std::string::npos) return false;
    while (++pos < json.size() && json[pos] == ' ') {}
    if (json.compare(pos, 4, "true")  == 0) { out = true;  return true; }
    if (json.compare(pos, 5, "false") == 0) { out = false; return true; }
    return false;
}

static bool jsonGetInt(const std::string& json,
                       const std::string& key, int& out) {
    auto pos = json.find('"' + key + '"');
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + key.size() + 2);
    if (pos == std::string::npos) return false;
    while (++pos < json.size() && json[pos] == ' ') {}
    if (pos >= json.size()) return false;
    char* end = nullptr;
    long val = std::strtol(json.c_str() + pos, &end, 10);
    if (end == json.c_str() + pos) return false;
    out = static_cast<int>(val);
    return true;
}

static bool jsonGetString(const std::string& json,
                          const std::string& key, std::string& out) {
    auto pos = json.find('"' + key + '"');
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + key.size() + 2);
    if (pos == std::string::npos) return false;
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return false;
    ++pos; // skip opening quote
    out.clear();
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) ++pos;
        out += json[pos++];
    }
    return true;
}

// ---------------------------------------------------------------------------
// Client implementation
// ---------------------------------------------------------------------------

Client::Client() = default;

Client::~Client() { disconnect(); }

void Client::disconnect() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    connectedPath_.clear();
}

// Resolve a Bluetooth MAC, device name, or /dev/ path to the serial device
// path using BtDiscovery (IOBluetooth on macOS).
std::string Client::resolvePath(const std::string& deviceOrMac,
                                std::string& err) {
    return bt::resolveDevicePath(deviceOrMac, err);
}

bool Client::connect(const std::string& deviceOrMac, std::string& err) {
    disconnect();

    std::string path = resolvePath(deviceOrMac, err);
    if (path.empty()) return false;

    fd_ = ::open(path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd_ < 0) {
        err = "Cannot open " + path + ": " + std::strerror(errno);
        return false;
    }

    // Switch back to blocking mode — we use select() for timeouts ourselves.
    int flags = fcntl(fd_, F_GETFL, 0);
    if (flags == -1 || fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        err = "fcntl failed: " + std::string(std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    // Configure raw mode; ignore errors since Bluetooth serial adapters often
    // don't support all termios attributes.
    struct termios tty{};
    if (tcgetattr(fd_, &tty) == 0) {
        cfmakeraw(&tty);
        tty.c_cc[VMIN]  = 0;
        tty.c_cc[VTIME] = 0;
        tcsetattr(fd_, TCSANOW, &tty);
    }

    connectedPath_ = path;

    return true;
}

bool Client::writeAll(const char* data, size_t n, std::string& err) {
    size_t written = 0;
    while (written < n) {
        ssize_t rc = ::write(fd_, data + written, n - written);
        if (rc < 0) {
            if (errno == EINTR) continue;
            err = "write error: " + std::string(std::strerror(errno));
            return false;
        }
        written += static_cast<size_t>(rc);
    }
    return true;
}

bool Client::readLine(std::string& line, int timeoutMs, std::string& err) {
    line.clear();
    using Clock = std::chrono::steady_clock;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);

    while (true) {
        auto now = Clock::now();
        if (now >= deadline) { err = "Response timeout"; return false; }

        auto usLeft = std::chrono::duration_cast<std::chrono::microseconds>(
            deadline - now).count();

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd_, &rfds);
        struct timeval tv{};
        tv.tv_sec  = usLeft / 1000000;
        tv.tv_usec = usLeft % 1000000;

        int ready = select(fd_ + 1, &rfds, nullptr, nullptr, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            err = "select error: " + std::string(std::strerror(errno));
            return false;
        }
        if (ready == 0) { err = "Response timeout"; return false; }

        char c;
        ssize_t rc = ::read(fd_, &c, 1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            err = "read error: " + std::string(std::strerror(errno));
            return false;
        }
        if (rc == 0) { err = "EOF on OpenXC serial device"; return false; }
        if (c == '\n') return true;
        if (c != '\r') line += c;
    }
}

// ---------------------------------------------------------------------------
// OpenXC JSON protocol
// ---------------------------------------------------------------------------

//
// Build the OpenXC diagnostic_request JSON string.
//
// Uses DiagnosticRequest from openxc/uds-c to validate that the mode byte
// and payload are well-formed before serialising to JSON.
//
std::string Client::buildRequest(uint32_t                    arbId,
                                 const std::vector<uint8_t>& udsReq,
                                 int                         bus) {
    // Populate a uds-c DiagnosticRequest from the raw UDS PDU so we benefit
    // from the library's field definitions and constants.
    DiagnosticRequest dr{};
    dr.arbitration_id = arbId;
    dr.mode           = udsReq[0];
    if (udsReq.size() > 1) {
        size_t payloadLen = udsReq.size() - 1;
        // Clamp to the library's hard limit (7 bytes); larger payloads are
        // uncommon in the diagnostics we issue but would be truncated here.
        if (payloadLen > MAX_UDS_REQUEST_PAYLOAD_LENGTH)
            payloadLen = MAX_UDS_REQUEST_PAYLOAD_LENGTH;
        std::memcpy(dr.payload, udsReq.data() + 1, payloadLen);
        dr.payload_length = static_cast<uint8_t>(payloadLen);
    }

    std::string payloadStr =
        bytesToHexStr(dr.payload_length ? dr.payload : nullptr,
                      dr.payload_length);

    std::ostringstream json;
    json << "{\"command\":\"diagnostic_request\",\"request\":{"
         << "\"id\":"    << dr.arbitration_id
         << ",\"mode\":" << static_cast<int>(dr.mode)
         << ",\"bus\":"  << bus;
    if (!payloadStr.empty())
        json << ",\"payload\":\"" << payloadStr << "\"";
    json << "},\"action\":\"add\"}";
    return json.str();
}

//
// Parse one line of OpenXC JSON into a reconstructed UDS response PDU.
//
// OpenXC diagnostic_response format:
//   {"bus":1,"id":2048,"mode":34,"success":true,"payload":"0xF190..."}
//
// Reconstruction rules:
//   success=true  → [mode+0x40] + payload_bytes
//   success=false → [0x7F, mode, NRC_from_payload_byte_0_or_0x22]
//
// Returns false (without setting err) when the line is a vehicle-data message
// rather than a diagnostic response — caller should skip and try next line.
//
bool Client::parseResponse(const std::string&    jsonLine,
                            uint8_t               requestMode,
                            std::vector<uint8_t>& udsResp,
                            std::string&          err) {
    udsResp.clear();

    // Heuristic: diagnostic response lines always contain a "mode" field.
    if (jsonLine.find("\"mode\"") == std::string::npos)
        return false; // vehicle data message – skip

    bool success = false;
    int  mode    = 0;
    std::string payload;

    jsonGetBool  (jsonLine, "success", success);
    jsonGetInt   (jsonLine, "mode",    mode);

    if (!success) {
        // Negative response: 0x7F + requestMode + NRC
        uint8_t nrc = static_cast<uint8_t>(NRC_CONDITIONS_NOT_CORRECT);
        if (jsonGetString(jsonLine, "payload", payload) && !payload.empty()) {
            auto bytes = hexStrToBytes(payload);
            if (!bytes.empty()) nrc = bytes[0];
        }
        udsResp = {0x7Fu, requestMode,
                   static_cast<uint8_t>(nrc)};
        return true;
    }

    // Positive response: [mode+0x40] + payload bytes
    udsResp.push_back(static_cast<uint8_t>((mode & 0xFF) + 0x40u));
    if (jsonGetString(jsonLine, "payload", payload) && !payload.empty()) {
        auto payloadBytes = hexStrToBytes(payload);
        udsResp.insert(udsResp.end(), payloadBytes.begin(), payloadBytes.end());
    }

    (void)err; // no parse error at this point
    return true;
}

// ---------------------------------------------------------------------------
// Public send/receive
// ---------------------------------------------------------------------------

bool Client::sendDiagnostic(uint32_t                    arbId,
                             const std::vector<uint8_t>& udsReq,
                             std::vector<uint8_t>&       udsResp,
                             int                         timeoutMs,
                             int                         bus,
                             std::string&                err) {
    if (fd_ < 0) { err = "OpenXC VI not connected"; return false; }
    if (udsReq.empty()) { err = "Empty UDS request"; return false; }

    const uint8_t requestMode = udsReq[0];

    // Send the JSON request terminated with a newline.
    std::string json = buildRequest(arbId, udsReq, bus) + "\n";
    if (!writeAll(json.c_str(), json.size(), err)) return false;

    // Read response lines, discarding vehicle-data messages, until we receive
    // a diagnostic response or the budget expires.
    using Clock = std::chrono::steady_clock;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);

    while (Clock::now() < deadline) {
        auto msLeft = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now()).count();
        if (msLeft <= 0) break;

        std::string line;
        std::string lineErr;
        if (!readLine(line, static_cast<int>(msLeft), lineErr)) {
            err = lineErr;
            return false;
        }
        if (line.empty()) continue;

        std::string parseErr;
        if (parseResponse(line, requestMode, udsResp, parseErr))
            return true;
        // Non-diagnostic line (vehicle data) – keep reading.
    }

    err = "Timeout waiting for OpenXC diagnostic response";
    return false;
}

} // namespace openxc
