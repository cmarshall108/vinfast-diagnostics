#include "DoIPClient.hpp"
#include "Logger.hpp"

#include <cstring>
#include <chrono>

#ifdef _WIN32
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <sys/time.h>
  #include <sys/select.h>
#endif

namespace doip {

// Upper bound on a single DoIP payload we will accept/allocate. Diagnostic
// scanner traffic is small; this guards against a corrupt/hostile length field
// triggering a multi-gigabyte allocation (robustness / DoS protection).
constexpr uint32_t kMaxPayload = 64u * 1024u;

// UDS negative-response framing constants.
constexpr uint8_t kUdsNegativeResponse = 0x7F;  // first byte of an NRC reply
constexpr uint8_t kNrcResponsePending  = 0x78;  // "request received, response pending"

// Routing activation response code: 0x10/0x11 indicate success.
constexpr uint8_t kRoutingActivationSuccess        = 0x10;
constexpr uint8_t kRoutingActivationSuccessConfirm = 0x11;

// Hard cap on consecutive 0x78 "response pending" frames before we give up, so
// a stuck ECU that streams pending forever cannot hang the worker indefinitely.
constexpr int kMaxResponsePending = 100;

// Decodes a DoIP Generic Header Negative Acknowledge code (payload 0x0000).
static const char* genericNackText(uint8_t c) {
    switch (c) {
        case 0x00: return "incorrect pattern format";
        case 0x01: return "unknown payload type";
        case 0x02: return "message too large";
        case 0x03: return "out of memory";
        case 0x04: return "invalid payload length";
        default:   return "reserved";
    }
}

// Trims a VIN read off the wire to printable ASCII so a non-conforming gateway
// cannot inject NULs/control characters into logs or the UI.
static std::string sanitizeVin(const char* p, size_t len) {
    std::string v;
    v.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)p[i];
        v.push_back((c >= 0x20 && c < 0x7F) ? (char)c : '?');
    }
    // Drop trailing padding/placeholder characters.
    while (!v.empty() && (v.back() == ' ' || v.back() == '?')) v.pop_back();
    return v;
}

// --- platform helpers ---------------------------------------------------
#ifdef _WIN32
static bool g_wsa = false;
static void ensureWsa() { if (!g_wsa) { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); g_wsa = true; } }
static int  closeSock(socket_t s) { return closesocket(s); }
#else
static void ensureWsa() {}
static int  closeSock(socket_t s) { return ::close(s); }
#endif

socket_t Client::invalidSocket() {
#ifdef _WIN32
    return INVALID_SOCKET;
#else
    return -1;
#endif
}

socket_t Client::invalidSocketValue() { return invalidSocket(); }

static void setRcvTimeout(socket_t s, int ms) {
#ifdef _WIN32
    DWORD t = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof t);
#else
    timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
#endif
}

// Builds an 8-byte DoIP generic header (version, ~version, type, length).
static std::vector<uint8_t> buildHeader(uint16_t type, uint32_t len) {
    std::vector<uint8_t> h;
    h.push_back(kProtocolVersion);
    h.push_back((uint8_t)~kProtocolVersion);
    h.push_back((type >> 8) & 0xFF);
    h.push_back(type & 0xFF);
    h.push_back((len >> 24) & 0xFF);
    h.push_back((len >> 16) & 0xFF);
    h.push_back((len >> 8) & 0xFF);
    h.push_back(len & 0xFF);
    return h;
}

Client::Client()  { ensureWsa(); tcp_ = invalidSocket(); }
Client::~Client() { disconnect(); }

// --- Discovery ----------------------------------------------------------
bool Client::discover(const std::string& broadcastIp, uint16_t port,
                      int timeoutMs, std::vector<Entity>& out, std::string& err) {
    return discoverImpl(broadcastIp, port, timeoutMs, VehicleIdentRequest, {}, out, err);
}

bool Client::discoverByVin(const std::string& broadcastIp, uint16_t port,
                           int timeoutMs, const std::string& vin,
                           std::vector<Entity>& out, std::string& err) {
    if (vin.size() != 17) { err = "VIN must be exactly 17 characters"; return false; }
    std::vector<uint8_t> pl(vin.begin(), vin.end());
    return discoverImpl(broadcastIp, port, timeoutMs, VehicleIdentReqVIN, pl, out, err);
}

bool Client::discoverByEid(const std::string& broadcastIp, uint16_t port,
                           int timeoutMs, const std::array<uint8_t, 6>& eid,
                           std::vector<Entity>& out, std::string& err) {
    std::vector<uint8_t> pl(eid.begin(), eid.end());
    return discoverImpl(broadcastIp, port, timeoutMs, VehicleIdentReqEID, pl, out, err);
}

bool Client::discoverImpl(const std::string& broadcastIp, uint16_t port,
                          int timeoutMs, uint16_t reqType,
                          const std::vector<uint8_t>& reqPayload,
                          std::vector<Entity>& out, std::string& err) {
    socket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == invalidSocket()) { err = "UDP socket creation failed"; return false; }

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char*)&yes, sizeof yes);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof yes);
    setRcvTimeout(s, timeoutMs);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    if (inet_pton(AF_INET, broadcastIp.c_str(), &dst.sin_addr) != 1) {
        err = "Invalid broadcast IP"; closeSock(s); return false;
    }

    // Vehicle Identification Request (broadcast: header only; targeted: VIN/EID
    // payload). Sent a few times because UDP is lossy and some gateways only
    // answer the request that arrives after their stack is ready.
    auto msg = buildHeader(reqType, (uint32_t)reqPayload.size());
    msg.insert(msg.end(), reqPayload.begin(), reqPayload.end());
    Logger::instance().hexDump(LogLevel::Tx, "UDP TX VehicleIdentRequest (x3)",
                               msg.data(), msg.size());
    bool anySent = false;
    for (int i = 0; i < 3; ++i) {
        if (sendto(s, (const char*)msg.data(), (int)msg.size(), 0,
                   (sockaddr*)&dst, sizeof dst) >= 0)
            anySent = true;
    }
    if (!anySent) {
        err = "sendto failed (broadcast not permitted on this interface?)";
        closeSock(s); return false;
    }

    // Collect every announcement/response that arrives before the timeout.
    uint8_t buf[512];
    while (true) {
        sockaddr_in from{};
#ifdef _WIN32
        int fl = sizeof from;
#else
        socklen_t fl = sizeof from;
#endif
        int n = recvfrom(s, (char*)buf, sizeof buf, 0, (sockaddr*)&from, &fl);
        if (n <= 0) break;  // timeout or error -> done collecting
        if (n < 8)  continue;

        uint16_t type = (buf[2] << 8) | buf[3];
        uint32_t plen = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                        ((uint32_t)buf[6] << 8) | buf[7];
        Logger::instance().hexDump(LogLevel::Rx, "UDP RX", buf, n);

        if (type != VehicleIdentResponse) continue;
        if ((int)plen + 8 > n || plen < 32) continue;

        const uint8_t* p = buf + 8;
        Entity e;
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, ipstr, sizeof ipstr);
        e.ip             = ipstr;
        e.vin            = sanitizeVin((const char*)p, 17);
        e.logicalAddress = (p[17] << 8) | p[18];
        std::memcpy(e.eid.data(), p + 19, 6);
        std::memcpy(e.gid.data(), p + 25, 6);
        e.furtherAction  = p[31];

        // De-duplicate (we sent the request multiple times).
        bool dup = false;
        for (const auto& x : out)
            if (x.ip == e.ip && x.logicalAddress == e.logicalAddress) { dup = true; break; }
        if (!dup) {
            Logger::instance().info("DoIP entity found: IP=" + e.ip +
                ", logical=0x" + byteHex((e.logicalAddress >> 8) & 0xFF) +
                byteHex(e.logicalAddress & 0xFF) + ", VIN=" + e.vin +
                ", EID=" + toHex(e.eid.data(), 6) + ", GID=" + toHex(e.gid.data(), 6) +
                ", furtherAction=0x" + byteHex(e.furtherAction));
            out.push_back(e);
        }
    }

    closeSock(s);
    if (out.empty()) { err = "No DoIP entities responded (timeout)"; return false; }
    Logger::instance().info("Discovery complete: " + std::to_string(out.size()) +
                            " entity(ies)");
    return true;
}

// Sends a single UDP DoIP request and returns the first matching response
// payload. Shared by Entity Status and Diagnostic Power Mode.
static bool udpRequest(const std::string& ip, uint16_t port, int timeoutMs,
                       uint16_t reqType, uint16_t wantType,
                       std::vector<uint8_t>& payloadOut, std::string& fromIp,
                       std::string& err) {
    socket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == Client::invalidSocketValue()) { err = "UDP socket creation failed"; return false; }
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char*)&yes, sizeof yes);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof yes);
    setRcvTimeout(s, timeoutMs);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &dst.sin_addr) != 1) {
        err = "Invalid IP"; closeSock(s); return false;
    }

    auto hdr = buildHeader(reqType, 0);
    Logger::instance().hexDump(LogLevel::Tx, "UDP TX", hdr.data(), hdr.size());
    if (sendto(s, (const char*)hdr.data(), (int)hdr.size(), 0,
               (sockaddr*)&dst, sizeof dst) < 0) {
        err = "sendto failed"; closeSock(s); return false;
    }

    uint8_t buf[512];
    while (true) {
        sockaddr_in from{};
#ifdef _WIN32
        int fl = sizeof from;
#else
        socklen_t fl = sizeof from;
#endif
        int n = recvfrom(s, (char*)buf, sizeof buf, 0, (sockaddr*)&from, &fl);
        if (n <= 0) break;
        if (n < 8) continue;
        Logger::instance().hexDump(LogLevel::Rx, "UDP RX", buf, n);
        uint16_t type = (buf[2] << 8) | buf[3];
        uint32_t plen = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                        ((uint32_t)buf[6] << 8) | buf[7];
        if (type != wantType) continue;
        if ((int)plen + 8 > n) plen = (uint32_t)(n - 8);
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, ipstr, sizeof ipstr);
        fromIp = ipstr;
        payloadOut.assign(buf + 8, buf + 8 + plen);
        closeSock(s);
        return true;
    }
    closeSock(s);
    err = "No response (timeout)";
    return false;
}

bool Client::entityStatus(const std::string& ip, uint16_t port, int timeoutMs,
                          EntityStatus& out, std::string& err) {
    std::vector<uint8_t> pl;
    if (!udpRequest(ip, port, timeoutMs, EntityStatusRequest, EntityStatusResponse,
                    pl, out.ip, err))
        return false;
    // Payload: nodeType(1) maxOpenSockets(1) currentlyOpenSockets(1) [maxDataSize(4)]
    if (pl.size() < 3) { err = "Entity status response too short"; return false; }
    out.nodeType       = pl[0];
    out.maxOpenSockets = pl[1];
    out.openSockets    = pl[2];
    if (pl.size() >= 7) {
        out.maxDataSize = ((uint32_t)pl[3] << 24) | ((uint32_t)pl[4] << 16) |
                          ((uint32_t)pl[5] << 8) | pl[6];
        out.hasMaxDataSize = true;
    }
    Logger::instance().info("DoIP entity status from " + out.ip + ": nodeType=0x" +
        byteHex(out.nodeType) + " (" + (out.nodeType == 0 ? "gateway" : "node") +
        "), sockets " + std::to_string(out.openSockets) + "/" +
        std::to_string(out.maxOpenSockets) +
        (out.hasMaxDataSize ? ", maxData=" + std::to_string(out.maxDataSize) + "B" : ""));
    return true;
}

bool Client::diagnosticPowerMode(const std::string& ip, uint16_t port, int timeoutMs,
                                 uint8_t& mode, std::string& err) {
    std::vector<uint8_t> pl; std::string from;
    if (!udpRequest(ip, port, timeoutMs, PowerModeInfoRequest, PowerModeInfoResponse,
                    pl, from, err))
        return false;
    if (pl.empty()) { err = "Power mode response empty"; return false; }
    mode = pl[0];
    const char* t = mode == 0 ? "not ready" : mode == 1 ? "ready"
                   : mode == 2 ? "not supported" : "reserved";
    Logger::instance().info("DoIP diagnostic power mode from " + from + ": 0x" +
                            byteHex(mode) + " (" + t + ")");
    return true;
}


// --- TCP session --------------------------------------------------------
// Connect with a bounded timeout so a wrong/unreachable gateway IP does not
// hang the worker thread for the OS default (~1-2 minutes).
static bool connectWithTimeout(socket_t s, sockaddr_in* a, int timeoutMs) {
#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int r = ::connect(s, (sockaddr*)a, sizeof *a);
    if (r == 0) { nb = 0; ioctlsocket(s, FIONBIO, &nb); return true; }
    if (WSAGetLastError() != WSAEWOULDBLOCK) return false;
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    int r = ::connect(s, (sockaddr*)a, sizeof *a);
    if (r == 0) { fcntl(s, F_SETFL, flags); return true; }
    if (errno != EINPROGRESS) return false;
#endif
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(s, &wset);
    timeval tv;
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    int sel = select((int)s + 1, nullptr, &wset, nullptr, &tv);
    if (sel <= 0) return false;  // timeout or error

    int soerr = 0;
#ifdef _WIN32
    int len = sizeof soerr;
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soerr, &len);
    u_long bk = 0; ioctlsocket(s, FIONBIO, &bk);
#else
    socklen_t len = sizeof soerr;
    getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &len);
    fcntl(s, F_SETFL, flags);
#endif
    return soerr == 0;
}

bool Client::connectTcp(const std::string& ip, uint16_t port, std::string& err,
                        int connectTimeoutMs, int rcvTimeoutMs) {
    disconnect();
    socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == invalidSocket()) { err = "TCP socket creation failed"; return false; }

    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) {
        err = "Invalid gateway IP"; closeSock(s); return false;
    }
    if (!connectWithTimeout(s, &a, connectTimeoutMs)) {
        err = "TCP connect failed/timeout to " + ip + " (check IP, cable, and "
              "that the DoIP gateway is reachable on this interface)";
        closeSock(s);
        return false;
    }
    // Disable Nagle: diagnostic frames are tiny request/response pairs, so
    // coalescing only adds latency to every exchange.
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);
    setRcvTimeout(s, rcvTimeoutMs);
    tcp_ = s;
    Logger::instance().info("TCP connected to " + ip + ":" + std::to_string(port));
    return true;
}

void Client::disconnect() {
    if (tcp_ != invalidSocket()) {
        closeSock(tcp_);
        tcp_ = invalidSocket();
    }
}

bool Client::sendAll(socket_t s, const uint8_t* d, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, (const char*)d + sent, (int)(len - sent), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

bool Client::recvAll(socket_t s, uint8_t* d, size_t len, int timeoutMs) {
    setRcvTimeout(s, timeoutMs);
    size_t got = 0;
    while (got < len) {
        int n = recv(s, (char*)d + got, (int)(len - got), 0);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

bool Client::readDoIPMessage(socket_t s, uint16_t& type,
                             std::vector<uint8_t>& payload, int timeoutMs,
                             std::string& err) {
    uint8_t h[8];
    if (!recvAll(s, h, 8, timeoutMs)) { err = "DoIP header read timeout"; return false; }

    // Validate the protocol version / inverse-version pair. Accept 0x01 and
    // 0x02 (ISO 13400-2:2010/2012); warn but continue on anything else.
    if (h[0] != (uint8_t)~h[1]) {
        Logger::instance().warn("DoIP header version/inverse mismatch (0x" +
            byteHex(h[0]) + " / 0x" + byteHex(h[1]) + ")");
    } else if (h[0] != 0x01 && h[0] != 0x02) {
        Logger::instance().warn("Unexpected DoIP protocol version 0x" + byteHex(h[0]));
    }

    type = (h[2] << 8) | h[3];
    uint32_t len = ((uint32_t)h[4] << 24) | ((uint32_t)h[5] << 16) |
                   ((uint32_t)h[6] << 8) | h[7];
    if (len > kMaxPayload) {
        err = "DoIP payload length " + std::to_string(len) +
              " exceeds sane limit (" + std::to_string(kMaxPayload) + ")";
        return false;
    }
    payload.resize(len);
    if (len > 0 && !recvAll(s, payload.data(), len, timeoutMs)) {
        err = "DoIP payload read timeout"; return false;
    }

    std::vector<uint8_t> full(h, h + 8);
    full.insert(full.end(), payload.begin(), payload.end());
    Logger::instance().hexDump(LogLevel::Rx, "TCP RX", full.data(), full.size());
    return true;
}

// --- Routing activation -------------------------------------------------
bool Client::routingActivation(uint16_t sourceAddr, uint8_t activationType,
                               std::string& err,
                               const std::vector<uint8_t>& oemSpecific) {
    if (!isConnected()) { err = "Not connected"; return false; }
    testerAddr_ = sourceAddr;

    std::vector<uint8_t> pl;
    pl.push_back((sourceAddr >> 8) & 0xFF);
    pl.push_back(sourceAddr & 0xFF);
    pl.push_back(activationType);
    pl.insert(pl.end(), {0x00, 0x00, 0x00, 0x00});  // ISO reserved
    // Optional 4-byte OEM-specific field (some gateways require it).
    if (oemSpecific.size() == 4)
        pl.insert(pl.end(), oemSpecific.begin(), oemSpecific.end());
    else if (!oemSpecific.empty())
        Logger::instance().warn("Ignoring OEM routing-activation field (must be 4 bytes, got " +
                                std::to_string(oemSpecific.size()) + ")");

    auto msg = buildHeader(RoutingActivationRequest, (uint32_t)pl.size());
    msg.insert(msg.end(), pl.begin(), pl.end());
    Logger::instance().hexDump(LogLevel::Tx, "TCP TX RoutingActivation",
                               msg.data(), msg.size());
    if (!sendAll(tcp_, msg.data(), msg.size())) {
        err = "send routing activation failed"; return false;
    }

    uint16_t type;
    std::vector<uint8_t> resp;
    if (!readDoIPMessage(tcp_, type, resp, 3000, err)) return false;
    if (type == GenericHeaderNack) {
        uint8_t nack = resp.empty() ? 0xFF : resp[0];
        err = "DoIP generic header NACK (code 0x" + byteHex(nack) + ": " +
              genericNackText(nack) + ")";
        return false;
    }
    if (type != RoutingActivationResponse) {
        err = "Unexpected response to routing activation (type 0x" +
              byteHex((type >> 8) & 0xFF) + byteHex(type & 0xFF) + ")";
        return false;
    }
    if (resp.size() < 5) { err = "Routing activation response too short"; return false; }

    // Byte 4 = routing activation response code; 0x10 = success.
    uint8_t code = resp[4];
    // Standard ISO 13400-2 routing activation response codes.
    auto codeText = [](uint8_t c) -> const char* {
        switch (c) {
            case 0x00: return "unknown source address denied";
            case 0x01: return "all sockets registered/active";
            case 0x02: return "SA different from activation request";
            case 0x03: return "SA already registered on another socket";
            case 0x04: return "missing authentication";
            case 0x05: return "rejected confirmation";
            case 0x06: return "unsupported activation type";
            case 0x10: return "success";
            case 0x11: return "success, requires confirmation";
            default:   return "manufacturer-specific / reserved";
        }
    };
    if (resp.size() >= 4) {
        uint16_t logicalGw = (resp[2] << 8) | resp[3];
        Logger::instance().info("Routing activation response: tester logical 0x" +
            byteHex(resp[0]) + byteHex(resp[1]) + ", gateway logical 0x" +
            byteHex((logicalGw >> 8) & 0xFF) + byteHex(logicalGw & 0xFF) +
            ", code 0x" + byteHex(code) + " (" + codeText(code) + ")");
    }
    if (code != kRoutingActivationSuccess && code != kRoutingActivationSuccessConfirm) {
        err = "Routing activation rejected (code 0x" + byteHex(code) + ": " +
              codeText(code) + ")";
        return false;
    }
    Logger::instance().info("Routing activation success (tester 0x" +
                            byteHex((sourceAddr >> 8) & 0xFF) + byteHex(sourceAddr & 0xFF) + ")");
    return true;
}

// --- Diagnostic message exchange ----------------------------------------
bool Client::sendDiagnostic(uint16_t source, uint16_t target,
                            const std::vector<uint8_t>& uds,
                            std::vector<uint8_t>& response, int timeoutMs,
                            std::string& err, bool functional) {
    if (!isConnected()) { err = "Not connected"; return false; }

    std::vector<uint8_t> pl;
    pl.push_back((source >> 8) & 0xFF);
    pl.push_back(source & 0xFF);
    pl.push_back((target >> 8) & 0xFF);
    pl.push_back(target & 0xFF);
    pl.insert(pl.end(), uds.begin(), uds.end());

    auto msg = buildHeader(DiagnosticMessage, (uint32_t)pl.size());
    msg.insert(msg.end(), pl.begin(), pl.end());
    Logger::instance().hexDump(LogLevel::Tx, "TCP TX DiagnosticMessage",
                               msg.data(), msg.size());
    if (!sendAll(tcp_, msg.data(), msg.size())) {
        err = "send diagnostic failed"; return false;
    }

    // Expect: DiagnosticPositiveAck (0x8002), then DiagnosticMessage (0x8001).
    // Absorb acks, alive-checks and UDS response-pending (0x78). A wall-clock
    // deadline (not a fixed iteration count) bounds the wait so legitimately
    // slow ECUs that emit many 0x78 frames are not cut off prematurely; each
    // 0x78 refreshes the deadline (UDS P2*server behaviour).
    using clock = std::chrono::steady_clock;
    auto deadline = clock::now() + std::chrono::milliseconds(timeoutMs);
    int pendingCount = 0;
    while (true) {
        auto now = clock::now();
        if (now >= deadline) break;
        int remaining = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - now).count();
        if (remaining <= 0) break;

        uint16_t type;
        std::vector<uint8_t> resp;
        if (!readDoIPMessage(tcp_, type, resp, remaining, err)) return false;

        if (type == GenericHeaderNack) {
            uint8_t nack = resp.empty() ? 0xFF : resp[0];
            err = "DoIP generic header NACK (code 0x" + byteHex(nack) + ": " +
                  genericNackText(nack) + ")";
            return false;
        }
        if (type == DiagnosticPositiveAck) continue;
        if (type == DiagnosticNegativeAck) {
            uint8_t nack = resp.size() >= 5 ? resp[4] : 0xFF;
            err = "DoIP diagnostic negative ack (code 0x" + byteHex(nack) + ")";
            return false;
        }
        if (type == AliveCheckRequest) {
            std::vector<uint8_t> apl = {(uint8_t)((source >> 8) & 0xFF),
                                        (uint8_t)(source & 0xFF)};
            auto ack = buildHeader(AliveCheckResponse, 2);
            ack.insert(ack.end(), apl.begin(), apl.end());
            sendAll(tcp_, ack.data(), ack.size());
            continue;
        }
        if (type == DiagnosticMessage) {
            if (resp.size() < 4) { err = "Diagnostic message too short"; return false; }
            // Validate addressing: byte 0..1 = responder (the ECU we targeted),
            // byte 2..3 = recipient (us). For physical addressing, ignore frames
            // not addressed to our tester. Functional addressing relaxes the
            // responder check (any ECU in the group may answer).
            uint16_t respSource = (resp[0] << 8) | resp[1];
            uint16_t respTarget = (resp[2] << 8) | resp[3];
            if (respTarget != source) {
                Logger::instance().warn("Ignoring diagnostic frame not addressed to "
                    "tester (target 0x" + byteHex((respTarget >> 8) & 0xFF) +
                    byteHex(respTarget & 0xFF) + ")");
                continue;
            }
            if (!functional && respSource != target) {
                Logger::instance().warn("Ignoring diagnostic frame from unexpected "
                    "source 0x" + byteHex((respSource >> 8) & 0xFF) +
                    byteHex(respSource & 0xFF) + " (expected 0x" +
                    byteHex((target >> 8) & 0xFF) + byteHex(target & 0xFF) + ")");
                continue;
            }
            std::vector<uint8_t> ud(resp.begin() + 4, resp.end());  // strip src/target
            // UDS response pending: 0x7F <SID> 0x78 -> keep waiting, refresh deadline.
            if (ud.size() >= 3 && ud[0] == kUdsNegativeResponse &&
                ud[2] == kNrcResponsePending) {
                if (++pendingCount > kMaxResponsePending) {
                    err = "Too many UDS response-pending (0x78) frames"; return false;
                }
                Logger::instance().info("UDS response pending (NRC 0x78), waiting...");
                deadline = clock::now() + std::chrono::milliseconds(timeoutMs);
                continue;
            }
            response = ud;
            return true;
        }
        // Ignore anything else and keep reading.
    }
    err = "No diagnostic response received";
    return false;
}

bool Client::sendDiagnosticMulti(uint16_t source, uint16_t target,
                                 const std::vector<uint8_t>& uds,
                                 std::vector<DiagResponse>& responses,
                                 int collectMs, std::string& err) {
    if (!isConnected()) { err = "Not connected"; return false; }

    std::vector<uint8_t> pl;
    pl.push_back((source >> 8) & 0xFF);
    pl.push_back(source & 0xFF);
    pl.push_back((target >> 8) & 0xFF);
    pl.push_back(target & 0xFF);
    pl.insert(pl.end(), uds.begin(), uds.end());

    auto msg = buildHeader(DiagnosticMessage, (uint32_t)pl.size());
    msg.insert(msg.end(), pl.begin(), pl.end());
    Logger::instance().hexDump(LogLevel::Tx, "TCP TX DiagnosticMessage (functional)",
                               msg.data(), msg.size());
    if (!sendAll(tcp_, msg.data(), msg.size())) {
        err = "send functional diagnostic failed"; return false;
    }

    // Collect for the whole window; multiple ECUs in the functional group may
    // each answer, so never return on the first reply.
    using clock = std::chrono::steady_clock;
    auto deadline = clock::now() + std::chrono::milliseconds(collectMs);
    while (true) {
        auto now = clock::now();
        if (now >= deadline) break;
        int remaining = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - now).count();
        if (remaining <= 0) break;

        uint16_t type;
        std::vector<uint8_t> resp;
        std::string rerr;
        if (!readDoIPMessage(tcp_, type, resp, remaining, rerr)) break;  // window elapsed

        if (type == DiagnosticPositiveAck || type == DiagnosticNegativeAck) continue;
        if (type == AliveCheckRequest) {
            std::vector<uint8_t> apl = {(uint8_t)((source >> 8) & 0xFF),
                                        (uint8_t)(source & 0xFF)};
            auto ack = buildHeader(AliveCheckResponse, 2);
            ack.insert(ack.end(), apl.begin(), apl.end());
            sendAll(tcp_, ack.data(), ack.size());
            continue;
        }
        if (type != DiagnosticMessage) continue;
        if (resp.size() < 4) continue;

        uint16_t respSource = (resp[0] << 8) | resp[1];
        uint16_t respTarget = (resp[2] << 8) | resp[3];
        if (respTarget != source) continue;  // not addressed to our tester

        std::vector<uint8_t> ud(resp.begin() + 4, resp.end());
        // Skip "response pending" placeholders; wait for the real reply.
        if (ud.size() >= 3 && ud[0] == kUdsNegativeResponse &&
            ud[2] == kNrcResponsePending)
            continue;

        bool dup = false;
        for (auto& r : responses)
            if (r.source == respSource) { dup = true; break; }
        if (!dup) {
            responses.push_back({respSource, ud});
            Logger::instance().info("Functional response from ECU 0x" +
                byteHex((respSource >> 8) & 0xFF) + byteHex(respSource & 0xFF));
        }
    }

    if (responses.empty()) { err = "No ECUs responded to functional request"; return false; }
    return true;
}

} // namespace doip
