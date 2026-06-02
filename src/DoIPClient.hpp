#pragma once
//
// DoIPClient.hpp - Minimal DoIP (ISO 13400-2) client.
//
// Implements:
//   * UDP Vehicle Identification Request/Response (discovery, port 13400)
//   * TCP Routing Activation (0x0005 / 0x0006)
//   * TCP Diagnostic Message exchange (0x8001 / 0x8002 / 0x8003)
//   * Alive-check response and UDS "response pending" (NRC 0x78) handling
//
#include <cstdint>
#include <string>
#include <vector>
#include <array>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using socket_t = SOCKET;
#else
  using socket_t = int;
#endif

// Forward declaration: the optional CAN (ISO 15765 / mvci32.dll) backup
// transport used automatically when a DoIP diagnostic exchange fails.
namespace can { class Client; }

namespace doip {

constexpr uint16_t kDefaultPort      = 13400;
constexpr uint8_t  kProtocolVersion  = 0x02;   // ISO 13400-2:2012

// DoIP payload types (ISO 13400-2, table of payload type values).
enum PayloadType : uint16_t {
    GenericHeaderNack        = 0x0000,
    VehicleIdentRequest      = 0x0001,
    VehicleIdentReqEID       = 0x0002,   // targeted by Entity ID
    VehicleIdentReqVIN       = 0x0003,   // targeted by VIN
    VehicleIdentResponse     = 0x0004,
    RoutingActivationRequest = 0x0005,
    RoutingActivationResponse= 0x0006,
    AliveCheckRequest        = 0x0007,
    AliveCheckResponse       = 0x0008,
    EntityStatusRequest      = 0x4001,
    EntityStatusResponse     = 0x4002,
    PowerModeInfoRequest     = 0x4003,
    PowerModeInfoResponse    = 0x4004,
    DiagnosticMessage        = 0x8001,
    DiagnosticPositiveAck    = 0x8002,
    DiagnosticNegativeAck    = 0x8003,
};

// A discovered DoIP entity (typically the in-vehicle gateway).
struct Entity {
    std::string            ip;
    uint16_t               logicalAddress = 0;
    std::string            vin;
    std::array<uint8_t, 6> eid{};
    std::array<uint8_t, 6> gid{};
    uint8_t                furtherAction = 0;
};

// DoIP Entity Status (ISO 13400-2 payload 0x4002) - node capabilities.
struct EntityStatus {
    std::string ip;
    uint8_t     nodeType        = 0;   // 0x00 = DoIP gateway, 0x01 = DoIP node
    uint8_t     maxOpenSockets  = 0;   // max concurrent TCP sockets supported
    uint8_t     openSockets     = 0;   // currently open TCP sockets
    uint32_t    maxDataSize     = 0;   // max diagnostic message size (optional)
    bool        hasMaxDataSize  = false;
};

// One diagnostic response collected during functional enumeration: which ECU
// answered (its logical/source address) and the raw UDS payload it returned.
struct DiagResponse {
    uint16_t             source = 0;
    std::vector<uint8_t> uds;
};


class Client {
public:
    Client();
    ~Client();

    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;

    // --- Discovery (UDP) ------------------------------------------------
    // Broadcasts a Vehicle Identification Request and collects responses
    // until the receive timeout elapses.
    bool discover(const std::string& broadcastIp, uint16_t port, int timeoutMs,
                  std::vector<Entity>& out, std::string& err);

    // Targeted Vehicle Identification (0x0003 by VIN / 0x0002 by EID). Lets a
    // tester wake/identify one specific vehicle on a shared segment instead of
    // every entity that answers the plain broadcast.
    bool discoverByVin(const std::string& broadcastIp, uint16_t port, int timeoutMs,
                       const std::string& vin, std::vector<Entity>& out,
                       std::string& err);
    bool discoverByEid(const std::string& broadcastIp, uint16_t port, int timeoutMs,
                       const std::array<uint8_t, 6>& eid, std::vector<Entity>& out,
                       std::string& err);

    // DoIP Entity Status (0x4001/0x4002, UDP). Asks an entity how many TCP
    // sockets it supports / has open and its max diagnostic message size -
    // useful to confirm a gateway is reachable and has capacity before a
    // session. Send to a unicast IP (the gateway) or a broadcast address.
    bool entityStatus(const std::string& ip, uint16_t port, int timeoutMs,
                      EntityStatus& out, std::string& err);

    // DoIP Diagnostic Power Mode (0x4003/0x4004, UDP). Reports whether the
    // vehicle is in a power state ready for diagnostics/programming:
    //   0x00 = not ready, 0x01 = ready, 0x02 = not supported.
    // Checking this before flashing avoids programming in a low-power state.
    bool diagnosticPowerMode(const std::string& ip, uint16_t port, int timeoutMs,
                             uint8_t& mode, std::string& err);

    // --- Session (TCP) --------------------------------------------------
    // connectTimeoutMs bounds the TCP handshake; rcvTimeoutMs is the default
    // per-read socket timeout applied after connecting.
    bool connectTcp(const std::string& ip, uint16_t port, std::string& err,
                    int connectTimeoutMs = 3000, int rcvTimeoutMs = 2000);
    bool isConnected() const { return tcp_ != invalidSocket(); }
    void disconnect();

    // Routing activation must succeed before any diagnostic exchange.
    // activationType: 0x00 = default, 0x01 = WWH-OBD, 0xE0 = central security.
    // oemSpecific, when 4 bytes, is appended as the ISO-optional OEM field that
    // some gateways require.
    bool routingActivation(uint16_t sourceAddr, uint8_t activationType,
                           std::string& err,
                           const std::vector<uint8_t>& oemSpecific = {});

    // Sends a UDS request to `target` and returns the raw UDS response bytes
    // (DoIP header and address fields stripped). timeoutMs is the response
    // budget; each UDS "response pending" (NRC 0x78) extends it. When
    // functional is true, `target` is treated as a functional address and the
    // strict "addressed to our tester" reply check is relaxed.
    //
    // If the DoIP exchange fails and a CAN backup transport has been registered
    // (setCanBackup) and is connected, the request is transparently retried
    // over UDS-on-CAN (ISO 15765 via mvci32.dll).
    bool sendDiagnostic(uint16_t source, uint16_t target,
                        const std::vector<uint8_t>& uds,
                        std::vector<uint8_t>& response, int timeoutMs,
                        std::string& err, bool functional = false);

    // Registers an optional CAN backup transport. When set, a failed DoIP
    // diagnostic exchange automatically falls back to it. Pass nullptr to
    // disable. The pointer is borrowed; the caller retains ownership.
    void setCanBackup(can::Client* backup) { canBackup_ = backup; }
    bool usingCanBackup() const { return lastUsedCanBackup_; }

    // Sends one (typically functional) request and collects EVERY diagnostic
    // response that arrives within collectMs, keyed by responder source
    // address (de-duplicated). Unlike sendDiagnostic this never returns early
    // on the first reply, so it can enumerate all ECUs in a functional group.
    bool sendDiagnosticMulti(uint16_t source, uint16_t target,
                             const std::vector<uint8_t>& uds,
                             std::vector<DiagResponse>& responses, int collectMs,
                             std::string& err);

    uint16_t testerAddress() const { return testerAddr_; }

    // Platform sentinel for an invalid socket (exposed for UDP helpers).
    static socket_t invalidSocketValue();

private:
    // Shared implementation for broadcast and targeted Vehicle Identification.
    bool discoverImpl(const std::string& broadcastIp, uint16_t port, int timeoutMs,
                      uint16_t reqType, const std::vector<uint8_t>& reqPayload,
                      std::vector<Entity>& out, std::string& err);

    // Core DoIP-only diagnostic exchange (no CAN fallback). The public
    // sendDiagnostic wraps this and adds the CAN backup retry.
    bool sendDiagnosticDoIP(uint16_t source, uint16_t target,
                            const std::vector<uint8_t>& uds,
                            std::vector<uint8_t>& response, int timeoutMs,
                            std::string& err, bool functional);

    static socket_t invalidSocket();
    bool sendAll(socket_t s, const uint8_t* data, size_t len);
    bool recvAll(socket_t s, uint8_t* data, size_t len, int timeoutMs);
    bool readDoIPMessage(socket_t s, uint16_t& payloadType,
                         std::vector<uint8_t>& payload, int timeoutMs,
                         std::string& err);

    socket_t tcp_;
    uint16_t testerAddr_ = 0x0E80;  // updated by routingActivation()
    can::Client* canBackup_ = nullptr;   // optional CAN fallback (not owned)
    bool lastUsedCanBackup_ = false;     // true if the last send fell back to CAN
};

} // namespace doip
