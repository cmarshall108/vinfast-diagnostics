#pragma once
//
// CloudClient.hpp - VinFast connected-car cloud client.
//
// Talks to VinFast's app back-end the same way the owner phone app does:
//   * Auth0 resource-owner-password login -> access token
//   * Signed REST calls (X-HASH / X-HASH-2 HMAC headers) for vehicle list,
//     remote commands, wake-up, telemetry pull and charging data
//   * AWS Cognito + SigV4 to build a presigned AWS IoT MQTT-over-WSS URL
//
// This is reverse-engineered community knowledge, not an official SDK. All
// HTTP is synchronous (libcurl) and meant to be driven from a worker thread.
// Credentials live only in memory and are sent over HTTPS to VinFast; they are
// never written to disk or to the log.
//
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace cloud {

struct Vehicle {
    std::string vin;
    std::string userId;
    std::string model;     // marketing name
    std::string plate;     // licence plate
};

struct ActiveCharge {
    bool   active   = false;
    double powerKw  = 0.0;
    double targetSoc= 0.0;
    double soc      = 0.0;
    int    remainMin= 0;
};

struct ChargeSession {
    std::string startTime;
    std::string location;
    double      energyKwh = 0.0;
    double      startSoc  = 0.0;
    double      endSoc    = 0.0;
    int         durationMin = 0;
};

class CloudClient {
public:
    // Region selection (code: "VN"/"US"/"EU"). Default VN.
    void        setRegion(const std::string& code);
    std::string region() const;

    // Auth0 password-grant login. On success stores the access token.
    bool login(const std::string& email, const std::string& password,
               std::string& err);
    bool loggedIn() const;
    void logout();

    // GET the user's vehicles; also caches the first one as the active vehicle.
    bool getVehicles(std::vector<Vehicle>& out, std::string& err);

    // Active vehicle accessors (valid after getVehicles()).
    std::string vin()    const;
    std::string userId() const;
    std::string model()  const;

    // Signed remote command (see kRemoteCommands). Returns the request id text.
    bool sendCommand(int commandType, std::string& reqId, std::string& err);

    // Wake the T-Box so it pushes a fresh telemetry burst.
    bool wakeup(std::string& err);

    // Ask the back-end to read live resources (fire-and-forget; values arrive
    // over MQTT). Returns the HTTP body for inspection.
    bool requestTelemetry(std::string& body, std::string& err);

    // Charging info via REST.
    bool fetchActiveCharge(ActiveCharge& out, std::string& err);
    bool fetchChargeHistory(std::vector<ChargeSession>& out, std::string& err);

    // Build a presigned wss:// AWS IoT MQTT URL (Cognito identity + SigV4).
    // Requires a region whose Cognito pool is known (currently VN).
    bool buildMqttUrl(std::string& url, std::string& err);

private:
    // --- HTTP -------------------------------------------------------------
    struct HttpResult { long status = 0; std::string body; };
    bool httpRequest(const std::string& method, const std::string& url,
                     const std::vector<std::string>& headers,
                     const std::string& body, HttpResult& out, std::string& err);

    // Build the common signed headers for an API path.
    std::vector<std::string> signedHeaders(const std::string& method,
                                           const std::string& apiPath,
                                           bool withVin) const;

    mutable std::mutex mutex_;
    std::string regionCode_ = "VN";
    std::string accessToken_;
    std::string vin_;
    std::string userId_;
    std::string model_;
    std::string plate_;
};

} // namespace cloud
