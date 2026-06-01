#pragma once
//
// SovdClient.hpp - Service-Oriented Vehicle Diagnostics (SOVD) client.
//
// SOVD (ASAM / ISO 20078) is the REST/HTTP successor to classic UDS-over-DoIP.
// Where DoIPClient/UDSClient speak binary DoIP frames and numeric DIDs/RIDs,
// SOVD exposes the same diagnostic data as a self-describing JSON API:
//
//   GET  {base}/components                              -> list ECUs
//   GET  {base}/components/{id}/data/{resource}         -> read data (~ 0x22)
//   GET  {base}/components/{id}/faults                  -> read DTCs (~ 0x19)
//   POST {base}/components/{id}/operations/{op}/executions  -> routine (~ 0x31)
//
// This client is intended as an *underlying backup* diagnostic path: when a
// vehicle/gateway is not reachable over low-level DoIP (e.g. only a SOVD HTTP
// endpoint is exposed, or the activation line is not asserted) the same logical
// reads can be attempted over SOVD. Authentication is an OAuth2 bearer token
// (SOVD's model) rather than UDS SecurityAccess seed/key.
//
// All HTTP is synchronous (libcurl) and meant to be driven from a worker
// thread, matching CloudClient.
//
#include <cstdint>
#include <string>
#include <vector>

namespace sovd {

// A diagnostic component (the SOVD equivalent of a DoIP/UDS ECU).
struct Component {
    std::string id;     // resource id used in URIs, e.g. "bms"
    std::string name;   // human-readable name
};

// A fault/DTC entry returned from a component's /faults collection.
struct Fault {
    std::string code;       // e.g. "P0A80" or "0x1A2B00"
    std::string status;     // raw status text/value
    std::string severity;   // optional severity
};

class SovdClient {
public:
    // Base URL of the SOVD endpoint, e.g. "http://192.168.0.10:13401/vehicle/v1"
    // (no trailing slash required). Optional OAuth2 bearer token for auth.
    void setBaseUrl(const std::string& url);
    void setBearerToken(const std::string& token);
    std::string baseUrl() const { return base_; }
    bool configured() const { return !base_.empty(); }

    // Backup-availability probe: GET {base}/components and report whether the
    // endpoint answers with a 2xx. This is the cheap "is SOVD there?" check the
    // app uses before falling back from DoIP. `httpStatus` receives the code.
    bool checkAvailability(long& httpStatus, std::string& err);

    // GET {base}/components -> parsed component list.
    bool listComponents(std::vector<Component>& out, std::string& err);

    // GET {base}/components/{component}/data/{resource}. Returns the raw JSON
    // body (resource payloads are application-specific, so the caller decodes).
    bool readData(const std::string& component, const std::string& resource,
                  std::string& jsonBody, std::string& err);

    // UDS<->SOVD bridge: read a classic UDS DataIdentifier over SOVD by mapping
    // well-known DIDs (e.g. 0xF190 -> "vin") to SOVD resource names. Returns
    // false with err set if the DID has no known SOVD mapping.
    bool readDataByDid(const std::string& component, uint16_t did,
                       std::string& jsonBody, std::string& err);

    // GET {base}/components/{component}/faults -> parsed fault list.
    bool readFaults(const std::string& component, std::vector<Fault>& out,
                    std::string& err);

    // POST {base}/components/{component}/operations/{op}/executions with an
    // optional JSON request body. Returns the response body (e.g. execution id
    // / status). This is the SOVD analogue of RoutineControl (0x31 start).
    bool executeOperation(const std::string& component, const std::string& op,
                          const std::string& jsonRequest, std::string& jsonResponse,
                          std::string& err);

    // Maps a UDS DID to its SOVD resource name, or "" if unknown. Static so the
    // table can be reused/tested without an instance.
    static std::string didToResource(uint16_t did);

private:
    struct HttpResult { long status = 0; std::string body; };
    bool httpRequest(const std::string& method, const std::string& url,
                     const std::string& body, HttpResult& out, std::string& err);
    std::string url(const std::string& path) const;

    std::string base_;
    std::string token_;
};

} // namespace sovd
