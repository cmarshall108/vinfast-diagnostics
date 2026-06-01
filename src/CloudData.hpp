#pragma once
//
// CloudData.hpp - VinFast connected-car cloud reference data.
//
// These constants describe VinFast's *cloud* telemetry/control API as
// reverse-engineered by the owner community (notably the Home Assistant
// integration thangnd85/vinfast-connected-car, MIT, and the APK alias map in
// tahung9x/VF-DB). They are completely
// separate from the on-vehicle DoIP/UDS diagnostic bus: the cloud path talks
// to VinFast's app back-end (Auth0 + REST) and AWS IoT, NOT to the car's
// gateway. Region hosts, the OMA-LWM2M telemetry resource map and the remote
// command list below come from public community sources and may change at any
// time without notice.
//
#include <string>
#include <vector>

namespace cloud {

// ---- Shared app identifiers (from the community client) --------------------
constexpr const char* kAuth0ClientId = "jE5xt50qC7oIh1f32qMzA6hGznIU5mgH";
constexpr const char* kDeviceId      = "vfdashboard-community-edition";
constexpr const char* kAppVersion    = "2.17.5";

// ---- Region presets --------------------------------------------------------
// US/EU Cognito identity-pool IDs are not published, so MQTT presigning is only
// available where cognitoPool is non-empty (VN). REST endpoints work for all.
struct CloudRegion {
    const char* code;          // "VN" / "US" / "EU"
    const char* label;         // display name
    const char* auth0Domain;
    const char* apiBase;       // REST base (no trailing slash)
    const char* awsRegion;
    const char* cognitoPool;   // "" when unknown
    const char* iotEndpoint;
};
extern const std::vector<CloudRegion> kCloudRegions;

// Returns the region preset for a code (default VN if not found).
const CloudRegion& cloudRegion(const std::string& code);

// ---- Remote commands (POST .../remote/app/command, commandType) ------------
struct RemoteCommand {
    int         type;
    const char* label;
    bool        stateChanging;  // true => GUI asks for confirmation first
};
extern const std::vector<RemoteCommand> kRemoteCommands;

// ---- OMA-LWM2M telemetry resources (VF8 / platform B) ----------------------
// Code is "objectId_instanceId_resourceId" (instance/resource zero-padded to 5
// digits) as published by the vehicle T-Box over MQTT.
struct TelemetryResource {
    const char* code;
    const char* name;   // English label
    const char* unit;   // "" when none
};
extern const std::vector<TelemetryResource> kVF8Telemetry;

// "name (unit)" for a resource code, or the raw code when unknown.
std::string telemetryName(const std::string& code);

} // namespace cloud
