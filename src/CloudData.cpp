//
// CloudData.cpp - VinFast connected-car cloud reference data.
//
#include "CloudData.hpp"

namespace cloud {

const std::vector<CloudRegion> kCloudRegions = {
    // code  label                  auth0Domain          apiBase                                        awsRegion         cognitoPool                                              iotEndpoint
    {"VN", "Vietnam",       "vin3s.au.auth0.com", "https://mobile.connected-car.vinfast.vn", "ap-southeast-1", "ap-southeast-1:c6537cdf-92dd-4b1f-99a8-9826f153142a", "prod.iot.connected-car.vinfast.vn"},
    {"US", "United States", "vin3s.us.auth0.com", "https://api.us.vinfastauto.com",          "us-east-1",      "",                                                   "prod.iot.us.connected-car.vinfast.vn"},
    {"EU", "Europe",        "vin3s.eu.auth0.com", "https://api.eu.vinfastauto.com",          "eu-central-1",   "",                                                   "prod.iot.eu.connected-car.vinfast.vn"},
};

const CloudRegion& cloudRegion(const std::string& code) {
    for (const auto& r : kCloudRegions)
        if (code == r.code) return r;
    return kCloudRegions.front();   // VN default
}

const std::vector<RemoteCommand> kRemoteCommands = {
    {1, "Lock doors",   true},
    {2, "Unlock doors", true},
    {3, "Sound horn",   true},
    {4, "Flash lights", true},
    {5, "Climate ON",   true},
    {6, "Climate OFF",  true},
    {7, "Open trunk",   true},
};

// VF8 (platform B) telemetry resources, translated from the community client.
const std::vector<TelemetryResource> kVF8Telemetry = {
    // GPS / identity
    {"00006_00001_00000", "Latitude",                 "deg"},
    {"00006_00001_00001", "Longitude",                "deg"},
    {"00006_00001_00002", "Altitude",                 "m"},
    {"00005_00001_00030", "Software version (FRP)",   ""},
    {"34196_00001_00004", "T-Box version",            ""},
    {"34181_00001_00007", "Licence plate / name",     ""},
    {"34180_00001_00010", "Ready state / vehicle ID", ""},

    // Energy / range
    {"34180_00001_00011", "Battery charge (SOC)",     "%"},
    {"34180_00001_00007", "Estimated range",          "km"},
    {"34220_00001_00001", "Battery health (SOH)",     "%"},
    {"34183_00001_00005", "12V battery",              "%"},
    {"34181_00000_00000", "12V battery",              "%"},

    // Charging
    {"34183_00000_00001", "Charging status",          ""},
    {"34183_00000_00004", "Charge plug / time",       ""},
    {"34183_00000_00009", "Charge time remaining",    "min"},
    {"34183_00000_00012", "Charge power (station)",   "kW"},
    {"34183_00000_00015", "Charge voltage",           "V"},
    {"34183_00000_00016", "Charge current",           "A"},
    {"34193_00001_00012", "Charge target",            "%"},
    // Extended charging resources (community const_common.py; VF8 subscribes to
    // the 34193 series via the cloud's extra-resource registration).
    {"34193_00001_00031", "Charge plug connected",    ""},
    {"34193_00001_00005", "Charging status",          ""},
    {"34193_00001_00007", "Charge time remaining",    "min"},
    {"34193_00001_00026", "Charge time estimate",     "min"},
    {"34193_00001_00013", "Charge completion time",   ""},
    {"34193_00001_00032", "Charge system relay",      ""},
    {"34193_00001_00016", "Charge session ID",        ""},
    {"34193_00001_00014", "Charge target",            "%"},
    {"34193_00001_00019", "Charge target",            "%"},

    // Motion
    {"34187_00000_00000", "Gear position",            ""},
    {"34188_00000_00000", "Speed",                    "km/h"},
    {"34199_00000_00000", "Total odometer",           "km"},
    {"34183_00001_00029", "Electronic parking brake", ""},
    {"34183_00001_00035", "Foot brake switch",        ""},

    // Climate / temperature
    {"34189_00000_00000", "Outside temperature",      "C"},
    {"34190_00000_00000", "Cabin temperature",        "C"},
    {"34183_00001_00007", "Outside temperature",      "C"},
    {"34183_00001_00015", "Cabin temperature",        "C"},
    {"34184_00001_00004", "HVAC status",              ""},
    {"34184_00001_00011", "Air intake mode",          ""},
    {"34184_00001_00012", "Air direction",            ""},
    {"34184_00001_00009", "Defrost",                  ""},
    {"34184_00001_00025", "Fan level",                ""},
    {"34184_00001_00041", "Cooling level",            ""},
    {"34224_00001_00005", "HVAC set temperature",     "C"},

    // Tyre pressure
    {"34190_00000_00001", "Tyre pressure front-left", "bar"},
    {"34190_00001_00001", "Tyre pressure front-right","bar"},
    {"34190_00002_00001", "Tyre pressure rear-left",  "bar"},
    {"34190_00003_00001", "Tyre pressure rear-right", "bar"},

    // Security / modes
    {"34213_00001_00003", "Central lock",             ""},
    {"34234_00001_00003", "Security status",          ""},
    {"34186_00005_00004", "Hazard lights",            ""},
    {"34205_00001_00001", "Valet mode",               ""},
    {"34206_00001_00001", "Camp mode",                ""},
    {"34207_00001_00001", "Pet mode",                 ""},

    // Doors / windows
    {"10351_00002_00050", "Driver door",              ""},
    {"10351_00001_00050", "Passenger door",           ""},
    {"10351_00004_00050", "Rear driver door",         ""},
    {"10351_00003_00050", "Rear passenger door",      ""},
    {"10351_00006_00050", "Trunk",                    ""},
    {"10351_00005_00050", "Hood",                     ""},
    {"34215_00002_00002", "Driver window",            ""},
    {"34215_00001_00002", "Passenger window",         ""},
    {"34215_00004_00002", "Rear driver window",       ""},
    {"34215_00003_00002", "Rear passenger window",    ""},
    {"34213_00003_00003", "Window motor status",      ""},
    {"34213_00002_00003", "Trunk motor status",       ""},
    {"34213_00004_00003", "Headlight flash status",   ""},
};

std::string telemetryName(const std::string& code) {
    for (const auto& t : kVF8Telemetry) {
        if (code == t.code) {
            std::string s = t.name;
            if (t.unit && t.unit[0]) { s += " ("; s += t.unit; s += ")"; }
            return s;
        }
    }
    return code;
}

} // namespace cloud
