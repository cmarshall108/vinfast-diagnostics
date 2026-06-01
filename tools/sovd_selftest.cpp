//
// sovd_selftest.cpp - Headless check for the SOVD (REST/JSON) backup path.
//
// Drives src/SovdClient against the SOVD mock served by tools/doip_simulator.py
// (--sovd, default port 13401) and validates the resource model the client
// relies on. Built with -DBUILD_DOIP_SELFTEST=ON (links libcurl).
//
//   Terminal 1:  python3 tools/doip_simulator.py --host 127.0.0.1 --sovd
//   Terminal 2:  ./build/sovd_selftest 127.0.0.1
//
#include "SovdClient.hpp"
#include "Logger.hpp"

#include <cstdio>
#include <string>

static int g_pass = 0, g_fail = 0;

static void check(const char* name, bool ok, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
                detail.empty() ? "" : " - ", detail.c_str());
    if (ok) ++g_pass; else ++g_fail;
}

int main(int argc, char** argv) {
    const std::string ip   = argc > 1 ? argv[1] : "127.0.0.1";
    const std::string port = argc > 2 ? argv[2] : "13401";
    const std::string base = "http://" + ip + ":" + port + "/vehicle/v1";
    std::printf("SOVD self-test against %s\n", base.c_str());

    sovd::SovdClient sv;
    sv.setBaseUrl(base);
    std::string err;

    // 1. Availability probe (the DoIP-fallback "is SOVD there?" check).
    {
        long st = 0;
        bool ok = sv.checkAvailability(st, err);
        check("checkAvailability (HTTP 2xx)", ok && st == 200,
              ok ? ("HTTP " + std::to_string(st)) : err);
    }

    // 2. Component discovery (~ ECU enumeration).
    std::vector<sovd::Component> comps;
    {
        bool ok = sv.listComponents(comps, err);
        check("listComponents", ok && !comps.empty(),
              ok ? (std::to_string(comps.size()) + " components") : err);
    }

    // 3. Read VIN via the UDS DID -> SOVD resource bridge (0xF190 -> "vin").
    {
        std::string body;
        bool ok = sv.readDataByDid("bms", 0xF190, body, err);
        bool hasVin = ok && body.find("RP8AB1AB1PE000123") != std::string::npos;
        check("readDataByDid(0xF190 -> vin)", hasVin, ok ? body : err);
    }

    // 4. DID with no SOVD mapping -> clean error, not a crash.
    {
        std::string body;
        bool ok = sv.readDataByDid("bms", 0x1234, body, err);
        check("readDataByDid(unmapped DID) rejected", !ok, err);
    }

    // 5. Read faults (~ ReadDTCInformation 0x19).
    {
        std::vector<sovd::Fault> faults;
        bool ok = sv.readFaults("bms", faults, err);
        check("readFaults", ok && !faults.empty(),
              ok ? (std::to_string(faults.size()) + " faults, first=" +
                    (faults.empty() ? "" : faults.front().code)) : err);
    }

    // 6. Execute an operation (~ RoutineControl 0x31 start).
    {
        std::string resp;
        bool ok = sv.executeOperation("bms", "self_test", "{\"parameters\":{}}", resp, err);
        check("executeOperation(self_test)", ok && resp.find("running") != std::string::npos,
              ok ? resp : err);
    }

    std::printf("\nResult: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
