//
// doip_selftest.cpp - Headless end-to-end check for the DoIP/UDS client.
//
// Drives src/DoIPClient + src/UDSClient against tools/doip_simulator.py and
// verifies the features added to the stack. Build with -DBUILD_DOIP_SELFTEST=ON.
//
//   Terminal 1:  python3 tools/doip_simulator.py
//   Terminal 2:  ./build/doip_selftest 127.0.0.1
//
#include "DoIPClient.hpp"
#include "UDSClient.hpp"
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
    const std::string ip = argc > 1 ? argv[1] : "127.0.0.1";
    const uint16_t    port = 13400;
    std::printf("DoIP self-test against %s:%u\n", ip.c_str(), port);

    doip::Client client;
    std::string err;

    // 1. Broadcast discovery + VIN sanitization.
    {
        std::vector<doip::Entity> ents;
        bool ok = client.discover(ip, port, 1500, ents, err);
        check("discover (broadcast)", ok && !ents.empty(), ok ? "" : err);
        if (ok && !ents.empty()) {
            const auto& e = ents.front();
            bool clean = true;
            for (char c : e.vin) if ((unsigned char)c < 0x20 || (unsigned char)c >= 0x7F) clean = false;
            check("VIN sanitized (printable)", clean, "VIN=\"" + e.vin + "\"");
        }
    }

    // 2. Targeted discovery by VIN.
    {
        std::vector<doip::Entity> ents;
        bool ok = client.discoverByVin(ip, port, 1500, "RP8AB1AB1PE000123", ents, err);
        check("discoverByVin", ok && !ents.empty(), ok ? "" : err);
    }

    // 3. Entity status + power mode (UDP).
    {
        doip::EntityStatus st;
        bool ok = client.entityStatus(ip, port, 1500, st, err);
        check("entityStatus", ok, ok ? "" : err);
        uint8_t mode = 0xFF;
        bool ok2 = client.diagnosticPowerMode(ip, port, 1500, mode, err);
        check("diagnosticPowerMode (ready)", ok2 && mode == 0x01, ok2 ? "" : err);
    }

    // 4. TCP connect + routing activation (TCP_NODELAY path).
    {
        bool ok = client.connectTcp(ip, port, err);
        check("connectTcp", ok, ok ? "" : err);
        if (ok) {
            bool ra = client.routingActivation(0x0E80, 0x00, err);
            check("routingActivation", ra, ra ? "" : err);
        }
    }

    // 5. Functional enumeration (multi-response collect).
    {
        UDSClient uds(client, 0x0E80);
        std::vector<uint16_t> found;
        bool ok = uds.enumerateEcus(0xE400, found, err, 1200);
        check("enumerateEcus (functional)", ok && found.size() >= 2,
              ok ? (std::to_string(found.size()) + " ECUs") : err);
    }

    // 6. ReadDataByIdentifier on BMS -> exercises 0x78 response-pending refresh.
    {
        UDSClient uds(client, 0x0E80);
        auto data = uds.readDataByIdentifier(0x1003, 0xF190, err);
        check("readDataByIdentifier 0x1003/F190 (0x78 path)",
              data.has_value() && !data->empty(), data ? "" : err);
    }

    client.disconnect();
    std::printf("\nResult: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
