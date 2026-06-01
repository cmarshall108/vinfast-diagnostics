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

    // 7. Full UDS reprogramming sequence on the VCU (0x1010). Validates the
    //    flash flow and the four acceptance criteria: correct positive
    //    responses, proper block sequence counter, no unexpected NRC, and a
    //    successful application start after the closing ECU reset.
    {
        UDSClient uds(client, 0x0E80);
        const uint16_t vcu = 0x1010;
        bool seq_ok = true;

        // (1) enter programming session (0x10 02)
        bool s1 = uds.diagnosticSessionControl(vcu, UdsSession::Programming, err);
        check("flash: programming session (0x10 02)", s1, s1 ? "" : err);
        seq_ok &= s1;

        // (2) security access (0x27): seed then key (test transform key=seed^0xFF)
        auto seed = uds.requestSeed(vcu, 0x01, err);
        bool s2a = seed.has_value() && !seed->empty();
        check("flash: requestSeed (0x27 01)", s2a, s2a ? "" : err);
        bool s2b = false;
        if (s2a) {
            std::vector<uint8_t> key;
            for (uint8_t b : *seed) key.push_back(b ^ 0xFF);
            s2b = uds.sendKey(vcu, 0x01, key, err);
        }
        check("flash: sendKey (0x27 02)", s2b, s2b ? "" : err);
        seq_ok &= s2a && s2b;

        // (3) erase memory via RoutineControl (0x31 01)
        std::vector<uint8_t> rstat;
        bool s3 = uds.routineControl(vcu, RoutineCtrl::Start, 0xFF00, {}, rstat, err);
        check("flash: erase routine (0x31 01 FF00)", s3, s3 ? "" : err);
        seq_ok &= s3;

        // (4-6) download a multi-block image -> RequestDownload/TransferData/
        //       RequestTransferExit. 3000 bytes over a 1024-byte block size is
        //       three blocks, exercising the block-sequence counter (1,2,3).
        std::vector<uint8_t> image(3000);
        for (size_t i = 0; i < image.size(); ++i) image[i] = (uint8_t)(i & 0xFF);
        size_t lastDone = 0;
        bool s4 = uds.downloadBlock(vcu, 0xA0000000, image, 4, 4, 0x00,
            [&](size_t done, size_t /*total*/) { lastDone = done; }, err);
        check("flash: downloadBlock (0x34/0x36/0x37)", s4, s4 ? "" : err);
        check("flash: all bytes transferred", s4 && lastDone == image.size(),
              std::to_string(lastDone) + "/" + std::to_string(image.size()));
        seq_ok &= s4 && lastDone == image.size();

        // (7) ECU reset (0x11 01)
        bool s7 = uds.ecuReset(vcu, EcuResetType::HardReset, err);
        check("flash: ECU reset (0x11 01)", s7, s7 ? "" : err);
        seq_ok &= s7;

        // verify the application started after reset (running-software DID
        // 0xF1A0 reports 0x01 = application once a flash has completed).
        auto app = uds.readDataByIdentifier(vcu, 0xF1A0, err);
        bool started = app.has_value() && !app->empty() && app->front() == 0x01;
        check("flash: application started after reset (DID F1A0=01)", started,
              app ? "" : err);

        check("flash: full sequence ok (no unexpected NRC)", seq_ok && started);
    }

    // 8. AUTOSAR DCM live-data services: 0x2A ReadDataByPeriodicIdentifier and
    //    0x2C DynamicallyDefineDataIdentifier on the BMS (0x1003).
    {
        UDSClient uds(client, 0x0E80);
        const uint16_t bms = 0x1003;
        std::string err;

        // 0x2A: schedule then stop a periodic identifier.
        bool p1 = uds.readDataByPeriodicIdentifier(bms, PeriodicMode::SlowRate,
                                                    {0x90}, err);
        check("periodic: schedule 0x2A (slow rate)", p1, p1 ? "" : err);
        bool p2 = uds.readDataByPeriodicIdentifier(bms, PeriodicMode::StopSending,
                                                    {}, err);
        check("periodic: stop 0x2A", p2, p2 ? "" : err);

        // 0x2C: define a dynamic DID 0xF300 from two source DIDs, then read it
        // back with one 0x22 and confirm the bytes were assembled from sources.
        // VIN (0xF190) bytes 1-3 = "RP8" and SW version (0xF195) bytes 1-2.
        std::vector<DddSource> srcs = {
            {0xF190, 1, 3},   // "RP8"
            {0xF195, 1, 2},   // 0x01 0x02
        };
        bool d1 = uds.defineDynamicDataIdentifier(bms, 0xF300, srcs, err);
        check("dynamic: define 0x2C DDDID F300", d1, d1 ? "" : err);

        auto val = uds.readDataByIdentifier(bms, 0xF300, err);
        bool assembled = val.has_value() && val->size() == 5 &&
                         (*val)[0] == 'R' && (*val)[1] == 'P' && (*val)[2] == '8' &&
                         (*val)[3] == 0x01 && (*val)[4] == 0x02;
        check("dynamic: read assembled DDDID (0x22 F300)", assembled,
              val ? "" : err);

        bool d2 = uds.clearDynamicDataIdentifier(bms, 0xF300, err);
        check("dynamic: clear 0x2C DDDID F300", d2, d2 ? "" : err);

        // After clearing, the dynamic DID must no longer resolve.
        std::string e2;
        auto gone = uds.readDataByIdentifier(bms, 0xF300, e2);
        check("dynamic: cleared DDDID no longer reads", !gone.has_value());
    }

    client.disconnect();
    std::printf("\nResult: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
