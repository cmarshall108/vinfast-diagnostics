#include "Elm327Client.hpp"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <util.h>
#else
#include <pty.h>
#endif
#include <unistd.h>

namespace {

bool writeAll(int fd, const std::string& value) {
    size_t written = 0;
    while (written < value.size()) {
        const ssize_t count = ::write(fd, value.data() + written, value.size() - written);
        if (count <= 0) return false;
        written += static_cast<size_t>(count);
    }
    return true;
}

} // namespace

bool runExchange(elm327::CanProfile profile,
                 const std::vector<std::string>& profileCommands) {
    int master = -1;
    int slave = -1;
    char slaveName[256] = {};
    if (openpty(&master, &slave, slaveName, nullptr, nullptr) != 0) {
        std::cerr << "openpty failed: " << std::strerror(errno) << '\n';
        return false;
    }
    std::vector<std::string> expected = {
        "ATZ", "ATE0", "ATL0", "ATS0", "ATH1", "ATCAF1", "ATAL", "ATAT1"
    };
    expected.insert(expected.end(), profileCommands.begin(), profileCommands.end());
    expected.insert(expected.end(), {
        "ATSH7E0", "ATCRA7E8", "ATH0", "22F190",
        "ATSH7DF", "ATCRA", "ATH1", "0100"
    });
    std::atomic<bool> emulatorOk{true};
    std::thread emulator([&] {
        std::string pending;
        size_t commandIndex = 0;
        while (commandIndex < expected.size()) {
            char character = 0;
            if (::read(master, &character, 1) != 1) {
                emulatorOk = false;
                break;
            }
            if (character != '\r') {
                pending.push_back(character);
                continue;
            }
            if (pending != expected[commandIndex]) {
                std::cerr << "expected " << expected[commandIndex]
                          << ", received " << pending << '\n';
                emulatorOk = false;
                break;
            }
            const std::string reply = pending == "ATZ"
                ? "ELM327 v1.5\r>"
                : pending == "22F190"
                    ? "62 F1 90 56 46 38\r>"
                    : pending == "0100"
                        ? "7E8 04 41 00 BE 1F\r7E9 04 41 00 80 00\r>"
                    : "OK\r>";
            if (!writeAll(master, reply)) {
                emulatorOk = false;
                break;
            }
            pending.clear();
            ++commandIndex;
        }
    });

    elm327::Client client;
    std::string error;
    bool connected = client.connect(slaveName, profile, error);
    std::vector<uint8_t> response;
    bool sent = connected && client.sendDiagnostic(
        0x7E0, 0x7E8, {0x22, 0xF1, 0x90}, response, 1500, error);
    std::vector<elm327::Response> responses;
    bool sentMulti = sent && client.sendDiagnosticMulti(
        0x7DF, {0x01, 0x00}, responses, 1500, error);
    client.disconnect();
    emulator.join();
    ::close(slave);
    ::close(master);

    const std::vector<uint8_t> expectedResponse = {0x62, 0xF1, 0x90, 0x56, 0x46, 0x38};
        if (!connected || !sent || !sentMulti || response != expectedResponse ||
            responses.size() != 2 || responses[0].arbitrationId != 0x7E8 ||
            responses[1].arbitrationId != 0x7E9 || !emulatorOk) {
        std::cerr << "ELM327 exchange failed: " << error << '\n';
        return false;
    }
    return true;
}

int main() {
    if (!runExchange(elm327::CanProfile::HighSpeed500, {"ATSP6"})) return 1;
    if (!runExchange(elm327::CanProfile::MediumSpeed250, {"ATSP8"})) return 1;
    if (!runExchange(elm327::CanProfile::MediumSpeed125,
                     {"ATPB 80 04", "ATSPB"})) return 1;
    return 0;
}