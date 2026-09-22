#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace elm327 {

enum class CanProfile {
    HighSpeed500,
    MediumSpeed125,
    MediumSpeed250,
};

struct Response {
    uint32_t arbitrationId = 0;
    std::vector<uint8_t> uds;
};

class Client {
public:
    Client();
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    bool connect(const std::string& path, CanProfile profile, std::string& err);
    void disconnect();
    bool isConnected() const;
    const std::string& connectedPath() const { return connectedPath_; }

    bool sendDiagnostic(uint32_t requestId, uint32_t responseId,
                        const std::vector<uint8_t>& request,
                        std::vector<uint8_t>& response, int timeoutMs,
                        std::string& err);
    bool sendDiagnosticMulti(uint32_t requestId,
                             const std::vector<uint8_t>& request,
                             std::vector<Response>& responses, int collectMs,
                             std::string& err);

private:
    bool openSerial(const std::string& path, std::string& err);
    bool initialize(CanProfile profile, std::string& err);
    bool command(const std::string& text, std::string& reply, int timeoutMs,
                 std::string& err);
    bool writeAll(const char* data, size_t size, std::string& err);
    bool readUntilPrompt(std::string& reply, int timeoutMs, std::string& err);
    void disconnectUnlocked();

#ifdef _WIN32
    void* handle_ = nullptr;
#else
    int fd_ = -1;
#endif
    mutable std::mutex ioMutex_;
    std::atomic<bool> connected_{false};
    std::string connectedPath_;
};

} // namespace elm327