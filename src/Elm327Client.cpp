#include "Elm327Client.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <thread>

#ifdef _WIN32
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <windows.h>
#else
  #include <fcntl.h>
  #include <sys/select.h>
  #include <termios.h>
  #include <unistd.h>
#endif

namespace elm327 {
namespace {

std::string trim(const std::string& value) {
    size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first]))) ++first;
    size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
    return value.substr(first, last - first);
}

std::string upper(std::string value) {
    for (char& character : value)
        character = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    return value;
}

std::string hexId(uint32_t id) {
    std::ostringstream out;
    out << std::hex << std::uppercase << std::setfill('0')
        << std::setw(id > 0x7FFu ? 8 : 3) << id;
    return out.str();
}

std::string hexBytes(const std::vector<uint8_t>& bytes) {
    std::ostringstream out;
    for (uint8_t byte : bytes)
        out << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

bool parseHexLine(const std::string& input, uint32_t& arbitrationId,
                  std::vector<uint8_t>& bytes) {
    std::string compact;
    compact.reserve(input.size());
    for (unsigned char character : input) {
        if (std::isxdigit(character)) compact.push_back(static_cast<char>(character));
        else if (!std::isspace(character) && character != ':') return false;
    }
    if (compact.size() < 2) return false;

    arbitrationId = 0;
    size_t offset = 0;
    if (compact.size() >= 5 && compact.size() % 2 == 1) {
        arbitrationId = static_cast<uint32_t>(
            std::strtoul(compact.substr(0, 3).c_str(), nullptr, 16));
        offset = 3;
    }
    if ((compact.size() - offset) % 2 != 0) return false;

    bytes.clear();
    for (size_t index = offset; index + 1 < compact.size(); index += 2)
        bytes.push_back(static_cast<uint8_t>(std::strtoul(compact.substr(index, 2).c_str(), nullptr, 16)));
    if (arbitrationId != 0 && bytes.size() > 1 && bytes[0] <= 8 &&
            bytes[0] == bytes.size() - 1) {
        bytes.erase(bytes.begin());
    }
    return !bytes.empty();
}

bool isStatusLine(const std::string& line) {
    const std::string value = upper(trim(line));
    return value.empty() || value == "OK" || value == "SEARCHING..." ||
           value == "BUS INIT: OK" || value.rfind("ELM327", 0) == 0;
}

bool isErrorReply(const std::string& reply) {
    const std::string value = upper(reply);
    return value.find("NO DATA") != std::string::npos ||
           value.find("UNABLE TO CONNECT") != std::string::npos ||
           value.find("BUS ERROR") != std::string::npos ||
           value.find("CAN ERROR") != std::string::npos ||
           value.find("STOPPED") != std::string::npos ||
           value.find('?') != std::string::npos;
}

bool parsePayloadReply(const std::string& reply, const std::string& requestEcho,
                       std::vector<uint8_t>& payload) {
    payload.clear();
    std::string normalized = reply;
    std::replace(normalized.begin(), normalized.end(), '\r', '\n');
    std::istringstream lines(normalized);
    std::string line;
    while (std::getline(lines, line)) {
        line = trim(line);
        if (isStatusLine(line) || upper(line) == requestEcho) continue;
        const size_t separator = line.find(':');
        if (separator != std::string::npos) line = trim(line.substr(separator + 1));

        std::string compact;
        for (unsigned char character : line) {
            if (std::isxdigit(character)) compact.push_back(static_cast<char>(character));
            else if (!std::isspace(character)) { compact.clear(); break; }
        }
        if (compact.empty() || compact.size() % 2 != 0) continue;
        for (size_t index = 0; index < compact.size(); index += 2)
            payload.push_back(static_cast<uint8_t>(
                std::strtoul(compact.substr(index, 2).c_str(), nullptr, 16)));
    }
    return !payload.empty();
}

} // namespace

Client::Client() = default;
Client::~Client() { disconnect(); }

bool Client::isConnected() const {
    return connected_.load(std::memory_order_acquire);
}

bool Client::openSerial(const std::string& path, std::string& err) {
#ifdef _WIN32
    std::string device = path;
    if (device.rfind("\\\\.\\", 0) != 0) device = "\\\\.\\" + device;
    HANDLE handle = CreateFileA(device.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        err = "Cannot open ELM327 serial port " + path + " (Windows error " +
              std::to_string(GetLastError()) + ")";
        return false;
    }
    DCB dcb{};
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(handle, &dcb)) {
        CloseHandle(handle);
        err = "Cannot read ELM327 serial settings";
        return false;
    }
    dcb.BaudRate = CBR_38400;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    if (!SetCommState(handle, &dcb)) {
        CloseHandle(handle);
        err = "Cannot configure ELM327 serial port";
        return false;
    }
    COMMTIMEOUTS timeouts{};
    timeouts.ReadIntervalTimeout = 20;
    timeouts.ReadTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutConstant = 1000;
    SetCommTimeouts(handle, &timeouts);
    PurgeComm(handle, PURGE_RXCLEAR | PURGE_TXCLEAR);
    handle_ = handle;
#else
    fd_ = ::open(path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd_ < 0) {
        err = "Cannot open ELM327 serial port " + path + ": " + std::strerror(errno);
        return false;
    }
    termios tty{};
    if (tcgetattr(fd_, &tty) != 0) {
        err = "Cannot read ELM327 serial settings: " + std::string(std::strerror(errno));
        disconnectUnlocked();
        return false;
    }
    cfmakeraw(&tty);
    cfsetispeed(&tty, B38400);
    cfsetospeed(&tty, B38400);
    tty.c_cflag |= CLOCAL | CREAD;
    tty.c_cflag &= ~(PARENB | CSTOPB | CSIZE);
    tty.c_cflag |= CS8;
    if (tcsetattr(fd_, TCSANOW, &tty) != 0) {
        err = "Cannot configure ELM327 serial port: " + std::string(std::strerror(errno));
        disconnectUnlocked();
        return false;
    }
    tcflush(fd_, TCIOFLUSH);
    int flags = fcntl(fd_, F_GETFL, 0);
    if (flags >= 0) fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK);
#endif
    connectedPath_ = path;
    connected_.store(true, std::memory_order_release);
    return true;
}

bool Client::connect(const std::string& path, CanProfile profile, std::string& err) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    disconnectUnlocked();
    if (path.empty() || path == "auto" || path == "usb") {
        err = "Select the ELM327 serial port (for example COM3 or /dev/cu.usbserial-*)";
        return false;
    }
    if (!openSerial(path, err)) return false;
    if (!initialize(profile, err)) {
        disconnectUnlocked();
        return false;
    }
    return true;
}

void Client::disconnectUnlocked() {
    connected_.store(false, std::memory_order_release);
#ifdef _WIN32
    if (handle_) CloseHandle(static_cast<HANDLE>(handle_));
    handle_ = nullptr;
#else
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
#endif
    connectedPath_.clear();
}

void Client::disconnect() {
    std::lock_guard<std::mutex> lock(ioMutex_);
    disconnectUnlocked();
}

bool Client::writeAll(const char* data, size_t size, std::string& err) {
#ifdef _WIN32
    size_t written = 0;
    while (written < size) {
        DWORD count = 0;
        if (!WriteFile(static_cast<HANDLE>(handle_), data + written,
                       static_cast<DWORD>(size - written), &count, nullptr)) {
            err = "ELM327 serial write failed";
            return false;
        }
        written += count;
    }
#else
    size_t written = 0;
    while (written < size) {
        ssize_t count = ::write(fd_, data + written, size - written);
        if (count < 0) {
            if (errno == EINTR) continue;
            err = "ELM327 serial write failed: " + std::string(std::strerror(errno));
            return false;
        }
        written += static_cast<size_t>(count);
    }
#endif
    return true;
}

bool Client::readUntilPrompt(std::string& reply, int timeoutMs, std::string& err) {
    reply.clear();
    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    while (Clock::now() < deadline) {
        char buffer[128];
        int count = 0;
#ifdef _WIN32
        DWORD read = 0;
        if (!ReadFile(static_cast<HANDLE>(handle_), buffer, sizeof(buffer), &read, nullptr)) {
            err = "ELM327 serial read failed";
            return false;
        }
        count = static_cast<int>(read);
#else
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(fd_, &readSet);
        timeval wait{0, 50000};
        int ready = select(fd_ + 1, &readSet, nullptr, nullptr, &wait);
        if (ready < 0) {
            if (errno == EINTR) continue;
            err = "ELM327 serial select failed: " + std::string(std::strerror(errno));
            return false;
        }
        if (ready > 0) count = static_cast<int>(::read(fd_, buffer, sizeof(buffer)));
#endif
        if (count < 0) {
            err = "ELM327 serial read failed";
            return false;
        }
        if (count == 0) continue;
        reply.append(buffer, static_cast<size_t>(count));
        if (reply.find('>') != std::string::npos) return true;
    }
    err = "ELM327 response timed out";
    return false;
}

bool Client::command(const std::string& text, std::string& reply, int timeoutMs,
                     std::string& err) {
    std::string wire = text + "\r";
    if (!writeAll(wire.data(), wire.size(), err)) return false;
    if (!readUntilPrompt(reply, timeoutMs, err)) return false;
    const size_t prompt = reply.find('>');
    if (prompt != std::string::npos) reply.erase(prompt);
    if (isErrorReply(reply)) {
        err = "ELM327 rejected '" + text + "': " + trim(reply);
        return false;
    }
    return true;
}

bool Client::initialize(CanProfile profile, std::string& err) {
    std::string reply;
    if (!command("ATZ", reply, 3000, err)) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    if (upper(reply).find("ELM327") == std::string::npos) {
        err = "Serial device did not identify as an ELM327 adapter: " + trim(reply);
        return false;
    }
    const char* common[] = {"ATE0", "ATL0", "ATS0", "ATH1", "ATCAF1", "ATAL", "ATAT1"};
    for (const char* item : common)
        if (!command(item, reply, 1500, err)) return false;

    if (profile == CanProfile::HighSpeed500)
        return command("ATSP6", reply, 1500, err);
    if (profile == CanProfile::MediumSpeed250)
        return command("ATSP8", reply, 1500, err);

    // Protocol B options 0x80 select 11-bit CAN with fixed eight-byte frames;
    // divisor 0x04 selects 125 kbit/s (500 / 4), per the ELM327 datasheet.
    // Many cheap clones omit protocol B; fail instead of using the wrong rate.
    if (!command("ATPB 80 04", reply, 1500, err)) {
        err = "This ELM327 does not support the protocol-B 125 kbit/s MS-CAN profile: " + err;
        return false;
    }
    return command("ATSPB", reply, 1500, err);
}

bool Client::sendDiagnostic(uint32_t requestId, uint32_t responseId,
                            const std::vector<uint8_t>& request,
                            std::vector<uint8_t>& response, int timeoutMs,
                            std::string& err) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    if (!isConnected()) { err = "ELM327 is not connected"; return false; }
    if (request.empty()) { err = "Empty UDS request"; return false; }

    std::string reply;
    if (!command("ATSH" + hexId(requestId), reply, 1200, err)) return false;
    if (responseId != 0 && !command("ATCRA" + hexId(responseId), reply, 1200, err)) return false;
    if (!command("ATH0", reply, 1200, err)) return false;
    const std::string requestText = hexBytes(request);
    if (!command(requestText, reply, timeoutMs, err)) return false;
    if (parsePayloadReply(reply, requestText, response)) return true;
    err = "ELM327 returned no matching diagnostic response: " + trim(reply);
    return false;
}

bool Client::sendDiagnosticMulti(uint32_t requestId,
                                 const std::vector<uint8_t>& request,
                                 std::vector<Response>& responses, int collectMs,
                                 std::string& err) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    responses.clear();
    if (!isConnected()) { err = "ELM327 is not connected"; return false; }

    std::string reply;
    if (!command("ATSH" + hexId(requestId), reply, 1200, err)) return false;
    if (!command("ATCRA", reply, 1200, err)) return false;
    if (!command("ATH1", reply, 1200, err)) return false;
    const std::string requestText = hexBytes(request);
    if (!command(requestText, reply, collectMs, err)) return false;

    std::replace(reply.begin(), reply.end(), '\r', '\n');
    std::istringstream lines(reply);
    std::string line;
    while (std::getline(lines, line)) {
        line = trim(line);
        if (isStatusLine(line) || upper(line) == requestText) continue;
        uint32_t id = 0;
        std::vector<uint8_t> bytes;
        if (parseHexLine(line, id, bytes)) responses.push_back({id, std::move(bytes)});
    }
    if (!responses.empty()) return true;
    err = "ELM327 returned no diagnostic responses: " + trim(reply);
    return false;
}

} // namespace elm327