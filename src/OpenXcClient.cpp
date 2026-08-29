#include "OpenXcClient.hpp"
#include "BtDiscovery.hpp"

// openxc/uds-c – DiagnosticRequest struct + UDS constants.
// isotp-c and bitfield-c are linked transitively.
extern "C" {
#include <uds/uds.h>
}

#include <algorithm>
#include <cctype>
#include <chrono>
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
    #include <cerrno>
  #include <dirent.h>
    #include <fcntl.h>
    #include <sys/ioctl.h>
    #include <sys/select.h>
  #include <sys/stat.h>
    #include <termios.h>
    #include <unistd.h>
#endif

#ifdef OPENXC_HAVE_LIBUSB
#include <libusb.h>
#endif

namespace openxc {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Encode bytes as "0xAABBCC..."; returns "" for an empty span.
static std::string bytesToHexStr(const uint8_t* data, size_t len) {
    if (!data || len == 0) return "";
    std::ostringstream ss;
    ss << "0x";
    for (size_t i = 0; i < len; ++i)
        ss << std::hex << std::uppercase
           << std::setfill('0') << std::setw(2)
           << static_cast<int>(data[i]);
    return ss.str();
}

// Decode "0xAABBCC..." or "AABBCC..." into bytes.
static std::vector<uint8_t> hexStrToBytes(const std::string& hex) {
    const char* p = hex.c_str();
    if (hex.size() >= 2 && hex[0] == '0' &&
        (hex[1] == 'x' || hex[1] == 'X')) {
        p += 2;
    }
    std::vector<uint8_t> out;
    size_t len = std::strlen(p);
    for (size_t i = 0; i + 1 < len; i += 2) {
        char buf[3] = {p[i], p[i + 1], '\0'};
        out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }
    return out;
}

static std::string trimCopy(const std::string& s) {
    size_t begin = 0;
    while (begin < s.size() && std::isspace(static_cast<unsigned char>(s[begin]))) ++begin;
    size_t end = s.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1]))) --end;
    return s.substr(begin, end - begin);
}

#ifdef _WIN32
static std::string windowsError(const char* what) {
    DWORD code = GetLastError();
    char* msg = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   reinterpret_cast<LPSTR>(&msg), 0, nullptr);
    std::string out = std::string(what) + " failed (" + std::to_string(code) + ")";
    if (msg) {
        out += ": ";
        out += msg;
        LocalFree(msg);
        while (!out.empty() && (out.back() == '\r' || out.back() == '\n')) out.pop_back();
    }
    return out;
}

static std::string stripWindowsComPrefix(const std::string& s) {
    if (s.compare(0, 4, "\\\\.\\") == 0) return s.substr(4);
    return s;
}

static std::string normalizeWindowsSerialPath(const std::string& s) {
    if (s.compare(0, 4, "\\\\.\\") == 0) return s;
    if (s.size() >= 4 && (s[0] == 'C' || s[0] == 'c') &&
        (s[1] == 'O' || s[1] == 'o') && (s[2] == 'M' || s[2] == 'm'))
        return "\\\\.\\" + s;
    return s;
}
#endif

// ---------------------------------------------------------------------------
// Tiny JSON field extractors (no external JSON library required)
// ---------------------------------------------------------------------------

static bool jsonGetBool(const std::string& json,
                        const std::string& key, bool& out) {
    auto pos = json.find('"' + key + '"');
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + key.size() + 2);
    if (pos == std::string::npos) return false;
    while (++pos < json.size() && json[pos] == ' ') {}
    if (json.compare(pos, 4, "true")  == 0) { out = true;  return true; }
    if (json.compare(pos, 5, "false") == 0) { out = false; return true; }
    return false;
}

static bool jsonGetInt(const std::string& json,
                       const std::string& key, int& out) {
    auto pos = json.find('"' + key + '"');
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + key.size() + 2);
    if (pos == std::string::npos) return false;
    while (++pos < json.size() && json[pos] == ' ') {}
    if (pos >= json.size()) return false;
    char* end = nullptr;
    long val = std::strtol(json.c_str() + pos, &end, 10);
    if (end == json.c_str() + pos) return false;
    out = static_cast<int>(val);
    return true;
}

static bool jsonGetString(const std::string& json,
                          const std::string& key, std::string& out) {
    auto pos = json.find('"' + key + '"');
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + key.size() + 2);
    if (pos == std::string::npos) return false;
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return false;
    ++pos; // skip opening quote
    out.clear();
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) ++pos;
        out += json[pos++];
    }
    return true;
}

// ---------------------------------------------------------------------------
// USB serial port enumeration
// ---------------------------------------------------------------------------

static bool looksLikeUsbSerialPath(const std::string& s) {
    if (s.empty()) return false;
#ifdef _WIN32
    // COM3, COM12, \\.\COM3
    if (s.compare(0, 4, "\\\\.\\") == 0) return true;
    if (s.size() >= 4 && (s[0] == 'C' || s[0] == 'c') &&
        (s[1] == 'O' || s[1] == 'o') && (s[2] == 'M' || s[2] == 'm')) {
        for (size_t i = 3; i < s.size(); ++i)
            if (!std::isdigit(static_cast<unsigned char>(s[i]))) return false;
        return true;
    }
    return false;
#else
    if (s[0] != '/') return false;
    static const char* patterns[] = {
        "/dev/ttyUSB", "/dev/ttyACM",
        "/dev/cu.usbmodem", "/dev/cu.usbserial",
        "/dev/tty.usbmodem", "/dev/tty.usbserial",
        "/dev/cu.OpenXC", "/dev/tty.OpenXC"
    };
    for (const char* p : patterns)
        if (s.compare(0, std::strlen(p), p) == 0) return true;
    return false;
#endif
}

#ifdef __APPLE__
static bool startsWithLower(const std::string& s, const char* lowerPrefix) {
    const size_t n = std::strlen(lowerPrefix);
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) != lowerPrefix[i])
            return false;
    }
    return true;
}

static std::string macOpenXcCalloutPath(const std::string& path) {
    static constexpr const char* incomingPrefix = "/dev/tty.";
    if (!startsWithLower(path, "/dev/tty.openxc")) return path;
    return std::string("/dev/cu.") + path.substr(std::strlen(incomingPrefix));
}
#endif

static bool looksLikeAutoUsbSerialPath(const std::string& s) {
    if (!looksLikeUsbSerialPath(s)) return false;
#ifdef __APPLE__
    if (startsWithLower(s, "/dev/cu.openxc") ||
        startsWithLower(s, "/dev/tty.openxc"))
        return false;
#endif
    return true;
}

static bool pathExists(const std::string& path) {
#ifdef _WIN32
    std::string dev = stripWindowsComPrefix(path);
    if (looksLikeUsbSerialPath(dev)) {
        char target[1024];
        return QueryDosDeviceA(dev.c_str(), target, sizeof(target)) != 0;
    }
    const DWORD att = GetFileAttributesA(path.c_str());
    return att != INVALID_FILE_ATTRIBUTES;
#else
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
#endif
}

std::vector<std::string> Client::enumerateUsbSerialPorts() {
    std::vector<std::string> out;

#ifdef _WIN32
    // QueryDosDevice lists all DOS devices; COM ports appear as "COMn".
    char buf[65536];
    DWORD len = QueryDosDeviceA(nullptr, buf, sizeof(buf));
    if (len > 0) {
        for (const char* p = buf; *p; p += std::strlen(p) + 1) {
            std::string dev(p);
            if (looksLikeUsbSerialPath(dev)) {
                std::string full = "\\\\.\\" + dev;
                if (pathExists(full)) out.push_back(full);
            }
        }
    }
#else
    DIR* dir = ::opendir("/dev");
    if (!dir) return out;
    while (dirent* ent = ::readdir(dir)) {
        std::string name = ent->d_name;
        std::string path = "/dev/" + name;
        if (looksLikeAutoUsbSerialPath(path) && pathExists(path))
            out.push_back(path);
    }
    ::closedir(dir);
#endif

    // Sort so OpenXC/VI-looking names and shorter paths come first.
    std::sort(out.begin(), out.end(), [](const std::string& a,
                                         const std::string& b) {
        auto score = [](const std::string& s) -> int {
            std::string low;
            for (char c : s) low += static_cast<char>(std::tolower(c));
            if (low.find("openxc") != std::string::npos) return 0;
            if (low.find("usbmodem") != std::string::npos) return 1;
            if (low.find("usbserial") != std::string::npos) return 2;
            if (low.find("ttyacm") != std::string::npos) return 3;
            if (low.find("ttyusb") != std::string::npos) return 4;
            return 5;
        };
        const int sa = score(a), sb = score(b);
        if (sa != sb) return sa < sb;
        return a < b;
    });

#ifdef OPENXC_HAVE_LIBUSB
    // If a raw-USB OpenXC VI (vendor interface, no serial node) is attached,
    // advertise it first so "auto" connect reaches it directly via libusb.
    {
        libusb_context* ctx = nullptr;
        if (libusb_init(&ctx) == 0) {
            libusb_device_handle* h =
                libusb_open_device_with_vid_pid(ctx, 0x1BC4, 0x0001);
            if (h) {
                out.insert(out.begin(), "usb:1BC4:0001");
                libusb_close(h);
            }
            libusb_exit(ctx);
        }
    }
#endif

    return out;
}

// ---------------------------------------------------------------------------
// Client implementation
// ---------------------------------------------------------------------------

Client::Client() = default;

Client::~Client() { disconnect(); }

bool Client::isConnected() const {
    if (usbMode_) return usbHandle_ != nullptr;
    if (btConnection_) return bt::rfcommConnected(btConnection_);
#ifdef _WIN32
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
#else
    return fd_ >= 0;
#endif
}

void Client::disconnect() {
#ifdef OPENXC_HAVE_LIBUSB
    if (usbMode_ && usbHandle_) {
        auto* h = static_cast<libusb_device_handle*>(usbHandle_);
        libusb_release_interface(h, usbIface_);
        libusb_close(h);
        if (usbCtx_) libusb_exit(static_cast<libusb_context*>(usbCtx_));
    }
#endif
    usbHandle_ = nullptr;
    usbCtx_    = nullptr;
    usbMode_   = false;
    usbRxBuf_.clear();
    if (btConnection_) {
        bt::closeRfcommConnection(btConnection_);
        btConnection_ = nullptr;
    }
#ifdef _WIN32
    if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
#else
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
#endif
    connectedPath_.clear();
}

// ---------------------------------------------------------------------------
// Native raw-USB (libusb) backend
//
// The stock Ford OpenXC VI (VID 0x1BC4, PID 0x0001) presents a vendor-specific
// interface (class 0xFF) with bulk endpoints rather than a USB-CDC serial port,
// so macOS creates no /dev/cu.* node. We talk to it directly: the VI streams
// NUL-delimited OpenXC JSON on the bulk IN endpoint and accepts NUL-terminated
// JSON commands / diagnostic_request messages on the bulk OUT endpoint - the
// exact same wire format the serial backend uses, so the whole protocol layer
// above is unchanged.
// ---------------------------------------------------------------------------
bool Client::isUsbToken(const std::string& token) {
    std::string t = trimCopy(token);
    for (char& c : t) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return t == "usb" || t == "openxc-usb" || t.rfind("usb:", 0) == 0;
}

bool Client::connectUsb(const std::string& token, std::string& err) {
#ifndef OPENXC_HAVE_LIBUSB
    (void)token;
    err = "This build has no native USB support (libusb not found at build time)";
    return false;
#else
    // Default to the Ford/OpenXC reference VI; allow "usb:VID:PID" overrides.
    uint16_t vid = 0x1BC4, pid = 0x0001;
    {
        std::string t = trimCopy(token);
        size_t c1 = t.find(':');
        if (c1 != std::string::npos) {
            size_t c2 = t.find(':', c1 + 1);
            if (c2 != std::string::npos) {
                vid = (uint16_t)std::strtoul(t.substr(c1 + 1, c2 - c1 - 1).c_str(), nullptr, 16);
                pid = (uint16_t)std::strtoul(t.substr(c2 + 1).c_str(), nullptr, 16);
            }
        }
    }

    libusb_context* ctx = nullptr;
    if (libusb_init(&ctx) != 0) { err = "libusb_init failed"; return false; }

    // The OpenXC VI enumerates only briefly: with no CAN/vehicle activity its
    // firmware sleeps and the device electrically drops off the USB bus. Poll
    // for it to appear so the user can plug it in (or catch the wake window)
    // right after pressing Connect, instead of failing instantly.
    constexpr int kUsbAppearMs = 12000;
    libusb_device_handle* h = nullptr;
    {
        using Clock = std::chrono::steady_clock;
        auto deadline = Clock::now() + std::chrono::milliseconds(kUsbAppearMs);
        for (;;) {
            h = libusb_open_device_with_vid_pid(ctx, vid, pid);
            if (h || Clock::now() >= deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    }
    if (!h) {
        char buf[224];
        std::snprintf(buf, sizeof buf,
            "OpenXC VI (USB %04X:%04X) not found. Reconnect or power-cycle the "
            "VI and verify its USB connection before trying again.", vid, pid);
        err = buf;
        libusb_exit(ctx);
        return false;
    }

    // Vendor interfaces have no kernel driver on macOS; on Linux detach any.
    libusb_set_auto_detach_kernel_driver(h, 1);   // ignored where unsupported

    // Discover the FIRST bulk IN / OUT endpoints on the first interface. The
    // Ford VI exposes two bulk IN endpoints (0x82 data, 0x8B logging); command
    // responses only come back on the first (0x82), so we must keep the first
    // one found and not let a later endpoint overwrite it.
    int iface = 0;
    unsigned char epIn = usbEpIn_, epOut = usbEpOut_;
    bool haveIn = false, haveOut = false;
    libusb_config_descriptor* cfg = nullptr;
    libusb_device* dev = libusb_get_device(h);
    if (dev && libusb_get_active_config_descriptor(dev, &cfg) == 0 && cfg) {
        if (cfg->bNumInterfaces > 0) {
            const libusb_interface& itf = cfg->interface[0];
            if (itf.num_altsetting > 0) {
                const libusb_interface_descriptor& id = itf.altsetting[0];
                iface = id.bInterfaceNumber;
                for (int e = 0; e < id.bNumEndpoints; ++e) {
                    unsigned char a = id.endpoint[e].bEndpointAddress;
                    unsigned char ty = id.endpoint[e].bmAttributes & 0x03;
                    if (ty != LIBUSB_TRANSFER_TYPE_BULK) continue;
                    if (a & 0x80) { if (!haveIn)  { epIn  = a; haveIn  = true; } }
                    else          { if (!haveOut) { epOut = a; haveOut = true; } }
                }
            }
        }
        libusb_free_config_descriptor(cfg);
    }

    if (libusb_claim_interface(h, iface) != 0) {
        err = "Found the OpenXC VI but could not claim its USB interface "
              "(another process may be using it)";
        libusb_close(h);
        libusb_exit(ctx);
        return false;
    }

    usbHandle_ = h;
    usbCtx_    = ctx;
    usbMode_   = true;
    usbIface_  = iface;
    usbEpIn_   = epIn;
    usbEpOut_  = epOut;
    usbRxBuf_.clear();
    char pbuf[32];
    std::snprintf(pbuf, sizeof pbuf, "usb:%04X:%04X", vid, pid);
    connectedPath_ = pbuf;
    return true;
#endif
}

// Resolve a user-supplied identifier to the serial device path.
// If it already looks like a serial path or COM port, use it directly;
// otherwise treat it as a Bluetooth MAC/name and resolve via BtDiscovery.
std::string Client::resolvePath(const std::string& deviceOrMac,
                                std::string& err) {
    std::string trimmed = trimCopy(deviceOrMac);

    if (trimmed.empty()) {
        err = "No OpenXC device specified";
        return "";
    }

    if (looksLikeUsbSerialPath(trimmed)) {
        std::string serialPath =
#ifdef _WIN32
            normalizeWindowsSerialPath(trimmed);
#else
            trimmed;
#endif
#ifdef __APPLE__
        serialPath = macOpenXcCalloutPath(serialPath);
#endif
        if (!pathExists(serialPath)) {
            err = "Serial device does not exist: " + serialPath;
            if (serialPath != trimmed)
            err += " (mapped from " + trimmed + ")";
            return "";
        }
        return serialPath;
    }

    return bt::resolveDevicePath(trimmed, err);
}

bool Client::connect(const std::string& deviceOrMac, std::string& err) {
    disconnect();

    // Native raw-USB backend: the stock VI has no serial node, so route
    // "usb" / "usb:VID:PID" straight to libusb before any path resolution.
    if (isUsbToken(deviceOrMac))
        return connectUsb(deviceOrMac, err);

#ifdef __APPLE__
    if (!looksLikeUsbSerialPath(deviceOrMac)) {
        btConnection_ = bt::openRfcommConnection(deviceOrMac, err);
        if (btConnection_) {
            connectedPath_ = "bluetooth:" + trimCopy(deviceOrMac);
            return true;
        }
        return false;
    }
#endif

    std::string path = resolvePath(deviceOrMac, err);
    if (path.empty()) return false;

    // Bring up the Bluetooth ACL/RFCOMM link for BT serial nodes before opening.
    // A paired-but-disconnected VI exposes a node that accepts writes but never
    // replies; this is a no-op for USB serial and on non-macOS platforms.
    if (!bt::prepareSerialPath(path, err))
        return false;

#ifdef _WIN32
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = windowsError(("Cannot open " + path).c_str());
        return false;
    }

    SetupComm(h, 4096, 4096);
    PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);

    DCB dcb{};
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(h, &dcb)) {
        err = windowsError("GetCommState");
        CloseHandle(h);
        return false;
    }
    dcb.BaudRate = 230400;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    if (!SetCommState(h, &dcb)) {
        err = windowsError("SetCommState");
        CloseHandle(h);
        return false;
    }

    COMMTIMEOUTS timeouts{};
    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.ReadTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 1000;
    if (!SetCommTimeouts(h, &timeouts)) {
        err = windowsError("SetCommTimeouts");
        CloseHandle(h);
        return false;
    }

    handle_ = h;
    connectedPath_ = path;
    return true;
#else
    fd_ = ::open(path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd_ < 0) {
        err = "Cannot open " + path + ": " + std::strerror(errno);
        return false;
    }

    // Switch back to blocking mode — we use select() for timeouts ourselves.
    int flags = fcntl(fd_, F_GETFL, 0);
    if (flags == -1 || fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        err = "fcntl failed: " + std::string(std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    // Configure raw mode; ignore errors since Bluetooth serial adapters often
    // don't support all termios attributes.
    struct termios tty{};
    if (tcgetattr(fd_, &tty) == 0) {
        cfmakeraw(&tty);
#ifdef B230400
        cfsetispeed(&tty, B230400);
        cfsetospeed(&tty, B230400);
#else
        cfsetispeed(&tty, B115200);
        cfsetospeed(&tty, B115200);
#endif
        tty.c_cflag &= ~(PARENB | CSTOPB | CSIZE);
        tty.c_cflag |= CS8 | CLOCAL | CREAD;
#ifdef CRTSCTS
        tty.c_cflag &= ~CRTSCTS;
#endif
        tty.c_cc[VMIN]  = 0;
        tty.c_cc[VTIME] = 0;
        tcsetattr(fd_, TCSANOW, &tty);
        tcflush(fd_, TCIOFLUSH);
    }

    int modem = 0;
    if (ioctl(fd_, TIOCMGET, &modem) == 0) {
        modem |= TIOCM_DTR | TIOCM_RTS;
        ioctl(fd_, TIOCMSET, &modem);
    }

    connectedPath_ = path;

    return true;
#endif
}

bool Client::writeAll(const char* data, size_t n, std::string& err) {
#ifdef OPENXC_HAVE_LIBUSB
    if (usbMode_) {
        auto* h = static_cast<libusb_device_handle*>(usbHandle_);
        constexpr uint8_t kOpenXcControlRequest = 0x83;
        if (n > 0xFFFFu) {
            err = "OpenXC control request is too large";
            return false;
        }
        for (int attempt = 0; attempt < 3; ++attempt) {
            int r = libusb_control_transfer(h, 0x40, kOpenXcControlRequest,
                    0, 0, reinterpret_cast<unsigned char*>(const_cast<char*>(data)),
                    static_cast<uint16_t>(n), 1000);
            if (r >= 0) {
                if (static_cast<size_t>(r) == n) {
                    return true;
                }
                err = "OpenXC USB control write was incomplete";
                return false;
            }
            if ((r != LIBUSB_ERROR_TIMEOUT && r != LIBUSB_ERROR_PIPE) || attempt == 2) {
                if (r == LIBUSB_ERROR_TIMEOUT || r == LIBUSB_ERROR_PIPE) {
                    int transferred = 0;
                    int bulkResult = libusb_bulk_transfer(h, usbEpOut_,
                            reinterpret_cast<unsigned char*>(const_cast<char*>(data)),
                            static_cast<int>(n), &transferred, 2000);
                    if (bulkResult == 0 && static_cast<size_t>(transferred) == n) {
                        return true;
                    }
                        err = std::string("OpenXC USB control and bulk writes failed: ") +
                            libusb_error_name(bulkResult);
                    return false;
                }
                err = std::string("OpenXC USB control write failed: ") +
                        libusb_error_name(r);
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return false;
    }
#endif
    if (btConnection_) return bt::writeRfcomm(btConnection_, data, n, err);
#ifdef _WIN32
    size_t written = 0;
    while (written < n) {
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(n - written, 1u << 20));
        DWORD done = 0;
        if (!WriteFile(static_cast<HANDLE>(handle_), data + written, chunk, &done, nullptr)) {
            err = windowsError("WriteFile");
            return false;
        }
        if (done == 0) {
            err = "WriteFile wrote zero bytes";
            return false;
        }
        written += done;
    }
    return true;
#else
    size_t written = 0;
    while (written < n) {
        ssize_t rc = ::write(fd_, data + written, n - written);
        if (rc < 0) {
            if (errno == EINTR) continue;
            err = "write error: " + std::string(std::strerror(errno));
            return false;
        }
        written += static_cast<size_t>(rc);
    }
    return true;
#endif
}

bool Client::readLine(std::string& line, int timeoutMs, std::string& err) {
    line.clear();
#ifdef OPENXC_HAVE_LIBUSB
    if (usbMode_) return readLineUsb(line, timeoutMs, err);
#endif
    if (btConnection_) {
        using Clock = std::chrono::steady_clock;
        const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
        while (Clock::now() < deadline) {
            int remainingMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - Clock::now()).count();
            char character = 0;
            int received = bt::readRfcomm(btConnection_, &character,
                                           std::max(1, remainingMs), err);
            if (received <= 0) return false;
            if (character == '\0' || character == '\n') {
                if (!line.empty()) return true;
            } else if (character != '\r') {
                line += character;
            }
        }
        err = "Response timeout";
        return false;
    }
    using Clock = std::chrono::steady_clock;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);

    while (true) {
        auto now = Clock::now();
        if (now >= deadline) { err = "Response timeout"; return false; }

#ifdef _WIN32
        char c = 0;
        DWORD got = 0;
        if (!ReadFile(static_cast<HANDLE>(handle_), &c, 1, &got, nullptr)) {
            err = windowsError("ReadFile");
            return false;
        }
        if (got == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        if (c == '\0' || c == '\n') {
            if (line.empty()) continue;
            return true;
        }
        if (c != '\r') line += c;
#else
        auto usLeft = std::chrono::duration_cast<std::chrono::microseconds>(
            deadline - now).count();

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd_, &rfds);
        struct timeval tv{};
        tv.tv_sec  = usLeft / 1000000;
        tv.tv_usec = usLeft % 1000000;

        int ready = select(fd_ + 1, &rfds, nullptr, nullptr, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            err = "select error: " + std::string(std::strerror(errno));
            return false;
        }
        if (ready == 0) { err = "Response timeout"; return false; }

        char c;
        ssize_t rc = ::read(fd_, &c, 1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            err = "read error: " + std::string(std::strerror(errno));
            return false;
        }
        if (rc == 0) { err = "EOF on OpenXC serial device"; return false; }
        if (c == '\0' || c == '\n') {
            if (line.empty()) continue;
            return true;
        }
        if (c != '\r') line += c;
#endif
    }
}

// Extract one NUL/newline-delimited message from the buffered USB bulk stream,
// refilling the buffer with bulk reads until a delimiter arrives or timeout.
bool Client::readLineUsb(std::string& line, int timeoutMs, std::string& err) {
#ifndef OPENXC_HAVE_LIBUSB
    (void)line; (void)timeoutMs; err = "USB backend not built"; return false;
#else
    line.clear();
    using Clock = std::chrono::steady_clock;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    auto* h = static_cast<libusb_device_handle*>(usbHandle_);

    for (;;) {
        // Consume any complete message already buffered.
        for (size_t i = 0; i < usbRxBuf_.size(); ++i) {
            char c = usbRxBuf_[i];
            if (c == '\0' || c == '\n') {
                line.assign(usbRxBuf_.data(), i);
                usbRxBuf_.erase(0, i + 1);
                // Drop a stray CR from CRLF-style traces.
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty()) { i = (size_t)-1; continue; }  // skip blanks
                return true;
            }
        }

        auto now = Clock::now();
        if (now >= deadline) { err = "Response timeout"; return false; }
        int msLeft = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                         deadline - now).count();

        unsigned char buf[512];
        int transferred = 0;
        int r = libusb_bulk_transfer(h, usbEpIn_, buf, (int)sizeof buf,
                                     &transferred, msLeft > 0 ? std::min(msLeft, 200) : 1);
        if ((r == 0 || r == LIBUSB_ERROR_TIMEOUT) && transferred > 0) {
            usbRxBuf_.append(reinterpret_cast<char*>(buf), (size_t)transferred);
            continue;
        }
        if (r == 0 || r == LIBUSB_ERROR_TIMEOUT) continue;   // no data yet
        err = std::string("USB bulk read failed: ") + libusb_error_name(r);
        return false;
    }
#endif
}

// ---------------------------------------------------------------------------
// OpenXC JSON protocol
// ---------------------------------------------------------------------------

//
// Build the OpenXC diagnostic_request JSON string.
//
// Uses DiagnosticRequest from openxc/uds-c for the arbitration-id and mode
// fields, but serializes the full caller-supplied UDS payload. SecurityAccess
// keys, dynamic DID definitions and transfer services routinely exceed the
// library's 7-byte request-payload struct, so truncating to that struct would
// send malformed UDS requests to the ECU.
//
std::string Client::buildRequest(uint32_t                    arbId,
                                 const std::vector<uint8_t>& udsReq,
                                 int                         bus) {
    // Populate a uds-c DiagnosticRequest from the raw UDS PDU so we benefit
    // from the library's field definitions and constants.
    DiagnosticRequest dr{};
    dr.arbitration_id = arbId;
    dr.mode           = udsReq[0];
    std::string payloadStr = udsReq.size() > 1
        ? bytesToHexStr(udsReq.data() + 1, udsReq.size() - 1)
        : "";

    std::ostringstream json;
    json << "{\"command\":\"diagnostic_request\",\"request\":{"
         << "\"id\":"    << dr.arbitration_id
         << ",\"mode\":" << static_cast<int>(dr.mode)
         << ",\"bus\":"  << bus;
        // The legacy OpenXC diagnostics bridge represents the subfunction for
        // session control and tester-present as a one-byte PID. This produces the
        // same ISO-TP UDS PDU while following the proven 10 01 / 3E 80 command
        // path used by the firmware CLI.
        if ((dr.mode == 0x10 || dr.mode == 0x3e) && udsReq.size() == 2) {
            json << ",\"pid\":" << static_cast<int>(udsReq[1]);
        } else if (!payloadStr.empty()) {
        json << ",\"payload\":\"" << payloadStr << "\"";
        }
    json << "},\"action\":\"add\"}";
    return json.str();
}

//
// Parse one line of OpenXC JSON into a reconstructed UDS response PDU.
//
// OpenXC diagnostic_response format:
//   {"bus":1,"id":2016,"mode":34,"success":true,"payload":"0xF190..."}
//
// IMPORTANT — OpenXC `id` is NOT the raw CAN response arbitration ID for
// physical requests. Stock vi-firmware (wrapDiagnosticResponseWithSabot)
// rewrites:
//   physical:  message_id = can_response_arb_id - 0x8  (== request arb id)
//   functional 0x7DF: message_id = actual responding module arb id
// openxc-python matches the same way (response id == request id).
// Callers must therefore pass the *request* arbitration ID as expectedId for
// physical exchanges, or 0 to accept any diagnostic response on the bus.
//
// Reconstruction rules:
//   success=true  → [mode+0x40] + payload_bytes
//   success=false → [0x7F, mode, NRC_from_payload_byte_0_or_0x22]
//
// Returns false (without setting err) when the line is a vehicle-data message
// rather than a diagnostic response — caller should skip and try next line.
//
bool Client::parseResponse(const std::string& jsonLine,
                           uint8_t requestMode,
                           uint32_t expectedId,
                           int expectedBus,
                           DiagnosticFrame& frame,
                           std::string& err) {
    frame = {};

    // Diagnostic responses include id, bus, mode and success. Vehicle data
    // messages may contain overlapping field names, so require the full set.
    if (jsonLine.find("\"mode\"") == std::string::npos ||
        jsonLine.find("\"success\"") == std::string::npos)
        return false; // vehicle data message – skip

    bool success = false;
    int  mode    = 0;
    int  bus     = 0;
    int  id      = 0;
    std::string payload;

    if (!jsonGetBool(jsonLine, "success", success) ||
        !jsonGetInt(jsonLine, "mode", mode) ||
        !jsonGetInt(jsonLine, "bus", bus) ||
        !jsonGetInt(jsonLine, "id", id))
        return false;

    if (expectedBus > 0 && bus != expectedBus) return false;
    // Match OpenXC's published id (request arb for physical; module arb for
    // functional). Also accept request+8 in case a non-stock VI publishes the
    // raw CAN response id.
    if (expectedId != 0) {
        const uint32_t published = static_cast<uint32_t>(id);
        const uint32_t altCanResp = (expectedId + 0x8u) <= 0x7FFu
                                        ? (expectedId + 0x8u) : 0u;
        const uint32_t infoCanResp = expectedId >= 0x680u && expectedId <= 0x6FFu
                         ? expectedId - 0x80u : 0u;
        if (published != expectedId &&
            !(altCanResp != 0u && published == altCanResp) &&
            !(infoCanResp != 0u && published == infoCanResp))
            return false;
    }

    const uint8_t positiveSid = static_cast<uint8_t>(requestMode + 0x40u);
    const uint8_t modeByte = static_cast<uint8_t>(mode & 0xFF);
    if (modeByte != requestMode && modeByte != positiveSid && modeByte != 0x7Fu) return false;

    frame.arbitrationId = static_cast<uint32_t>(id);
    frame.bus = bus;

    if (!success) {
        // Negative response: 0x7F + requestMode + NRC
        uint8_t nrc = static_cast<uint8_t>(NRC_CONDITIONS_NOT_CORRECT);
        if (jsonGetString(jsonLine, "payload", payload) && !payload.empty()) {
            auto bytes = hexStrToBytes(payload);
            if (!bytes.empty()) nrc = bytes[0];
        }
        frame.uds = {0x7Fu, requestMode, static_cast<uint8_t>(nrc)};
        return true;
    }

    // Positive response: [mode+0x40] + payload bytes
    frame.uds.push_back(modeByte == positiveSid ? modeByte : positiveSid);
    if (jsonGetString(jsonLine, "payload", payload) && !payload.empty()) {
        auto payloadBytes = hexStrToBytes(payload);
        frame.uds.insert(frame.uds.end(), payloadBytes.begin(), payloadBytes.end());
    }

    (void)err; // no parse error at this point
    return true;
}

// ---------------------------------------------------------------------------
// Public send/receive
// ---------------------------------------------------------------------------

bool Client::sendCommand(const std::string& command, std::string& response,
                         int timeoutMs, std::string& err) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    if (!isConnected()) { err = "OpenXC VI not connected"; return false; }
    std::string json = command;
    json.push_back('\0');
    if (!writeAll(json.c_str(), json.size(), err)) return false;
    return readLine(response, timeoutMs, err);
}

bool Client::sendDiagnostic(uint32_t                    arbId,
                             uint32_t                    expectedId,
                             const std::vector<uint8_t>& udsReq,
                             std::vector<uint8_t>&       udsResp,
                             int                         timeoutMs,
                             int                         bus,
                             std::string&                err) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    if (!isConnected()) { err = "OpenXC VI not connected"; return false; }
    if (udsReq.empty()) { err = "Empty UDS request"; return false; }

    const uint8_t requestMode = udsReq[0];

    // Discard any bytes buffered from a previous exchange (late responses or
    // unsolicited vehicle-data frames) so this request's response can't be
    // confused with stale data - important for rapid per-address probe scans.
#ifdef OPENXC_HAVE_LIBUSB
    if (usbMode_) usbRxBuf_.clear();
#endif

    // Send the JSON request terminated with OpenXC's stock NUL delimiter.
    std::string json = buildRequest(arbId, udsReq, bus);
    json.push_back('\0');
    if (!writeAll(json.c_str(), json.size(), err)) return false;

    // Read response messages, discarding vehicle-data messages, until we receive
    // a diagnostic response or the budget expires.
    using Clock = std::chrono::steady_clock;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    lastRxCount_ = 0;
    lastRxSample_.clear();

    while (Clock::now() < deadline) {
        auto msLeft = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now()).count();
        if (msLeft <= 0) break;

        std::string line;
        std::string lineErr;
        if (!readLine(line, static_cast<int>(msLeft), lineErr)) {
            err = lineErr;
            return false;
        }
        if (line.empty()) continue;

        // Track what the VI returned so a "no matching response" outcome can be
        // told apart from "no data at all" by the caller.
        ++lastRxCount_;
        lastRxSample_ = line.size() > 140 ? line.substr(0, 140) : line;

        std::string parseErr;
        DiagnosticFrame frame;
        // expectedId: OpenXC physical responses publish the *request* arb id
        // (not request+8). Pass arbId for physical; 0 to accept any id.
        if (parseResponse(line, requestMode, expectedId, bus, frame, parseErr)) {
            bool pending = frame.uds.size() >= 3 && frame.uds[0] == 0x7Fu &&
                           frame.uds[1] == requestMode && frame.uds[2] == 0x78u;
            if (pending) {
                deadline = Clock::now() + std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : 2000);
                continue;
            }
            udsResp = std::move(frame.uds);
            return true;
        }
        // Non-diagnostic line (vehicle data) – keep reading.
    }

    err = "Timeout waiting for OpenXC diagnostic response";
    return false;
}

bool Client::sendDiagnosticMulti(uint32_t                    arbId,
                                 const std::vector<uint8_t>& udsReq,
                                 std::vector<DiagnosticFrame>& responses,
                                 int                         collectMs,
                                 int                         bus,
                                 std::string&                err) {
    std::lock_guard<std::mutex> lock(ioMutex_);
    responses.clear();
    if (!isConnected()) { err = "OpenXC VI not connected"; return false; }
    if (udsReq.empty()) { err = "Empty UDS request"; return false; }

    const uint8_t requestMode = udsReq[0];
    std::string json = buildRequest(arbId, udsReq, bus);
    json.push_back('\0');
    if (!writeAll(json.c_str(), json.size(), err)) return false;

    using Clock = std::chrono::steady_clock;
    auto deadline = Clock::now() + std::chrono::milliseconds(collectMs > 0 ? collectMs : 2000);

    while (Clock::now() < deadline) {
        auto msLeft = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now()).count();
        if (msLeft <= 0) break;

        std::string line;
        std::string lineErr;
        if (!readLine(line, static_cast<int>(msLeft), lineErr)) {
            if (!responses.empty() && lineErr == "Response timeout") return true;
            err = lineErr;
            return false;
        }
        if (line.empty()) continue;

        DiagnosticFrame frame;
        std::string parseErr;
        if (!parseResponse(line, requestMode, 0, bus, frame, parseErr))
            continue;

        bool pending = frame.uds.size() >= 3 && frame.uds[0] == 0x7Fu &&
                       frame.uds[1] == requestMode && frame.uds[2] == 0x78u;
        if (pending) {
            deadline = Clock::now() + std::chrono::milliseconds(collectMs > 0 ? collectMs : 2000);
            continue;
        }

        bool duplicate = false;
        for (const auto& existing : responses) {
            if (existing.arbitrationId == frame.arbitrationId && existing.uds == frame.uds) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) responses.push_back(std::move(frame));
    }

    if (!responses.empty()) return true;
    err = "Timeout waiting for OpenXC diagnostic responses";
    return false;
}

} // namespace openxc
