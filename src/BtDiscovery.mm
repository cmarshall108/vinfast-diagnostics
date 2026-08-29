// BtDiscovery.mm
//
// macOS IOBluetooth.framework implementation of BtDiscovery.hpp.
//
// How macOS exposes Classic BT SPP devices as serial ports
// ─────────────────────────────────────────────────────────
// 1. The user pairs the OpenXC VI in macOS Bluetooth preferences.
// 2. The IOBluetoothSerialManager kernel extension registers one virtual
//    serial port per RFCOMM channel in the device's SPP service record.
// 3. The port is named  /dev/cu.<BT-device-name>  where the Bluetooth device
//    name is used verbatim – including spaces – as the suffix.
//    e.g. "OpenXC VI" → /dev/cu.OpenXC VI-SPP  or  /dev/cu.OpenXC-VI
//    The exact suffix depends on macOS version and the VI's firmware name.
// 4. Opening /dev/cu.* triggers macOS to establish the Bluetooth connection if
//    the device is within range and powered on.
//
// This file provides:
//   • pairedSppDevices()   – lists paired devices with SPP service
//   • resolveDevicePath()  – maps a MAC / device name → /dev/cu.* path,
//                            opening the RFCOMM channel first if needed

#include "BtDiscovery.hpp"

#ifdef __APPLE__

#import <Foundation/Foundation.h>
#import <IOBluetooth/IOBluetooth.h>

#include <dirent.h>
#include <fnmatch.h>
#include <unistd.h>
#include <sys/stat.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace bt {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// IOBluetooth address format: "04-c4-61-c3-69-d0" → "04:C4:61:C3:69:D0"
static std::string normaliseAddress(NSString* addr) {
    if (!addr) return {};
    std::string s([addr UTF8String]);
    for (char& c : s) {
        if (c == '-') c = ':';
        else c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return s;
}

// Keep only [0-9A-F] from a MAC-like string and uppercase.
static std::string normaliseAddressToken(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isxdigit(c))
            out += static_cast<char>(std::toupper(c));
    }
    return out;
}

// Lowercase and strip non-alphanumeric characters for fuzzy comparisons.
static std::string foldedToken(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c))
            out += static_cast<char>(std::tolower(c));
    }
    return out;
}

// Convert a normalised MAC "04:C4:61:C3:69:D0" to IOBluetooth format
// "04-c4-61-c3-69-d0" (dashes, lowercase).
static NSString* macToIOBt(const std::string& mac) {
    std::string s = mac;
    for (char& c : s) {
        if (c == ':') c = '-';
        else c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return [NSString stringWithUTF8String:s.c_str()];
}

// Check whether a device's service list contains the Serial Port Profile
// (SPP, UUID 0x1101).  Also returns the RFCOMM channel ID if found.
static bool hasSpp(IOBluetoothDevice* dev, uint8_t& channelOut) {
    IOBluetoothSDPUUID* sppUUID = [IOBluetoothSDPUUID uuid16:0x1101];
    for (IOBluetoothSDPServiceRecord* svc in dev.services) {
        if ([svc hasServiceFromArray:@[sppUUID]]) {
            uint8_t ch = 1;
            [svc getRFCOMMChannelID:&ch];
            channelOut = ch;
            return true;
        }
    }
    // Some VIs register under the "Dialup Networking" class (0x1103) instead.
    IOBluetoothSDPUUID* dunUUID = [IOBluetoothSDPUUID uuid16:0x1103];
    for (IOBluetoothSDPServiceRecord* svc in dev.services) {
        if ([svc hasServiceFromArray:@[dunUUID]]) {
            uint8_t ch = 1;
            [svc getRFCOMMChannelID:&ch];
            channelOut = ch;
            return true;
        }
    }
    return false;
}

// Scan /dev for all cu.* entries and return the full paths.
static std::vector<std::string> listCuDevices() {
    std::vector<std::string> out;
    DIR* d = opendir("/dev");
    if (!d) return out;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (std::strncmp(e->d_name, "cu.", 3) == 0)
            out.push_back(std::string("/dev/") + e->d_name);
    }
    closedir(d);
    return out;
}

// Derive candidate /dev/cu.* names for a given Bluetooth device name.
//
// macOS serial port naming:
//   • Spaces are replaced by dashes or underscores (driver-version-dependent)
//   • Special characters that are illegal in file names (colons, slashes …)
//     are stripped or replaced — so a device whose BT name IS its MAC address
//     ("04:C4:61:C3:69:D0") gets a path like /dev/cu.04C461C369D0
static std::string sanitiseName(const std::string& btName,
                                 char spaceReplacement,
                                 bool stripSpecial) {
    std::string s;
    for (unsigned char c : btName) {
        if (c == ' ') {
            if (spaceReplacement) s += spaceReplacement;
        } else if (std::isalnum(c) || c == '-' || c == '_' || c == '.') {
            s += static_cast<char>(c);
        } else {
            // Colon, slash, etc.  Strip or convert to dash.
            if (!stripSpecial) s += '-';
        }
    }
    return s;
}

static std::vector<std::string> candidatePaths(const std::string& btName) {
    std::vector<std::string> names;
    names.push_back(btName);                        // verbatim (may have spaces)
    names.push_back(sanitiseName(btName, '-',  false));  // spaces→dash, specials→dash
    names.push_back(sanitiseName(btName, '_',  false));  // spaces→underscore
    names.push_back(sanitiseName(btName, '-',  true));   // spaces→dash,  specials stripped
    names.push_back(sanitiseName(btName, '\0', true));   // everything stripped

    // Deduplicate, preserve order
    std::vector<std::string> unique;
    for (const auto& n : names) {
        if (!n.empty() &&
            std::find(unique.begin(), unique.end(), n) == unique.end())
            unique.push_back(n);
    }

    std::vector<std::string> paths;
    for (const auto& n : unique) {
        paths.push_back("/dev/cu." + n);
        for (const char* suf : {"-SPP", "-SPPSlave", "-SerialPortServer",
                                "-SerialPort", "-1", "-0"})
            paths.push_back("/dev/cu." + n + suf);
    }
    return paths;
}

// Check which of the candidate paths actually exist.
static std::string firstExistingPath(const std::vector<std::string>& paths) {
    for (const auto& p : paths) {
        struct stat st{};
        if (stat(p.c_str(), &st) == 0) return p;
    }
    return {};
}

// Fuzzy-search all /dev/cu.* entries for one that contains a substring
// matching the device name (case-insensitive, ignoring colons / spaces).
static std::string fuzzyMatchPath(const std::string& btName) {
    if (btName.empty()) return {};

    // Build a lowercased token stripped of spaces, colons, and other
    // non-alphanumeric chars.
    std::string token = foldedToken(btName);
    if (token.size() < 3) return {}; // too short to match reliably

    for (const auto& p : listCuDevices()) {
        std::string base = p.substr(8); // strip "/dev/cu."
        std::string lower = foldedToken(base);
        if (lower.find(token) != std::string::npos) return p;
    }
    return {};
}

// If macOS already exposed a single OpenXC serial node, use it directly.
// This avoids relying on sometimes-empty IOBluetooth display names.
static std::string uniqueOpenXcCuPath() {
    std::vector<std::string> matches;
    for (const auto& p : listCuDevices()) {
        std::string base = p.substr(8); // strip "/dev/cu."
        std::string token = foldedToken(base);
        if (token.find("openxc") != std::string::npos)
            matches.push_back(p);
    }
    if (matches.size() == 1) return matches.front();
    return {};
}

// Ensure a BR/EDR (ACL) baseband connection exists to the device.
//
// We use openConnection:withPageTimeout:authenticationRequired: with a nil
// target so the call is synchronous.  This is deliberately *not*
// openRFCOMMChannelSync: that call opens a specific RFCOMM channel and can
// block for 10-30 s before timing out; it also conflicts with macOS's own
// Bluetooth serial port driver which manages RFCOMM internally.
//
// After the ACL link is up, macOS's IOBluetoothSerialManager KEXT picks up
// the SPP service record and creates/activates the /dev/cu.* node.
static bool ensureConnected(IOBluetoothDevice* dev, std::string& err) {
    if (dev.isConnected) return true;

    // Page timeout: units of 0.625 ms; 0x1000 ≈ 2.56 s (enough for range check)
    constexpr BluetoothHCIPageTimeout kPageTimeout = 0x1000;
    IOReturn result = [dev openConnection:nil
                         withPageTimeout:kPageTimeout
                   authenticationRequired:NO];

    if (result == kIOReturnSuccess || result == (IOReturn)kIOReturnStillOpen)
        return true;

    // Translate the most common error codes to human-readable messages.
    const char* detail = "";
    switch (result) {
        case (IOReturn)kIOReturnTimeout:
            detail = ": device out of range or powered off";
            break;
        case (IOReturn)kIOReturnNotAttached:
            detail = ": device not found (not paired?)";
            break;
        case (IOReturn)kIOReturnExclusiveAccess:
            detail = ": device busy with another connection";
            break;
        default:
            break;
    }
    err = "Bluetooth connection failed (IOReturn=" +
          std::to_string(result) + ")" + detail;
    return false;
}

} // namespace bt

namespace bt {
class Connection {
public:
    std::mutex mutex;
    std::condition_variable received;
    std::deque<char> input;
    bool connected = false;
    IOBluetoothRFCOMMChannel* channel = nil;
    id delegate = nil;
};
} // namespace bt

@interface OpenXcRfcommDelegate : NSObject <IOBluetoothRFCOMMChannelDelegate> {
@public
    bt::Connection* connection;
}
@end

@implementation OpenXcRfcommDelegate
- (void)rfcommChannelData:(IOBluetoothRFCOMMChannel*)channel
                     data:(void*)data
                   length:(size_t)length {
    (void)channel;
    if (!connection || !data || length == 0) return;
    std::lock_guard<std::mutex> guard(connection->mutex);
    const char* bytes = static_cast<const char*>(data);
    connection->input.insert(connection->input.end(), bytes, bytes + length);
    connection->received.notify_all();
}

- (void)rfcommChannelClosed:(IOBluetoothRFCOMMChannel*)channel {
    (void)channel;
    if (!connection) return;
    std::lock_guard<std::mutex> guard(connection->mutex);
    connection->connected = false;
    connection->received.notify_all();
}
@end

namespace bt {

static IOBluetoothDevice* findPairedSppDevice(const std::string& macOrName,
                                               uint8_t& channelOut) {
    const std::string address = normaliseAddressToken(macOrName);
    const std::string name = foldedToken(macOrName);
    for (IOBluetoothDevice* device in [IOBluetoothDevice pairedDevices]) {
        uint8_t channel = 1;
        if (!hasSpp(device, channel)) continue;
        const std::string deviceAddress = normaliseAddress(device.addressString);
        const std::string deviceName = device.name ? [device.name UTF8String] : "";
        if ((!address.empty() && normaliseAddressToken(deviceAddress) == address) ||
            (!name.empty() && foldedToken(deviceName).find(name) != std::string::npos)) {
            channelOut = channel;
            return device;
        }
    }
    return nil;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::vector<Device> pairedSppDevices() {
    NSArray<IOBluetoothDevice*>* paired = [IOBluetoothDevice pairedDevices];
    if (!paired) return {};

    std::vector<Device> results;
    for (IOBluetoothDevice* dev in paired) {
        uint8_t channelID = 1;
        if (!hasSpp(dev, channelID)) continue;

        Device d;
        d.name    = dev.name ? [dev.name UTF8String] : "";
        d.address = normaliseAddress(dev.addressString);
        d.connected = dev.isConnected;

        // Try to find an already-active serial port.
        if (!d.name.empty()) {
            auto cands = candidatePaths(d.name);
            d.devPath  = firstExistingPath(cands);
            if (d.devPath.empty())
                d.devPath = fuzzyMatchPath(d.name);
        }

        results.push_back(std::move(d));
    }

    // Sort: OpenXC VIs first (name contains "OpenXC" or "VI").
    std::stable_sort(results.begin(), results.end(),
                     [](const Device& a, const Device& b) {
        auto isOpenXc = [](const std::string& name) {
            std::string low;
            for (unsigned char c : name) low += std::tolower(c);
            return low.find("openxc") != std::string::npos ||
                   low.find("openxc-vi") != std::string::npos;
        };
        return isOpenXc(a.name) && !isOpenXc(b.name);
    });

    return results;
}

std::string resolveDevicePath(const std::string& macOrName, std::string& err) {
    // 1. If it's already a /dev/ path, return directly.
    if (macOrName.rfind("/dev/", 0) == 0) return macOrName;

    // 2. Find the IOBluetooth device matching this address/name.
    IOBluetoothDevice* target = nil;
    IOBluetoothDevice* targetByAddress = nil;
    IOBluetoothDevice* targetByName = nil;

    const std::string queryFolded = foldedToken(macOrName);
    const std::string queryAddrToken = normaliseAddressToken(macOrName);

    // Try address lookup first (works when macOrName is a MAC).
    NSString* addrStr = macToIOBt(macOrName);
    target = [IOBluetoothDevice deviceWithAddressString:addrStr];

    // Reconcile against paired-devices cache so we get stable name metadata.
    for (IOBluetoothDevice* dev in [IOBluetoothDevice pairedDevices]) {
        const std::string devAddr = normaliseAddress(dev.addressString);
        if (!queryAddrToken.empty() &&
            normaliseAddressToken(devAddr) == queryAddrToken) {
            targetByAddress = dev;
        }

        if (dev.name && !queryFolded.empty()) {
            const std::string devName = [dev.name UTF8String];
            const std::string devFolded = foldedToken(devName);
            if (!devFolded.empty() &&
                devFolded.find(queryFolded) != std::string::npos) {
                targetByName = dev;
            }
        }
    }

    if (targetByAddress) {
        target = targetByAddress;
    } else if ((!target || !target.isPaired) && targetByName) {
        target = targetByName;
    }

    if (!target || !target.isPaired) {
        // Fall back to scanning paired devices by name substring.
        std::string lowerQuery = macOrName;
        for (char& c : lowerQuery) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        for (IOBluetoothDevice* dev in [IOBluetoothDevice pairedDevices]) {
            if (!dev.name) continue;
            std::string lower([dev.name UTF8String]);
            for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower.find(lowerQuery) != std::string::npos) {
                target = dev;
                break;
            }
        }
    }

    if (!target) {
        err = "No paired Bluetooth device found for \"" + macOrName +
              "\". Pair the OpenXC VI in macOS Bluetooth settings first.";
        return {};
    }

    std::string devName = target.name ? [target.name UTF8String] : "";
    std::string devAddr = normaliseAddress(target.addressString);

    // Some IOBluetooth handles returned by address can have an empty display
    // name. Recover the user-facing name from paired-devices metadata.
    if (devName.empty() && targetByAddress && targetByAddress.name)
        devName = [targetByAddress.name UTF8String];
    if (devName.empty() && targetByName && targetByName.name)
        devName = [targetByName.name UTF8String];

    if (devAddr.empty() && !queryAddrToken.empty()) {
        for (IOBluetoothDevice* dev in [IOBluetoothDevice pairedDevices]) {
            const std::string candAddr = normaliseAddress(dev.addressString);
            if (normaliseAddressToken(candAddr) == queryAddrToken) {
                devAddr = candAddr;
                if (devName.empty() && dev.name)
                    devName = [dev.name UTF8String];
                break;
            }
        }
    }

    if (devAddr.empty() && !queryAddrToken.empty()) {
        // Best-effort display formatting when only raw MAC-like input is known.
        for (size_t i = 0; i + 1 < queryAddrToken.size(); i += 2) {
            if (!devAddr.empty()) devAddr += ":";
            devAddr += queryAddrToken.substr(i, 2);
        }
    }

    // 3. Check if a serial port node already exists.
    std::string path;
    if (!devName.empty()) {
        auto cands = candidatePaths(devName);
        path = firstExistingPath(cands);
        if (path.empty()) path = fuzzyMatchPath(devName);
    }
    if (path.empty() && !devAddr.empty()) path = fuzzyMatchPath(devAddr);
    if (path.empty()) path = fuzzyMatchPath(macOrName);
    if (path.empty()) path = uniqueOpenXcCuPath();
    if (!path.empty()) return path;

    // 4. Serial port not yet active.  Establish the BR/EDR ACL link so that
    //    macOS's IOBluetoothSerialManager can register the /dev/cu.* node.
    std::string connErr;
    if (!ensureConnected(target, connErr)) {
        err = connErr + "\n\nDevice: \"" + devName + "\"  [" +
              (devAddr.empty() ? macOrName : devAddr) + "]" +
              "\nAction: ensure the OpenXC VI is powered on and within" +
              " Bluetooth range, then try again.";
        return {};
    }

    // Give the kernel serial manager up to 2 s to create the /dev/cu.* node.
    for (int i = 0; i < 8; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        if (!devName.empty()) {
            auto cands = candidatePaths(devName);
            path = firstExistingPath(cands);
            if (path.empty()) path = fuzzyMatchPath(devName);
        }
        if (path.empty() && !devAddr.empty()) path = fuzzyMatchPath(devAddr);
        if (path.empty()) path = fuzzyMatchPath(macOrName);
        if (path.empty()) path = uniqueOpenXcCuPath();
        if (!path.empty()) return path;
    }

    if (devName.empty()) devName = "Unknown";

    err = "Connected to \"" + devName + "\" over Bluetooth but no"
          " /dev/cu.* serial port appeared.\n\n"
          "Possible causes:\n"
          "  \u2022 The VI firmware does not advertise an SPP service.\n"
          "  \u2022 IOBluetoothSerialManager is disabled (check System Extensions).\n"
          "  \u2022 Try disconnecting and reconnecting the device in macOS Bluetooth"
          " settings.";
    return {};
}

bool prepareSerialPath(const std::string& devPath, std::string& err) {
    // Only device nodes are candidates; anything else is left untouched.
    if (devPath.rfind("/dev/", 0) != 0) return true;

    // Reduce "/dev/cu.OpenXC-VI-A7B7" -> "OpenXC-VI-A7B7" for name matching.
    std::string base = devPath;
    auto slash = base.find_last_of('/');
    if (slash != std::string::npos) base = base.substr(slash + 1);
    if (base.rfind("cu.", 0) == 0) base = base.substr(3);
    else if (base.rfind("tty.", 0) == 0) base = base.substr(4);

    const std::string baseFolded = foldedToken(base);
    if (baseFolded.empty()) return true;

    // Find the paired SPP device whose name maps to this serial node.
    IOBluetoothDevice* match = nil;
    for (IOBluetoothDevice* dev in [IOBluetoothDevice pairedDevices]) {
        uint8_t channelID = 1;
        if (!hasSpp(dev, channelID)) continue;

        const std::string name = dev.name ? [dev.name UTF8String] : "";
        const std::string nameFolded = foldedToken(name);
        bool matched = !nameFolded.empty() &&
            (baseFolded.find(nameFolded) != std::string::npos ||
             nameFolded.find(baseFolded) != std::string::npos);
        if (!matched && !name.empty()) {
            for (const auto& cand : candidatePaths(name)) {
                if (cand == devPath) { matched = true; break; }
            }
        }
        if (matched) { match = dev; break; }
    }

    // Not a recognised paired Bluetooth node (e.g. a USB serial port): no-op.
    if (!match) return true;
    if (match.isConnected) return true;

    std::string connErr;
    if (!ensureConnected(match, connErr)) {
        err = connErr;
        return false;
    }

    // Give the kernel serial manager a moment to (re)activate the node now that
    // the ACL link is up.
    for (int i = 0; i < 20; ++i) {
        struct stat st{};
        if (stat(devPath.c_str(), &st) == 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return true;
}

Connection* openRfcommConnection(const std::string& macOrName, std::string& err) {
    uint8_t channelID = 1;
    IOBluetoothDevice* device = findPairedSppDevice(macOrName, channelID);
    if (!device) {
        err = "No paired Bluetooth SPP device found for \"" + macOrName +
              "\". Pair the OpenXC VI in macOS Bluetooth settings first.";
        return nullptr;
    }

    auto* connection = new Connection;
    auto* delegate = [[OpenXcRfcommDelegate alloc] init];
    delegate->connection = connection;
    IOBluetoothRFCOMMChannel* channel = nil;
    IOReturn result = [device openRFCOMMChannelSync:&channel
                                      withChannelID:channelID
                                           delegate:delegate];
    if (result != kIOReturnSuccess || !channel) {
        delegate->connection = nullptr;
        [delegate release];
        delete connection;
        err = "Unable to open Bluetooth SPP RFCOMM channel (IOReturn=" +
              std::to_string(result) + ")";
        return nullptr;
    }

    connection->channel = channel;
    connection->delegate = delegate;
    connection->connected = true;
    return connection;
}

void closeRfcommConnection(Connection* connection) {
    if (!connection) return;
    {
        std::lock_guard<std::mutex> guard(connection->mutex);
        connection->connected = false;
        connection->received.notify_all();
    }
    auto* delegate = static_cast<OpenXcRfcommDelegate*>(connection->delegate);
    if (delegate) delegate->connection = nullptr;
    if (connection->channel) [connection->channel closeChannel];
    if (delegate) [delegate release];
    delete connection;
}

bool rfcommConnected(const Connection* connection) {
    if (!connection) return false;
    std::lock_guard<std::mutex> guard(const_cast<Connection*>(connection)->mutex);
    return connection->connected;
}

bool writeRfcomm(Connection* connection, const char* data, size_t size,
                 std::string& err) {
    if (!connection || !data) { err = "Bluetooth RFCOMM connection is closed"; return false; }
    if (!rfcommConnected(connection)) { err = "Bluetooth RFCOMM connection is closed"; return false; }
    size_t offset = 0;
    while (offset < size) {
        const UInt16 chunk = static_cast<UInt16>(std::min<size_t>(size - offset, UINT16_MAX));
        IOReturn result = [connection->channel writeSync:(void*)(data + offset) length:chunk];
        if (result != kIOReturnSuccess) {
            err = "Bluetooth RFCOMM write failed (IOReturn=" + std::to_string(result) + ")";
            return false;
        }
        offset += chunk;
    }
    return true;
}

int readRfcomm(Connection* connection, char* data, int timeoutMs, std::string& err) {
    if (!connection || !data) { err = "Bluetooth RFCOMM connection is closed"; return -1; }
    std::unique_lock<std::mutex> lock(connection->mutex);
    if (connection->input.empty() && connection->connected) {
        connection->received.wait_for(lock, std::chrono::milliseconds(timeoutMs), [connection] {
            return !connection->input.empty() || !connection->connected;
        });
    }
    if (!connection->input.empty()) {
        *data = connection->input.front();
        connection->input.pop_front();
        return 1;
    }
    err = connection->connected ? "Response timeout" : "Bluetooth RFCOMM connection closed";
    return 0;
}

} // namespace bt

#else // !__APPLE__

namespace bt {

std::vector<Device> pairedSppDevices() { return {}; }

std::string resolveDevicePath(const std::string& macOrName, std::string& err) {
    if (macOrName.rfind("/dev/", 0) == 0 || macOrName.rfind("COM", 0) == 0)
        return macOrName;
    err = "Bluetooth auto-discovery is only supported on macOS. "
          "Enter the serial port path manually (e.g. /dev/ttyUSB0).";
    return {};
}

bool prepareSerialPath(const std::string&, std::string&) { return true; }

} // namespace bt

#endif // __APPLE__
