// BtDiscovery.mm
//
// macOS IOBluetooth.framework implementation of BtDiscovery.hpp.
//
// This file provides:
//   • pairedSppDevices() – lists paired devices with SPP service
//   • Direct RFCOMM transport for a selected device MAC or name

#include "BtDiscovery.hpp"

#ifdef __APPLE__

#import <Foundation/Foundation.h>
#import <IOBluetooth/IOBluetooth.h>

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

std::vector<Device> pairedSppDevices() {
    NSArray<IOBluetoothDevice*>* paired = [IOBluetoothDevice pairedDevices];
    if (!paired) return {};

    std::vector<Device> results;
    for (IOBluetoothDevice* device in paired) {
        uint8_t channel = 1;
        if (!hasSpp(device, channel)) continue;
        results.push_back({
            device.name ? [device.name UTF8String] : "",
            normaliseAddress(device.addressString),
            device.isConnected,
        });
    }
    std::stable_sort(results.begin(), results.end(), [](const Device& a, const Device& b) {
        return foldedToken(a.name).find("openxc") != std::string::npos &&
               foldedToken(b.name).find("openxc") == std::string::npos;
    });
    return results;
}

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

Connection* openRfcommConnection(const std::string&, std::string& err) {
    err = "Direct Bluetooth SPP is currently supported on macOS only.";
    return nullptr;
}

void closeRfcommConnection(Connection*) { }
bool rfcommConnected(const Connection*) { return false; }
bool writeRfcomm(Connection*, const char*, size_t, std::string& err) {
    err = "Bluetooth RFCOMM connection is unavailable.";
    return false;
}
int readRfcomm(Connection*, char*, int, std::string& err) {
    err = "Bluetooth RFCOMM connection is unavailable.";
    return -1;
}

} // namespace bt

#endif // __APPLE__
