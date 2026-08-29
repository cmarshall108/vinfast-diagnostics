#pragma once
//
// BtDiscovery.hpp
//
// Platform-agnostic C++ interface for Bluetooth Classic device discovery,
// specifically targeting OpenXC Vehicle Interfaces (which use the Bluetooth
// Serial Port Profile / SPP over RFCOMM).
//
// macOS implementation: src/BtDiscovery.mm (IOBluetooth.framework)
// Non-Apple platforms: stubs returning empty results.
//
#include <string>
#include <vector>

namespace bt {

class Connection;

// A paired Bluetooth device that advertises the Serial Port Profile (SPP).
struct Device {
    std::string name;     // e.g. "OpenXC VI"
    std::string address;  // Normalised MAC: "04:C4:61:C3:69:D0" (colons, uppercase)
    bool        connected = false; // true when macOS already has an open link
};

// Return all paired Bluetooth devices that provide an SPP/RFCOMM service.
// Devices that look like an OpenXC VI (name contains "OpenXC" or "VI") are
// listed first.  Call is synchronous and fast (queries the OS paired-devices
// cache — does NOT perform an active radio scan).
//
// Returns an empty vector on non-Apple platforms.
std::vector<Device> pairedSppDevices();

// Open a paired Classic Bluetooth SPP service directly through IOBluetooth.
// This avoids depending on macOS to create a /dev/cu.* serial node.
Connection* openRfcommConnection(const std::string& macOrName, std::string& err);
void closeRfcommConnection(Connection* connection);
bool rfcommConnected(const Connection* connection);
bool writeRfcomm(Connection* connection, const char* data, size_t size,
                 std::string& err);
int readRfcomm(Connection* connection, char* data, int timeoutMs,
               std::string& err);

} // namespace bt
