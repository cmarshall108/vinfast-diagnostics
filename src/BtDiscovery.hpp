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
    std::string devPath;  // Serial device path if already active, e.g.
                          // "/dev/cu.OpenXC-VI"; empty when the device exists
                          // in the paired list but has not yet been connected.
    bool        connected = false; // true when macOS already has an open link
};

// Return all paired Bluetooth devices that provide an SPP/RFCOMM service.
// Devices that look like an OpenXC VI (name contains "OpenXC" or "VI") are
// listed first.  Call is synchronous and fast (queries the OS paired-devices
// cache — does NOT perform an active radio scan).
//
// Returns an empty vector on non-Apple platforms.
std::vector<Device> pairedSppDevices();

// Given a Bluetooth MAC address ("04:C4:61:C3:69:D0") or partial device name,
// find the corresponding /dev/cu.* serial path.
//
// On macOS: walks IOBluetooth paired devices, derives the macOS kernel serial
// port name from the device's Bluetooth name, then confirms the path exists in
// /dev/.  If the path does not exist the function asks IOBluetooth to open the
// RFCOMM channel, which causes the kernel to create the /dev/cu.* node; it
// then retries the search.
//
// Returns the /dev/cu.* path, or an empty string with `err` set on failure.
std::string resolveDevicePath(const std::string& macOrName, std::string& err);

// Ensure the Bluetooth ACL/RFCOMM link behind a serial device node is actually
// established before it is opened.
//
// macOS can expose a /dev/cu.* node for a paired VI whose data channel is not
// connected; opening such a node succeeds but no bytes ever flow. When devPath
// matches a paired SPP device, this brings up the baseband link so the kernel
// serial manager activates a live RFCOMM channel.
//
// For non-Bluetooth paths (USB serial), unrecognised nodes, or non-Apple
// platforms this is a no-op that returns true. Returns false with `err` set
// only when a matching Bluetooth device is found but cannot be connected.
bool prepareSerialPath(const std::string& devPath, std::string& err);

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
