#include "BtDiscovery.hpp"

#ifndef __APPLE__

namespace bt {

std::vector<Device> pairedSppDevices() { return {}; }

std::string resolveDevicePath(const std::string& macOrName, std::string& err) {
    if (macOrName.rfind("/dev/", 0) == 0 || macOrName.rfind("COM", 0) == 0 ||
        macOrName.rfind("\\\\.\\COM", 0) == 0)
        return macOrName;
    err = "Bluetooth auto-discovery is only supported on macOS. "
          "Enter the USB serial port path manually (e.g. /dev/ttyUSB0 or COM3).";
    return {};
}

bool prepareSerialPath(const std::string&, std::string&) { return true; }

} // namespace bt

#endif // __APPLE__