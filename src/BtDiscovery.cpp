#include "BtDiscovery.hpp"

#ifndef __APPLE__

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