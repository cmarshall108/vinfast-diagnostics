#include "BtDiscovery.hpp"

#ifndef __APPLE__

namespace bt {

std::vector<Device> pairedSppDevices() { return {}; }

} // namespace bt

#endif // __APPLE__