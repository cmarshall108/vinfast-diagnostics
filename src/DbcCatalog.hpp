#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace can {

struct DbcEnumValue {
    int64_t value = 0;
    std::string label;
};

struct DbcSignal {
    std::string name;
    uint16_t startBit = 0;
    uint8_t length = 0;
    bool bigEndian = true;
    bool isSigned = false;
    double factor = 1.0;
    double offset = 0.0;
    std::string unit;
    std::string comment;
    std::vector<DbcEnumValue> values;
};

struct DbcMessage {
    uint32_t id = 0;
    std::string name;
    std::string transmitter;
    uint8_t dlc = 0;
    std::vector<DbcSignal> signalList;
};

struct DbcNetwork {
    std::string name;
    std::string sourceFile;
    std::vector<DbcMessage> messages;
};

struct DbcRoute {
    std::string destinationNetwork;
    uint32_t destinationMessageId = 0;
    std::string destinationMessageName;
    std::string destinationSignalName;
    std::string sourceNetwork;
    uint32_t sourceMessageId = 0;
    std::string sourceMessageName;
    std::string sourceSignalName;
    std::string conversionId;
};

struct DbcDecodedSignal {
    std::string name;
    double value = 0.0;
    std::string display;
};

const std::vector<DbcNetwork>& dbcNetworks();
const std::vector<DbcRoute>& dbcRoutes();
const DbcNetwork* findDbcNetwork(const std::string& name);
const DbcMessage* findDbcMessage(const DbcNetwork& network, uint32_t id);
std::vector<DbcDecodedSignal> decodeDbcFrame(const std::string& network,
                                             uint32_t canId,
                                             const uint8_t* data,
                                             size_t length);
std::vector<std::string> dbcRouteDescriptions(const std::string& network,
                                              uint32_t messageId,
                                              const std::string& signalName);

} // namespace can