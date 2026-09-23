#include "DbcCatalog.hpp"

#include <QFile>
#include <QString>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <regex>
#include <sstream>
#include <unordered_map>

namespace can {
namespace {

struct BundledFile {
    const char* network;
    const char* filename;
};

const BundledFile kDatabaseFiles[] = {
    {"Info_CAN", "01_Info_CAN_Matrix_BEV_v10.7.5.dbc"},
    {"Body_CAN", "03_Body_CAN_Matrix_BEV_v10.7.5.dbc"},
    {"Diag_CAN", "05_Diag_CAN_Matrix_BEV_v10.6.dbc"},
    {"PT_CAN", "06_PT_CAN_Matrix_BEV_v10.7.4.dbc"},
    {"Chassis_CAN", "09_Chassis_CAN_Matrix_BEV_v10.7.1.dbc"},
    {"BA_CAN", "11_BA_CAN_Matrix_BEV_v10.7.5.dbc"},
    {"ASU_Body_Private_Bus", "12_ASU_Body_Private_Bus_BEV_v10.6.dbc"},
};

const char* const kRoutingFiles[] = {
    "ToBA_v10.7.1.csv", "ToBody_v10.7.3.csv", "ToChassis_v10.7.1.csv",
    "ToDiag_v10.7.5.csv", "ToInfo_v10.7.5.csv", "ToPT_v10.7.1.csv",
    "ToPT_v10.7.4.csv", "ToXGWLIN1_v10.6.9.csv", "ToXGWLIN2_v10.6.9.csv",
};

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

uint32_t parseId(const std::string& text, int base) {
    char* end = nullptr;
    const unsigned long value = std::strtoul(text.c_str(), &end, base);
    return end && *end == '\0' ? static_cast<uint32_t>(value) : 0;
}

std::vector<std::string> parseCsvRow(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    bool quoted = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (ch == '"') {
            if (quoted && i + 1 < line.size() && line[i + 1] == '"') {
                field.push_back('"');
                ++i;
            } else {
                quoted = !quoted;
            }
        } else if (ch == ',' && !quoted) {
            fields.push_back(std::move(field));
            field.clear();
        } else {
            field.push_back(ch);
        }
    }
    fields.push_back(std::move(field));
    return fields;
}

bool loadResource(const QString& resourcePath, std::string& contents) {
    QFile file(resourcePath);
    if (!file.open(QIODevice::ReadOnly)) return false;
    contents = file.readAll().toStdString();
    return true;
}

DbcNetwork parseDbc(const BundledFile& source) {
    DbcNetwork network;
    network.name = source.network;
    network.sourceFile = source.filename;

    std::string contents;
    if (!loadResource(QStringLiteral(":/can/dbcs/%1").arg(source.filename), contents))
        return network;

    static const std::regex messagePattern(
        R"rx(^\s*BO_\s+(\d+)\s+([^\s:]+):\s+(\d+)\s+(\S+).*$)rx");
    static const std::regex signalPattern(
        R"rx(^\s*SG_\s+(\S+)(?:\s+\S+)?\s*:\s*(\d+)\|(\d+)@(\d)([+-])\s*\(([^,]+),([^\)]+)\)\s*\[[^\]]*\]\s*"([^"]*)"(?:\s+.*)?$)rx");
    static const std::regex commentPattern(
        R"rx(^\s*CM_\s+SG_\s+(\d+)\s+(\S+)\s+"(.*)"\s*;\s*$)rx");
    static const std::regex valuePattern(
        R"rx(^\s*VAL_\s+(\d+)\s+(\S+)\s+(.*);\s*$)rx");
    static const std::regex enumPairPattern(R"rx((-?\d+)\s+"([^"]*)")rx");

    std::istringstream input(contents);
    std::string line;
    DbcMessage* current = nullptr;
    while (std::getline(input, line)) {
        std::smatch match;
        if (std::regex_match(line, match, messagePattern)) {
            DbcMessage message;
            message.id = parseId(match[1].str(), 10);
            message.name = match[2].str();
            message.dlc = static_cast<uint8_t>(parseId(match[3].str(), 10));
            message.transmitter = match[4].str();
            network.messages.push_back(std::move(message));
            current = &network.messages.back();
            continue;
        }
        if (std::regex_match(line, match, signalPattern)) {
            if (!current) continue;
            DbcSignal signal;
            signal.name = match[1].str();
            signal.startBit = static_cast<uint16_t>(parseId(match[2].str(), 10));
            signal.length = static_cast<uint8_t>(parseId(match[3].str(), 10));
            signal.bigEndian = match[4].str() == "0";
            signal.isSigned = match[5].str() == "-";
            signal.factor = std::strtod(match[6].str().c_str(), nullptr);
            signal.offset = std::strtod(match[7].str().c_str(), nullptr);
            signal.unit = match[8].str();
            current->signalList.push_back(std::move(signal));
            continue;
        }
        if (std::regex_match(line, match, commentPattern)) {
            const uint32_t id = parseId(match[1].str(), 10);
            for (auto& message : network.messages) {
                if (message.id != id) continue;
                for (auto& signal : message.signalList)
                    if (signal.name == match[2].str()) signal.comment = match[3].str();
                break;
            }
            continue;
        }
        if (std::regex_match(line, match, valuePattern)) {
            const uint32_t id = parseId(match[1].str(), 10);
            for (auto& message : network.messages) {
                if (message.id != id) continue;
                for (auto& signal : message.signalList) {
                    if (signal.name != match[2].str()) continue;
                    const std::string encoded = match[3].str();
                    for (std::sregex_iterator it(encoded.begin(), encoded.end(), enumPairPattern), end;
                         it != end; ++it) {
                        signal.values.push_back({
                            std::strtoll((*it)[1].str().c_str(), nullptr, 10), (*it)[2].str()});
                    }
                }
                break;
            }
        }
    }
    return network;
}

std::vector<DbcRoute> parseRoutes() {
    std::vector<DbcRoute> routes;
    for (const char* filename : kRoutingFiles) {
        std::string contents;
        if (!loadResource(QStringLiteral(":/can/routing/%1").arg(filename), contents))
            continue;
        std::istringstream input(contents);
        std::string line;
        bool header = true;
        while (std::getline(input, line)) {
            if (header) { header = false; continue; }
            auto fields = parseCsvRow(line);
            if (fields.size() < 17 || fields[1] != "Msg") continue;
            DbcRoute route;
            route.destinationNetwork = fields[2];
            route.destinationMessageId = parseId(fields[3], 0);
            route.destinationMessageName = fields[4];
            route.destinationSignalName = fields[5];
            route.sourceNetwork = fields[9];
            route.sourceMessageId = parseId(fields[10], 0);
            route.sourceMessageName = fields[11];
            route.sourceSignalName = fields[12];
            route.conversionId = fields[16];
            routes.push_back(std::move(route));
        }
    }
    return routes;
}

struct CatalogData {
    std::vector<DbcNetwork> networks;
    std::vector<DbcRoute> routes;

    CatalogData() {
        for (const auto& source : kDatabaseFiles) {
            auto network = parseDbc(source);
            if (!network.messages.empty()) networks.push_back(std::move(network));
        }
        routes = parseRoutes();
    }
};

const CatalogData& catalog() {
    static const CatalogData data;
    return data;
}

uint64_t extractRaw(const uint8_t* data, size_t length, const DbcSignal& signal,
                    bool& valid) {
    uint64_t raw = 0;
    int bit = signal.startBit;
    valid = signal.length > 0 && signal.length <= 64;
    for (int index = 0; valid && index < signal.length; ++index) {
        const int byte = bit >> 3;
        const int position = bit & 7;
        if (byte < 0 || static_cast<size_t>(byte) >= length) {
            valid = false;
            break;
        }
        const uint64_t current = (data[byte] >> position) & 1u;
        if (signal.bigEndian) {
            raw = (raw << 1) | current;
            bit = position == 0 ? byte * 8 + 15 : bit - 1;
        } else {
            raw |= current << index;
            ++bit;
        }
    }
    return raw;
}

std::string formatValue(double value, const DbcSignal& signal) {
    std::ostringstream output;
    const double nearest = std::round(value);
    if (std::abs(value - nearest) < 0.000001) output << std::fixed << std::setprecision(0) << value;
    else output << std::fixed << std::setprecision(3) << value;
    std::string text = output.str();
    if (text.find('.') != std::string::npos) {
        while (!text.empty() && text.back() == '0') text.pop_back();
        if (!text.empty() && text.back() == '.') text.pop_back();
    }
    if (!signal.unit.empty()) text += " " + signal.unit;
    return text;
}

} // namespace

const std::vector<DbcNetwork>& dbcNetworks() { return catalog().networks; }
const std::vector<DbcRoute>& dbcRoutes() { return catalog().routes; }

const DbcNetwork* findDbcNetwork(const std::string& name) {
    for (const auto& network : dbcNetworks())
        if (network.name == name) return &network;
    return nullptr;
}

const DbcMessage* findDbcMessage(const DbcNetwork& network, uint32_t canId) {
    for (const auto& message : network.messages)
        if (message.id == canId) return &message;
    return nullptr;
}

std::vector<DbcDecodedSignal> decodeDbcFrame(const std::string& networkName,
                                             uint32_t canId,
                                             const uint8_t* data,
                                             size_t length) {
    std::vector<DbcDecodedSignal> decoded;
    if (!data || length == 0) return decoded;
    const DbcNetwork* network = findDbcNetwork(networkName);
    if (!network) return decoded;
    const DbcMessage* message = findDbcMessage(*network, canId);
    if (!message) return decoded;
    for (const auto& signal : message->signalList) {
        bool valid = false;
        const uint64_t raw = extractRaw(data, length, signal, valid);
        if (!valid) continue;
        int64_t signedRaw = static_cast<int64_t>(raw);
        if (signal.isSigned && signal.length < 64 && (raw & (uint64_t{1} << (signal.length - 1))))
            signedRaw = static_cast<int64_t>(raw | (~uint64_t{0} << signal.length));
        const double value = static_cast<double>(signedRaw) * signal.factor + signal.offset;
        std::string display;
        const auto enumValue = std::find_if(signal.values.begin(), signal.values.end(),
            [signedRaw](const DbcEnumValue& item) { return item.value == signedRaw; });
        if (enumValue != signal.values.end()) display = enumValue->label;
        else display = formatValue(value, signal);
        decoded.push_back({signal.name, value, std::move(display)});
    }
    return decoded;
}

std::vector<std::string> dbcRouteDescriptions(const std::string& network,
                                              uint32_t messageId,
                                              const std::string& signalName) {
    std::vector<std::string> descriptions;
    for (const auto& route : dbcRoutes()) {
        if (route.destinationNetwork == network && route.destinationMessageId == messageId &&
                route.destinationSignalName == signalName) {
            descriptions.push_back(route.sourceNetwork + " 0x" + [&route] {
                std::ostringstream id;
                id << std::uppercase << std::hex << route.sourceMessageId;
                return id.str();
            }() + " " + route.sourceMessageName + "." + route.sourceSignalName +
                " -> " + route.destinationNetwork + " " + route.destinationMessageName +
                "." + route.destinationSignalName);
        }
    }
    return descriptions;
}

} // namespace can