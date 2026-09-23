#include "VF8Data.hpp"
#include "DbcCatalog.hpp"

#include <cmath>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool putMotorola(std::vector<uint8_t>& data, int startBit, int length, uint64_t raw) {
    int bit = startBit;
    for (int index = 0; index < length; ++index) {
        const int byte = bit >> 3;
        const int position = bit & 7;
        if (byte < 0 || byte >= static_cast<int>(data.size())) return false;
        if ((raw >> (length - index - 1)) & 1u)
            data[byte] |= static_cast<uint8_t>(1u << position);
        bit = position == 0 ? byte * 8 + 15 : bit - 1;
    }
    return true;
}

const VF8CanValue* findValue(const std::vector<VF8CanValue>& values,
                             const char* name) {
    for (const auto& value : values)
        if (std::strcmp(value.signal, name) == 0) return &value;
    return nullptr;
}

bool checkValue(const std::vector<VF8CanValue>& values, const char* name,
                double expected) {
    const auto* value = findValue(values, name);
    if (!value || std::abs(value->value - expected) > 0.001) {
        std::cerr << "unexpected/missing signal " << name << '\n';
        return false;
    }
    return true;
}

bool checkDisplay(const std::vector<VF8CanValue>& values, const char* name,
                  const char* expected) {
    const auto* value = findValue(values, name);
    if (!value || value->display != expected) {
        std::cerr << "unexpected/missing display for " << name << '\n';
        return false;
    }
    return true;
}

} // namespace

int main() {
    const auto& networks = can::dbcNetworks();
    if (networks.size() != 7 || can::dbcRoutes().size() < 1000) {
        std::cerr << "bundled CAN databases or routing tables did not load\n";
        return 1;
    }
    const auto* info = can::findDbcNetwork("Info_CAN");
    if (!info || !can::findDbcMessage(*info, 0x165) ||
        can::dbcRouteDescriptions("Info_CAN", 0x85, "ACM_Crash_Sts").empty()) {
        std::cerr << "expected Info-CAN message/routing metadata is missing\n";
        return 1;
    }

    std::vector<uint8_t> charge(8);
    if (!putMotorola(charge, 38, 7, 83) ||
        !putMotorola(charge, 43, 8, 231) ||
        !putMotorola(charge, 47, 3, 5) ||
        !putMotorola(charge, 48, 6, 42)) return 1;
    const auto chargeValues = vf8DecodeCanFrame(0x165, charge.data(), charge.size());
    const auto dbcChargeValues = can::decodeDbcFrame(
        "Info_CAN", 0x165, charge.data(), charge.size());
    if (!checkValue(chargeValues, "VCU_CPValue", 83) ||
        !checkValue(chargeValues, "VCU_ACChargingVoltage", 231) ||
        !checkValue(chargeValues, "VCU_MinCurrentOfACCharging", 5) ||
        !checkValue(chargeValues, "VCU_MaxCurrentOfACCharging", 42)) return 1;
    bool dbcPilotMatches = false;
    for (const auto& value : dbcChargeValues)
        if (value.name == "VCU_CPValue" && std::abs(value.value - 83) < 0.001)
            dbcPilotMatches = true;
    if (!dbcPilotMatches) {
        std::cerr << "DBC-backed signal decode failed\n";
        return 1;
    }

    std::vector<uint8_t> status(8);
    if (!putMotorola(status, 23, 4, 5) ||
        !putMotorola(status, 29, 4, 2) ||
        !putMotorola(status, 31, 2, 3) ||
        !putMotorola(status, 47, 8, 180) ||
        !putMotorola(status, 63, 8, 4)) return 1;
    const auto statusValues = vf8DecodeCanFrame(0x215, status.data(), status.size());
    if (!checkDisplay(statusValues, "BMS_ERR_LEV", "Emergency off condition") ||
        !checkDisplay(statusValues, "BMS_Sys_STS", "HV power-up successful") ||
        !checkDisplay(statusValues, "BMS_ISU_Status", "Level 3 (<100 kOhm)") ||
        !checkValue(statusValues, "BMS_SOH", 90) ||
        !checkDisplay(statusValues, "BMS_HV_Sts", "AC charge")) return 1;

    std::vector<uint8_t> faults(8);
    if (!putMotorola(faults, 14, 1, 1) || !putMotorola(faults, 34, 1, 1)) return 1;
    const auto faultValues = vf8DecodeCanFrame(0x225, faults.data(), faults.size());
    if (!checkDisplay(faultValues, "FRMo_bErrChrgnAllwdExtMon", "Error") ||
        !checkDisplay(faultValues, "EHPMon_bErrHvilMon", "Error")) return 1;

    std::vector<uint8_t> relays(8);
    if (!putMotorola(relays, 14, 1, 1) || !putMotorola(relays, 18, 3, 2)) return 1;
    const auto relayValues = vf8DecodeCanFrame(0x375, relays.data(), relays.size());
    if (!checkDisplay(relayValues, "BMS_MainPosRelay_ERR", "Normal") ||
        !checkDisplay(relayValues, "BMS_MainPosRelay_STS", "Closed")) return 1;

    std::vector<uint8_t> warnings(8);
    if (!putMotorola(warnings, 14, 1, 1) || !putMotorola(warnings, 19, 1, 1)) return 1;
    const auto warningValues = vf8DecodeCanFrame(0x493, warnings.data(), warnings.size());
    if (!checkValue(warningValues, "BMS_ThermalRunaway", 1) ||
        !checkValue(warningValues, "BMS_Warning_Isolation", 1)) return 1;

    if (vf8CanMessageName(0x230) != nullptr ||
        findValue(vf8DecodeCanFrame(0x214, status.data(), status.size()), "BMS_MinCellSOC")) {
        std::cerr << "catalog contains a signal absent from the supplied CAN DBC\n";
        return 1;
    }

    if (std::string(kVF8DealerDtcReport.vin) != "RLLV1AEB0RH004878" ||
        kVF8DealerDtcReport.printedDtcCount != 167 ||
        kVF8BatteryHealthReport.items.size() != 33) {
        std::cerr << "dealer report metadata or battery health table is incomplete\n";
        return 1;
    }
    if (!vf8DtcLookup("B0073-1B") || !vf8DtcLookup("B00731B") ||
        std::string(vf8DtcLookup("B0073-1B")) !=
            "Belt Pretensioner 2nd Row Driver Side Circuit Resistance Above Threshold") {
        std::cerr << "dealer-form DTC lookup failed\n";
        return 1;
    }
    if (vf8DtcDescribe("U2C49-82") != "Alive / sequence counter incorrect or not updated") {
        std::cerr << "dealer-form failure-type decoding failed\n";
        return 1;
    }

    const VF8DealerSystem* dealerBms = nullptr;
    const VF8DealerSystem* dealerAdas = nullptr;
    const VF8DealerSystem* dealerTrm = nullptr;
    int dealerSupplyVoltageOccurrences = 0;
    int dealerObservationCount = 0;
    int dealerNoResponseCount = 0;
    for (const auto& system : kVF8DealerDtcReport.systems) {
        if (std::string(system.code) == "BMS") dealerBms = &system;
        if (std::string(system.code) == "ADAS") dealerAdas = &system;
        if (std::string(system.code) == "TRM") dealerTrm = &system;
        dealerObservationCount += static_cast<int>(system.dtcs.size());
        if (!system.responded) ++dealerNoResponseCount;
        for (const auto& dtc : system.dtcs)
            if (std::string(dtc.dtc) == "U1101-16") ++dealerSupplyVoltageOccurrences;
    }
    if (!dealerBms || !dealerAdas || !dealerTrm || dealerBms->dtcs.size() != 9 ||
        dealerAdas->responded || dealerTrm->responded || dealerNoResponseCount != 2 ||
        dealerObservationCount != 165 || dealerSupplyVoltageOccurrences < 3) {
        std::cerr << "dealer ECU associations, duplicates, or no-response records are missing\n";
        return 1;
    }
    return 0;
}