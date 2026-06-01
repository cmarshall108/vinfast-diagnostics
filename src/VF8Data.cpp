#include "VF8Data.hpp"

#include <cstdio>
#include <cstdlib>
#include <unordered_map>

// ===========================================================================
// ECU list
//
// "code" matches the diagnostic system names reported by the Autel scan where
// applicable; engineering-only controllers (from the on-vehicle "ECUs
// Information" screen) are also included so a full scan can address them.
// HW/SW part numbers are the ACTUAL part numbers read from the vehicle.
// placeholderAddr values are NOT official - configure them in the UI.
// ===========================================================================
const std::vector<VF8Ecu> kVF8Ecus = {
    // Autel-scanned diagnostic systems (confirmed to respond to UDS).
    {"XGW",     "Extendable Gateway",                    0x1001, "EEP30009521-01", "SOW30050503-04"},
    {"VCU",     "Vehicle Control Unit",                  0x1002, "",               "SOW30050205-30"},
    {"BMS",     "Battery Management System",             0x1003, "BAT30002013-01", "SOW30002100-25"},
    {"MCU",     "Motor Control Unit",                    0x1004, "",               ""},
    {"ESC",     "Electronic Stability Control",          0x1005, "",               ""},
    {"EPS",     "Electric Power Steering",               0x1006, "CHS30004062-01", "SOW30000224-02"},
    {"ADAS",    "Advanced Driver Assistance System",     0x1007, "",               ""},
    {"BCM",     "Body Control Module",                   0x1008, "EEP30220027-01", "SOW30220361-01"},
    {"CCU",     "Climate Control Unit",                  0x1009, "EEP30006107-04", "SOW30006116-04"},
    {"DDC",     "DC-DC Converter",                       0x100A, "EEP30005276-03", "SOW30050170-10"},
    {"MHU",     "Multimedia Headunit",                   0x100B, "EEP30005211-01", "SOW30051001-84"},
    {"RLS",     "Rain / Light Sensor",                   0x100C, "",               ""},
    // Engineering controllers (from on-vehicle ECUs Information screen).
    {"TBOX",    "Telematics Box",                        0x100D, "EEP30005211-01", "SOW30052001-53"},
    {"ACM",     "Airbag Control Module",                 0x100E, "EEP30010045-02", "SOW30010051-01"},
    {"HUD",     "Head-Up Display",                       0x100F, "EEP30006274-01", "SOW30205101-31"},
    {"EDS_F",   "Electric Drive System - Front",         0x1010, "EEH30073014-01", "SOW30073520-01"},
    {"EDS_R",   "Electric Drive System - Rear",          0x1011, "EEH30073015-01", "SOW30073522-01"},
    {"PSM_D",   "Power Supply Module - Driver",          0x1012, "BIN30023940-01", "SOW30171972-01"},
    {"MRGEN",   "Mid-Range Radar / Gen Module",          0x1013, "EEP30008110-01", "SOW30008009-05"},
    {"SCAM",    "Surround/Smart Camera Module",          0x1014, "EEP30008131-01", "SOW30008021-11"},
    {"RCU",     "Restraint Control Unit",                0x1015, "CHS30014035-01", "SOW30000411-02"},
    {"IDR",     "Interior Domain / Radar",               0x1016, "",               "SOW20000213-02"},
    {"SRR_FR",  "Short-Range Radar - Front Right",       0x1017, "EEP30008133-01", "SOW30008022-05"},
    {"SRR_FL",  "Short-Range Radar - Front Left",        0x1018, "EEP30008133-01", "SOW30008022-05"},
    {"SRR_RR",  "Short-Range Radar - Rear Right",        0x1019, "EEP30008133-01", "SOW30008022-05"},
    {"SRR_RL",  "Short-Range Radar - Rear Left",         0x101A, "EEP30008133-01", "SOW30008022-05"},
    {"DCDC",    "DC-DC Converter (HV)",                  0x101B, "EEP30005276-03", "SOW30050170-10"},
    {"APM",     "Auxiliary Power Module",                0x101C, "EEP10006197-03", "SOW30050770-02"},
    {"SHVU_F",  "Smart HV Unit - Front",                 0x101D, "BIN30022879-01", "SOW30171038-01"},
    {"OCS",     "Occupant Classification System",        0x101E, "BIN30022839-01", "SOW30022845-01"},
    {"BCM_BPM", "Body Control - Battery Pack Monitor",   0x101F, "EEP30220027-01", "SOW30220363-01"},
};

// ===========================================================================
// Reference DTC scan - Autel MaxiCOM MK900-BT, captured 2026-03-30 19:28:52.
// 12 systems, 125 DTCs. Descriptions are filled where the Autel report gave
// real text; entries marked "" were reported only as "refer to service manual".
// ===========================================================================
const std::vector<VF8RefSystem> kVF8ReferenceScan = {
    {"MCU", "Motor Control Unit", {
        {"U015587", "History", ""},
        {"U042381", "History", ""},
        {"U160E81", "History", ""},
        {"U110887", "Current", "Airbag Control Module (ACM) ECU message missing"},
    }},
    {"BCM", "Body Control Module", {
        {"U110116", "History", ""},
        {"U110887", "Current", "Lost communication with Airbag Control Module"},
        {"U014687", "History", ""},
        {"U119188", "Current", ""},
        {"U020C87", "Current", ""},
        {"B101413", "History", "Right reverse lamp circuit: current below threshold / open load"},
        {"B101513", "History", "Left stop lamp circuit: current below threshold / open load"},
        {"B101613", "History", "Right stop lamp circuit: current below threshold / open load"},
        {"B10B871", "History", ""},
        {"B10EC00", "History", ""},
        {"U041682", "History", ""},
        {"U045D82", "History", ""},
        {"U047781", "History", ""},
        {"U01B081", "Current", ""},
        {"P058D09", "Current", ""},
    }},
    {"BMS", "Battery Management System", {
        {"U110116", "History", ""},
        {"P180000", "Current", ""},
        {"P124100", "Current", ""},
        {"P183401", "Current", ""},
        {"P18D000", "History", ""},
        {"P124003", "Current", ""},
        {"P0A9500", "Current", ""},
        {"U014687", "Current", ""},
        {"U110117", "History", ""},
        {"P0ABF86", "History", ""},
        {"U012587", "History", ""},
    }},
    {"VCU", "Vehicle Control Unit", {
        {"U125517", "History", ""},
        {"U125516", "History", ""},
        {"U092300", "Current", ""},
        {"P101716", "History", ""},
        {"U117188", "History", ""},
        {"P112900", "History", ""},
        {"P113700", "Current", ""},
        {"P103300", "History", ""},
        {"P115000", "History", ""},
        {"P115100", "History", ""},
        {"P118800", "History", ""},
        {"U110116", "History", ""},
        {"P105D38", "History", ""},
        {"P106B29", "History", ""},
    }},
    {"ESC", "Electronic Stability Control", {
        {"U015687", "History", ""},
        {"C059496", "History", ""},
        {"U041681", "Current", ""},
        {"U110887", "Current", ""},
    }},
    {"EPS", "Electric Power Steering", {
        {"U110116", "History", "Power supply - circuit voltage below threshold"},
    }},
    {"ADAS", "Advanced Driver Assistance System", {
        {"U113187", "History", ""}, {"U30031C", "History", ""}, {"U113387", "History", ""},
        {"U113087", "History", ""}, {"U113287", "History", ""}, {"U112987", "History", ""},
        {"U111189", "Current", ""}, {"U113081", "History", ""}, {"U116589", "Current", ""},
        {"U111489", "History", ""}, {"U118289", "History", ""}, {"U113381", "History", ""},
        {"U118789", "Current", ""}, {"U114081", "Current", ""}, {"U114289", "History", ""},
        {"U119689", "Current", ""}, {"B193504", "History", ""}, {"B193104", "History", ""},
        {"B193704", "History", ""}, {"B19084A", "History", ""}, {"B193304", "History", ""},
        {"B193404", "History", ""}, {"B193204", "History", ""}, {"B194004", "History", ""},
        {"B193904", "Current", ""}, {"B194204", "History", ""}, {"B194104", "History", ""},
        {"U119387", "History", ""}, {"U119287", "History", ""}, {"U113681", "History", ""},
    }},
    {"CCU", "Climate Control Unit", {
        {"B170E54", "Current", ""},
        {"U110887", "Current", "Lost communication with Airbag Control Module"},
    }},
    {"DDC", "DC-DC Converter", {
        {"C150C1C", "History", ""}, {"U113787", "History", ""}, {"U113887", "History", ""},
        {"U124329", "History", ""}, {"C153700", "History", ""}, {"C153600", "History", ""},
        {"U113987", "History", ""}, {"U114087", "History", ""}, {"U114187", "History", ""},
        {"U111589", "History", ""}, {"U112081", "History", ""}, {"U112389", "History", ""},
        {"U112681", "History", ""}, {"U113081", "History", ""}, {"U113381", "History", ""},
        {"U114081", "Current", ""}, {"U114881", "History", ""}, {"U118789", "Current", ""},
        {"U119389", "History", ""}, {"U113581", "History", ""}, {"U119689", "Current", ""},
    }},
    {"MHU", "Multimedia Headunit", {
        {"B161A03", "History", ""},
        {"U300004", "History", ""},
        {"U014687", "Current", ""},
        {"U015C87", "History", ""},
        {"B160D14", "History", ""},
        {"B160E14", "History", ""},
        {"U110116", "History", ""},
        {"B162004", "History", ""},
        {"B161B01", "History", ""},
        {"B161A01", "Current", ""},
    }},
    {"RLS", "Rain / Light Sensor", {
        {"U100304", "Current", ""},
        {"U100404", "Current", ""},
        {"U10041C", "Current", ""},
        {"U110116", "Current", ""},
    }},
    {"XGW", "Extendable Gateway", {
        {"B200101", "History", ""},
        {"B200001", "Current", ""},
        {"U117188", "History", "Chassis CAN - bus off"},
        {"U110887", "Current", "Lost communication with Airbag Control Module"},
        {"U019E87", "History", ""},
        {"U012287", "History", "Lost communication with vehicle dynamics control module"},
        {"U110116", "History", "Power supply circuit voltage below threshold"},
        {"B2001A2", "History", ""},
        {"B2000A2", "History", ""},
    }},
};

const char* vf8DtcLookup(const std::string& code) {
    // Return the first non-empty description recorded for this DTC string in
    // the reference scan (the same code can appear under several systems).
    for (const auto& sys : kVF8ReferenceScan) {
        for (const auto& d : sys.dtcs) {
            if (code == d.dtc && d.desc && d.desc[0] != '\0')
                return d.desc;
        }
    }
    return nullptr;
}

// ===========================================================================
// Standardized decoders (ISO 14229-1 / SAE J2012-DA)
// ===========================================================================

std::string vf8FailureType(uint8_t ftb) {
    // SAE J2012-DA "DTC Failure Type Byte" definitions. Only entries with high
    // confidence are listed; anything else returns a neutral hex label so no
    // inaccurate text is shown.
    static const std::unordered_map<uint8_t, const char*> t = {
        {0x00, "No sub-type information"},
        {0x01, "General electrical failure"},
        {0x02, "General signal failure"},
        {0x04, "System internal failure"},
        {0x07, "Mechanical failure"},
        {0x09, "Component failure"},
        {0x11, "Circuit short to ground"},
        {0x12, "Circuit short to battery"},
        {0x13, "Circuit open"},
        {0x14, "Circuit short to ground or open"},
        {0x15, "Circuit short to battery or open"},
        {0x16, "Circuit voltage below threshold"},
        {0x17, "Circuit voltage above threshold"},
        {0x18, "Circuit current below threshold"},
        {0x19, "Circuit current above threshold"},
        {0x1A, "Circuit resistance below threshold"},
        {0x1B, "Circuit resistance above threshold"},
        {0x1C, "Circuit voltage out of range"},
        {0x1D, "Circuit current out of range"},
        {0x21, "Signal amplitude below minimum"},
        {0x22, "Signal amplitude above maximum"},
        {0x29, "Signal invalid"},
        {0x2F, "Signal erratic"},
        {0x49, "Internal electronic failure"},
        {0x4A, "Incorrect component installed"},
        {0x54, "Missing calibration"},
        {0x55, "Not programmed"},
        {0x62, "Signal compare failure"},
        {0x81, "Invalid serial data received"},
        {0x82, "Alive / sequence counter incorrect or not updated"},
        {0x83, "Value of signal protection calculation incorrect"},
        {0x87, "Missing message"},
        {0x88, "Bus off"},
        {0x92, "Performance or incorrect operation"},
        {0x96, "Component internal failure"},
    };
    auto it = t.find(ftb);
    if (it != t.end()) return it->second;
    char buf[24];
    std::snprintf(buf, sizeof buf, "failure type 0x%02X", ftb);
    return buf;
}

const char* vf8SaeBaseDtc(const std::string& base5) {
    // SAE J2012 ISO/SAE-controlled (generic) base DTCs that appear in the VF8
    // scan. Manufacturer-controlled bases (U1xxx, U2xxx, B1xxx, B2xxx, P1xxx,
    // C1xxx, etc.) are intentionally omitted - their meaning is not standard.
    static const std::unordered_map<std::string, const char*> t = {
        {"U0122", "Lost Communication With Vehicle Dynamics Control Module"},
        {"U0125", "Lost Communication With Multi-axis Acceleration Sensor Module"},
        {"U0146", "Lost Communication With Gateway A"},
        {"U0155", "Lost Communication With Instrument Panel Cluster (IPC) Control Module"},
        {"U0416", "Invalid Data Received From Vehicle Dynamics Control Module"},
        {"U0423", "Invalid Data Received From Instrument Panel Cluster (IPC) Control Module"},
        {"U3000", "Control Module (internal fault / self test)"},
    };
    auto it = t.find(base5);
    return it != t.end() ? it->second : nullptr;
}

const char* vf8BestGuessBaseDtc(const std::string& base5) {
    // BEST-GUESS interpretations of the manufacturer-specific base codes that
    // appear in this vehicle's scan. Inferred from (a) the controlling ECU,
    // (b) the SAE letter prefix (U=network, P=powertrain/HV, C=chassis,
    // B=body), and (c) DTC numbering conventions. These are informed estimates
    // - NOT official VinFast definitions - but they are far more useful than a
    // bare failure-type byte. Several are corroborated by the Autel report
    // (e.g. U1108 = ACM lost comm, U1171 = chassis CAN bus-off, B1014/15/16 =
    // reverse/stop lamp circuits).
    static const std::unordered_map<std::string, const char*> t = {
        // ---- U: network / communication ----------------------------------
        {"U015C", "Lost communication with a camera / sensor module"},
        {"U0156", "Lost communication with display / information-center module"},
        {"U019E", "Lost communication with restraint / occupant module"},
        {"U01B0", "Lost communication on a private CAN sub-bus"},
        {"U020C", "Lost communication with battery-energy control module"},
        {"U045D", "Invalid data received from a chassis control module"},
        {"U0477", "Invalid data received from a driver-assistance module"},
        {"U0923", "Invalid data received from interior / roof control module"},
        {"U1101", "Power-supply (KL30/KL15) voltage monitoring fault"},
        {"U1108", "Lost communication with Airbag Control Module (ACM)"},
        {"U1111", "Lost communication with a radar / camera sensor"},
        {"U1114", "Lost communication with a radar / camera sensor"},
        {"U1115", "Lost communication with a networked control module"},
        {"U1120", "Lost communication with a networked control module"},
        {"U1123", "Lost communication with a networked control module"},
        {"U1126", "Lost communication with a networked control module"},
        {"U1129", "Lost communication with a driver-assistance sensor"},
        {"U1130", "Lost communication with front radar sensor"},
        {"U1131", "Lost communication with front corner radar (right)"},
        {"U1132", "Lost communication with front corner radar (left)"},
        {"U1133", "Lost communication with rear corner radar"},
        {"U1135", "Lost communication with a networked control module"},
        {"U1136", "Lost communication with a driver-assistance sensor"},
        {"U1137", "Lost communication with a networked control module"},
        {"U1138", "Lost communication with a networked control module"},
        {"U1139", "Lost communication with a networked control module"},
        {"U1140", "Lost communication with surround-view camera"},
        {"U1141", "Lost communication with surround-view camera"},
        {"U1142", "Lost communication with surround-view camera"},
        {"U1148", "Lost communication with a driver-assistance module"},
        {"U1165", "Lost communication with a driver-assistance sensor"},
        {"U1171", "Chassis CAN communication bus fault"},
        {"U1182", "Lost communication with a driver-assistance module"},
        {"U1187", "Lost communication with a driver-assistance module"},
        {"U1191", "Lost communication with a body / comfort module"},
        {"U1192", "Lost communication with a driver-assistance module"},
        {"U1193", "Lost communication with a driver-assistance module"},
        {"U1196", "Lost communication with a driver-assistance module"},
        {"U1243", "Lost communication / configuration with DC-DC peripheral"},
        {"U1255", "Vehicle configuration / coding mismatch"},
        {"U160E", "Lost communication with a multimedia peripheral"},
        // ---- P: powertrain / high-voltage --------------------------------
        {"P058D", "Battery / charging-system voltage sensor fault"},
        {"P0A95", "High-voltage system / HV fuse fault"},
        {"P0ABF", "Hybrid/EV battery current-sensor circuit fault"},
        {"P1017", "Drive-motor / inverter torque monitoring fault"},
        {"P1033", "HV contactor / pre-charge fault"},
        {"P105D", "Powertrain internal control fault"},
        {"P106B", "Powertrain internal control fault"},
        {"P1129", "Powertrain torque-control performance fault"},
        {"P1137", "Drive-motor performance fault"},
        {"P1150", "High-voltage system performance fault"},
        {"P1151", "High-voltage system performance fault"},
        {"P1188", "Powertrain coolant / thermal-management fault"},
        {"P1240", "HV battery contactor / pre-charge fault"},
        {"P1241", "HV battery contactor / pre-charge fault"},
        {"P1800", "Battery-management internal / control fault"},
        {"P1834", "Battery isolation / HV interlock fault"},
        {"P18D0", "Battery cell / balancing fault"},
        // ---- C: chassis ---------------------------------------------------
        {"C0594", "Electronic stability control performance fault"},
        {"C150C", "DC-DC converter output fault"},
        {"C1536", "DC-DC converter / chassis sensor fault"},
        {"C1537", "DC-DC converter / chassis sensor fault"},
        // ---- B: body ------------------------------------------------------
        {"B1014", "Right reverse-lamp circuit fault"},
        {"B1015", "Left stop-lamp circuit fault"},
        {"B1016", "Right stop-lamp circuit fault"},
        {"B10B8", "Body-control output circuit fault"},
        {"B10EC", "Body-control module internal fault"},
        {"B160D", "Audio / amplifier output circuit fault"},
        {"B160E", "Audio / amplifier output circuit fault"},
        {"B161A", "Microphone / audio-input circuit fault"},
        {"B161B", "Microphone / audio-input circuit fault"},
        {"B1620", "Display / touchscreen interface fault"},
        {"B170E", "Climate-control actuator / sensor fault"},
        {"B1908", "Driver-assistance radar alignment / blockage"},
        {"B1931", "Driver-assistance radar / camera fault"},
        {"B1932", "Driver-assistance radar / camera fault"},
        {"B1933", "Driver-assistance radar / camera fault"},
        {"B1934", "Driver-assistance radar / camera fault"},
        {"B1935", "Driver-assistance radar / camera fault"},
        {"B1937", "Driver-assistance radar / camera fault"},
        {"B1939", "Driver-assistance radar / camera fault"},
        {"B1940", "Driver-assistance radar / camera fault"},
        {"B1941", "Driver-assistance radar / camera fault"},
        {"B1942", "Driver-assistance radar / camera fault"},
        {"B2000", "Gateway / anti-theft system fault"},
        {"B2001", "Gateway / anti-theft system fault"},
    };
    auto it = t.find(base5);
    return it != t.end() ? it->second : nullptr;
}

std::string vf8DtcDescribe(const std::string& autelCode) {
    // 1) Explicit text captured from the scan tool, if any.
    if (const char* exact = vf8DtcLookup(autelCode))
        return exact;

    if (autelCode.size() < 7)
        return "(refer to vehicle service manual)";

    std::string base = autelCode.substr(0, 5);              // e.g. "U0146"
    uint8_t ftb = (uint8_t)std::strtoul(autelCode.substr(5, 2).c_str(), nullptr, 16);
    std::string ftbText = vf8FailureType(ftb);

    // 2) Standardized base description combined with the failure type.
    if (const char* base_desc = vf8SaeBaseDtc(base))
        return std::string(base_desc) + " - " + ftbText;

    // 3) Best-guess manufacturer base description combined with the failure type.
    if (const char* guess = vf8BestGuessBaseDtc(base))
        return std::string(guess) + " - " + ftbText + " (best guess)";

    // 4) Unknown base: report the standardized failure type only.
    return ftbText;
}

// ---- Standard protocol identifiers (ISO 14229 / SAE J1979 / ISO 13400) -----
// These are protocol-standardized and manufacturer-independent, so they apply
// to the VF8's standard UDS/DoIP stack even though VinFast-private identifiers
// are not published.

const std::vector<StdDid> kStandardDids = {
    {0xF180, "Boot Software Identification",            true},
    {0xF181, "Application Software Identification",     true},
    {0xF182, "Application Data Identification",         true},
    {0xF183, "Boot Software Fingerprint",              false},
    {0xF184, "Application Software Fingerprint",       false},
    {0xF186, "Active Diagnostic Session",             false},
    {0xF187, "Vehicle Manufacturer Spare Part Number", true},
    {0xF188, "Vehicle Manufacturer ECU SW Number",     true},
    {0xF189, "Vehicle Manufacturer ECU SW Version",    true},
    {0xF18A, "System Supplier Identifier",             true},
    {0xF18B, "ECU Manufacturing Date",                false},
    {0xF18C, "ECU Serial Number",                      true},
    {0xF190, "VIN (Vehicle Identification Number)",    true},
    {0xF191, "Vehicle Manufacturer ECU HW Number",     true},
    {0xF192, "System Supplier ECU HW Number",          true},
    {0xF193, "System Supplier ECU HW Version",         true},
    {0xF194, "System Supplier ECU SW Number",          true},
    {0xF195, "System Supplier ECU SW Version",         true},
    {0xF197, "System Name / Engine Type",              true},
    {0xF198, "Repair Shop Code / Tester Serial",       true},
    {0xF199, "Programming Date",                      false},
    {0xF19D, "ECU Installation Date",                 false},
    {0xF1A0, "Vehicle Manufacturer Specific (F1A0)",  false},
    {0xF40C, "OBD Engine Speed (live)",               false},
    {0xF40D, "OBD Vehicle Speed (live)",              false},
};

const std::vector<ObdService> kObdServices = {
    {0x01, "Show current data (live PIDs)"},
    {0x02, "Show freeze-frame data"},
    {0x03, "Show stored DTCs"},
    {0x04, "Clear DTCs and stored values"},
    {0x07, "Show pending DTCs"},
    {0x09, "Request vehicle information (VIN, CALID)"},
    {0x0A, "Show permanent DTCs"},
};

const std::vector<DoipAddrRange> kDoipAddrRanges = {
    {0x0000, 0x0000, "ISO/SAE reserved"},
    {0x0001, 0x0DFF, "Vehicle manufacturer specific"},
    {0x0E00, 0x0FFF, "Reserved for addresses of external test equipment"},
    {0x1000, 0x7FFF, "Vehicle manufacturer specific (ECUs / gateways)"},
    {0x8000, 0xCFFF, "Reserved by ISO 13400"},
    {0xD000, 0xDFFF, "Reserved for SAE"},
    {0xE000, 0xE3FF, "Functional group: DoIP entities"},
    {0xE400, 0xE7FF, "Functional group: legislated OBD diagnostics"},
    {0xE800, 0xEFFF, "Reserved by ISO 13400"},
    {0xF000, 0xFFFF, "Reserved by ISO 13400"},
};


