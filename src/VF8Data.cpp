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
//
// canReqId values are Info-CAN DiagReq arbitration IDs from
// 01_Info_CAN_Matrix_BEV_V10.6.dbc where a matching BO_ exists
// (DiagResp = DiagReq - 0x80). Transport passes 0x600-0x7FF through as raw
// CAN request IDs. altAddr is tried automatically if the primary fails:
//   • XGW also tries legislated OBD physical 0x7E0 (OBD-port path)
//   • modules with a second DBC name (EPS2, CCUR, …) try that DiagReq
// Modules with no DBC DiagReq keep a legacy 0x10xx placeholder so the UI still
// lists them; those will not answer until a real ID is configured.
// ===========================================================================
const std::vector<VF8Ecu> kVF8Ecus = {

    // Autel-scanned diagnostic systems (confirmed to respond to UDS on-vehicle).
    // XGW: Info 0x682 first; OBD 0x7E0 as automatic fallback for pin 6/14.
    {"XGW",     "Extendable Gateway",                    0x0682, "EEP30009521-01", "SOW30050503-04", 0x07E0},
    {"VCU",     "Vehicle Control Unit",                  0x06AC, "",               "SOW30050205-30"},
    {"BMS",     "Battery Management System",             0x0693, "BAT30002013-01", "SOW30002100-25"},
    {"MCU",     "Motor Control Unit",                    0x1004, "",               ""},
    {"ESC",     "Electronic Stability Control",          0x1005, "",               ""},
    {"EPS",     "Electric Power Steering",               0x06A8, "CHS30004062-01", "SOW30000224-02", 0x06AB},
    {"ADAS",    "Advanced Driver Assistance System",     0x06C0, "",               ""},
    {"BCM",     "Body Control Module",                   0x0681, "EEP30220027-01", "SOW30220361-01"},
    {"CCU",     "Climate Control Unit",                  0x0689, "EEP30006107-04", "SOW30006116-04", 0x0694},
    {"DDC",     "DC-DC Converter",                       0x06BD, "EEP30005276-03", "SOW30050170-10"},
    {"MHU",     "Multimedia Headunit",                   0x0684, "EEP30005211-01", "SOW30051001-84"},
    {"RLS",     "Rain / Light Sensor",                   0x100C, "",               ""},

    // Engineering controllers (from on-vehicle ECUs Information screen).
    {"TBOX",    "Telematics Box",                        0x100D, "EEP30005211-01", "SOW30052001-53"},
    {"ACM",     "Airbag Control Module",                 0x0688, "EEP30010045-02", "SOW30010051-01"},
    {"HUD",     "Head-Up Display",                       0x068D, "EEP30006274-01", "SOW30205101-31", 0x068B},
    {"EDS_F",   "Electric Drive System - Front",         0x069B, "EEH30073014-01", "SOW30073520-01"},
    {"EDS_R",   "Electric Drive System - Rear",          0x069A, "EEH30073015-01", "SOW30073522-01"},
    {"PSM_D",   "Power Supply Module - Driver",          0x069E, "BIN30023940-01", "SOW30171972-01"},
    {"MRGEN",   "Mid-Range Radar / Gen Module",          0x06A5, "EEP30008110-01", "SOW30008009-05"},
    {"SCAM",    "Surround/Smart Camera Module",          0x06A6, "EEP30008131-01", "SOW30008021-11"},
    {"RCU",     "Restraint Control Unit",                0x06A7, "CHS30014035-01", "SOW30000411-02"},
    {"IDR",     "Interior Domain / Radar",               0x1016, "",               "SOW20000213-02"}, // no DBC DiagReq; placeholder
    {"SRR_FR",  "Short-Range Radar - Front Right",       0x06B4, "EEP30008133-01", "SOW30008022-05"},
    {"SRR_FL",  "Short-Range Radar - Front Left",        0x06B5, "EEP30008133-01", "SOW30008022-05"},
    {"SRR_RR",  "Short-Range Radar - Rear Right",        0x06B6, "EEP30008133-01", "SOW30008022-05"},
    {"SRR_RL",  "Short-Range Radar - Rear Left",         0x06B7, "EEP30008133-01", "SOW30008022-05"},
    {"DCDC",    "DC-DC Converter (HV)",                  0x06BD, "EEP30005276-03", "SOW30050170-10"},
    {"APM",     "Auxiliary Power Module",                0x06C1, "EEP10006197-03", "SOW30050770-02", 0x06E4},
    {"SHVU_F",  "Smart HV Unit - Front",                 0x06C2, "BIN30022879-01", "SOW30171038-01"},
    {"OCS",     "Occupant Classification System",        0x06C4, "BIN30022839-01", "SOW30022845-01"},
    {"BCM_BPM", "Body Control - Battery Pack Monitor",   0x06FB, "EEP30220027-01", "SOW30220363-01"},
};

// ===========================================================================
// Reference DTC scan - Autel MaxiCOM MK900-BT, captured 2026-03-30 19:28:52.
// 12 systems, 125 DTCs. Descriptions are filled where the Autel report gave
// real text; entries marked "" were reported only as "refer to service manual".
// ===========================================================================
const std::vector<VF8RefSystem> kVF8ReferenceScan = {
    {"MCU", "Motor Control Unit", {
        {"U015587", "History", "Lost Communication With Instrument Panel Cluster (IPC) Control Module - Missing message"},
        {"U042381", "History", "Invalid Data Received From Instrument Panel Cluster (IPC) Control Module - Invalid serial data received"},
        {"U160E81", "History", "Lost communication with a multimedia peripheral - Invalid serial data received"},
        {"U110887", "Current", "Airbag Control Module (ACM) ECU message missing"},
    }},
    {"BCM", "Body Control Module", {
        {"U110116", "History", "Power-supply (KL30/KL15) voltage monitoring fault - Circuit voltage below threshold"},
        {"U110887", "Current", "Lost communication with Airbag Control Module"},
        {"U014687", "History", "Lost Communication With Gateway A - Missing message"},
        {"U119188", "Current", "Lost communication with a body / comfort module - Bus off"},
        {"U020C87", "Current", "Lost communication with battery-energy control module - Missing message"},
        {"B101413", "History", "Right reverse lamp circuit: current below threshold / open load"},
        {"B101513", "History", "Left stop lamp circuit: current below threshold / open load"},
        {"B101613", "History", "Right stop lamp circuit: current below threshold / open load"},
        {"B10B871", "History", "Body-control output circuit fault - Actuator stuck"},
        {"B10EC00", "History", "Body-control module internal fault - No sub-type information"},
        {"U041682", "History", "Invalid Data Received From Vehicle Dynamics Control Module - Alive / sequence counter incorrect or not updated"},
        {"U045D82", "History", "Invalid data received from a chassis control module - Alive / sequence counter incorrect or not updated"},
        {"U047781", "History", "Invalid data received from a driver-assistance module - Invalid serial data received"},
        {"U01B081", "Current", "Lost communication on a private CAN sub-bus - Invalid serial data received"},
        {"P058D09", "Current", "Battery / charging-system voltage sensor fault - Component failure"},
    }},
    {"BMS", "Battery Management System", {
        {"U110116", "History", "Power-supply (KL30/KL15) voltage monitoring fault - Circuit voltage below threshold"},
        {"P180000", "Current", "Battery-management internal / control fault - No sub-type information"},
        {"P124100", "Current", "HV battery contactor / pre-charge fault - No sub-type information"},
        {"P183401", "Current", "Battery isolation / HV interlock fault - General electrical failure"},
        {"P18D000", "History", "Battery cell / balancing fault - No sub-type information"},
        {"P124003", "Current", "HV battery contactor / pre-charge fault - Frequency modulation / pulse width modulation failure"},
        {"P0A9500", "Current", "High-voltage system / HV fuse fault - No sub-type information"},
        {"U014687", "Current", "Lost Communication With Gateway A - Missing message"},
        {"U110117", "History", "Power-supply (KL30/KL15) voltage monitoring fault - Circuit voltage above threshold"},
        {"P0ABF86", "History", "Hybrid/EV battery current-sensor circuit fault - Signal invalid / signal protection calculation failure"},
        {"U012587", "History", "Lost Communication With Multi-axis Acceleration Sensor Module - Missing message"},
    }},
    {"VCU", "Vehicle Control Unit", {
        {"U125517", "History", "Vehicle configuration / coding mismatch - Circuit voltage above threshold"},
        {"U125516", "History", "Vehicle configuration / coding mismatch - Circuit voltage below threshold"},
        {"U092300", "Current", "Invalid data received from interior / roof control module - No sub-type information"},
        {"P101716", "History", "Drive-motor / inverter torque monitoring fault - Circuit voltage below threshold"},
        {"U117188", "History", "Chassis CAN communication bus fault - Bus off"},
        {"P112900", "History", "Powertrain torque-control performance fault - No sub-type information"},
        {"P113700", "Current", "Drive-motor performance fault - No sub-type information"},
        {"P103300", "History", "HV contactor / pre-charge fault - No sub-type information"},
        {"P115000", "History", "High-voltage system performance fault - No sub-type information"},
        {"P115100", "History", "High-voltage system performance fault - No sub-type information"},
        {"P118800", "History", "Powertrain coolant / thermal-management fault - No sub-type information"},
        {"U110116", "History", "Power-supply (KL30/KL15) voltage monitoring fault - Circuit voltage below threshold"},
        {"P105D38", "History", "Powertrain internal control fault - Frequency / pulse width out of range"},
        {"P106B29", "History", "Powertrain internal control fault - Signal invalid"},
    }},
    {"ESC", "Electronic Stability Control", {
        {"U015687", "History", "Lost communication with display / information-center module - Missing message"},
        {"C059496", "History", "Electronic stability control performance fault - Component internal failure"},
        {"U041681", "Current", "Invalid Data Received From Vehicle Dynamics Control Module - Invalid serial data received"},
        {"U110887", "Current", "Lost communication with Airbag Control Module (ACM) - Missing message"},
    }},
    {"EPS", "Electric Power Steering", {
        {"U110116", "History", "Power supply - circuit voltage below threshold"},
    }},
    {"ADAS", "Advanced Driver Assistance System", {
        {"U113187", "History", "Lost communication with front corner radar (right) - Missing message"},
        {"U30031C", "History", "Battery / power-supply voltage out of range - Circuit voltage out of range"},
        {"U113387", "History", "Lost communication with rear corner radar - Missing message"},
        {"U113087", "History", "Lost communication with front radar sensor - Missing message"},
        {"U113287", "History", "Lost communication with front corner radar (left) - Missing message"},
        {"U112987", "History", "Lost communication with a driver-assistance sensor - Missing message"},
        {"U111189", "Current", "Lost communication with a radar / camera sensor - Signal invalid / invalid serial data"},
        {"U113081", "History", "Lost communication with front radar sensor - Invalid serial data received"},
        {"U116589", "Current", "Lost communication with a driver-assistance sensor - Signal invalid / invalid serial data"},
        {"U111489", "History", "Lost communication with a radar / camera sensor - Signal invalid / invalid serial data"},
        {"U118289", "History", "Lost communication with a driver-assistance module - Signal invalid / invalid serial data"},
        {"U113381", "History", "Lost communication with rear corner radar - Invalid serial data received"},
        {"U118789", "Current", "Lost communication with a driver-assistance module - Signal invalid / invalid serial data"},
        {"U114081", "Current", "Lost communication with surround-view camera - Invalid serial data received"},
        {"U114289", "History", "Lost communication with surround-view camera - Signal invalid / invalid serial data"},
        {"U119689", "Current", "Lost communication with a driver-assistance module - Signal invalid / invalid serial data"},
        {"B193504", "History", "Driver-assistance radar / camera fault - System internal failure"},
        {"B193104", "History", "Driver-assistance radar / camera fault - System internal failure"},
        {"B193704", "History", "Driver-assistance radar / camera fault - System internal failure"},
        {"B19084A", "History", "Driver-assistance radar alignment / blockage - Incorrect component installed"},
        {"B193304", "History", "Driver-assistance radar / camera fault - System internal failure"},
        {"B193404", "History", "Driver-assistance radar / camera fault - System internal failure"},
        {"B193204", "History", "Driver-assistance radar / camera fault - System internal failure"},
        {"B194004", "History", "Driver-assistance radar / camera fault - System internal failure"},
        {"B193904", "Current", "Driver-assistance radar / camera fault - System internal failure"},
        {"B194204", "History", "Driver-assistance radar / camera fault - System internal failure"},
        {"B194104", "History", "Driver-assistance radar / camera fault - System internal failure"},
        {"U119387", "History", "Lost communication with a driver-assistance module - Missing message"},
        {"U119287", "History", "Lost communication with a driver-assistance module - Missing message"},
        {"U113681", "History", "Lost communication with a driver-assistance sensor - Invalid serial data received"},
    }},
    {"CCU", "Climate Control Unit", {
        {"B170E54", "Current", "Climate-control actuator / sensor fault - Missing calibration"},
        {"U110887", "Current", "Lost communication with Airbag Control Module"},
    }},
    {"DDC", "DC-DC Converter", {
        {"C150C1C", "History", "DC-DC converter output fault - Circuit voltage out of range"},
        {"U113787", "History", "Lost communication with a networked control module - Missing message"},
        {"U113887", "History", "Lost communication with a networked control module - Missing message"},
        {"U124329", "History", "Lost communication / configuration with DC-DC peripheral - Signal invalid"},
        {"C153700", "History", "DC-DC converter / chassis sensor fault - No sub-type information"},
        {"C153600", "History", "DC-DC converter / chassis sensor fault - No sub-type information"},
        {"U113987", "History", "Lost communication with a networked control module - Missing message"},
        {"U114087", "History", "Lost communication with surround-view camera - Missing message"},
        {"U114187", "History", "Lost communication with surround-view camera - Missing message"},
        {"U111589", "History", "Lost communication with a networked control module - Signal invalid / invalid serial data"},
        {"U112081", "History", "Lost communication with a networked control module - Invalid serial data received"},
        {"U112389", "History", "Lost communication with a networked control module - Signal invalid / invalid serial data"},
        {"U112681", "History", "Lost communication with a networked control module - Invalid serial data received"},
        {"U113081", "History", "Lost communication with front radar sensor - Invalid serial data received"},
        {"U113381", "History", "Lost communication with rear corner radar - Invalid serial data received"},
        {"U114081", "Current", "Lost communication with surround-view camera - Invalid serial data received"},
        {"U114881", "History", "Lost communication with a driver-assistance module - Invalid serial data received"},
        {"U118789", "Current", "Lost communication with a driver-assistance module - Signal invalid / invalid serial data"},
        {"U119389", "History", "Lost communication with a driver-assistance module - Signal invalid / invalid serial data"},
        {"U113581", "History", "Lost communication with a networked control module - Invalid serial data received"}, {"U119689", "Current", "Lost communication with a driver-assistance module - Signal invalid / invalid serial data"},
    }},
    {"MHU", "Multimedia Headunit", {
        {"B161A03", "History", "Microphone / audio-input circuit fault - Frequency modulation / pulse width modulation failure"},
        {"U300004", "History", "Control Module (internal fault / self test) - System internal failure"},
        {"U014687", "Current", "Lost Communication With Gateway A - Missing message"},
        {"U015C87", "History", "Lost communication with a camera / sensor module - Missing message"},
        {"B160D14", "History", "Audio / amplifier output circuit fault - Circuit short to ground or open"},
        {"B160E14", "History", "Audio / amplifier output circuit fault - Circuit short to ground or open"},
        {"U110116", "History", "Power-supply (KL30/KL15) voltage monitoring fault - Circuit voltage below threshold"},
        {"B162004", "History", "Display / touchscreen interface fault - System internal failure"},
        {"B161B01", "History", "Microphone / audio-input circuit fault - General electrical failure"},
        {"B161A01", "Current", "Microphone / audio-input circuit fault - General electrical failure"},
    }},
    {"RLS", "Rain / Light Sensor", {
        {"U100304", "Current", "Lost communication with body-control / gateway module - System internal failure"},
        {"U100404", "Current", "Lost communication with a networked control module - System internal failure"},
        {"U10041C", "Current", "Lost communication with a networked control module - Circuit voltage out of range"},
        {"U110116", "Current", "Power-supply (KL30/KL15) voltage monitoring fault - Circuit voltage below threshold"},
    }},
    {"XGW", "Extendable Gateway", {
        {"B200101", "History", "Gateway / anti-theft system fault - General electrical failure"},
        {"B200001", "Current", "Gateway / anti-theft system fault - General electrical failure"},
        {"U117188", "History", "Chassis CAN - bus off"},
        {"U110887", "Current", "Lost communication with Airbag Control Module"},
        {"U019E87", "History", "Lost communication with restraint / occupant module - Missing message"},
        {"U012287", "History", "Lost communication with vehicle dynamics control module"},
        {"U110116", "History", "Power supply circuit voltage below threshold"},
        {"B2001A2", "History", "Gateway / anti-theft system fault - Voltage / temperature signal erratic"},
        {"B2000A2", "History", "Gateway / anti-theft system fault - Voltage / temperature signal erratic"},
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
        {"U0001", "High Speed CAN Communication Bus"},
        {"U0100", "Lost Communication With ECM/PCM (Vehicle Control Unit / VCU)"},
        {"U0110", "Lost Communication With Drive Motor Control Module 'A' (MCU)"},
        {"U0111", "Lost Communication With Battery Energy Control Module 'A' (BMS)"},
        {"U0122", "Lost Communication With Vehicle Dynamics Control Module"},
        {"U0125", "Lost Communication With Multi-axis Acceleration Sensor Module"},
        {"U0140", "Lost Communication With Body Control Module (BCM)"},
        {"U0146", "Lost Communication With Gateway A"},
        {"U0155", "Lost Communication With Instrument Panel Cluster (IPC) Control Module"},
        {"U0292", "Lost Communication With Drive Motor Control Module 'B' (Rear EDS)"},
        {"U0293", "Lost Communication With Hybrid Vehicle Control ECU"},
        {"U3000", "Control Module (internal fault / self test)"},
        {"U3006", "Control Module Input Power 'A' Range/Performance"},
        {"U300A", "Ignition Switch / KL15 Signal Circuit Fault"},
        {"P0A78", "Drive Motor/Generator 'A' Inverter Performance"},
        {"P0A7A", "Generator Inverter Performance"},
        {"P0A81", "BMS Battery Pack Cooling Fan Control Circuit"},
        {"P0AA6", "Hybrid/EV Battery System Isolation Fault (HV Leakage)"},
        {"P0AC0", "Hybrid/EV Battery Pack Current Sensor Range/Performance"},
        {"P0B3C", "Hybrid/EV Battery Voltage Monitoring Circuit Low"},
        {"P0C76", "Hybrid/EV Battery System Discharge Time Too Long"},
        {"P0D57", "Proximity Detection Connection Circuit Fault (OBC/Charging)"},
        {"P0D97", "Smart Charge Coupler Lock Control Fault"},
        {"C0034", "Right Front Wheel Speed Sensor Circuit"},
        {"C0035", "Left Front Wheel Speed Sensor Circuit"},
        {"C0037", "Left Rear Wheel Speed Sensor Circuit"},
        {"C003A", "Right Rear Wheel Speed Sensor Circuit"},
        {"C0513", "Steering Angle Sensor (SAS) Signal Range/Performance"},
        {"C0561", "System Disabled - Invalid Data Received from Vehicle Control Module"},
    };
    auto it = t.find(base5);
    return it != t.end() ? it->second : nullptr;
}

const char* vf8Dtc(const std::string& base5) {
    // NOT all are official VinFast definitions - but they are far more useful than a
    // bare failure-type byte. Several are corroborated by the Autel report
    // (e.g. U1108 = ACM lost comm, U1171 = chassis CAN bus-off, B1014/15/16 =
    // reverse/stop lamp circuits).
    static const std::unordered_map<std::string, const char*> t = {
        // ---- U: network / communication ----------------------------------
        {"U1000", "Class 2 Communication / CAN Network Parameter Fault"},
        {"U1100", "Lost Communication with Central Gateway Module"},
        {"U1200", "Private CAN / LIN Sub-bus Communication Offline"},
        {"U1300", "Chassis CAN Sub-bus Performance / Timeout"},
        {"U1401", "ADAS Camera Control Module Communication Lost"},
        {"U1402", "ADAS Front Radar Module Communication Lost"},
        {"U1403", "ADAS LiDAR / Corner Radar Communication Lost"},
        {"U1500", "LIN Bus Master/Slave Communication Error"},
        {"U1800", "High Speed CAN-Bus off / Communication Disrupted"},
        {"U015C", "Lost communication with a camera / sensor module"},
        {"U0156", "Lost communication with display / information-center module"},
        {"U0160", "Lost communication with Central Gateway (XGW)"},
        {"U019E", "Lost communication with restraint / occupant module"},
        {"U01B0", "Lost communication on a private CAN sub-bus"},
        {"U020C", "Lost communication with battery-energy control module"},
        {"U045D", "Invalid data received from a chassis control module"},
        {"U0477", "Invalid data received from a driver-assistance module"},
        {"U0923", "Invalid data received from interior / roof control module"},
        {"U1003", "Lost communication with body-control / gateway module"},
        {"U1004", "Lost communication with a networked control module"},
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
        {"U3003", "Battery / power-supply voltage out of range"},
        
        // ---- P: powertrain / high-voltage --------------------------------
        {"P058D", "Battery / charging-system voltage sensor fault"},
        {"P0A95", "High-voltage system / HV fuse fault"},
        {"P0ABF", "Hybrid/EV battery current-sensor circuit fault"},
        {"P1017", "Drive-motor / inverter torque monitoring fault"},
        {"P1033", "HV contactor / pre-charge fault"},
        {"P1110", "Coolant / thermal-management circuit fault"},
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
        {"P1805", "BMS HV Pre-charge Timeout / Voltage Mismatch"},
        {"P1810", "BMS Battery Cell Over-temperature"},
        {"P1820", "BMS High-Voltage Contactor Stuck Closed"},
        {"P1821", "BMS High-Voltage Contactor Stuck Open"},
        {"P1825", "BMS High-Voltage Interlock Loop (HVIL) Open"},
        {"P1850", "Coolant Switching/Control Valve Position Sensor Fault"},
        {"P1855", "Active Chiller Refrigerant Valve / Temp Sensor Fault"},
        {"P1A00", "Traction Inverter Thermal Overload / Over-Temperature"},
        {"P1A05", "Motor Rotor Position / Resolver Sensor Calibration Fault"},
        {"P1A10", "Motor Temperature Sensor Circuit Range/Performance"},
        {"P1A20", "DC-DC Over-Current / Over-Temperature"},
        {"P1A30", "Active Discharge Failure (HV bus discharge inactive)"},
        {"P1A50", "HV PTC Cabin Heater Module Fault"},
        {"P1A60", "HV Heat Pump / A/C Compressor Performance Fault"},
        {"P1B00", "OBC On-Board Charger Control Module Hardware Fault"},
        {"P1B05", "OBC Input Voltage/Current Out of Range"},
        {"P1B10", "OBC Thermal / Charging Over-Temperature Derating"},
       
        // ---- C: chassis ---------------------------------------------------
        {"C0594", "Electronic stability control performance fault"},
        {"C150C", "DC-DC converter output fault"},
        {"C1536", "DC-DC converter / chassis sensor fault"},
        {"C1537", "DC-DC converter / chassis sensor fault"},
        {"C150A", "Electric Parking Brake (EPB) Actuator Stuck"},
        {"C1515", "Steering Torque Sensor Calibration Not Programmed"},
        {"C1520", "EPS Motor Current/Phase Feedback Error"},
        
        // ---- B: body ------------------------------------------------------
        {"B10A0", "Crash Sensor / Airbag Deployment Signal Input Active"},
        {"B10E7", "Ignition Switch / Start Button Control Loop Fault"},
        {"B1100", "SRS / Restraint Control Module (ACM) Module Internal Fault"},
        {"B1300", "Passive Entry System / LF Antenna Failure"},
        {"B1400", "Sunload Solar or Ambient Light Sensor Circuit Fault"},
        {"B1500", "Door Glass Regulator / Window Motor Position Failure"},
        {"B1800", "Seat Occupancy Sensor / Buckle Pre-tensioner Loop Fault"},
        {"B2005", "Immobilizer / Anti-Theft Key Handshake Refused"},
        {"B200A", "Secure Gateway (SGW) Security Lockout Active"},
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

    if (const char* vf8_dtc = vf8Dtc(base))
        return std::string(vf8_dtc) + " - " + ftbText + "";

    // 4) Unknown base: report the standardized failure type only.
    return ftbText;
}

// ---- Standard protocol identifiers (ISO 14229 / SAE J1979 / ISO 13400) -----
// These are protocol-standardized and manufacturer-independent, so they apply
// to the VF8's standard UDS stack even though VinFast-private identifiers
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

const std::vector<UdsAddrRange> kUdsAddrRanges = {
    {0x0000, 0x0000, "ISO/SAE reserved"},
    {0x0001, 0x0DFF, "Vehicle manufacturer specific"},
    {0x0E00, 0x0FFF, "Reserved for addresses of external test equipment"},
    {0x1000, 0x7FFF, "Vehicle manufacturer specific (ECUs / gateways)"},
    {0x8000, 0xCFFF, "Reserved by ISO 13400"},
    {0xD000, 0xDFFF, "Reserved for SAE"},
    {0xE000, 0xE3FF, "Functional group: diagnostic entities"},
    {0xE400, 0xE7FF, "Functional group: legislated OBD diagnostics"},
    {0xE800, 0xEFFF, "Reserved by ISO 13400"},
    {0xF000, 0xFFFF, "Reserved by ISO 13400"},
};


// ===========================================================================
// VF8 Info-CAN bus signal catalog
// ===========================================================================

// --- enum (value) tables ---------------------------------------------------
static const VF8Enum kEnHVSys[]     = {{0,"Not ready"},{1,"HV On"},{2,"ReadyToDrive"},
                                       {3,"Charging"},{4,"Error"},{0,nullptr}};
static const VF8Enum kEnGear[]      = {{0,"P"},{1,"R"},{2,"N"},{3,"D"},{7,"Fault"},{0,nullptr}};
static const VF8Enum kEnDriveMode[] = {{0,"Normal"},{1,"ECO"},{2,"Sport"},{7,"Invalid"},{0,nullptr}};
static const VF8Enum kEnSocState[]  = {{0,"deviation >15%"},{1,"deviation <15%"},
                                       {2,"deviation <10%"},{3,"invalid"},{0,nullptr}};
static const VF8Enum kEnDoorAjar[]  = {{0,"Closed"},{1,"Opened"},{3,"invalid"},{0,nullptr}};
static const VF8Enum kEnLock[]      = {{0,"Unlocked"},{1,"Locked"},{3,"invalid"},{0,nullptr}};
static const VF8Enum kEnGun[]       = {{0,"disconnect"},{1,"connect"},{0,nullptr}};
static const VF8Enum kEnHVIL[]      = {{0,"Closed"},{1,"Open/short to batt"},
                                       {2,"short to ground"},{0,nullptr}};
static const VF8Enum kEnHVOnOff[]   = {{0,"HV Off"},{1,"Precharge"},{2,"HV On"},
                                       {3,"Fail to HV on"},{0,nullptr}};

// --- message / signal catalog ----------------------------------------------
// Fields: name, startBit, length, bigEndian, isSigned, scale, offset, unit, enum
const std::vector<VF8CanMessage> kVF8InfoCanBus = {
    {0x0D9, "VCU_HV_DrvSys_status", "XGW_Info", 8, {
        {"VCU_HVsystem_status", 14, 3, true, false, 1,      0,   "",  kEnHVSys},
        {"VCU_ACPD_Percent",    23, 12,true, false, 0.0625, 0,   "%", nullptr},
        {"VCU_ACTGear",         34, 3, true, false, 1,      0,   "",  kEnGear},
        {"VCU_ACT_DriveMode",   38, 3, true, false, 1,      0,   "",  kEnDriveMode},
    }},
    {0x104, "BAS_Measured_Data", "XGW_Info", 8, {
        {"SOH_SUL",   23, 8, true, false, 1, 0, "%", nullptr},
        {"SOC_STATE", 31, 2, true, false, 1, 0, "",  kEnSocState},
    }},
    {0x105, "BCM_STAT_DOOR_FLAP", "XGW_Info", 4, {
        {"BCM_STAT_TrunkAjar",  17, 2, true, false, 1, 0, "", kEnDoorAjar},
        {"BCM_STAT_DoorAjarFL",  19, 2, true, false, 1, 0, "", kEnDoorAjar},
        {"BCM_STAT_DoorAjarFR",  21, 2, true, false, 1, 0, "", kEnDoorAjar},
        {"BCM_STAT_DoorAjarRL",  23, 2, true, false, 1, 0, "", kEnDoorAjar},
        {"BCM_STAT_DoorAjarRR",  25, 2, true, false, 1, 0, "", kEnDoorAjar},
        {"BCM_STAT_BonnetAjar",  27, 2, true, false, 1, 0, "", kEnDoorAjar},
    }},
    {0x107, "BCM_STAT_CENTRAL_LOCK", "XGW_Info", 3, {
        {"STAT_DoorLockFL", 23, 2, true, false, 1, 0, "", kEnLock},
    }},
    {0x10A, "BCM_VOLTAGE", "XGW_Info", 8, {
        {"UBatt",           23, 14, true, false, 0.0009777, 3,     "V",   nullptr},
        {"LV_Batt_Temp",    39, 8,  true, false, 1,         -40,   "degC",nullptr},
        {"LV_SOC",          47, 8,  true, false, 1,         0,     "%",   nullptr},
        {"LV_Batt_Current", 55, 16, true, false, 0.03125,   -1536, "A",   nullptr},
    }},
    {0x123, "VCU_ACCharging_Info", "XGW_Info", 8, {
        {"ACCharging_MaxChargingPower", 23, 10, true, false, 0.1, 0, "kW", nullptr},
        {"CurrentACChargingPower",      39, 16, true, false, 0.1, 0, "kW", nullptr},
        {"ACCharging_MaxCurrent",       55, 16, true, false, 0.1, 0, "A",  nullptr},
    }},
    {0x124, "VCU_DCCharging_Info", "XGW_Info", 8, {
        {"DCCharging_MaxChargingPower", 23, 10, true, false, 0.1, 0, "kW", nullptr},
        {"CurrentDCChargingPower",      39, 16, true, false, 0.1, 0, "kW", nullptr},
        {"DCCharging_MaxCurrent",       55, 16, true, false, 0.1, 0, "A",  nullptr},
    }},
    {0x165, "VCU_ChargingConnection", "XGW_Info", 8, {
        {"VCU_AcChgGunIn",        12, 1, true, false, 1, 0, "",  kEnGun},
        {"VCU_DCChgGunIn",        13, 1, true, false, 1, 0, "",  kEnGun},
        {"VCU_ACChargingVoltage", 43, 8, true, false, 1, 0, "V", nullptr},
    }},
    {0x176, "BMS_HVMeas1", "XGW_Info", 8, {
        {"BMS_HVPackVol_MEAS", 23, 16, true, false, 0.1, 0, "V", nullptr},
        {"BMS_HVLinkVol_MEAS", 39, 16, true, false, 0.1, 0, "V", nullptr},
    }},
    {0x17E, "SAS_Sensor", "XGW_Info", 7, {
        {"SAS_SteerWhlRotSpd",  21, 14, true, false, 0.125,  -1024, "deg/s", nullptr},
        {"SAS_SteerWheelAngle", 47, 16, true, false, 0.0238, -780,  "deg",   nullptr},
    }},
    {0x214, "BMS_Sts_0x214", "XGW_Info", 8, {
        {"BMS_Display_SOC", 21, 10, true, false, 0.1, 0, "%", nullptr},
        {"BMS_MinCellSOC",  27, 10, true, false, 0.1, 0, "%", nullptr},
        {"BMS_MaxCellSOC",  33, 10, true, false, 0.1, 0, "%", nullptr},
    }},
    {0x215, "BMS_Sts", "XGW_Info", 8, {
        {"BMS_HVIL_STS",      17, 2,  true, false, 1,   0, "",  kEnHVIL},
        {"BMS_HVOnOff_STS",   19, 2,  true, false, 1,   0, "",  kEnHVOnOff},
        {"BMS_SocActual_EST", 25, 10, true, false, 0.1, 0, "%", nullptr},
        {"BMS_SOH",           47, 8,  true, false, 0.5, 0, "%", nullptr},
        {"BMS_SOE",           55, 8,  true, false, 0.5, 0, "%", nullptr},
    }},
    {0x216, "BMS_ChgParamReq", "XGW_Info", 8, {
        {"BMS_RemainChargeTime", 21, 14, true, false, 1,   0, "min", nullptr},
        {"BMS_ChgVoltage_REQ",   37, 14, true, false, 0.1, 0, "V",   nullptr},
        {"BMS_ChgCurrent_REQ",   55, 16, true, false, 0.1, 0, "A",   nullptr},
    }},
    {0x230, "BMS_CapacityThrput", "XGW_Info", 8, {
        {"BMS_Capacity_Thrput_Charge",    7,  32, true, true, 1, 0, "Ah", nullptr},
        {"BMS_Capacity_Thrput_Discharge", 39, 32, true, true, 1, 0, "Ah", nullptr},
    }},
    {0x245, "BMS_CellTemp", "XGW_Info", 8, {
        {"BMS_MinCellTemp",        31, 8, true, false, 1, -40, "degC", nullptr},
        {"BMS_PackTemp",           47, 8, true, false, 1, -40, "degC", nullptr},
        {"BMS_MaxCellTemp",        55, 8, true, false, 1, -40, "degC", nullptr},
        {"BMS_MaxMinDiffCellTemp", 63, 8, true, false, 1, -40, "degC", nullptr},
    }},
    {0x254, "IDB_AVL_RPM_WHL_REAR", "XGW_Info", 8, {
        {"AVL_RPM_WHL_RLH", 23, 16, true, false, 0.0156, -511.9844, "rad/s", nullptr},
        {"AVL_RPM_WHL_RRH", 39, 16, true, false, 0.0156, -511.9844, "rad/s", nullptr},
    }},
    {0x255, "IDB_AVL_RPM_WHL_FRONT", "XGW_Info", 8, {
        {"AVL_RPM_WHL_FLH", 23, 16, true, false, 0.0156, -511.9844, "rad/s", nullptr},
        {"AVL_RPM_WHL_FRH", 39, 16, true, false, 0.0156, -511.9844, "rad/s", nullptr},
    }},
};

// --- decoder ---------------------------------------------------------------
namespace {

// Extract a raw field per the Vector/DBC bit convention.
uint64_t extractBits(const uint8_t* d, size_t len, const VF8CanSignal& s) {
    uint64_t val = 0;
    int bit = s.startBit;
    for (int k = 0; k < s.length; ++k) {
        int byte = bit >> 3;
        int pos  = bit & 7;
        if (byte < 0 || (size_t)byte >= len) return 0;   // out of range -> 0
        uint64_t b = (d[byte] >> pos) & 1u;
        if (s.bigEndian) {
            // Motorola: MSB first, walk toward the LSB, jumping to the next
            // byte's MSB when the low bit of a byte is reached.
            val = (val << 1) | b;
            bit = (pos == 0) ? (byte * 8 + 15) : (bit - 1);
        } else {
            // Intel: LSB first, walk upward.
            val |= (b << k);
            ++bit;
        }
    }
    return val;
}

std::string formatVal(double v, const VF8CanSignal& s, long raw) {
    if (s.values) {
        for (const VF8Enum* e = s.values; e->text; ++e)
            if (e->value == raw) return e->text;
    }
    char buf[64];
    // Choose precision from the scale so integers stay clean.
    if (s.scale == (double)(long)s.scale && s.offset == (double)(long)s.offset)
        std::snprintf(buf, sizeof buf, "%ld", (long)v);
    else
        std::snprintf(buf, sizeof buf, "%.3f", v);
    std::string out = buf;
    if (s.unit && s.unit[0]) { out += ' '; out += s.unit; }
    return out;
}

} // namespace

const char* vf8CanMessageName(uint32_t canId) {
    for (const auto& m : kVF8InfoCanBus)
        if (m.canId == canId) return m.name;
    return nullptr;
}

std::vector<VF8CanValue> vf8DecodeCanFrame(uint32_t canId,
                                           const uint8_t* data, size_t len) {
    std::vector<VF8CanValue> out;
    if (!data || len == 0) return out;
    for (const auto& m : kVF8InfoCanBus) {
        if (m.canId != canId) continue;
        for (const auto& s : m.sigs) {
            // Skip signals whose payload isn't present in this (possibly short)
            // frame.
            int lastBit = s.bigEndian ? s.startBit : s.startBit + s.length - 1;
            if ((size_t)(lastBit / 8) >= len && !s.bigEndian) continue;
            uint64_t raw = extractBits(data, len, s);
            long sraw = (long)raw;
            if (s.isSigned && s.length < 64 && (raw & (1ull << (s.length - 1))))
                sraw = (long)(raw | (~0ull << s.length));   // sign-extend
            double eng = (double)sraw * s.scale + s.offset;
            out.push_back({s.name, eng, formatVal(eng, s, sraw)});
        }
        break;
    }
    return out;
}

