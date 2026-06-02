#pragma once
//
// VF8Data.hpp - 2024 VinFast VF8 (platform "VF e34") reference data.
//
// All data here was transcribed from on-vehicle engineering screens and an
// Autel MaxiCOM MK900-BT diagnostic report captured from a specific vehicle
// (VIN RLLV1AEB0RH004878). Use it for ECU naming, scan coverage and DTC
// description lookup.
//
// IMPORTANT: DoIP *logical addresses* are NOT exposed by the Autel report or
// the engineering menus, so the addresses below are PLACEHOLDERS only. They
// are sequential and clearly not official - edit them in the UI to match the
// real gateway routing before relying on them.
//
#include <cstdint>
#include <string>
#include <vector>

// ---- Vehicle reference (from engineering "About"/"TBox Information" screens)
namespace vf8 {

constexpr const char* kModel        = "VinFast VF8 (platform VF e34)";
constexpr const char* kModelYear    = "2024";
constexpr const char* kVin          = "RLLV1AEB0RH004878";
constexpr const char* kMarket       = "US";
constexpr const char* kVariant      = "ECO";
constexpr const char* kFirmware     = "FRS 8A.4.9.16";
constexpr const char* kMhuSoftware  = "VF8_US_SOP1.3.53B_FRS9.6.1.16V3_240731";
constexpr const char* kTboxProject  = "VF8.4.5.71.US.e35cdd0866";
constexpr const char* kBluetoothMac = "04:C4:61:C3:69:D0";

} // namespace vf8

// ---- ECU definition --------------------------------------------------------
struct VF8Ecu {
    const char* code;            // short diagnostic name
    const char* name;            // human-readable description
    uint16_t    placeholderAddr; // PLACEHOLDER DoIP logical address (configure!)
    const char* hwPart;          // HW part number from engineering ECUs menu ("" if n/a)
    const char* swPart;          // SW part number from engineering ECUs menu ("" if n/a)
    uint16_t    altAddr = 0;     // alternative DoIP logical-address candidate to try if the
                                 // primary fails. Derived from the VinFast ECU-identifier byte
                                 // surfaced by the connected-car telemetry (object 34220, see
                                 // tahung9x/VF-DB). 0 = no alternative known.
};

// Combined list of diagnostic systems (Autel) and engineering controllers.
extern const std::vector<VF8Ecu> kVF8Ecus;

// ---- Reference DTC scan (Autel MaxiCOM, 2026-03-30) -------------------------
struct VF8RefDtc {
    const char* dtc;     // e.g. "U110887"
    const char* status;  // "Current" or "History"
    const char* desc;    // textual description, or "" when none was provided
};

struct VF8RefSystem {
    const char*               code;  // system short name as scanned by Autel
    const char*               name;  // full name
    std::vector<VF8RefDtc>    dtcs;
};

extern const std::vector<VF8RefSystem> kVF8ReferenceScan;

// Returns a known textual description for an Autel-form DTC string
// (e.g. "U110887"), or nullptr if none is known.
const char* vf8DtcLookup(const std::string& autelCode);

// ---- Standardized decoders (ISO 14229-1 / SAE J2012-DA) --------------------
// These are protocol-standardized and therefore high-confidence regardless of
// manufacturer. Several are independently confirmed by the Autel report text
// (e.g. FTB 0x87 = "missing message", 0x88 = "bus off", 0x16 = "voltage below
// threshold").

// Decodes the trailing failure-type byte (last 2 hex digits of a DTC) to text.
// Falls back to "failure type 0xNN" for bytes outside the confident set.
std::string vf8FailureType(uint8_t ftb);

// Returns the SAE J2012 base-DTC description for a 5-char base (e.g. "U0146"),
// or nullptr when the base code is manufacturer-specific / unknown.
const char* vf8SaeBaseDtc(const std::string& base5);

// Returns a manufacturer-specific 5-char base (e.g. "U1108", "B1935")
// that is NOT in the SAE-standardized set. These are
// heuristic interpretations inferred from the controlling ECU, the SAE letter
// prefix (P/C/B/U), and DTC numbering conventions - treat them as informed
// estimates, not official VinFast definitions. Returns nullptr if no guess.
const char* vf8Dtc(const std::string& base5);

// Full description for an Autel-form DTC (e.g. "U014687"):
//   1) explicit text captured in the reference scan, else
//   2) "<SAE base description> - <failure type>", else
//   3) "<best-guess base description> - <failure type>", else
//   4) just the failure-type text.
std::string vf8DtcDescribe(const std::string& autelCode);

// ---- Standard protocol identifiers usable on the VF8 -----------------------
//
// No VinFast-proprietary DoIP/UDS specification (private logical addresses,
// SecurityAccess seed/key algorithm or manufacturer DIDs/routines) is publicly
// documented - those live only in VinFast's dealer tooling. However the VF8 is
// built on a STANDARD ISO 14229 (UDS) over ISO 13400 (DoIP-ENET) stack reached
// through the OBD port, so the ISO-standardized identification DID block and
// the SAE J1979 / ISO 15031 legislated OBD-II services below are protocol-
// guaranteed and therefore reliable on this vehicle.

// An ISO 14229-1 standardized Data Identifier (the F1xx identification block
// plus a few common ones). `did` is the 0x22 argument; `ascii` hints whether
// the value is printable text (true) or raw bytes (false).
struct StdDid {
    uint16_t    did;
    const char* name;
    bool        ascii;
};

// ISO 14229-1 Annex C standardized DIDs (manufacturer-independent).
extern const std::vector<StdDid> kStandardDids;

// A legislated SAE J1979 / ISO 15031-5 OBD-II service (a.k.a. "mode") that is
// emissions-mandated and works uniformly across manufacturers.
struct ObdService {
    uint8_t     sid;     // request service id (mode), e.g. 0x01, 0x03, 0x09
    const char* name;
};

extern const std::vector<ObdService> kObdServices;

// ISO 13400-2 reserved/standard logical-address ranges (for reference in the
// UI). VinFast's actual node addresses are not public, but DoIP mandates these
// ranges, so they bound what a valid configured address can be.
struct DoipAddrRange {
    uint16_t    first;
    uint16_t    last;
    const char* meaning;
};

extern const std::vector<DoipAddrRange> kDoipAddrRanges;


