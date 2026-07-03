#pragma once
//
// UDSClient.hpp - Unified Diagnostic Services (ISO 14229) over the configured
// transport client (OpenXC Bluetooth primary, CAN fallback optional).
//
// Implements the subset required by the application:
//   0x10 DiagnosticSessionControl
//   0x11 ECUReset
//   0x14 ClearDiagnosticInformation
//   0x19 ReadDTCInformation (sub-functions 0x01,0x02,0x04,0x06,0x0A,0x14)
//   0x22 ReadDataByIdentifier
//   0x23 ReadMemoryByAddress
//   0x27 SecurityAccess (request seed / send key)
//   0x28 CommunicationControl
//   0x2A ReadDataByPeriodicIdentifier (schedule / stop)
//   0x2C DynamicallyDefineDataIdentifier (define by id / clear)
//   0x2E WriteDataByIdentifier
//   0x2F InputOutputControlByIdentifier (returnControlToECU)
//   0x31 RoutineControl (start / stop / requestResults)
//   0x35 RequestUpload / 0x36 TransferData / 0x37 RequestTransferExit
//   0x38 RequestFileTransfer
//   0x3E TesterPresent
//   0x83 AccessTimingParameter
//   0x84 SecuredDataTransmission
//   0x85 ControlDTCSetting
//   0x86 ResponseOnEvent
//   0x87 LinkControl
//
#include "OpenXcTransport.hpp"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <optional>

struct Dtc {
    uint32_t    code   = 0;   // 3-byte DTC value
    uint8_t     status = 0;   // status-of-DTC byte
    std::string text;         // formatted, e.g. "P0420-00"
};

// ISO 14229-1 diagnostic session identifiers.
enum class UdsSession : uint8_t {
    Default   = 0x01,
    Programming = 0x02,
    Extended  = 0x03,
    SafetySystem = 0x04,
};

// ISO 14229-1 ECUReset (0x11) reset types.
enum class EcuResetType : uint8_t {
    HardReset             = 0x01,
    KeyOffOnReset         = 0x02,
    SoftReset             = 0x03,
    EnableRapidPowerShutDown  = 0x04,
    DisableRapidPowerShutDown = 0x05,
};

// ISO 14229-1 RoutineControl (0x31) sub-functions.
enum class RoutineCtrl : uint8_t {
    Start   = 0x01,
    Stop    = 0x02,
    Results = 0x03,
};

// ISO 14229-1 CommunicationControl (0x28) control-type sub-functions.
enum class CommCtrl : uint8_t {
    EnableRxTx           = 0x00,  // resume normal communication
    EnableRxDisableTx    = 0x01,
    DisableRxEnableTx    = 0x02,
    DisableRxTx          = 0x03,  // silence the bus (used before flashing)
};

// ISO 14229-1 ReadDataByPeriodicIdentifier (0x2A) transmission modes.
enum class PeriodicMode : uint8_t {
    SlowRate   = 0x01,
    MediumRate = 0x02,
    FastRate   = 0x03,
    StopSending = 0x04,
};

// One source element of a DynamicallyDefineDataIdentifier (0x2C, defineByIdentifier):
// take `size` bytes starting at 1-based `position` from the response of `sourceDid`.
struct DddSource {
    uint16_t sourceDid = 0;
    uint8_t  position  = 1;   // 1-based byte position in the source DID's data
    uint8_t  size      = 1;   // number of bytes to copy
};

// ISO 14229-1 InputOutputControlByIdentifier (0x2F) control-option parameters.
enum class IoControlOption : uint8_t {
    ReturnControlToECU  = 0x00,  // hand the actuator back to the ECU (safe)
    ResetToDefault      = 0x01,  // command the ECU's default value
    FreezeCurrentState  = 0x02,  // hold the present value
    ShortTermAdjustment = 0x03,  // drive a caller-specified value (active test)
};

// ISO 14229-1 LinkControl (0x87) sub-functions. Used to negotiate a faster
// diagnostic link (e.g. before reprogramming).
enum class LinkControlType : uint8_t {
    VerifyModeFixedParameter    = 0x01,  // verify a fixed baudrate identifier
    VerifyModeSpecificParameter = 0x02,  // verify a specific baudrate value
    TransitionMode              = 0x03,  // switch to the verified baudrate
};

// ISO 14229-1 AccessTimingParameter (0x83) sub-functions.
enum class TimingParamAccess : uint8_t {
    ReadExtendedSet     = 0x01,  // read the ECU's supported timing limits
    SetToDefault        = 0x02,  // restore default P2/P2* timing
    ReadCurrentlyActive = 0x03,  // read the currently active timing
    SetToGivenValues    = 0x04,  // apply caller-supplied timing values
};

// ISO 14229-1 RequestFileTransfer (0x38) modeOfOperation values.
enum class FileTransferMode : uint8_t {
    AddFile     = 0x01,
    DeleteFile  = 0x02,
    ReplaceFile = 0x03,
    ReadFile    = 0x04,
    ReadDir     = 0x05,
    ResumeFile  = 0x06,
};


class UDSClient {
public:
    UDSClient(openxc::Transport& transport, uint16_t testerAddr)
        : transport_(transport), tester_(testerAddr) {}

    void setTester(uint16_t a) { tester_ = a; }

    // 0x10 - switch diagnostic session (e.g. Extended before clearing DTCs).
    bool diagnosticSessionControl(uint16_t target, UdsSession session,
                                  std::string& err);

    // 0x27 - security access. requestSeed uses an odd sub-function (level),
    // sendKey the following even sub-function. The key derivation is
    // manufacturer-proprietary, so a user-supplied key callback is required.
    // Returns the seed bytes; empty seed means "already unlocked" (0x00 seed).
    std::optional<std::vector<uint8_t>>
    requestSeed(uint16_t target, uint8_t level, std::string& err);
    bool sendKey(uint16_t target, uint8_t level,
                 const std::vector<uint8_t>& key, std::string& err);

    // 0x22 - returns the data bytes following the echoed DID, or nullopt.
    std::optional<std::vector<uint8_t>>
    readDataByIdentifier(uint16_t target, uint16_t did, std::string& err);

    // Reads a standard set of identification DIDs (VIN, part/serial numbers,
    // SW/HW versions) and returns a multi-line human-readable summary. Missing
    // DIDs are skipped silently. `anyOk` reports whether at least one read
    // succeeded (a useful reachability signal).
    std::string readEcuIdentification(uint16_t target, bool& anyOk);

    // One discovered identification DID from a sweep.
    struct IdentField {
        uint16_t    did    = 0;
        std::string label;        // human label if the DID is well-known
        std::string value;        // decoded ASCII if printable, else hex
        bool        printable = false;
    };

    // Sweeps the standard ISO 14229 identification block (0xF180-0xF1FF) with
    // read-only 0x22 requests and returns every DID that answers. This both
    // CONFIRMS the address (a positive read proves a live ECU) and harvests the
    // real part/serial/version numbers without any destructive action. `answered`
    // receives the number of DIDs that responded. Absent DIDs are skipped fast.
    std::vector<IdentField> sweepIdentificationDids(uint16_t target, int& answered,
                                                    int timeoutMs = 800);


    // 0x19 / 0x02 - reads DTCs matching the status mask (e.g. 0x08 confirmed).
    bool readDTCByStatusMask(uint16_t target, uint8_t mask,
                             std::vector<Dtc>& out, std::string& err);

    // 0x19 / 0x01 - reportNumberOfDTCByStatusMask. Returns the count the ECU
    // reports for the mask plus its DTC-format identifier (out params).
    bool readNumberOfDTCByStatusMask(uint16_t target, uint8_t mask,
                                     uint16_t& count, uint8_t& formatId,
                                     std::string& err);

    // 0x19 / 0x0A - reportSupportedDTC. Lists every DTC the ECU knows about
    // (regardless of current status) - useful to learn an ECU's fault catalog.
    bool readSupportedDTC(uint16_t target, std::vector<Dtc>& out,
                          std::string& err);

    // 0x19 / 0x04 - reportDTCSnapshotRecordByDTCNumber (freeze-frame). Returns
    // the raw snapshot payload for a specific 3-byte DTC and record number
    // (0xFF = all records). Snapshot layout is ECU-specific, so raw bytes are
    // returned for the caller to display/decode.
    bool readDTCSnapshot(uint16_t target, uint32_t dtc, uint8_t recordNumber,
                         std::vector<uint8_t>& raw, std::string& err);

    // 0x14 - clears DTCs for a DTC group (0xFFFFFF = all groups).
    bool clearDiagnosticInformation(uint16_t target, uint32_t group,
                                    std::string& err);

    // 0x11 - ECUReset. After a positive response the ECU reboots; expect a
    // brief loss of communication.
    bool ecuReset(uint16_t target, EcuResetType type, std::string& err);

    // 0x85 - ControlDTCSetting. on=true -> 0x01 (resume logging),
    // on=false -> 0x02 (suspend logging during repair work).
    bool controlDTCSetting(uint16_t target, bool on, std::string& err);

    // 0x3E - keep-alive. suppressPositiveResponse avoids a reply (0x80 bit).
    bool testerPresent(uint16_t target, std::string& err,
                       bool suppressPositiveResponse = false);

    // Lightweight reachability probe: sends TesterPresent and reports whether
    // ANY (positive or negative) UDS response came back - a negative response
    // still proves the ECU/address exists and is routable.
    bool probe(uint16_t target, std::string& err);

    // Functional ECU enumeration. Broadcasts a TesterPresent (0x3E) to a
    // functional group address and returns the logical (source) addresses of
    // every ECU that answers within collectMs. This is the fastest way to
    // build an ECU map for a vehicle with no published address list, since one
    // request reaches every ECU in the group at once. `functionalAddr` is
    // OEM-specific (common functional range is 0xE000-0xE3FF); try a few
    // if unknown. Returns false (err set) if nothing responds.
    bool enumerateEcus(uint16_t functionalAddr, std::vector<uint16_t>& found,
                       std::string& err, int collectMs = 1500);

    // -------------------------------------------------------------------
    // Safe service-discovery primitives (option 2).
    //
    // Each "probe" tells whether an identifier EXISTS without performing any
    // destructive action. They use only read-only / restorative sub-functions:
    //   - DID:     0x22 ReadDataByIdentifier (pure read)
    //   - Routine: 0x31 0x03 requestRoutineResults (does NOT start a routine)
    //   - IO:      0x2F <DID> 0x00 returnControlToECU (hands control BACK to
    //              the ECU - never seizes an actuator)
    //
    // Return code: 1 = positive response (exists), 0 = negative response but
    // the ID is recognized (exists, e.g. NRC 0x22/0x33), -1 = not present
    // (NRC 0x31 requestOutOfRange / 0x11 / 0x12) or no response. `resp` holds
    // the raw reply for logging. `timeoutMs` keeps absent-ID scans responsive.
    // -------------------------------------------------------------------
    int probeDID(uint16_t target, uint16_t did,
                 std::vector<uint8_t>& resp, std::string& err, int timeoutMs = 1500);
    int probeRoutine(uint16_t target, uint16_t rid,
                     std::vector<uint8_t>& resp, std::string& err, int timeoutMs = 1500);
    int probeIOControl(uint16_t target, uint16_t did,
                       std::vector<uint8_t>& resp, std::string& err, int timeoutMs = 1500);

    // 0x2F <DID> 0x00 - returnControlToECU. Restores normal ECU control of an
    // I/O channel that may have been seized; safe to call unconditionally.
    bool ioReturnControlToECU(uint16_t target, uint16_t did, std::string& err);

    // -------------------------------------------------------------------
    // Additional standard ISO 14229 services (diagnostics / programming).
    // These can change ECU state, so callers should gate them behind a
    // confirmation. Each logs its decoded TX/RX through Logger.
    // -------------------------------------------------------------------

    // 0x2E WriteDataByIdentifier - writes `data` to a configuration/coding DID.
    bool writeDataByIdentifier(uint16_t target, uint16_t did,
                               const std::vector<uint8_t>& data, std::string& err);

    // 0x23 ReadMemoryByAddress - reads `size` bytes from `address`.
    // addrBytes/sizeBytes give the byte-widths used in the
    // addressAndLengthFormatIdentifier (1-4 each). Raw bytes returned in `out`.
    bool readMemoryByAddress(uint16_t target, uint32_t address, uint32_t size,
                             uint8_t addrBytes, uint8_t sizeBytes,
                             std::vector<uint8_t>& out, std::string& err);

    // 0x31 RoutineControl - start/stop/requestResults for a routine id. The
    // raw positive-response payload (after the echoed sub-func + RID) is
    // returned in `out` for routine-status info. Start/Stop can be invasive.
    bool routineControl(uint16_t target, RoutineCtrl sub, uint16_t routineId,
                        const std::vector<uint8_t>& params,
                        std::vector<uint8_t>& out, std::string& err);

    // 0x28 CommunicationControl - enable/disable normal Rx/Tx. commType is the
    // communication-type bitfield (0x01 normal, 0x02 network-management,
    // 0x03 both). Disabling is commonly required before reprogramming.
    bool communicationControl(uint16_t target, CommCtrl control, uint8_t commType,
                              std::string& err);

    // 0x2A ReadDataByPeriodicIdentifier - schedules the ECU to transmit one or
    // more periodic data identifiers (PDIDs, the low byte of the 0xF2xx range)
    // at the requested rate, or stops them (PeriodicMode::StopSending). The
    // positive response (0x6A) only acknowledges scheduling; the recurring data
    // is then pushed by the ECU. `pdids` are the 1-byte periodic identifiers.
    bool readDataByPeriodicIdentifier(uint16_t target, PeriodicMode mode,
                                      const std::vector<uint8_t>& pdids,
                                      std::string& err);

    // 0x2C / 0x01 DynamicallyDefineDataIdentifier (defineByIdentifier) - builds
    // a composite dynamic DID (`dddid`, typically 0xF200-0xF2FF) by packing
    // selected byte ranges from other source DIDs. Once defined, the dynamic
    // DID can be read in a single 0x22 (ReadDataByIdentifier), collapsing many
    // round-trips into one - the AUTOSAR DCM way to stream a bundle of signals.
    bool defineDynamicDataIdentifier(uint16_t target, uint16_t dddid,
                                     const std::vector<DddSource>& sources,
                                     std::string& err);

    // 0x2C / 0x03 clearDynamicallyDefinedDataIdentifier - clears one dynamic
    // DID, or every dynamic DID when `dddid` is 0x0000.
    bool clearDynamicDataIdentifier(uint16_t target, uint16_t dddid,
                                    std::string& err);

    // -------------------------------------------------------------------
    // Reprogramming / block transfer (ISO 14229 services 0x34/0x36/0x37).
    //
    // The full flash sequence over a high-bandwidth diagnostic link beats CAN for
    // reprogramming: a large software image is pushed in big TransferData
    // blocks rather than tiny CAN frames. The caller is responsible for first
    // entering the programming session (0x10 0x02), unlocking SecurityAccess
    // (0x27) and any erase/pre-conditions routines (0x31). These services are
    // INVASIVE - gate them behind explicit user confirmation.
    // -------------------------------------------------------------------

    // 0x34 RequestDownload - announces an upcoming download of `size` bytes to
    // `memoryAddress`. addrBytes/sizeBytes are the byte-widths packed into the
    // addressAndLengthFormatIdentifier (1-4 each). `dataFormatId` is the
    // compression/encryption identifier (0x00 = none). On success the ECU
    // reports the maximum TransferData block length (including the 0x36 SID and
    // block-sequence-counter overhead) in `maxBlockLength`.
    bool requestDownload(uint16_t target, uint32_t memoryAddress, uint32_t size,
                         uint8_t addrBytes, uint8_t sizeBytes, uint8_t dataFormatId,
                         uint32_t& maxBlockLength, std::string& err);

    // 0x36 TransferData - sends one block. `blockSequenceCounter` starts at
    // 0x01 after RequestDownload and increments per block, wrapping 0xFF->0x00.
    // The ECU echoes the counter in its positive response.
    bool transferData(uint16_t target, uint8_t blockSequenceCounter,
                      const std::vector<uint8_t>& data, std::string& err);

    // 0x37 RequestTransferExit - terminates the download. `params` is an
    // optional transferRequestParameterRecord; `out` receives any
    // transferResponseParameterRecord (e.g. a CRC) the ECU returns.
    bool requestTransferExit(uint16_t target, const std::vector<uint8_t>& params,
                             std::vector<uint8_t>& out, std::string& err);

    // Orchestrates a full firmware block download: RequestDownload (0x34) ->
    // TransferData (0x36) loop sized to the ECU-reported maxBlockLength ->
    // RequestTransferExit (0x37). `progress(bytesDone, total)` is invoked after
    // each accepted block when set. Caller must already be in the programming
    // session with security unlocked. Returns false (err set) on the first
    // failed step.
    bool downloadBlock(uint16_t target, uint32_t memoryAddress,
                       const std::vector<uint8_t>& image,
                       uint8_t addrBytes, uint8_t sizeBytes, uint8_t dataFormatId,
                       const std::function<void(size_t, size_t)>& progress,
                       std::string& err);

    // 0x19 / 0x06 - reportDTCExtendedDataRecordByDTCNumber. Returns the raw
    // extended-data payload for a 3-byte DTC and record number (0xFF = all).
    bool readDTCExtendedData(uint16_t target, uint32_t dtc, uint8_t recordNumber,
                             std::vector<uint8_t>& raw, std::string& err);

    // 0x19 / 0x14 - reportDTCFaultDetectionCounter. Lists DTCs together with
    // their fault-detection counters (pending/aging info).
    bool readDTCFaultDetectionCounter(uint16_t target, std::vector<Dtc>& out,
                                      std::string& err);

    // SAE J1979 / ISO 15031 legislated OBD-II request (e.g. mode 0x09 PID 0x02
    // = VIN, mode 0x03 = stored DTCs). Returns the raw response payload AFTER
    // the positive-response service byte. Works on any emissions-compliant ECU.
    bool obdRequest(uint16_t target, const std::vector<uint8_t>& modePid,
                    std::vector<uint8_t>& out, std::string& err);

    // 0x2F InputOutputControlByIdentifier - the bidirectional "active test" /
    // actuator-control service. `option` selects the control behaviour;
    // `controlState` carries the value bytes for ShortTermAdjustment (empty for
    // the other options). `controlEnableMask` is appended after the state bytes
    // when non-empty (records-with-mask ECUs). The positive-response payload
    // after the echoed DID is returned in `out`. INVASIVE for non-return
    // options - gate behind confirmation and restore with ReturnControlToECU.
    bool inputOutputControl(uint16_t target, uint16_t did, IoControlOption option,
                            const std::vector<uint8_t>& controlState,
                            const std::vector<uint8_t>& controlEnableMask,
                            std::vector<uint8_t>& out, std::string& err);

    // 0x24 ReadScalingDataByIdentifier - returns the scaling/format description
    // for a DID (data type, byte count, unit, formula bytes) so a raw 0x22 value
    // can be interpreted. Raw scaling record returned in `out`.
    bool readScalingDataByIdentifier(uint16_t target, uint16_t did,
                                     std::vector<uint8_t>& out, std::string& err);

    // 0x3D WriteMemoryByAddress - writes `data` to `address`. addrBytes/sizeBytes
    // are the byte-widths packed into the addressAndLengthFormatIdentifier.
    // INVASIVE - changes raw ECU memory; gate behind confirmation.
    bool writeMemoryByAddress(uint16_t target, uint32_t address,
                              const std::vector<uint8_t>& data,
                              uint8_t addrBytes, uint8_t sizeBytes, std::string& err);

    // 0x35 RequestUpload - announces an upload (ECU -> tester) of `size` bytes
    // from `memoryAddress`. Mirrors RequestDownload; reports the ECU's maximum
    // TransferData block length in `maxBlockLength`.
    bool requestUpload(uint16_t target, uint32_t memoryAddress, uint32_t size,
                       uint8_t addrBytes, uint8_t sizeBytes, uint8_t dataFormatId,
                       uint32_t& maxBlockLength, std::string& err);

    // Orchestrates a full memory READOUT: RequestUpload (0x35) -> TransferData
    // (0x36) receive loop -> RequestTransferExit (0x37). The uploaded image is
    // appended to `image`. Caller must already be in a session that permits the
    // read (often the programming session with security unlocked).
    bool uploadBlock(uint16_t target, uint32_t memoryAddress, uint32_t size,
                     uint8_t addrBytes, uint8_t sizeBytes, uint8_t dataFormatId,
                     std::vector<uint8_t>& image,
                     const std::function<void(size_t, size_t)>& progress,
                     std::string& err);

    // 0x87 LinkControl - negotiates a faster diagnostic link. For VerifyMode*
    // `param` is the baudrate identifier/value; TransitionMode takes no param.
    bool linkControl(uint16_t target, LinkControlType sub,
                     const std::vector<uint8_t>& param, std::string& err);

    // 0x83 AccessTimingParameter - reads or sets the session P2/P2* timing.
    // `request` carries the timing values for SetToGivenValues (empty otherwise);
    // the ECU's timing record is returned in `out` for the Read sub-functions.
    bool accessTimingParameter(uint16_t target, TimingParamAccess sub,
                               const std::vector<uint8_t>& request,
                               std::vector<uint8_t>& out, std::string& err);

    // 0x29 Authentication - generic ISO 14229:2020 authentication exchange (PKI
    // certificate / challenge-response). `subFunction` selects the step (e.g.
    // 0x00 deAuthenticate, 0x01 verifyCertificateUnidirectional,
    // 0x03 proofOfOwnership, 0x08 requestChallengeForAuthentication). `data`
    // carries the step-specific payload; the response after the echoed
    // sub-function is returned in `out`.
    bool authentication(uint16_t target, uint8_t subFunction,
                        const std::vector<uint8_t>& data,
                        std::vector<uint8_t>& out, std::string& err);

    // 0x38 RequestFileTransfer - file-system operation against an ECU that
    // exposes one (OTA staging, log retrieval). `filePath` is the ASCII path;
    // size params apply to Add/Replace/Resume. The response record is returned
    // in `out`. INVASIVE for write/delete modes.
    bool requestFileTransfer(uint16_t target, FileTransferMode mode,
                             const std::string& filePath, uint8_t dataFormatId,
                             uint64_t fileSizeUncompressed, uint64_t fileSizeCompressed,
                             std::vector<uint8_t>& out, std::string& err);

    // 0x84 SecuredDataTransmission - sends a security-protected payload record
    // (e.g. MAC/nonce/ciphertext wrapper defined by the ECU's security layer).
    // Returns the response record in `out`.
    bool securedDataTransmission(uint16_t target,
                                 const std::vector<uint8_t>& in,
                                 std::vector<uint8_t>& out,
                                 std::string& err);

    // 0x86 ResponseOnEvent - configures/stops event-triggered responses.
    // `eventType` carries the ISO eventType byte, `eventWindowTime` is the
    // window-time parameter, `eventTypeRecord` is event-specific data, and
    // `serviceRequestRecord` is the UDS request to trigger when the event fires.
    // Returns the ECU response record in `out`.
    bool responseOnEvent(uint16_t target, uint8_t eventType,
                         uint8_t eventWindowTime,
                         const std::vector<uint8_t>& eventTypeRecord,
                         const std::vector<uint8_t>& serviceRequestRecord,
                         std::vector<uint8_t>& out, std::string& err);

    // Best-effort recovery: returns control of every touched I/O DID to the
    // ECU, re-enables DTC logging (0x85 on) and drops back to the default
    // session (0x10 0x01). `summary` accumulates a human-readable result.
    void restoreSafeState(uint16_t target, const std::vector<uint16_t>& touchedIoDids,
                          std::string& summary);

private:
    bool request(uint16_t target, const std::vector<uint8_t>& req,
                 std::vector<uint8_t>& resp, std::string& err);

    // Lower-level send that does NOT treat a negative response as a hard error.
    // Returns 1 positive, 0 negative (nrc set), -1 transport/no response.
    int rawRequest(uint16_t target, const std::vector<uint8_t>& req,
                   std::vector<uint8_t>& resp, uint8_t& nrc, std::string& err,
                   int timeoutMs = 5000);

    openxc::Transport& transport_;
    uint16_t           tester_;
};

// Decoding helpers (defined in UDSClient.cpp).
std::string decodeDtc(uint32_t code);          // "P0420-00"
std::string decodeDtcStatus(uint8_t status);   // human-readable status bits
std::string dtcLifecycle(uint8_t status);      // active/history classification
std::string dtcDescription(uint32_t code);     // best-effort generic text
std::string nrcText(uint8_t nrc);              // negative response code text
