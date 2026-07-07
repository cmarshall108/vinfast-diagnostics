//
// CanClient.cpp - UDS-over-CAN transport via Toyota's Mini-VCI (mvci32.dll).
//
// Toyota's Mini-VCI ships the XHorse "MVCI Driver for TOYOTA TIS", whose
// mvci32.dll is a SAE J2534 v04.04 PassThru library (PassThru* exports). We
// dynamically load it and drive an ISO 15765 (UDS-over-CAN) channel through
// the J2534 interface so the app keeps running on machines without the device;
// every other platform compiles a stub that reports the backup as unavailable.
//
#include "CanClient.hpp"
#include "Logger.hpp"
#include "VF8Data.hpp"

#include <cstring>

// The real Mini-VCI integration is 32-bit-Windows only (mvci32.dll is a 32-bit
// DLL). These headers must be included at global scope - never inside
// namespace can - or the whole standard library lands in can::std.
#if defined(_WIN32) && !defined(_WIN64)
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <thread>
#endif

namespace can {

bool Client::platformSupported() {
#if defined(_WIN32) && !defined(_WIN64)
    return true;   // 32-bit Windows: can load Toyota's 32-bit mvci32.dll
#else
    return false;  // 64-bit Windows / other OSes cannot load the 32-bit DLL
#endif
}

// ===========================================================================
//  Windows implementation - real Toyota Mini-VCI / J2534 PassThru integration
//  (32-bit only: mvci32.dll is a 32-bit DLL and a 64-bit process can't load it)
// ===========================================================================
#if defined(_WIN32) && !defined(_WIN64)

namespace {

// --- SAE J2534 PassThru API ------------------------------------------------
// Toyota's Mini-VCI driver (mvci32.dll) is a J2534 v04.04 PassThru library.
// These declarations mirror the J2534-1 header so we can bind the exports.

// Protocol IDs.
constexpr unsigned long J_J1850PWM = 1;
constexpr unsigned long J_J1850VPW = 2;
constexpr unsigned long J_ISO9141  = 3;
constexpr unsigned long J_ISO14230 = 4;
constexpr unsigned long J_CAN      = 5;
constexpr unsigned long J_ISO15765 = 6;

// Connect flags / TxFlags / RxStatus bits.
constexpr unsigned long J_CAN_29BIT_ID         = 0x00000100u;
constexpr unsigned long J_ISO15765_FRAME_PAD   = 0x00000040u;
constexpr unsigned long J_TX_MSG_TYPE          = 0x00000001u; // RxStatus: loopback echo
constexpr unsigned long J_ISO15765_FIRST_FRAME = 0x00000002u; // RxStatus: FF indication

// Filter types.
constexpr unsigned long J_PASS_FILTER          = 0x00000001u;
constexpr unsigned long J_FLOW_CONTROL_FILTER  = 0x00000003u;

// Ioctl IDs (buffer clears + K-line initialisation).
constexpr unsigned long J_CLEAR_RX_BUFFER = 0x00000008u;
constexpr unsigned long J_CLEAR_TX_BUFFER = 0x00000009u;
constexpr unsigned long J_FIVE_BAUD_INIT  = 0x00000005u; // ISO 9141-2 slow init
constexpr unsigned long J_FAST_INIT       = 0x00000006u; // ISO 14230-4 fast init

// Return codes (subset of the J2534 error space).
constexpr long J_STATUS_NOERROR   = 0x00;
constexpr long J_ERR_TIMEOUT      = 0x09;
constexpr long J_ERR_BUFFER_EMPTY = 0x10;

constexpr unsigned long J_MSG_DATA_SIZE = 4128;

#pragma pack(push, 1)
struct PASSTHRU_MSG {
    unsigned long ProtocolID;
    unsigned long RxStatus;
    unsigned long TxFlags;
    unsigned long Timestamp;
    unsigned long DataSize;
    unsigned long ExtraDataIndex;
    unsigned char Data[J_MSG_DATA_SIZE];
};
#pragma pack(pop)

// Byte-array argument used by the K-line initialisation ioctls.
struct SBYTE_ARRAY {
    unsigned long  NumOfBytes;
    unsigned char* BytePtr;
};

// --- J2534 function pointer types (all __stdcall, return int32 status) ------
using PFN_PassThruOpen    = long (__stdcall*)(const void* pName, unsigned long* pDeviceID);
using PFN_PassThruClose   = long (__stdcall*)(unsigned long DeviceID);
using PFN_PassThruConnect = long (__stdcall*)(unsigned long DeviceID, unsigned long ProtocolID,
                                              unsigned long Flags, unsigned long BaudRate,
                                              unsigned long* pChannelID);
using PFN_PassThruDisconnect = long (__stdcall*)(unsigned long ChannelID);
using PFN_PassThruReadMsgs   = long (__stdcall*)(unsigned long ChannelID, PASSTHRU_MSG* pMsg,
                                                 unsigned long* pNumMsgs, unsigned long Timeout);
using PFN_PassThruWriteMsgs  = long (__stdcall*)(unsigned long ChannelID, PASSTHRU_MSG* pMsg,
                                                 unsigned long* pNumMsgs, unsigned long Timeout);
using PFN_PassThruStartMsgFilter = long (__stdcall*)(unsigned long ChannelID, unsigned long FilterType,
                                                     PASSTHRU_MSG* pMask, PASSTHRU_MSG* pPattern,
                                                     PASSTHRU_MSG* pFlowControl, unsigned long* pFilterID);
using PFN_PassThruStopMsgFilter  = long (__stdcall*)(unsigned long ChannelID, unsigned long FilterID);
using PFN_PassThruIoctl   = long (__stdcall*)(unsigned long ChannelID, unsigned long IoctlID,
                                              void* pInput, void* pOutput);
using PFN_PassThruReadVersion = long (__stdcall*)(unsigned long DeviceID, char* pFirmware,
                                                  char* pDll, char* pApi);
using PFN_PassThruGetLastError = long (__stdcall*)(char* pErrorDescription);

} // namespace

// Concrete Windows implementation state (J2534 / Toyota Mini-VCI).
struct Client::Impl {
    HMODULE dll = nullptr;
    bool    deviceOpen  = false;
    bool    channelOpen = false;
    bool    haveFilter  = false;
    unsigned long deviceId  = 0;
    unsigned long channelId = 0;
    unsigned long filterId  = 0;
    Config  cfg;

    PFN_PassThruOpen            Open = nullptr;
    PFN_PassThruClose           Close = nullptr;
    PFN_PassThruConnect         Connect = nullptr;
    PFN_PassThruDisconnect      Disconnect = nullptr;
    PFN_PassThruReadMsgs        ReadMsgs = nullptr;
    PFN_PassThruWriteMsgs       WriteMsgs = nullptr;
    PFN_PassThruStartMsgFilter  StartMsgFilter = nullptr;
    PFN_PassThruStopMsgFilter   StopMsgFilter = nullptr;
    PFN_PassThruIoctl           Ioctl = nullptr;
    PFN_PassThruReadVersion     ReadVersion = nullptr;
    PFN_PassThruGetLastError    GetLastErrorText = nullptr;

    // The driver's human-readable description of the most recent failure.
    std::string lastError() {
        char buf[128] = {0};
        if (GetLastErrorText && GetLastErrorText(buf) == J_STATUS_NOERROR && buf[0])
            return std::string(buf);
        return "unknown J2534 error";
    }

    // Installs (or replaces) the ISO 15765 flow-control filter binding the
    // physical request id we transmit on to the response id the ECU answers
    // with. Required before the device will accept/assemble ISO-TP frames.
    bool installFlowControl(unsigned long reqId, unsigned long respId, std::string& err) {
        unsigned long txf = J_ISO15765_FRAME_PAD | (cfg.extendedId ? J_CAN_29BIT_ID : 0);
        auto fill = [&](PASSTHRU_MSG& m, unsigned long id) {
            m = PASSTHRU_MSG{};
            m.ProtocolID = J_ISO15765;
            m.TxFlags    = txf;
            m.DataSize   = 4;
            m.Data[0] = (unsigned char)((id >> 24) & 0xFF);
            m.Data[1] = (unsigned char)((id >> 16) & 0xFF);
            m.Data[2] = (unsigned char)((id >> 8) & 0xFF);
            m.Data[3] = (unsigned char)(id & 0xFF);
        };
        PASSTHRU_MSG mask, pattern, flow;
        fill(mask, 0xFFFFFFFFu);  // match all four id bytes
        fill(pattern, respId);    // ECU -> tester id
        fill(flow, reqId);        // tester -> ECU id

        if (haveFilter && StopMsgFilter) {
            StopMsgFilter(channelId, filterId);
            haveFilter = false;
        }
        long s = StartMsgFilter(channelId, J_FLOW_CONTROL_FILTER,
                                &mask, &pattern, &flow, &filterId);
        if (s != J_STATUS_NOERROR) {
            err = "PassThruStartMsgFilter failed (" + lastError() + ")";
            return false;
        }
        haveFilter = true;
        return true;
    }
};

Client::Client() : impl_(std::make_unique<Impl>()) {}

Client::~Client() { disconnect(); }

bool Client::isConnected() const {
    return impl_ && impl_->channelOpen;
}

bool Client::connect(const Config& cfg, std::string& err) {
    disconnect();
    impl_->cfg = cfg;

    impl_->dll = LoadLibraryA(cfg.dllPath.c_str());
    if (!impl_->dll) {
        err = "Cannot load Toyota Mini-VCI driver '" + cfg.dllPath +
              "' (install the XHorse 'MVCI Driver for TOYOTA TIS')";
        return false;
    }

    auto resolve = [&](auto& fn, const char* name) -> bool {
        fn = reinterpret_cast<std::decay_t<decltype(fn)>>(
            GetProcAddress(impl_->dll, name));
        if (!fn) err = std::string("mvci32.dll missing J2534 export '") + name + "'";
        return fn != nullptr;
    };

    if (!resolve(impl_->Open,           "PassThruOpen") ||
        !resolve(impl_->Close,          "PassThruClose") ||
        !resolve(impl_->Connect,        "PassThruConnect") ||
        !resolve(impl_->Disconnect,     "PassThruDisconnect") ||
        !resolve(impl_->ReadMsgs,       "PassThruReadMsgs") ||
        !resolve(impl_->WriteMsgs,      "PassThruWriteMsgs") ||
        !resolve(impl_->StartMsgFilter, "PassThruStartMsgFilter") ||
        !resolve(impl_->StopMsgFilter,  "PassThruStopMsgFilter")) {
        disconnect();
        return false;
    }
    // Optional exports - best-effort (diagnostics / version reporting only).
    impl_->Ioctl            = reinterpret_cast<PFN_PassThruIoctl>(
        GetProcAddress(impl_->dll, "PassThruIoctl"));
    impl_->ReadVersion      = reinterpret_cast<PFN_PassThruReadVersion>(
        GetProcAddress(impl_->dll, "PassThruReadVersion"));
    impl_->GetLastErrorText = reinterpret_cast<PFN_PassThruGetLastError>(
        GetProcAddress(impl_->dll, "PassThruGetLastError"));

    // 1) Open the device (NULL selects the single attached Mini-VCI).
    if (impl_->Open(nullptr, &impl_->deviceId) != J_STATUS_NOERROR) {
        err = "PassThruOpen failed (" + impl_->lastError() +
              "); is the Mini-VCI plugged in?";
        disconnect();
        return false;
    }
    impl_->deviceOpen = true;

    // 2) Open an ISO 15765 (UDS-over-CAN) channel at the requested bit rate.
    unsigned long flags = cfg.extendedId ? J_CAN_29BIT_ID : 0;
    if (impl_->Connect(impl_->deviceId, J_ISO15765, flags, cfg.baudrate,
                       &impl_->channelId) != J_STATUS_NOERROR) {
        err = "PassThruConnect(ISO15765) failed (" + impl_->lastError() + ")";
        disconnect();
        return false;
    }
    impl_->channelOpen = true;

    // 3) Bind the request/response identifiers via an ISO-TP flow-control
    //    filter (mandatory for ISO 15765 segmented transfers).
    if (!impl_->installFlowControl(cfg.reqId, cfg.respId, err)) {
        disconnect();
        return false;
    }

    if (impl_->ReadVersion) {
        char fw[80] = {0}, dl[80] = {0}, api[80] = {0};
        if (impl_->ReadVersion(impl_->deviceId, fw, dl, api) == J_STATUS_NOERROR)
            Logger::instance().info(std::string("Mini-VCI firmware ") + fw +
                                    ", DLL " + dl + ", J2534 " + api);
    }
    Logger::instance().info(
        "CAN backup (Toyota Mini-VCI / J2534) link up: ISO 15765 @ " +
        std::to_string(cfg.baudrate) + " bit/s, req 0x" +
        byteHex((uint8_t)(cfg.reqId >> 8)) + byteHex((uint8_t)cfg.reqId) +
        " resp 0x" + byteHex((uint8_t)(cfg.respId >> 8)) + byteHex((uint8_t)cfg.respId));
    return true;
}

void Client::setAddressing(uint32_t reqId, uint32_t respId, std::string& err) {
    if (!isConnected()) { err = "CAN link not connected"; return; }
    impl_->cfg.reqId  = reqId;
    impl_->cfg.respId = respId;
    impl_->installFlowControl(reqId, respId, err);
}

bool Client::sendDiagnostic(uint16_t /*source*/, uint16_t /*target*/,
                            const std::vector<uint8_t>& uds,
                            std::vector<uint8_t>& response, int timeoutMs,
                            std::string& err, bool functional) {
    response.clear();
    if (!isConnected()) { err = "CAN link not connected"; return false; }
    if (uds.empty())    { err = "Empty UDS request"; return false; }

    // Build the ISO 15765 frame: 4-byte CAN id (big-endian) + UDS payload. The
    // device performs ISO-TP segmentation and reassembly.
    PASSTHRU_MSG tx{};
    tx.ProtocolID = J_ISO15765;
    tx.TxFlags    = J_ISO15765_FRAME_PAD | (impl_->cfg.extendedId ? J_CAN_29BIT_ID : 0);
    uint32_t id   = impl_->cfg.reqId;
    tx.Data[0] = (unsigned char)((id >> 24) & 0xFF);
    tx.Data[1] = (unsigned char)((id >> 16) & 0xFF);
    tx.Data[2] = (unsigned char)((id >> 8) & 0xFF);
    tx.Data[3] = (unsigned char)(id & 0xFF);
    size_t n = std::min<size_t>(uds.size(), J_MSG_DATA_SIZE - 4);
    std::memcpy(tx.Data + 4, uds.data(), n);
    tx.DataSize = (unsigned long)(4 + n);

    unsigned long numMsgs = 1;
    long ws = impl_->WriteMsgs(impl_->channelId, &tx, &numMsgs,
                               timeoutMs > 0 ? (unsigned long)timeoutMs : 1000);
    if (ws != J_STATUS_NOERROR) {
        err = "PassThruWriteMsgs failed (" + impl_->lastError() + ")";
        return false;
    }

    // Read until a genuine response payload arrives, skipping the transmit
    // loopback echo and ISO-TP first-frame indications. A UDS "response
    // pending" (NRC 0x78) extends the deadline so long services can finish.
    (void)functional;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : 2000);
    for (;;) {
        long remMs = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                         deadline - std::chrono::steady_clock::now()).count();
        if (remMs <= 0) { err = "CAN UDS timeout (no response)"; return false; }

        PASSTHRU_MSG rx{};
        unsigned long got = 1;
        long rs = impl_->ReadMsgs(impl_->channelId, &rx, &got,
                                  (unsigned long)std::min<long>(remMs, 200));
        if (rs == J_ERR_BUFFER_EMPTY || rs == J_ERR_TIMEOUT || got == 0)
            continue;  // nothing yet; keep polling until our own deadline
        if (rs != J_STATUS_NOERROR) {
            err = "PassThruReadMsgs failed (" + impl_->lastError() + ")";
            return false;
        }
        if (rx.RxStatus & J_TX_MSG_TYPE)          continue;  // our loopback echo
        if (rx.RxStatus & J_ISO15765_FIRST_FRAME) continue;  // FF indication
        if (rx.DataSize <= 4)                      continue;  // id only, no data

        std::vector<uint8_t> rxu(rx.Data + 4, rx.Data + rx.DataSize);
        bool pending = rxu.size() >= 3 && rxu[0] == 0x7F && rxu[2] == 0x78;
        if (pending) {
            deadline = std::chrono::steady_clock::now() +
                       std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : 2000);
            continue;
        }
        response = std::move(rxu);
        return true;
    }
}

bool Client::sendDiagnosticMulti(uint16_t /*source*/, uint16_t /*target*/,
                                 const std::vector<uint8_t>& uds,
                                 std::vector<MultiResponse>& responses,
                                 int collectMs, std::string& err) {
    if (!isConnected()) { err = "CAN link not connected"; return false; }
    if (uds.empty())    { err = "Empty UDS request"; return false; }

    PASSTHRU_MSG tx{};
    tx.ProtocolID = J_ISO15765;
    tx.TxFlags    = J_ISO15765_FRAME_PAD | (impl_->cfg.extendedId ? J_CAN_29BIT_ID : 0);
    uint32_t id   = impl_->cfg.reqId;
    tx.Data[0] = (unsigned char)((id >> 24) & 0xFF);
    tx.Data[1] = (unsigned char)((id >> 16) & 0xFF);
    tx.Data[2] = (unsigned char)((id >> 8) & 0xFF);
    tx.Data[3] = (unsigned char)(id & 0xFF);
    size_t n = std::min<size_t>(uds.size(), J_MSG_DATA_SIZE - 4);
    std::memcpy(tx.Data + 4, uds.data(), n);
    tx.DataSize = (unsigned long)(4 + n);

    unsigned long numMsgs = 1;
    if (impl_->WriteMsgs(impl_->channelId, &tx, &numMsgs,
                         collectMs > 0 ? (unsigned long)collectMs : 1000) != J_STATUS_NOERROR) {
        err = "PassThruWriteMsgs failed (" + impl_->lastError() + ")";
        return false;
    }

    // Collect every distinct responder for the whole window; multiple ECUs in
    // the functional group may each answer, so never stop on the first reply.
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(collectMs > 0 ? collectMs : 1000);
    while (std::chrono::steady_clock::now() < deadline) {
        long remMs = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                         deadline - std::chrono::steady_clock::now()).count();
        if (remMs <= 0) break;

        PASSTHRU_MSG rx{};
        unsigned long got = 1;
        long rs = impl_->ReadMsgs(impl_->channelId, &rx, &got,
                                  (unsigned long)std::min<long>(remMs, 200));
        if (rs == J_ERR_BUFFER_EMPTY || rs == J_ERR_TIMEOUT || got == 0) continue;
        if (rs != J_STATUS_NOERROR) break;  // treat as end of window
        if (rx.RxStatus & J_TX_MSG_TYPE)          continue;
        if (rx.RxStatus & J_ISO15765_FIRST_FRAME) continue;
        if (rx.DataSize <= 4)                      continue;

        // Responder id = the 4-byte CAN id the ECU answered on.
        uint32_t src = ((uint32_t)rx.Data[0] << 24) | ((uint32_t)rx.Data[1] << 16) |
                       ((uint32_t)rx.Data[2] << 8)  |  (uint32_t)rx.Data[3];
        std::vector<uint8_t> rxu(rx.Data + 4, rx.Data + rx.DataSize);
        bool pending = rxu.size() >= 3 && rxu[0] == 0x7F && rxu[2] == 0x78;
        if (pending) continue;

        uint16_t key = (uint16_t)(src & 0xFFFF);
        bool dup = false;
        for (auto& mr : responses)
            if (mr.source == key && mr.uds == rxu) { dup = true; break; }
        if (!dup) responses.push_back({key, std::move(rxu)});
    }

    if (responses.empty()) { err = "No ECUs responded to functional CAN request"; return false; }
    return true;
}

void Client::disconnect() {
    if (!impl_) return;
    if (impl_->haveFilter && impl_->StopMsgFilter)
        impl_->StopMsgFilter(impl_->channelId, impl_->filterId);
    impl_->haveFilter = false;

    if (impl_->channelOpen && impl_->Disconnect)
        impl_->Disconnect(impl_->channelId);
    impl_->channelOpen = false;

    if (impl_->deviceOpen && impl_->Close)
        impl_->Close(impl_->deviceId);
    impl_->deviceOpen = false;

    if (impl_->dll) { FreeLibrary(impl_->dll); impl_->dll = nullptr; }
}

// ---------------------------------------------------------------------------
//  OBD-II protocol discovery
//
//  We don't yet know whether the target vehicle (e.g. a 2024 VinFast VF8)
//  speaks CAN, K-line or J1850, so this sweeps every standard OBD-II transport
//  the Mini-VCI's J2534 driver can attempt and reports which one(s) the vehicle
//  actually answers on. It is fully self-contained: it loads the DLL, opens its
//  own device, and tears everything down before returning, so it never touches
//  an in-use backup link.
// ---------------------------------------------------------------------------
bool Client::scanObdProtocols(const std::string& dllPath,
                              const std::function<void(float)>& progress,
                              const std::function<void(const ProtocolProbe&)>& report,
                              const std::atomic<bool>& cancel,
                              std::string& err) {
    HMODULE dll = LoadLibraryA(dllPath.c_str());
    if (!dll) {
        err = "Cannot load Toyota Mini-VCI driver '" + dllPath +
              "' (install the XHorse 'MVCI Driver for TOYOTA TIS')";
        return false;
    }
    auto get = [&](const char* n) { return GetProcAddress(dll, n); };
    auto pOpen   = reinterpret_cast<PFN_PassThruOpen>(get("PassThruOpen"));
    auto pClose  = reinterpret_cast<PFN_PassThruClose>(get("PassThruClose"));
    auto pConn   = reinterpret_cast<PFN_PassThruConnect>(get("PassThruConnect"));
    auto pDisc   = reinterpret_cast<PFN_PassThruDisconnect>(get("PassThruDisconnect"));
    auto pRead   = reinterpret_cast<PFN_PassThruReadMsgs>(get("PassThruReadMsgs"));
    auto pWrite  = reinterpret_cast<PFN_PassThruWriteMsgs>(get("PassThruWriteMsgs"));
    auto pStartF = reinterpret_cast<PFN_PassThruStartMsgFilter>(get("PassThruStartMsgFilter"));
    auto pStopF  = reinterpret_cast<PFN_PassThruStopMsgFilter>(get("PassThruStopMsgFilter"));
    auto pIoctl  = reinterpret_cast<PFN_PassThruIoctl>(get("PassThruIoctl"));
    if (!pOpen || !pClose || !pConn || !pDisc || !pRead || !pWrite || !pStartF || !pStopF) {
        err = "mvci32.dll is missing required J2534 PassThru exports";
        FreeLibrary(dll);
        return false;
    }

    unsigned long deviceId = 0;
    if (pOpen(nullptr, &deviceId) != J_STATUS_NOERROR) {
        err = "PassThruOpen failed; is the Mini-VCI plugged in?";
        FreeLibrary(dll);
        return false;
    }

    // Renders raw bytes as space-separated hex for the result detail column.
    auto toHex = [](const unsigned char* p, size_t n) {
        std::string s;
        for (size_t i = 0; i < n; ++i) {
            if (i) s += ' ';
            s += byteHex(p[i]);
        }
        return s;
    };

    // Describes a single candidate transport to attempt.
    struct Cand {
        std::string   name;
        unsigned long protocol;
        unsigned long baud;
        unsigned long connFlags;
        bool          sniffOnly;   // passive: just listen for any live frame
        unsigned long canId;       // active CAN/ISO15765 functional request id
        bool          can29;       // 29-bit identifiers
        std::vector<unsigned char> klineHeader; // legacy header bytes (J1850/K-line)
    };

    const std::vector<unsigned char> hdrKwp  = {0x68, 0x6A, 0xF1}; // ISO 9141 / 14230 functional
    const std::vector<unsigned char> hdrVpw  = {0x68, 0x6A, 0xF1}; // J1850 VPW functional
    const std::vector<unsigned char> hdrPwm  = {0x61, 0x6A, 0xF1}; // J1850 PWM functional

    // Order matters: the first candidate is tried first. The VF8 TBOX firmware
    // (etc/init.d/init-can.sh) brings up a single classic-CAN bus at
    // 500 kbit/s ("ip link set can0 type can bitrate 500000", no FD, no
    // listen-only), so ISO 15765-4 CAN 500k 11-bit is the correct primary
    // protocol and is probed first; the remaining rows are fallbacks for other
    // wiring / legacy vehicles.
    std::vector<Cand> cands = {
        {"ISO 15765-4 CAN 500k 11-bit", J_ISO15765, 500000, 0,             false, 0x7DF,       false, {}},
        {"ISO 15765-4 CAN 500k 29-bit", J_ISO15765, 500000, J_CAN_29BIT_ID,false, 0x18DB33F1u, true,  {}},
        {"ISO 15765-4 CAN 250k 11-bit", J_ISO15765, 250000, 0,             false, 0x7DF,       false, {}},
        {"ISO 15765-4 CAN 250k 29-bit", J_ISO15765, 250000, J_CAN_29BIT_ID,false, 0x18DB33F1u, true,  {}},
        {"Raw CAN sniff 500k",          J_CAN,      500000, 0,             true,  0,           false, {}},
        {"Raw CAN sniff 250k",          J_CAN,      250000, 0,             true,  0,           false, {}},
        {"SAE J1850 VPW",               J_J1850VPW, 10400,  0,             false, 0,           false, hdrVpw},
        {"SAE J1850 PWM",               J_J1850PWM, 41600,  0,             false, 0,           false, hdrPwm},
        {"ISO 9141-2 (K-line)",         J_ISO9141,  10400,  0,             false, 0,           false, hdrKwp},
        {"ISO 14230-4 KWP (K-line)",    J_ISO14230, 10400,  0,             false, 0,           false, hdrKwp},
    };

    const float total = (float)cands.size();
    for (size_t i = 0; i < cands.size(); ++i) {
        if (cancel.load()) break;
        if (progress) progress((float)i / total);
        const Cand& c = cands[i];
        ProtocolProbe out;
        out.protocol = c.name;

        unsigned long channelId = 0;
        if (pConn(deviceId, c.protocol, c.connFlags, c.baud, &channelId) != J_STATUS_NOERROR) {
            out.linkUp = false;
            out.detail = "VCI could not open this protocol";
            if (report) report(out);
            continue;
        }
        out.linkUp = true;

        // Build an ISO 15765 4-byte big-endian id helper.
        auto putId = [](PASSTHRU_MSG& m, unsigned long id) {
            m.Data[0] = (unsigned char)((id >> 24) & 0xFF);
            m.Data[1] = (unsigned char)((id >> 16) & 0xFF);
            m.Data[2] = (unsigned char)((id >> 8) & 0xFF);
            m.Data[3] = (unsigned char)(id & 0xFF);
        };

        unsigned long filterId = 0;
        bool haveFilter = false;

        if (c.protocol == J_ISO15765) {
            // ISO-TP needs a flow-control filter binding our request id to the
            // ECU's response id (request id + 8 for the standard OBD pairing).
            unsigned long respId = c.can29 ? 0x18DAF110u : (c.canId + 8);
            unsigned long txf = J_ISO15765_FRAME_PAD | (c.can29 ? J_CAN_29BIT_ID : 0);
            PASSTHRU_MSG mask{}, patt{}, flow{};
            mask.ProtocolID = patt.ProtocolID = flow.ProtocolID = J_ISO15765;
            mask.TxFlags = patt.TxFlags = flow.TxFlags = txf;
            mask.DataSize = patt.DataSize = flow.DataSize = 4;
            putId(mask, 0xFFFFFFFFu);
            putId(patt, respId);
            putId(flow, c.canId);
            haveFilter = pStartF(channelId, J_FLOW_CONTROL_FILTER, &mask, &patt, &flow, &filterId)
                         == J_STATUS_NOERROR;
        } else {
            // Everything else: pass-all filter so reads return every frame.
            PASSTHRU_MSG mask{}, patt{};
            mask.ProtocolID = patt.ProtocolID = c.protocol;
            mask.DataSize = patt.DataSize = (c.protocol == J_CAN) ? 4 : 1;
            haveFilter = pStartF(channelId, J_PASS_FILTER, &mask, &patt, nullptr, &filterId)
                         == J_STATUS_NOERROR;
        }

        // K-line protocols require an initialisation handshake before traffic.
        if (c.protocol == J_ISO9141) {
            unsigned char addr = 0x33;                 // OBD-II functional address
            SBYTE_ARRAY in{1, &addr}, kb{0, nullptr};
            unsigned char keybytes[2] = {0, 0};
            kb.NumOfBytes = 2; kb.BytePtr = keybytes;
            if (pIoctl) pIoctl(channelId, J_FIVE_BAUD_INIT, &in, &kb);
        } else if (c.protocol == J_ISO14230) {
            PASSTHRU_MSG sc{}, scr{};
            sc.ProtocolID = J_ISO14230;
            unsigned char fast[] = {0xC1, 0x33, 0xF1, 0x81};
            sc.DataSize = sizeof(fast);
            std::memcpy(sc.Data, fast, sizeof(fast));
            if (pIoctl) pIoctl(channelId, J_FAST_INIT, &sc, &scr);
        }

        if (c.sniffOnly) {
            // Passive discovery: listen for genuine bus frames. A modern EV
            // constantly broadcasts on CAN, so this alone confirms both that
            // the bus is CAN and at what bit rate. While listening we also try
            // to decode any frame that matches the curated VF8 Info-CAN catalog
            // and surface the named signal values.
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1200);
            std::string firstFrame;
            std::vector<std::string> decoded;
            unsigned long seenIds[8] = {0};
            int seenCount = 0;
            while (std::chrono::steady_clock::now() < deadline) {
                if (cancel.load()) break;
                PASSTHRU_MSG rx{}; unsigned long got = 1;
                long rs = pRead(channelId, &rx, &got, 200);
                if (rs != J_STATUS_NOERROR || got == 0) continue;
                if (rx.RxStatus & J_TX_MSG_TYPE) continue;     // ignore our own echo
                if (rx.DataSize == 0) continue;
                out.responded = true;
                if (firstFrame.empty()) {
                    unsigned long n = std::min<unsigned long>(rx.DataSize, 12);
                    firstFrame = toHex(rx.Data, n);
                }
                // Raw CAN frames carry a 4-byte big-endian arbitration id prefix.
                if (rx.DataSize > 4 && (int)decoded.size() < 6) {
                    uint32_t id = ((uint32_t)rx.Data[0] << 24) | ((uint32_t)rx.Data[1] << 16) |
                                  ((uint32_t)rx.Data[2] << 8)  |  (uint32_t)rx.Data[3];
                    const char* mn = vf8CanMessageName(id);
                    bool dup = false;
                    for (int k = 0; k < seenCount; ++k) if (seenIds[k] == id) dup = true;
                    if (mn && !dup) {
                        if (seenCount < 8) seenIds[seenCount++] = id;
                        char idbuf[8];
                        std::snprintf(idbuf, sizeof idbuf, "0x%03X", id & 0x7FF);
                        std::string line = std::string(idbuf) + " " + mn + ":";
                        auto vals = vf8DecodeCanFrame(id, rx.Data + 4, rx.DataSize - 4);
                        for (const auto& v : vals)
                            line += " " + std::string(v.signal) + "=" + v.display + ";";
                        decoded.push_back(line);
                    }
                }
                // Keep listening a little to catch known frames, but stop early
                // once we've decoded a useful handful.
                if ((int)decoded.size() >= 6) break;
            }
            if (!out.responded) {
                out.detail = "no bus activity";
            } else {
                out.detail = "live frame: " + firstFrame;
                for (const auto& line : decoded) out.detail += "\n    " + line;
            }
        } else {
            // Active discovery: ask for OBD-II Mode 01 PID 00 (supported PIDs)
            // and watch for any reply.
            PASSTHRU_MSG tx{};
            tx.ProtocolID = c.protocol;
            if (c.protocol == J_ISO15765) {
                tx.TxFlags = J_ISO15765_FRAME_PAD | (c.can29 ? J_CAN_29BIT_ID : 0);
                putId(tx, c.canId);
                tx.Data[4] = 0x01; tx.Data[5] = 0x00;   // service 01, PID 00
                tx.DataSize = 6;
            } else if (c.protocol == J_CAN) {
                // Raw CAN single frame: 11-bit functional id 0x7DF, PCI=0x02.
                putId(tx, 0x7DF);
                tx.Data[4] = 0x02; tx.Data[5] = 0x01; tx.Data[6] = 0x00;
                tx.DataSize = 8;                        // pad to a full CAN frame
            } else {
                // J1850 / K-line: header bytes then the OBD service/PID; the
                // device appends the checksum.
                size_t h = c.klineHeader.size();
                std::memcpy(tx.Data, c.klineHeader.data(), h);
                tx.Data[h] = 0x01; tx.Data[h + 1] = 0x00;
                tx.DataSize = (unsigned long)(h + 2);
            }

            unsigned long numMsgs = 1;
            if (pWrite(channelId, &tx, &numMsgs, 1000) == J_STATUS_NOERROR) {
                auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(900);
                while (std::chrono::steady_clock::now() < deadline) {
                    if (cancel.load()) break;
                    PASSTHRU_MSG rx{}; unsigned long got = 1;
                    long rs = pRead(channelId, &rx, &got, 200);
                    if (rs != J_STATUS_NOERROR || got == 0) continue;
                    if (rx.RxStatus & J_TX_MSG_TYPE)          continue; // loopback echo
                    if (rx.RxStatus & J_ISO15765_FIRST_FRAME) continue; // FF indication
                    unsigned long skip = (c.protocol == J_ISO15765 || c.protocol == J_CAN) ? 4 : 0;
                    if (rx.DataSize <= skip) continue;
                    out.responded = true;
                    unsigned long n = std::min<unsigned long>(rx.DataSize - skip, 16);
                    out.detail = "reply: " + toHex(rx.Data + skip, n);
                    break;
                }
                if (!out.responded) out.detail = "no response to OBD Mode 01";
            } else {
                out.detail = "transmit failed on this protocol";
            }
        }

        if (haveFilter && pStopF) pStopF(channelId, filterId);
        pDisc(channelId);
        if (report) report(out);
    }

    if (progress) progress(1.0f);
    pClose(deviceId);
    FreeLibrary(dll);
    return true;
}


// ===========================================================================
//  Stub - used on non-Windows platforms and on 64-bit Windows, since Toyota's
//  Mini-VCI J2534 driver (mvci32.dll) is a 32-bit DLL that only a 32-bit
//  process can load.
// ===========================================================================
#else // !(_WIN32 && !_WIN64)

struct Client::Impl {};

Client::Client() : impl_(nullptr) {}
Client::~Client() {}

bool Client::isConnected() const { return false; }

bool Client::connect(const Config& /*cfg*/, std::string& err) {
    err = "CAN backup (Toyota Mini-VCI / J2534 mvci32.dll) requires a 32-bit "
          "(x86) Windows build; mvci32.dll is a 32-bit DLL";
    return false;
}

void Client::setAddressing(uint32_t, uint32_t, std::string& err) {
    err = "CAN backup unavailable on this platform";
}

bool Client::sendDiagnostic(uint16_t, uint16_t, const std::vector<uint8_t>&,
                            std::vector<uint8_t>&, int, std::string& err, bool) {
    err = "CAN backup unavailable on this platform";
    return false;
}

bool Client::sendDiagnosticMulti(uint16_t, uint16_t, const std::vector<uint8_t>&,
                                 std::vector<MultiResponse>&, int, std::string& err) {
    err = "CAN backup unavailable on this platform";
    return false;
}

void Client::disconnect() {}

bool Client::scanObdProtocols(const std::string&,
                              const std::function<void(float)>&,
                              const std::function<void(const ProtocolProbe&)>&,
                              const std::atomic<bool>&,
                              std::string& err) {
    err = "OBD-II protocol discovery requires the Windows Mini-VCI (J2534) driver";
    return false;
}

#endif // _WIN32 && !_WIN64

} // namespace can
