//
// CanClient.cpp - UDS-over-CAN transport via the MVCI D-PDU API (mvci32.dll).
//
// The D-PDU API (ISO 22900-2) is dynamically loaded so the application keeps
// running on machines without an MVCI device. The Windows path implements the
// standard call sequence to open an ISO 15765 link and exchange UDS messages;
// every other platform compiles a stub that reports the backup as unavailable.
//
#include "CanClient.hpp"
#include "Logger.hpp"

#include <cstring>

namespace can {

bool Client::platformSupported() {
#ifdef _WIN32
    return true;
#else
    return false;
#endif
}

// ===========================================================================
//  Windows implementation - real MVCI / D-PDU API integration
// ===========================================================================
#ifdef _WIN32

#include <windows.h>
#include <chrono>
#include <thread>

namespace {

// --- ISO 22900-2 base types ------------------------------------------------
using UNUM8  = unsigned char;
using SNUM8  = signed char;
using CHAR8  = char;
using UNUM16 = unsigned short;
using SNUM16 = signed short;
using UNUM32 = unsigned int;
using SNUM32 = signed int;
using T_PDU_ERROR = UNUM32;

constexpr UNUM32 PDU_HANDLE_UNDEF = 0xFFFFFFFFu;
constexpr UNUM32 PDU_ID_UNDEF     = 0xFFFFFFFFu;

// --- Error codes (subset of e_PDU_ERROR) -----------------------------------
constexpr T_PDU_ERROR PDU_STATUS_NOERROR        = 0x00000000u;
constexpr T_PDU_ERROR PDU_ERR_EVENT_QUEUE_EMPTY = 0x00000002u; // no item pending

// --- Item types (T_PDU_IT) -------------------------------------------------
constexpr UNUM32 PDU_IT_PARAM     = 0x00001200u;
constexpr UNUM32 PDU_IT_RESULT    = 0x00001300u;
constexpr UNUM32 PDU_IT_STATUS    = 0x00001400u;
constexpr UNUM32 PDU_IT_ERROR     = 0x00001500u;
constexpr UNUM32 PDU_IT_INFO      = 0x00001600u;
constexpr UNUM32 PDU_IT_MODULE_ID = 0x00001900u;

// --- Communication primitive types (T_PDU_COPT) ----------------------------
constexpr UNUM32 PDU_COPT_STARTCOMM   = 0x00000001u;
constexpr UNUM32 PDU_COPT_STOPCOMM    = 0x00000002u;
constexpr UNUM32 PDU_COPT_UPDATEPARAM = 0x00000003u;
constexpr UNUM32 PDU_COPT_SENDRECV    = 0x00000004u;

// --- ComParam data types (T_PDU_PT) ----------------------------------------
constexpr UNUM32 PDU_PT_UNUM32   = 0x00000105u;
constexpr UNUM32 PDU_PT_BYTEFIELD = 0x00000107u;

// --- ComParam classes (T_PDU_PC) -------------------------------------------
constexpr UNUM32 PDU_PC_COM       = 0x00000003u;
constexpr UNUM32 PDU_PC_BUSTYPE   = 0x00000005u;
constexpr UNUM32 PDU_PC_UNIQUE_ID = 0x00000006u;

// --- Object types for PDUGetObjectId (T_PDU_OBJT) --------------------------
constexpr UNUM32 PDU_OBJT_PROTOCOL = 0x00000801u;
constexpr UNUM32 PDU_OBJT_BUSTYPE  = 0x00000802u;
constexpr UNUM32 PDU_OBJT_COMPARAM = 0x00000804u;

// --- Structures (binary layout per ISO 22900-2) ----------------------------
#pragma pack(push, 1)

struct PDU_FLAG_DATA {
    UNUM32 NumFlagBytes;
    UNUM8* pFlagData;
};

struct PDU_PIN_DATA {
    UNUM32 DLCPinNumber;
    UNUM32 PinTypeId;
};

struct PDU_RSC_DATA {
    UNUM32        BusTypeId;
    UNUM32        ProtocolId;
    UNUM32        NumPinData;
    PDU_PIN_DATA* pDpsPinData;
};

struct PDU_PARAM_ITEM {
    UNUM32 ItemType;          // PDU_IT_PARAM
    UNUM32 ComParamId;
    UNUM32 ComParamDataType;  // T_PDU_PT
    UNUM32 ComParamClass;     // T_PDU_PC
    void*  pComParamData;
};

struct PDU_COP_CTRL_DATA {
    UNUM32        Time;
    SNUM32        NumSendCycles;
    SNUM32        NumReceiveCycles;
    UNUM32        TempParamUpdate;
    PDU_FLAG_DATA TxFlag;
};

struct PDU_EVENT_ITEM {
    UNUM32 ItemType;     // T_PDU_IT
    UNUM32 hCop;         // CoP handle that produced this event
    void*  pCoPTag;
    UNUM32 Timestamp;
    void*  pData;        // points to a type-specific payload struct
};

// Payload referenced by PDU_EVENT_ITEM.pData for PDU_IT_RESULT. Only the
// leading fields (ItemType / NumDataBytes / pDataBytes) are read here; the
// struct is allocated by the DLL, so trailing fields are never dereferenced.
struct PDU_RESULT_DATA {
    UNUM32 ItemType;             // PDU_IT_RESULT
    UNUM32 NumDataBytes;         // length of pDataBytes
    UNUM8* pDataBytes;           // assembled UDS response
    void*  pExtraInfo;
    UNUM32 RxFlag;
    UNUM32 UniqueRespIdentifier;
    UNUM32 AcceptanceId;
    UNUM32 TimestampFlags;
};

#pragma pack(pop)

// --- D-PDU API function pointer types --------------------------------------
using PFN_PDUConstruct      = T_PDU_ERROR (__stdcall*)(CHAR8* optionStr, void* pCb);
using PFN_PDUDestruct       = T_PDU_ERROR (__stdcall*)(void);
using PFN_PDUGetObjectId    = T_PDU_ERROR (__stdcall*)(UNUM32 objType, UNUM32 nameLen,
                                                       CHAR8* pShortname, UNUM32* pObjId);
using PFN_PDUModuleConnect  = T_PDU_ERROR (__stdcall*)(UNUM32 hMod);
using PFN_PDUModuleDisconnect = T_PDU_ERROR (__stdcall*)(UNUM32 hMod);
using PFN_PDUCreateComLogicalLink = T_PDU_ERROR (__stdcall*)(
    UNUM32 hMod, PDU_RSC_DATA* pRscData, UNUM32 resourceId, void* pCllTag,
    UNUM32* phCLL, PDU_FLAG_DATA* pCllCreateFlag);
using PFN_PDUDestroyComLogicalLink = T_PDU_ERROR (__stdcall*)(UNUM32 hMod, UNUM32 hCLL);
using PFN_PDUConnect        = T_PDU_ERROR (__stdcall*)(UNUM32 hMod, UNUM32 hCLL);
using PFN_PDUDisconnect     = T_PDU_ERROR (__stdcall*)(UNUM32 hMod, UNUM32 hCLL);
using PFN_PDUSetComParam    = T_PDU_ERROR (__stdcall*)(UNUM32 hMod, UNUM32 hCLL,
                                                       PDU_PARAM_ITEM* pParamItem);
using PFN_PDUStartComPrimitive = T_PDU_ERROR (__stdcall*)(
    UNUM32 hMod, UNUM32 hCLL, UNUM32 CoPType, UNUM32 CoPDataSize, UNUM8* pCoPData,
    PDU_COP_CTRL_DATA* pCopCtrlData, void* pCoPTag, UNUM32* phCoP);
using PFN_PDUGetEventItem   = T_PDU_ERROR (__stdcall*)(UNUM32 hMod, UNUM32 hCLL,
                                                       PDU_EVENT_ITEM** pEventItem);
using PFN_PDUDestroyItem    = T_PDU_ERROR (__stdcall*)(void* pItem);

} // namespace

// Concrete Windows implementation state.
struct Client::Impl {
    HMODULE dll = nullptr;
    bool    constructed = false;
    bool    moduleConnected = false;
    bool    linkConnected = false;
    UNUM32  hMod = PDU_HANDLE_UNDEF;
    UNUM32  hCLL = PDU_HANDLE_UNDEF;
    Config  cfg;

    PFN_PDUConstruct              Construct = nullptr;
    PFN_PDUDestruct               Destruct = nullptr;
    PFN_PDUGetObjectId            GetObjectId = nullptr;
    PFN_PDUModuleConnect          ModuleConnect = nullptr;
    PFN_PDUModuleDisconnect       ModuleDisconnect = nullptr;
    PFN_PDUCreateComLogicalLink   CreateCLL = nullptr;
    PFN_PDUDestroyComLogicalLink  DestroyCLL = nullptr;
    PFN_PDUConnect                Connect = nullptr;
    PFN_PDUDisconnect             Disconnect = nullptr;
    PFN_PDUSetComParam            SetComParam = nullptr;
    PFN_PDUStartComPrimitive      StartComPrimitive = nullptr;
    PFN_PDUGetEventItem           GetEventItem = nullptr;
    PFN_PDUDestroyItem            DestroyItem = nullptr;

    // Resolve a standardized D-PDU short-name (protocol / bustype / ComParam)
    // to its numeric id via the DLL, avoiding hardcoded MDF-specific values.
    bool objectId(UNUM32 objType, const char* shortName, UNUM32& outId) {
        if (!GetObjectId) return false;
        std::string s(shortName);
        UNUM32 id = PDU_ID_UNDEF;
        T_PDU_ERROR e = GetObjectId(objType, (UNUM32)s.size(),
                                    const_cast<CHAR8*>(s.c_str()), &id);
        if (e != PDU_STATUS_NOERROR || id == PDU_ID_UNDEF) return false;
        outId = id;
        return true;
    }

    // Best-effort ComParam write of a single UNUM32 value (e.g. baudrate, CAN
    // id). Non-fatal: the MDF may already carry a usable default.
    void setUnum32(const char* shortName, UNUM32 pclass, UNUM32 value) {
        UNUM32 cpId = 0;
        if (!objectId(PDU_OBJT_COMPARAM, shortName, cpId)) {
            Logger::instance().warn(std::string("CAN: ComParam '") + shortName +
                                    "' not found in MVCI MDF (using default)");
            return;
        }
        PDU_PARAM_ITEM item{};
        item.ItemType        = PDU_IT_PARAM;
        item.ComParamId      = cpId;
        item.ComParamDataType = PDU_PT_UNUM32;
        item.ComParamClass   = pclass;
        item.pComParamData   = &value;
        T_PDU_ERROR e = SetComParam(hMod, hCLL, &item);
        if (e != PDU_STATUS_NOERROR)
            Logger::instance().warn(std::string("CAN: failed to set ComParam '") +
                                    shortName + "' (err 0x" + byteHex((uint8_t)e) + ")");
    }
};

Client::Client() : impl_(std::make_unique<Impl>()) {}

Client::~Client() { disconnect(); }

bool Client::isConnected() const {
    return impl_ && impl_->linkConnected;
}

bool Client::connect(const Config& cfg, std::string& err) {
    disconnect();
    impl_->cfg = cfg;

    impl_->dll = LoadLibraryA(cfg.dllPath.c_str());
    if (!impl_->dll) {
        err = "Cannot load MVCI library '" + cfg.dllPath +
              "' (is the pass-thru device driver installed?)";
        return false;
    }

    auto resolve = [&](auto& fn, const char* name) -> bool {
        fn = reinterpret_cast<std::decay_t<decltype(fn)>>(
            GetProcAddress(impl_->dll, name));
        if (!fn) err = std::string("mvci32.dll missing export '") + name + "'";
        return fn != nullptr;
    };

    if (!resolve(impl_->Construct,        "PDUConstruct") ||
        !resolve(impl_->Destruct,         "PDUDestruct") ||
        !resolve(impl_->GetObjectId,      "PDUGetObjectId") ||
        !resolve(impl_->ModuleConnect,    "PDUModuleConnect") ||
        !resolve(impl_->ModuleDisconnect, "PDUModuleDisconnect") ||
        !resolve(impl_->CreateCLL,        "PDUCreateComLogicalLink") ||
        !resolve(impl_->DestroyCLL,       "PDUDestroyComLogicalLink") ||
        !resolve(impl_->Connect,          "PDUConnect") ||
        !resolve(impl_->Disconnect,       "PDUDisconnect") ||
        !resolve(impl_->SetComParam,      "PDUSetComParam") ||
        !resolve(impl_->StartComPrimitive,"PDUStartComPrimitive") ||
        !resolve(impl_->GetEventItem,     "PDUGetEventItem") ||
        !resolve(impl_->DestroyItem,      "PDUDestroyItem")) {
        disconnect();
        return false;
    }

    // 1) Initialise the API.
    if (impl_->Construct(nullptr, nullptr) != PDU_STATUS_NOERROR) {
        err = "PDUConstruct failed";
        disconnect();
        return false;
    }
    impl_->constructed = true;

    // The module handle 0 selects the first/default MVCI module. A production
    // multi-device setup would enumerate via PDUGetModuleIds and pick one.
    impl_->hMod = 0;
    if (impl_->ModuleConnect(impl_->hMod) != PDU_STATUS_NOERROR) {
        err = "PDUModuleConnect failed (no MVCI module available)";
        disconnect();
        return false;
    }
    impl_->moduleConnected = true;

    // 2) Resolve the ISO 15765 protocol + CAN bus type by their standardized
    //    short-names so we do not depend on vendor-specific numeric ids.
    UNUM32 protocolId = PDU_ID_UNDEF, busTypeId = PDU_ID_UNDEF;
    if (!impl_->objectId(PDU_OBJT_PROTOCOL, "ISO_15765_3", protocolId)) {
        err = "MVCI MDF does not expose the ISO_15765_3 protocol";
        disconnect();
        return false;
    }
    impl_->objectId(PDU_OBJT_BUSTYPE, "ISO_11898_2_DWCAN", busTypeId);

    PDU_RSC_DATA rsc{};
    rsc.BusTypeId  = busTypeId;
    rsc.ProtocolId = protocolId;
    rsc.NumPinData = 0;
    rsc.pDpsPinData = nullptr;

    if (impl_->CreateCLL(impl_->hMod, &rsc, PDU_ID_UNDEF, nullptr,
                         &impl_->hCLL, nullptr) != PDU_STATUS_NOERROR ||
        impl_->hCLL == PDU_HANDLE_UNDEF) {
        err = "PDUCreateComLogicalLink(ISO_15765) failed";
        disconnect();
        return false;
    }

    // 3) Configure the link: bit rate, request/response CAN ids and the
    //    addressing format (11- vs 29-bit). These are best-effort writes.
    impl_->setUnum32("CP_Baudrate",          PDU_PC_BUSTYPE,   cfg.baudrate);
    impl_->setUnum32("CP_CanPhysReqFormat",  PDU_PC_UNIQUE_ID, cfg.extendedId ? 1u : 0u);
    impl_->setUnum32("CP_CanPhysReqId",      PDU_PC_UNIQUE_ID, cfg.reqId);
    impl_->setUnum32("CP_CanRespUSDTFormat", PDU_PC_UNIQUE_ID, cfg.extendedId ? 1u : 0u);
    impl_->setUnum32("CP_CanRespUSDTId",     PDU_PC_UNIQUE_ID, cfg.respId);

    // 4) Bring the link online.
    if (impl_->Connect(impl_->hMod, impl_->hCLL) != PDU_STATUS_NOERROR) {
        err = "PDUConnect failed";
        disconnect();
        return false;
    }
    impl_->linkConnected = true;

    Logger::instance().info(
        "CAN backup (mvci32) link up: ISO 15765 @ " +
        std::to_string(cfg.baudrate) + " bit/s, req 0x" +
        byteHex((uint8_t)(cfg.reqId >> 8)) + byteHex((uint8_t)cfg.reqId) +
        " resp 0x" + byteHex((uint8_t)(cfg.respId >> 8)) + byteHex((uint8_t)cfg.respId));
    return true;
}

void Client::setAddressing(uint32_t reqId, uint32_t respId, std::string& err) {
    if (!isConnected()) { err = "CAN link not connected"; return; }
    impl_->cfg.reqId  = reqId;
    impl_->cfg.respId = respId;
    impl_->setUnum32("CP_CanPhysReqId",  PDU_PC_UNIQUE_ID, reqId);
    impl_->setUnum32("CP_CanRespUSDTId", PDU_PC_UNIQUE_ID, respId);
}

bool Client::sendDiagnostic(uint16_t /*source*/, uint16_t /*target*/,
                            const std::vector<uint8_t>& uds,
                            std::vector<uint8_t>& response, int timeoutMs,
                            std::string& err, bool functional) {
    response.clear();
    if (!isConnected()) { err = "CAN link not connected"; return false; }
    if (uds.empty())    { err = "Empty UDS request"; return false; }

    PDU_COP_CTRL_DATA ctrl{};
    ctrl.Time             = 0;
    ctrl.NumSendCycles    = 1;
    ctrl.NumReceiveCycles = functional ? -1 : 1;   // -1 = unlimited (collect)
    ctrl.TempParamUpdate  = 0;
    ctrl.TxFlag.NumFlagBytes = 0;
    ctrl.TxFlag.pFlagData    = nullptr;

    UNUM32 hCoP = PDU_HANDLE_UNDEF;
    T_PDU_ERROR e = impl_->StartComPrimitive(
        impl_->hMod, impl_->hCLL, PDU_COPT_SENDRECV,
        (UNUM32)uds.size(), const_cast<UNUM8*>(uds.data()),
        &ctrl, nullptr, &hCoP);
    if (e != PDU_STATUS_NOERROR) {
        err = "PDUStartComPrimitive(SENDRECV) failed (err 0x" + byteHex((uint8_t)e) + ")";
        return false;
    }

    // Poll the event queue until our CoP yields a result/error or we time out.
    // A UDS "response pending" (NRC 0x78) extends the deadline so the ECU has
    // time to finish a long-running service.
    const auto start = std::chrono::steady_clock::now();
    auto deadline = start + std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : 2000);

    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline) {
            err = "CAN UDS timeout (no response)";
            return false;
        }

        PDU_EVENT_ITEM* item = nullptr;
        T_PDU_ERROR ge = impl_->GetEventItem(impl_->hMod, impl_->hCLL, &item);
        if (ge == PDU_ERR_EVENT_QUEUE_EMPTY || item == nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }
        if (ge != PDU_STATUS_NOERROR) {
            err = "PDUGetEventItem failed (err 0x" + byteHex((uint8_t)ge) + ")";
            if (item) impl_->DestroyItem(item);
            return false;
        }

        bool done = false;
        if (item->ItemType == PDU_IT_RESULT && item->pData) {
            auto* r = reinterpret_cast<PDU_RESULT_DATA*>(item->pData);
            if (r->pDataBytes && r->NumDataBytes > 0) {
                std::vector<uint8_t> rx(r->pDataBytes, r->pDataBytes + r->NumDataBytes);
                bool pending = rx.size() >= 3 && rx[0] == 0x7F && rx[2] == 0x78;
                if (pending) {
                    // Negative "response pending": keep waiting, refresh budget.
                    deadline = std::chrono::steady_clock::now() +
                               std::chrono::milliseconds(timeoutMs > 0 ? timeoutMs : 2000);
                } else {
                    response = std::move(rx);
                    done = true;
                }
            }
        } else if (item->ItemType == PDU_IT_ERROR) {
            err = "CAN link reported a transmission error";
            impl_->DestroyItem(item);
            return false;
        }
        // PDU_IT_STATUS / PDU_IT_INFO events are informational; ignore them.

        impl_->DestroyItem(item);
        if (done) return true;
    }
}

void Client::disconnect() {
    if (!impl_) return;
    if (impl_->linkConnected && impl_->Disconnect)
        impl_->Disconnect(impl_->hMod, impl_->hCLL);
    impl_->linkConnected = false;

    if (impl_->hCLL != PDU_HANDLE_UNDEF && impl_->DestroyCLL)
        impl_->DestroyCLL(impl_->hMod, impl_->hCLL);
    impl_->hCLL = PDU_HANDLE_UNDEF;

    if (impl_->moduleConnected && impl_->ModuleDisconnect)
        impl_->ModuleDisconnect(impl_->hMod);
    impl_->moduleConnected = false;

    if (impl_->constructed && impl_->Destruct)
        impl_->Destruct();
    impl_->constructed = false;

    if (impl_->dll) { FreeLibrary(impl_->dll); impl_->dll = nullptr; }
    impl_->hMod = PDU_HANDLE_UNDEF;
}

// ===========================================================================
//  Non-Windows stub - the MVCI D-PDU API (mvci32.dll) is Windows-only
// ===========================================================================
#else // !_WIN32

struct Client::Impl {};

Client::Client() : impl_(nullptr) {}
Client::~Client() {}

bool Client::isConnected() const { return false; }

bool Client::connect(const Config& /*cfg*/, std::string& err) {
    err = "CAN backup (mvci32.dll / MVCI D-PDU API) is only available on Windows";
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

void Client::disconnect() {}

#endif // _WIN32

} // namespace can
