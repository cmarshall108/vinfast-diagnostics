#pragma once
//
// Gui.hpp - Qt6 front-end for the OpenXC USB/Bluetooth UDS diagnostic scanner.
//
// The interface is modelled on TEXA IDC6: an icon-driven navigator down the
// left edge selects compact "pages" in a stacked view, and detail (ECU info,
// DTC lists, snapshots, add-signal forms, confirmations) is shown in relative
// popups so very little text is visible at once.
//
#include "OpenXcTransport.hpp"
#include "UDSClient.hpp"
#include "CloudClient.hpp"
#include "CanClient.hpp"

#include <QMainWindow>

class QResizeEvent;

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

QT_BEGIN_NAMESPACE
class QStackedWidget;
class QListWidget;
class QLabel;
class QPushButton;
class QProgressBar;
class QLineEdit;
class QDateTimeEdit;
class QSpinBox;
class QComboBox;
class QCheckBox;
class QPlainTextEdit;
class QTimer;
class QGridLayout;
class QToolButton;
class QTableWidget;
class QTreeWidget;
class QWidget;
QT_END_NAMESPACE

// Autel-style module-topology canvas (defined in Gui.cpp).
class EcuTopologyView;

class Gui : public QMainWindow {
    Q_OBJECT
public:
    Gui();
    ~Gui() override;

protected:
    void resizeEvent(QResizeEvent* event) override;

private:
    // A configurable target ECU.
    struct EcuRow {
        std::string name;
        uint16_t    logicalAddr = 0;
        uint16_t    altAddr = 0;      // alternative address to try if logicalAddr fails (0 = none)
        std::string statusMsg;
        std::string idInfo;
        std::vector<Dtc> dtcs;
        int         reachable = -1;   // -1 unknown, 0 no, 1 yes (from probe)
    };

    // A live-data watch item: a DID polled repeatedly from one ECU.
    struct LiveSignal {
        uint16_t    target = 0;   // ECU logical address
        uint16_t    did = 0;      // data identifier (0x22 argument)
        std::string name;
        int         interp = 0;   // 0 raw hex, 1 uint, 2 signed int, 3 ASCII
        double      scale = 1.0;  // engineering value = raw*scale + offset
        double      offset = 0.0;
        std::string unit;
        std::string rawHex;       // last raw response bytes
        std::string value;        // decoded display string
        int         ok = -1;      // -1 none yet, 0 fail, 1 ok
    };

    struct DiscoveredService {
        uint8_t     service;   // 0x22 DID, 0x31 routine, 0x2F IO
        uint16_t    id;
        int         exists;    // 1 positive, 0 exists-via-NRC
        std::string note;      // decoded reply / NRC text
    };

    // A timestamped capture of every readable BMS 0x22 DID plus whatever cloud
    // "ground-truth" (SOC / charging) was available at that instant. Comparing
    // two snapshots taken at different battery states reveals which raw DIDs
    // track SOC/charge - i.e. which carry battery data.
    struct BmsSnapshot {
        long long   tWallMs   = 0;
        double      cloudSoc  = -1;    // -1 = unknown
        double      cloudPower = -1;   // kW, -1 = unknown
        bool        cloudCharging = false;
        std::vector<std::pair<uint16_t, std::vector<uint8_t>>> dids;  // did -> raw
    };

    // --- UI construction ---
    void buildUi();
    QWidget* buildNav();
    QWidget* buildHeader();
    QWidget* buildDashboardPage();
    QWidget* buildConnectionPage();
    QWidget* buildEcuPage();
    QWidget* buildLivePage();
    QWidget* buildServicePage();
    QWidget* buildProtocolPage();
    QWidget* buildCloudPage();
    QWidget* buildReferencePage();
    QWidget* buildLogPage();
    void     applyStyle();

    // --- popups (relative to the triggering widget) ---
    void openEcuDialog(int idx, QWidget* anchor);
    void openAddSignalDialog(QWidget* anchor);
    bool confirmPopup(QWidget* anchor, const QString& title,
                      const QString& body, const QString& okText);

    // Extensive CAN discovery scan (every protocol/baud/addressing/id the MVCI
    // supports) shown in its own window.
    void openCanScanDialog(QWidget* anchor);

    // --- periodic refresh of dynamic views ---
    void refreshHeader();
    void refreshDashboard();
    void refreshEcuTiles();
    void refreshLive();
    void refreshServiceResults();
    void refreshProtocol();
    void refreshCloud();
    void refreshLog();
    void refreshActionState();

    // Appends a line to the protocol page output (thread-safe).
    void protoLine(const std::string& s);

    // Appends a line to the cloud page output (thread-safe).
    void cloudLine(const std::string& s);

    // --- network helpers (unchanged semantics) ---
    bool ensureConnected(std::string& err);
    bool ensureConnectedOrNotify(const QString& opName, std::string& err);
    void showDisconnectPopup(const QString& operationName, const QString& details);
    void startWorker(std::function<void()> fn);
    void startKeepAlive();
    void stopKeepAlive();
    void startLivePoll();
    void stopLivePoll();
    void syncSettingsFromUi();

    static uint16_t parseHex16(const QString& s, uint16_t def);

private slots:
    void onTick();

private:
    // --- network ---
    openxc::Transport transport_;   // OpenXC USB/Bluetooth serial primary transport
    can::Client canBackup_;         // CAN (ISO 15765 / mvci32.dll) backup transport

    // --- settings (synced from widgets via syncSettingsFromUi) ---
    std::string gatewayIp_   = "auto";
    int  testerAddr_     = 0x0E80;
    // Legislated OBD functional broadcast (not DoIP-style 0xE400).
    int  functionalAddr_ = 0x07DF;
    bool useFunctional_  = false;
    int  statusMask_     = 0x08;
    // Default physical target: Info-CAN XGW DiagReq (alt 0x7E0 tried on scan).
    int  gatewayAddr_    = 0x0682;
    int  sessionType_    = (int)UdsSession::Extended;
    bool autoExtendedOnClear_ = true;
    bool keepAlive_      = false;
    int  keepAliveTarget_= 0x0682;
    int  securityTarget_ = 0x0682;
    int  securityLevel_  = 0x01;
    std::string securityKeyHex_;
    std::string ecuKeyText_;      // per-ECU secret for VinFast HMAC-SHA1 seed->key
    std::string lastSeedHex_;

    // Default sweep covers Info DiagReq band + OBD physical range.
    int  sweepStart_ = 0x0680;
    int  sweepEnd_   = 0x07EF;
    bool sweepAddDiscovered_ = true;

    int  livePollMs_ = 500;
    bool liveBundle_ = false;   // bundle all live signals into one dynamic DID (0x2C) per cycle

    // OpenXC VI bus selection (1 or 2 on most VI hardware).
    int openxcBus_ = 1;

    // Fallback map for logical aliases outside 0x600-0x7FF:
    //   requestId  = canIdBase_ + (logicalAddr & 0xFF)
    //   responseId = requestId + canRespOffset_   (Info 0x680-0x6FF uses −0x80 auto)
    // Direct DiagReq / OBD IDs in 0x600-0x7FF are passed through unchanged.
    int  canIdBase_     = 0x700;
    int  canRespOffset_ = 0x08;

    // CAN backup (UDS over ISO 15765 via mvci32.dll). Used automatically when
    // the OpenXC exchange fails. Disabled by default.
    bool        canEnabled_   = false;
    std::string canDll_       = "mvci32.dll";
    int         canBaud_      = 500000;
    int         canReqId_     = 0x7E0;   // physical request CAN ID
    int         canRespId_    = 0x7E8;   // response CAN ID
    bool        canExtended_  = false;   // 29-bit identifiers

    // service-discovery settings
    int  svcTarget_       = 0x0693;  // BMS_DiagReq
    int  svcStart_        = 0x0000;
    int  svcEnd_          = 0x00FF;
    bool svcScanDIDs_     = true;
    bool svcScanRoutines_ = true;
    bool svcScanIO_       = false;
    bool svcSuspendDTC_   = true;
    bool svcExtendedSess_ = true;
    bool svcRestoreAfter_ = true;

    // --- shared state (guarded by mutex_) ---
    std::mutex                mutex_;
    std::vector<EcuRow>       ecus_;
    std::string               connStatus_ = "Disconnected";
    std::vector<LiveSignal>   liveSignals_;
    std::vector<DiscoveredService> svcResults_;
    std::string               protoLog_;
    size_t                    protoLogRev_ = 0;   // bumped on every append
    std::string               cloudLog_;
    size_t                    cloudLogRev_ = 0;   // bumped on every append

    // --- worker / background threads ---
    std::atomic<bool> busy_{false};
    std::atomic<bool> topologyScanCancel_{false};
    std::thread       worker_;
    std::atomic<bool> keepAliveRun_{false};
    std::thread       keepAliveThread_;
    std::atomic<bool> liveRun_{false};
    std::thread       liveThread_;
    std::mutex        netMutex_;

    // --- widgets ---
    QStackedWidget* pages_      = nullptr;
    QListWidget*    nav_        = nullptr;
    QLabel*         busyDot_    = nullptr;
    QLabel*         busyText_   = nullptr;
    QProgressBar*   busyBar_    = nullptr;
    QLabel*         connDot_    = nullptr;
    QLabel*         connText_   = nullptr;
    QLabel*         hdrSubtitle_= nullptr;
    QPushButton*    connectBtn_ = nullptr;

    // dashboard page
    QLabel*         dashModel_   = nullptr;
    QLabel*         dashVin_     = nullptr;
    QLabel*         dashMarket_  = nullptr;
    QLabel*         dashMhuSw_   = nullptr;
    QLabel*         dashTbox_    = nullptr;
    QLabel*         dashModules_ = nullptr;

    // connection page
    QLineEdit*   edGateway_   = nullptr;
    QPushButton* usbScanBtn_  = nullptr;  // discovers USB/serial OpenXC VI devices
    QPushButton* btScanBtn_   = nullptr;  // discovers paired Bluetooth OpenXC VI devices
    QLineEdit*   edTester_    = nullptr;
    QLineEdit*   edGwAddr_    = nullptr;
    QLineEdit* edFunctional_= nullptr;
    QCheckBox* cbFunctional_= nullptr;
    QLineEdit* edStatusMask_= nullptr;
    QComboBox* cbSession_   = nullptr;
    QCheckBox* cbAutoExt_   = nullptr;
    QCheckBox* cbKeepAlive_ = nullptr;
    QLineEdit* edKeepAliveTarget_ = nullptr;
    QLineEdit* edSecurityTarget_ = nullptr;
    QLineEdit* edSeedLevel_ = nullptr;
    QLineEdit* edEcuKey_    = nullptr;
    QLineEdit* edKey_       = nullptr;
    QLabel*    seedLabel_   = nullptr;
    QLineEdit* edSweepStart_= nullptr;
    QLineEdit* edSweepEnd_  = nullptr;
    QCheckBox* cbSweepAdd_  = nullptr;
    QLineEdit* edEnumFunc_  = nullptr;
    QSpinBox*  sbOpenxcBus_ = nullptr;
    QLineEdit* edCanIdBase_ = nullptr;
    QLineEdit* edCanRespOffset_ = nullptr;
    QCheckBox* cbCanEnabled_= nullptr;
    QLineEdit* edCanDll_    = nullptr;
    QLineEdit* edCanBaud_   = nullptr;
    QLineEdit* edCanReqId_  = nullptr;
    QLineEdit* edCanRespId_ = nullptr;
    QCheckBox* cbCanExt_    = nullptr;

    // ecu page (Autel-style module topology)
    EcuTopologyView* topology_     = nullptr;
    int              openEcuIdx_   = -1;   // currently open detail dialog index
    QWidget*         openEcuDialog_= nullptr;
    QPushButton*     scanAllBtn_   = nullptr;
    QPushButton*     stopScanBtn_  = nullptr;
    QPushButton*     clearAllBtn_  = nullptr;
    QPushButton*     addEcuBtn_    = nullptr;
    QLabel*          scanStateLabel_ = nullptr;

    // live page
    QLineEdit*    edLiveInterval_ = nullptr;
    QPushButton*  livePollBtn_    = nullptr;
    QTableWidget* liveTable_      = nullptr;
    QCheckBox*    cbLiveBundle_   = nullptr;

    // service page
    QLineEdit*    edSvcTarget_ = nullptr;
    QLineEdit*    edSvcStart_  = nullptr;
    QLineEdit*    edSvcEnd_    = nullptr;
    QCheckBox*    cbSvcDIDs_   = nullptr;
    QCheckBox*    cbSvcRoutines_ = nullptr;
    QCheckBox*    cbSvcIO_     = nullptr;
    QCheckBox*    cbSvcSuspend_= nullptr;
    QCheckBox*    cbSvcExt_    = nullptr;
    QCheckBox*    cbSvcRestore_= nullptr;
    QTableWidget* svcTable_    = nullptr;

    // protocol / advanced page
    QLineEdit*      edProtoTarget_     = nullptr;
    QLineEdit*      edProtoWriteDid_   = nullptr;
    QLineEdit*      edProtoWriteData_  = nullptr;
    QLineEdit*      edProtoMemAddr_    = nullptr;
    QSpinBox*       sbProtoMemSize_    = nullptr;
    QSpinBox*       sbProtoAddrBytes_  = nullptr;
    QSpinBox*       sbProtoSizeBytes_  = nullptr;
    QLineEdit*      edProtoRid_        = nullptr;
    QLineEdit*      edProtoRidParams_  = nullptr;
    QComboBox*      cbProtoRoutine_    = nullptr;
    QComboBox*      cbProtoComm_       = nullptr;
    QLineEdit*      edProtoCommType_   = nullptr;
    QLineEdit*      edProtoDtc_        = nullptr;
    QLineEdit*      edProtoDtcRec_     = nullptr;
    QComboBox*      cbProtoPeriodicMode_ = nullptr;
    QLineEdit*      edProtoPdid_       = nullptr;
    QLineEdit*      edProtoDddid_      = nullptr;
    QLineEdit*      edProtoDddSrc_     = nullptr;
    // actuator control (0x2F) + memory/scaling/upload + link/timing/auth + flash
    QLineEdit*      edProtoIoDid_      = nullptr;
    QComboBox*      cbProtoIoOption_   = nullptr;
    QLineEdit*      edProtoIoState_    = nullptr;
    QLineEdit*      edProtoIoMask_     = nullptr;
    QLineEdit*      edProtoScalingDid_ = nullptr;
    QLineEdit*      edProtoWmbaAddr_   = nullptr;
    QLineEdit*      edProtoWmbaData_   = nullptr;
    QSpinBox*       sbProtoWmbaAddrB_  = nullptr;
    QSpinBox*       sbProtoWmbaSizeB_  = nullptr;
    QLineEdit*      edProtoUpAddr_     = nullptr;
    QSpinBox*       sbProtoUpSize_     = nullptr;
    // full memory dump (chunked 0x35 upload streamed to a .bin file)
    QLineEdit*      edDumpAddr_        = nullptr;
    QLineEdit*      edDumpSize_        = nullptr;
    QLineEdit*      edDumpChunk_       = nullptr;
    QSpinBox*       sbDumpAddrB_       = nullptr;
    QSpinBox*       sbDumpSizeB_       = nullptr;
    QComboBox*      cbProtoLinkSub_    = nullptr;
    QLineEdit*      edProtoLinkParam_  = nullptr;
    QComboBox*      cbProtoTimingSub_  = nullptr;
    QLineEdit*      edProtoTimingVals_ = nullptr;
    QLineEdit*      edProtoAuthSub_    = nullptr;
    QLineEdit*      edProtoAuthData_   = nullptr;
    QLineEdit*      edProtoSecData_    = nullptr;
    QLineEdit*      edProtoRoeEventType_ = nullptr;
    QLineEdit*      edProtoRoeWindow_    = nullptr;
    QLineEdit*      edProtoRoeEventRec_  = nullptr;
    QLineEdit*      edProtoRoeSvcRec_    = nullptr;
    QComboBox*      cbProtoFileMode_   = nullptr;
    QLineEdit*      edProtoFilePath_   = nullptr;
    QLineEdit*      edProtoFileFmt_    = nullptr;
    QLineEdit*      edProtoFileSizeU_  = nullptr;
    QLineEdit*      edProtoFileSizeC_  = nullptr;
    QLineEdit*      edProtoFlashAddr_  = nullptr;
    QLineEdit*      edProtoFlashFile_  = nullptr;
    QPlainTextEdit* protoView_         = nullptr;
    size_t          protoViewRev_      = (size_t)-1;

    // BMS crash-data / HV-lockout reset (guided post-collision recovery)
    QLineEdit*      edCrashTarget_   = nullptr;
    QLineEdit*      edCrashSecLevel_ = nullptr;
    QLineEdit*      edCrashKey_      = nullptr;
    QLineEdit*      edCrashRid_      = nullptr;
    QLineEdit*      edCrashDtc_      = nullptr;

    // reference page
    QTreeWidget*  refTree_ = nullptr;

    // cloud page (reverse-engineered VinFast connected-car API)
    cloud::CloudClient cloud_;
    QComboBox*      cbCloudRegion_  = nullptr;
    QLineEdit*      edCloudEmail_   = nullptr;
    QLineEdit*      edCloudPass_    = nullptr;
    QLabel*         cloudVehLabel_  = nullptr;
    QPlainTextEdit* cloudView_      = nullptr;
    size_t          cloudViewRev_   = (size_t)-1;

    // engineering-menu TOTP generator
    QLineEdit*      edTotpSeed_     = nullptr;
    QDateTimeEdit*  edTotpTs_       = nullptr;
    QLineEdit*      edTotpTsText_   = nullptr;

    // BMS characterization (bus <-> cloud correlation)
    QLineEdit*      edBmsTarget_ = nullptr;
    QLineEdit*      edBmsStart_  = nullptr;
    QLineEdit*      edBmsEnd_    = nullptr;
    std::vector<BmsSnapshot> bmsSnapshots_;   // guarded by mutex_

    // log page
    QPlainTextEdit* logView_   = nullptr;
    QCheckBox*      cbAutoScroll_ = nullptr;
    QLabel*         logSaved_  = nullptr;
    size_t          lastLogCount_ = 0;

    QTimer* timer_ = nullptr;
};
