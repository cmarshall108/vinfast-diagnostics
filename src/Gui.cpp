#include "Gui.hpp"
#include "Logger.hpp"
#include "VF8Data.hpp"
#include "CloudData.hpp"

#include <QStackedWidget>
#include <QListWidget>
#include <QListWidgetItem>
#include <QLabel>
#include <QPushButton>
#include <QToolButton>
#include <QLineEdit>
#include <QSpinBox>
#include <QComboBox>
#include <QCheckBox>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QDialog>
#include <QMessageBox>
#include <QTimer>
#include <QFont>
#include <QFrame>
#include <QScrollBar>
#include <QStyle>
#include <QColor>
#include <QSizePolicy>
#include <QAbstractItemView>

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <set>
#include <thread>
#include <vector>

#ifdef _WIN32
  #include <direct.h>
  #define getcwd _getcwd
#else
  #include <unistd.h>
#endif

// ----- value/format helpers -----------------------------------------------
static std::string decodeLiveValue(const std::vector<uint8_t>& data, int interp,
                                   double scale, double offset,
                                   const std::string& unit) {
    if (data.empty()) return "(empty)";
    char buf[96];
    switch (interp) {
        case 1: {  // unsigned big-endian (up to 8 bytes)
            uint64_t v = 0;
            size_t n = data.size() > 8 ? 8 : data.size();
            for (size_t i = 0; i < n; ++i) v = (v << 8) | data[i];
            double eng = (double)v * scale + offset;
            std::snprintf(buf, sizeof buf, "%.3f %s (raw %llu)",
                          eng, unit.c_str(), (unsigned long long)v);
            return buf;
        }
        case 2: {  // signed big-endian
            uint64_t u = 0;
            size_t n = data.size() > 8 ? 8 : data.size();
            for (size_t i = 0; i < n; ++i) u = (u << 8) | data[i];
            int bits = (int)(n * 8);
            int64_t v = (int64_t)u;
            if (bits < 64 && (u & (1ull << (bits - 1))))
                v = (int64_t)(u | (~0ull << bits));
            double eng = (double)v * scale + offset;
            std::snprintf(buf, sizeof buf, "%.3f %s (raw %lld)",
                          eng, unit.c_str(), (long long)v);
            return buf;
        }
        case 3: {  // ASCII
            std::string s;
            for (uint8_t b : data) s.push_back((b >= 0x20 && b <= 0x7E) ? (char)b : '.');
            return s;
        }
        default:
            return toHex(data.data(), data.size());
    }
}

static QLineEdit* hexEdit(const QString& text, int maxLen) {
    auto* e = new QLineEdit(text);
    e->setMaxLength(maxLen);
    e->setMaximumWidth(28 + maxLen * 11);
    return e;
}
static std::vector<uint8_t> parseHexBytes(const std::string& s) {
    std::string h;
    for (char c : s) if (std::isxdigit((unsigned char)c)) h.push_back(c);
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back((uint8_t)std::strtoul(h.substr(i, 2).c_str(), nullptr, 16));
    return out;
}

uint16_t Gui::parseHex16(const QString& s, uint16_t def) {
    QString t = s.trimmed();
    if (t.startsWith("0x", Qt::CaseInsensitive)) t = t.mid(2);
    bool ok = false;
    uint v = t.toUInt(&ok, 16);
    return ok ? (uint16_t)v : def;
}

// ==========================================================================
// Construction
// ==========================================================================
Gui::Gui() {
    for (const auto& d : kVF8Ecus) {
        EcuRow r;
        r.name = std::string(d.code) + " - " + d.name;
        r.logicalAddr = d.placeholderAddr;
        r.altAddr = d.altAddr;
        r.statusMsg = "idle";
        ecus_.push_back(std::move(r));
    }

    buildUi();
    applyStyle();

    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, &Gui::onTick);
    timer_->start(200);

    setWindowTitle("VinFast VF8 - DoIP/UDS Diagnostic Scanner");
    resize(1180, 800);
}

Gui::~Gui() {
    stopLivePoll();
    stopKeepAlive();
    if (worker_.joinable()) worker_.join();
}

// ==========================================================================
// UI construction
// ==========================================================================
void Gui::buildUi() {
    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    root->addWidget(buildHeader());

    auto* body = new QHBoxLayout();
    body->setContentsMargins(0, 0, 0, 0);
    body->setSpacing(0);
    body->addWidget(buildNav());

    pages_ = new QStackedWidget(this);
    pages_->addWidget(buildDashboardPage());   // 0
    pages_->addWidget(buildConnectionPage());  // 1
    pages_->addWidget(buildEcuPage());         // 2
    pages_->addWidget(buildLivePage());        // 3
    pages_->addWidget(buildServicePage());     // 4
    pages_->addWidget(buildProtocolPage());    // 5
    pages_->addWidget(buildCloudPage());       // 6
    pages_->addWidget(buildReferencePage());   // 7
    pages_->addWidget(buildLogPage());         // 8
    body->addWidget(pages_, 1);

    root->addLayout(body, 1);
    setCentralWidget(central);

    connect(nav_, &QListWidget::currentRowChanged,
            pages_, &QStackedWidget::setCurrentIndex);
    nav_->setCurrentRow(0);
}

QWidget* Gui::buildNav() {
    nav_ = new QListWidget(this);
    nav_->setObjectName("nav");
    nav_->setFixedWidth(168);
    nav_->setSpacing(2);
    nav_->setFocusPolicy(Qt::NoFocus);
    const char* items[] = {"Dashboard", "Connection", "ECUs",
                           "Live Data", "Service Disc.", "Protocol",
                           "Cloud", "Reference", "Log"};
    for (const char* s : items) {
        auto* it = new QListWidgetItem(s, nav_);
        it->setSizeHint(QSize(160, 46));
        it->setTextAlignment(Qt::AlignCenter);
    }
    return nav_;
}

QWidget* Gui::buildHeader() {
    auto* hdr = new QFrame(this);
    hdr->setObjectName("header");
    hdr->setFixedHeight(72);
    auto* lay = new QHBoxLayout(hdr);
    lay->setContentsMargins(18, 8, 18, 8);

    auto* title = new QLabel("VinFast VF8");
    title->setObjectName("title");
    auto* vin = new QLabel(QString("VIN %1   ·   %2")
                               .arg(vf8::kVin).arg(vf8::kFirmware));
    vin->setObjectName("subtitle");
    auto* titleCol = new QVBoxLayout();
    titleCol->setSpacing(0);
    titleCol->addWidget(title);
    titleCol->addWidget(vin);
    lay->addLayout(titleCol);

    lay->addStretch(1);

    busyDot_ = new QLabel("●");
    busyDot_->setObjectName("dotIdle");
    busyText_ = new QLabel("Ready");
    lay->addWidget(busyDot_);
    lay->addWidget(busyText_);
    lay->addSpacing(18);

    connDot_ = new QLabel("●");
    connDot_->setObjectName("dotBad");
    connText_ = new QLabel("Disconnected");
    lay->addWidget(connDot_);
    lay->addWidget(connText_);
    lay->addSpacing(14);

    connectBtn_ = new QPushButton("Connect");
    connectBtn_->setObjectName("primary");
    connectBtn_->setMinimumWidth(120);
    lay->addWidget(connectBtn_);
    connect(connectBtn_, &QPushButton::clicked, this, [this] {
        if (client_.isConnected()) {
            stopLivePoll();
            stopKeepAlive();
            client_.disconnect();
            std::lock_guard<std::mutex> g(mutex_);
            connStatus_ = "Disconnected";
            return;
        }
        syncSettingsFromUi();
        startWorker([this] {
            std::string err;
            if (ensureConnected(err)) {
                std::lock_guard<std::mutex> g(mutex_);
                connStatus_ = "Connected to " + gatewayIp_;
            } else {
                Logger::instance().error(err);
                std::lock_guard<std::mutex> g(mutex_);
                connStatus_ = "Connect failed: " + err;
            }
        });
    });

    return hdr;
}

// ----- a reusable card/group ----------------------------------------------
static QGroupBox* card(const QString& title) {
    auto* g = new QGroupBox(title);
    g->setObjectName("card");
    return g;
}

QWidget* Gui::buildDashboardPage() {
    auto* page = new QWidget;
    auto* lay = new QVBoxLayout(page);
    lay->setContentsMargins(18, 18, 18, 18);
    lay->setSpacing(14);

    auto* info = card("Vehicle");
    auto* form = new QFormLayout(info);
    form->addRow("Model",     new QLabel(QString("%1 (%2)").arg(vf8::kModel).arg(vf8::kModelYear)));
    form->addRow("VIN",       new QLabel(vf8::kVin));
    form->addRow("Market",    new QLabel(QString("%1   ·   %2").arg(vf8::kMarket).arg(vf8::kVariant)));
    form->addRow("MHU SW",    new QLabel(vf8::kMhuSoftware));
    form->addRow("TBOX",      new QLabel(vf8::kTboxProject));
    lay->addWidget(info);

    auto* quick = card("Quick actions");
    auto* grid = new QGridLayout(quick);
    grid->setSpacing(10);
    struct QA { const char* label; int page; };
    auto addTile = [&](int r, int c, const QString& text, std::function<void()> fn) {
        auto* b = new QToolButton;
        b->setText(text);
        b->setObjectName("tile");
        b->setMinimumSize(170, 64);
        b->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        connect(b, &QToolButton::clicked, this, fn);
        grid->addWidget(b, r, c);
    };
    addTile(0, 0, "Discover ECUs\n(UDP broadcast)", [this] {
        syncSettingsFromUi();
        startWorker([this] {
            std::vector<doip::Entity> found; std::string err;
            if (client_.discover(broadcastIp_, (uint16_t)port_, 2000, found, err)) {
                std::lock_guard<std::mutex> g(mutex_);
                entities_ = std::move(found);
                Logger::instance().info("Discovery found " +
                    std::to_string(entities_.size()) + " entity(ies)");
            } else Logger::instance().warn("Discovery: " + err);
        });
    });
    addTile(0, 1, "Scan all ECUs\n(read DTCs)", [this] { nav_->setCurrentRow(2); });
    addTile(0, 2, "Live data", [this] { nav_->setCurrentRow(3); });
    addTile(1, 0, "Connection\nsettings", [this] { nav_->setCurrentRow(1); });
    addTile(1, 1, "Service\ndiscovery", [this] { nav_->setCurrentRow(4); });
    addTile(1, 2, "Reference\nscan", [this] { nav_->setCurrentRow(5); });
    lay->addWidget(quick);

    lay->addStretch(1);
    return page;
}

QWidget* Gui::buildConnectionPage() {
    auto* page = new QWidget;
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* inner = new QWidget;
    scroll->setWidget(inner);
    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->addWidget(scroll);

    auto* lay = new QVBoxLayout(inner);
    lay->setContentsMargins(18, 18, 18, 18);
    lay->setSpacing(14);

    // --- transport ---
    auto* net = card("Transport");
    auto* nf = new QFormLayout(net);
    edBroadcast_ = new QLineEdit(QString::fromStdString(broadcastIp_));
    edGateway_   = new QLineEdit(QString::fromStdString(gatewayIp_));
    sbPort_      = new QSpinBox; sbPort_->setRange(1, 65535); sbPort_->setValue(port_);
    edTester_    = hexEdit("0E80", 4);
    edGwAddr_    = hexEdit("1001", 4);
    edActivation_= hexEdit("00", 2);
    nf->addRow("Broadcast IP", edBroadcast_);
    nf->addRow("Gateway IP", edGateway_);
    nf->addRow("Port", sbPort_);
    nf->addRow("Tester source addr", edTester_);
    nf->addRow("Gateway logical addr", edGwAddr_);
    nf->addRow("Routing activation type", edActivation_);
    cbFunctional_ = new QCheckBox("Use functional addressing");
    edFunctional_ = hexEdit("E400", 4);
    auto* fr = new QHBoxLayout; fr->addWidget(cbFunctional_); fr->addWidget(edFunctional_); fr->addStretch(1);
    nf->addRow(fr);
    edStatusMask_ = hexEdit("08", 2);
    nf->addRow("DTC status mask", edStatusMask_);
    lay->addWidget(net);

    // --- session/security ---
    auto* sess = card("Session & Security  (0x10 / 0x27 / 0x3E)");
    auto* sf = new QFormLayout(sess);
    cbSession_ = new QComboBox;
    cbSession_->addItems({"Default (0x01)", "Programming (0x02)",
                          "Extended (0x03)", "SafetySystem (0x04)"});
    cbSession_->setCurrentIndex(2);
    sf->addRow("Session", cbSession_);
    cbAutoExt_ = new QCheckBox("Auto-enter Extended before Clear"); cbAutoExt_->setChecked(true);
    sf->addRow(cbAutoExt_);
    cbKeepAlive_ = new QCheckBox("Keep session alive (background TesterPresent)");
    sf->addRow(cbKeepAlive_);
    connect(cbKeepAlive_, &QCheckBox::toggled, this, [this](bool on) {
        keepAlive_ = on;
        if (on && client_.isConnected()) startKeepAlive();
        if (!on) stopKeepAlive();
    });

    auto* sbtns = new QHBoxLayout;
    auto* enterBtn = new QPushButton("Enter session");
    auto* tpBtn    = new QPushButton("Tester present");
    sbtns->addWidget(enterBtn); sbtns->addWidget(tpBtn); sbtns->addStretch(1);
    sf->addRow(sbtns);

    edSeedLevel_ = hexEdit("01", 2);
    sf->addRow("Seed level (odd sub-func)", edSeedLevel_);
    seedLabel_ = new QLabel("seed: -");
    sf->addRow(seedLabel_);
    edKey_ = new QLineEdit; edKey_->setPlaceholderText("computed key (hex)");
    sf->addRow("Key", edKey_);
    auto* secBtns = new QHBoxLayout;
    auto* seedBtn = new QPushButton("Request seed");
    auto* keyBtn  = new QPushButton("Send key");
    secBtns->addWidget(seedBtn); secBtns->addWidget(keyBtn); secBtns->addStretch(1);
    sf->addRow(secBtns);
    lay->addWidget(sess);

    // --- discovery / sweep ---
    auto* disc = card("ECU Discovery & Address Sweep");
    auto* df = new QVBoxLayout(disc);
    auto* discBtn = new QPushButton("Discover ECUs (UDP broadcast)");
    df->addWidget(discBtn);
    auto* sweepRow = new QHBoxLayout;
    edSweepStart_ = hexEdit("1000", 4);
    edSweepEnd_   = hexEdit("10FF", 4);
    cbSweepAdd_   = new QCheckBox("Add responders as ECU rows"); cbSweepAdd_->setChecked(true);
    auto* sweepBtn = new QPushButton("Run address sweep");
    sweepRow->addWidget(new QLabel("Start")); sweepRow->addWidget(edSweepStart_);
    sweepRow->addWidget(new QLabel("End"));   sweepRow->addWidget(edSweepEnd_);
    sweepRow->addWidget(cbSweepAdd_);
    sweepRow->addStretch(1);
    sweepRow->addWidget(sweepBtn);
    df->addLayout(sweepRow);
    auto* enumRow = new QHBoxLayout;
    edEnumFunc_ = hexEdit("E400", 4);
    auto* enumBtn = new QPushButton("Enumerate ECUs (functional)");
    enumRow->addWidget(new QLabel("Functional addr")); enumRow->addWidget(edEnumFunc_);
    enumRow->addStretch(1);
    enumRow->addWidget(enumBtn);
    df->addLayout(enumRow);
    df->addWidget(new QLabel(
        "<i>A reply (even a negative one) proves an address is routable - the "
        "fastest way to find the real VF8 ECU addresses.</i>"));
    lay->addWidget(disc);

    // --- SOVD backup (REST/HTTP fallback when UDS does not answer) ---
    auto* sovd = card("SOVD Backup  (REST fallback when UDS fails)");
    auto* svf = new QFormLayout(sovd);
    edSovdUrl_ = new QLineEdit(QString::fromStdString(sovdBaseUrl_));
    edSovdUrl_->setPlaceholderText("http://host:13401/vehicle/v1  (blank = disabled)");
    edSovdToken_ = new QLineEdit(QString::fromStdString(sovdToken_));
    edSovdToken_->setPlaceholderText("OAuth2 bearer token (optional)");
    edSovdToken_->setEchoMode(QLineEdit::Password);
    svf->addRow("SOVD base URL", edSovdUrl_);
    svf->addRow("Bearer token", edSovdToken_);
    svf->addRow(new QLabel(
        "<i>When an ECU does not respond to UDS/DoIP, Probe falls back to this "
        "SOVD endpoint and marks the module reachable if its component is "
        "listed.</i>"));
    lay->addWidget(sovd);

    lay->addStretch(1);

    // ---- wiring ----
    connect(enterBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        int s = sessionType_;
        startWorker([this, s] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            if (uds.diagnosticSessionControl((uint16_t)gatewayAddr_, (UdsSession)s, err))
                Logger::instance().info("Session 0x" + byteHex((uint8_t)s) + " active");
            else Logger::instance().error("SessionControl: " + err);
        });
    });
    connect(tpBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        startWorker([this] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            uint16_t tgt = useFunctional_ ? (uint16_t)functionalAddr_
                                          : (ecus_.empty() ? (uint16_t)gatewayAddr_
                                                           : ecus_.front().logicalAddr);
            if (uds.testerPresent(tgt, err)) Logger::instance().info("TesterPresent OK");
            else Logger::instance().error("TesterPresent: " + err);
        });
    });
    connect(seedBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        int lvl = securityLevel_;
        startWorker([this, lvl] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            auto seed = uds.requestSeed((uint16_t)gatewayAddr_, (uint8_t)lvl, err);
            std::lock_guard<std::mutex> g(mutex_);
            if (seed) {
                lastSeedHex_ = seed->empty() ? "(already unlocked)"
                                             : toHex(seed->data(), seed->size());
                Logger::instance().info("Seed: " + lastSeedHex_);
            } else { lastSeedHex_ = "request failed: " + err; Logger::instance().error(err); }
        });
    });
    connect(keyBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        int lvl = securityLevel_;
        std::string keyhex = securityKeyHex_;
        startWorker([this, lvl, keyhex] {
            auto key = parseHexBytes(keyhex);
            if (key.empty()) { Logger::instance().error("Key is empty/invalid hex"); return; }
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            if (uds.sendKey((uint16_t)gatewayAddr_, (uint8_t)lvl, key, err))
                Logger::instance().info("Security unlocked (level 0x" + byteHex((uint8_t)lvl) + ")");
            else Logger::instance().error("SendKey: " + err);
        });
    });
    connect(discBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        startWorker([this] {
            std::vector<doip::Entity> found; std::string err;
            if (client_.discover(broadcastIp_, (uint16_t)port_, 2000, found, err)) {
                std::lock_guard<std::mutex> g(mutex_);
                entities_ = std::move(found);
                Logger::instance().info("Discovery found " +
                    std::to_string(entities_.size()) + " entity(ies)");
            } else Logger::instance().warn("Discovery: " + err);
        });
    });
    connect(sweepBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        int start = sweepStart_, end = sweepEnd_; bool add = sweepAddDiscovered_;
        if (end - start + 1 < 1 || end - start + 1 > 4096) {
            Logger::instance().warn("Sweep range must be 1..4096 addresses");
            return;
        }
        startWorker([this, start, end, add] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            int found = 0;
            for (int a = start; a <= end && client_.isConnected(); ++a) {
                std::string e;
                if (uds.probe((uint16_t)a, e)) {
                    ++found;
                    Logger::instance().info("Address 0x" + byteHex((a >> 8) & 0xFF) +
                                            byteHex(a & 0xFF) + " responded");
                    if (add) {
                        std::lock_guard<std::mutex> g(mutex_);
                        bool exists = false;
                        for (auto& r : ecus_)
                            if (r.logicalAddr == (uint16_t)a) { exists = true; r.reachable = 1; break; }
                        if (!exists) {
                            EcuRow r; char nm[32];
                            std::snprintf(nm, sizeof nm, "Discovered 0x%04X", a);
                            r.name = nm; r.logicalAddr = (uint16_t)a;
                            r.statusMsg = "reachable (swept)"; r.reachable = 1;
                            ecus_.push_back(std::move(r));
                        }
                    }
                }
            }
            Logger::instance().info("Sweep complete: " + std::to_string(found) +
                                    " address(es) responded");
        });
    });

    connect(enumBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        uint16_t funcAddr = parseHex16(edEnumFunc_->text(), 0xE400);
        bool add = cbSweepAdd_->isChecked();
        startWorker([this, funcAddr, add] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::vector<uint16_t> found;
            if (!uds.enumerateEcus(funcAddr, found, err)) {
                Logger::instance().warn("Functional enumeration: " + err);
                return;
            }
            if (add) {
                std::lock_guard<std::mutex> g(mutex_);
                for (uint16_t a : found) {
                    bool exists = false;
                    for (auto& r : ecus_)
                        if (r.logicalAddr == a) { exists = true; r.reachable = 1; break; }
                    if (!exists) {
                        EcuRow r; char nm[32];
                        std::snprintf(nm, sizeof nm, "Discovered 0x%04X", a);
                        r.name = nm; r.logicalAddr = a;
                        r.statusMsg = "reachable (functional)"; r.reachable = 1;
                        ecus_.push_back(std::move(r));
                    }
                }
            }
        });
    });

    return page;
}

QWidget* Gui::buildEcuPage() {
    auto* page = new QWidget;
    auto* lay = new QVBoxLayout(page);
    lay->setContentsMargins(18, 18, 18, 18);
    lay->setSpacing(12);

    auto* toolbar = new QHBoxLayout;
    auto* scanBtn  = new QPushButton("Scan all (read DTCs)");
    auto* probeBtn = new QPushButton("Probe addresses");
    auto* clearBtn = new QPushButton("Clear DTCs on ALL"); clearBtn->setObjectName("danger");
    auto* addBtn   = new QPushButton("Add ECU");
    toolbar->addWidget(scanBtn);
    toolbar->addWidget(probeBtn);
    toolbar->addWidget(clearBtn);
    toolbar->addStretch(1);
    toolbar->addWidget(addBtn);
    lay->addLayout(toolbar);

    lay->addWidget(new QLabel(
        "<i>Tap an ECU to open its diagnostics. Addresses are placeholders - "
        "edit them in the popup to match the VF8 routing.</i>"));
    lay->addWidget(new QLabel(
        "<span style='color:#43d17a'>● connected</span> &nbsp;&nbsp; "
        "<span style='color:#e0556a'>○ no response</span> &nbsp;&nbsp; "
        "<span style='color:#9fb0c0'>· not probed</span> &nbsp;&nbsp; "
        "<span style='color:#f2b134'>●N = DTC count</span> &nbsp;&nbsp; "
        "<i>run \"Probe addresses\" to test connectivity.</i>"));

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    ecuTileHost_ = new QWidget;
    ecuTileGrid_ = new QGridLayout(ecuTileHost_);
    ecuTileGrid_->setSpacing(10);
    ecuTileGrid_->setContentsMargins(0, 0, 0, 0);
    scroll->setWidget(ecuTileHost_);
    lay->addWidget(scroll, 1);

    connect(scanBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        uint8_t mask = (uint8_t)statusMask_;
        bool functional = useFunctional_; uint16_t funcAddr = (uint16_t)functionalAddr_;
        startWorker([this, mask, functional, funcAddr] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            size_t count; { std::lock_guard<std::mutex> g(mutex_); count = ecus_.size(); }
            for (size_t i = 0; i < count; ++i) {
                uint16_t addr; { std::lock_guard<std::mutex> g(mutex_); addr = ecus_[i].logicalAddr; }
                uint16_t target = functional ? funcAddr : addr;
                std::vector<Dtc> dtcs; std::string e;
                if (uds.readDTCByStatusMask(target, mask, dtcs, e)) {
                    std::lock_guard<std::mutex> g(mutex_);
                    ecus_[i].dtcs = std::move(dtcs);
                    ecus_[i].statusMsg = "read OK (" + std::to_string(ecus_[i].dtcs.size()) + " DTC)";
                } else { std::lock_guard<std::mutex> g(mutex_); ecus_[i].statusMsg = "read failed: " + e; }
            }
            Logger::instance().info("Scan All complete");
        });
    });
    connect(probeBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        startWorker([this] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            size_t count; { std::lock_guard<std::mutex> g(mutex_); count = ecus_.size(); }
            int reachable = 0;
            for (size_t i = 0; i < count; ++i) {
                uint16_t addr, alt; std::string name, sovdId;
                { std::lock_guard<std::mutex> g(mutex_);
                  addr = ecus_[i].logicalAddr; alt = ecus_[i].altAddr;
                  name = ecus_[i].name; sovdId = ecus_[i].sovdId; }
                std::string e; bool ok = uds.probe(addr, e);
                if (!ok && alt != 0 && alt != addr) {
                    std::string e2;
                    if (uds.probe(alt, e2)) {
                        std::lock_guard<std::mutex> g(mutex_);
                        ecus_[i].logicalAddr = alt;   // adopt the working alternative address
                        ecus_[i].reachable = 1;
                        char buf[48];
                        std::snprintf(buf, sizeof buf, "reachable via alt 0x%04X", alt);
                        ecus_[i].statusMsg = buf;
                        ++reachable;
                        continue;
                    }
                }
                if (!ok && sovd_.configured()) {
                    std::string cid = sovdId.empty() ? deriveSovdId(name) : sovdId;
                    std::string detail;
                    if (sovdProbe(cid, detail)) {
                        std::lock_guard<std::mutex> g(mutex_);
                        ecus_[i].reachable = 1;
                        ecus_[i].sovdId = cid;            // remember the working component id
                        ecus_[i].statusMsg = "reachable " + detail;  // "reachable via SOVD (...)"
                        ++reachable;
                        Logger::instance().info(name + ": UDS silent, reachable over SOVD backup (" + cid + ")");
                        continue;
                    }
                }
                std::lock_guard<std::mutex> g(mutex_);
                ecus_[i].reachable = ok ? 1 : 0;
                ecus_[i].statusMsg = ok ? "reachable" : ("no response: " + e);
                if (ok) ++reachable;
            }
            Logger::instance().info("Probe complete: " + std::to_string(reachable) +
                                    "/" + std::to_string(count) + " replied");
        });
    });
    connect(clearBtn, &QPushButton::clicked, this, [this, clearBtn] {
        if (!confirmPopup(clearBtn, "Clear DTCs on ALL ECUs",
                "This erases stored fault history on EVERY module in the list. "
                "Record the codes first. Proceed?", "Yes, clear ALL"))
            return;
        syncSettingsFromUi();
        bool autoExt = autoExtendedOnClear_, functional = useFunctional_;
        uint16_t funcAddr = (uint16_t)functionalAddr_;
        startWorker([this, autoExt, functional, funcAddr] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            size_t count; { std::lock_guard<std::mutex> g(mutex_); count = ecus_.size(); }
            int cleared = 0;
            for (size_t i = 0; i < count; ++i) {
                uint16_t addr; { std::lock_guard<std::mutex> g(mutex_); addr = ecus_[i].logicalAddr; }
                uint16_t target = functional ? funcAddr : addr;
                if (autoExt) { std::string se; uds.diagnosticSessionControl(target, UdsSession::Extended, se); }
                std::string e; bool ok = uds.clearDiagnosticInformation(target, 0xFFFFFFu, e);
                std::lock_guard<std::mutex> g(mutex_);
                if (ok) { ecus_[i].dtcs.clear(); ecus_[i].statusMsg = "DTCs cleared"; ++cleared; }
                else ecus_[i].statusMsg = "clear failed: " + e;
                if (functional) break;
            }
            Logger::instance().info("Clear All complete: " + std::to_string(cleared) +
                (functional ? " (functional broadcast)" : ("/" + std::to_string(count))));
        });
    });
    connect(addBtn, &QPushButton::clicked, this, [this] {
        std::lock_guard<std::mutex> g(mutex_);
        EcuRow r; r.name = "New ECU"; r.logicalAddr = 0x1000; r.statusMsg = "idle";
        ecus_.push_back(std::move(r));
    });

    return page;
}

QWidget* Gui::buildLivePage() {
    auto* page = new QWidget;
    auto* lay = new QVBoxLayout(page);
    lay->setContentsMargins(18, 18, 18, 18);
    lay->setSpacing(12);

    auto* bar = new QHBoxLayout;
    livePollBtn_ = new QPushButton("Start polling"); livePollBtn_->setObjectName("primary");
    auto* interval = new QSpinBox; interval->setRange(50, 10000); interval->setSingleStep(50);
    interval->setValue(livePollMs_); interval->setSuffix(" ms");
    auto* addSig = new QPushButton("Add signal");
    auto* rmSig  = new QPushButton("Remove selected");
    cbLiveBundle_ = new QCheckBox("Bundle (0x2C)");
    cbLiveBundle_->setToolTip(
        "Define one dynamic DID (0x2C) covering every signal on each ECU and "
        "read the whole bundle with a single 0x22 per cycle, instead of one "
        "request per signal. Falls back to per-signal reads if unsupported.");
    cbLiveBundle_->setChecked(liveBundle_);
    bar->addWidget(livePollBtn_);
    bar->addWidget(new QLabel("Interval"));
    bar->addWidget(interval);
    bar->addWidget(cbLiveBundle_);
    bar->addStretch(1);
    bar->addWidget(addSig);
    bar->addWidget(rmSig);
    lay->addLayout(bar);

    liveTable_ = new QTableWidget(0, 5);
    liveTable_->setHorizontalHeaderLabels({"", "Name", "Tgt/DID", "Value", "Raw"});
    liveTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    liveTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    liveTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    liveTable_->setColumnWidth(0, 26);
    liveTable_->setColumnWidth(2, 100);
    liveTable_->verticalHeader()->setVisible(false);
    liveTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    liveTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    lay->addWidget(liveTable_, 1);

    connect(interval, qOverload<int>(&QSpinBox::valueChanged), this,
            [this](int v) { livePollMs_ = v; });
    connect(cbLiveBundle_, &QCheckBox::toggled, this, [this](bool on) { liveBundle_ = on; });
    connect(livePollBtn_, &QPushButton::clicked, this, [this] {
        if (liveRun_.load()) { stopLivePoll(); return; }
        syncSettingsFromUi();
        startWorker([this] {
            std::string e;
            if (!ensureConnected(e)) { Logger::instance().error(e); return; }
            startLivePoll();
        });
    });
    connect(addSig, &QPushButton::clicked, this, [this, addSig] { openAddSignalDialog(addSig); });
    connect(rmSig, &QPushButton::clicked, this, [this] {
        int row = liveTable_->currentRow();
        std::lock_guard<std::mutex> g(mutex_);
        if (row >= 0 && row < (int)liveSignals_.size())
            liveSignals_.erase(liveSignals_.begin() + row);
    });

    return page;
}

QWidget* Gui::buildServicePage() {
    auto* page = new QWidget;
    auto* lay = new QVBoxLayout(page);
    lay->setContentsMargins(18, 18, 18, 18);
    lay->setSpacing(12);

    lay->addWidget(new QLabel(
        "<b>Safe service enumerator.</b> Finds which DIDs / routines / I/O "
        "channels an ECU implements <i>without executing anything</i> - only "
        "read-only or restorative sub-functions are sent (0x22 read, 0x31 0x03 "
        "request-results, 0x2F 0x00 return-control)."));

    auto* cfg = card("Scan");
    auto* f = new QFormLayout(cfg);
    edSvcTarget_ = hexEdit("1003", 4);
    edSvcStart_  = hexEdit("0000", 4);
    edSvcEnd_    = hexEdit("00FF", 4);
    auto* tr = new QHBoxLayout;
    tr->addWidget(new QLabel("Target")); tr->addWidget(edSvcTarget_);
    tr->addWidget(new QLabel("Start"));  tr->addWidget(edSvcStart_);
    tr->addWidget(new QLabel("End"));    tr->addWidget(edSvcEnd_);
    tr->addStretch(1);
    f->addRow(tr);
    cbSvcDIDs_ = new QCheckBox("DIDs (0x22)"); cbSvcDIDs_->setChecked(true);
    cbSvcRoutines_ = new QCheckBox("Routines (0x31)"); cbSvcRoutines_->setChecked(true);
    cbSvcIO_ = new QCheckBox("I/O (0x2F)");
    auto* cr = new QHBoxLayout;
    cr->addWidget(cbSvcDIDs_); cr->addWidget(cbSvcRoutines_); cr->addWidget(cbSvcIO_); cr->addStretch(1);
    f->addRow("Categories", cr);
    cbSvcExt_ = new QCheckBox("Enter Extended session"); cbSvcExt_->setChecked(true);
    cbSvcSuspend_ = new QCheckBox("Suspend DTC logging during scan (0x85)"); cbSvcSuspend_->setChecked(true);
    cbSvcRestore_ = new QCheckBox("Restore safe state when finished"); cbSvcRestore_->setChecked(true);
    f->addRow("Fail-safes", cbSvcExt_);
    f->addRow("", cbSvcSuspend_);
    f->addRow("", cbSvcRestore_);
    auto* btns = new QHBoxLayout;
    auto* runBtn = new QPushButton("Run service discovery"); runBtn->setObjectName("primary");
    auto* restoreBtn = new QPushButton("Restore safe state");
    auto* clearBtn = new QPushButton("Clear results");
    btns->addWidget(runBtn); btns->addWidget(restoreBtn); btns->addWidget(clearBtn); btns->addStretch(1);
    f->addRow(btns);
    lay->addWidget(cfg);

    svcTable_ = new QTableWidget(0, 4);
    svcTable_->setHorizontalHeaderLabels({"Service", "ID", "", "Reply / note"});
    svcTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    svcTable_->setColumnWidth(0, 110);
    svcTable_->setColumnWidth(1, 60);
    svcTable_->setColumnWidth(2, 50);
    svcTable_->verticalHeader()->setVisible(false);
    svcTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    lay->addWidget(svcTable_, 1);

    connect(runBtn, &QPushButton::clicked, this, [this, runBtn] {
        syncSettingsFromUi();
        int span = svcEnd_ - svcStart_ + 1;
        int cats = (svcScanDIDs_?1:0)+(svcScanRoutines_?1:0)+(svcScanIO_?1:0);
        if (span < 1 || span > 4096 || cats == 0) {
            Logger::instance().warn("Service scan: pick at least one category and a 1..4096 range");
            return;
        }
        if (!confirmPopup(runBtn, "Run service discovery",
                QString("Actively probe ECU 0x%1 over 0x%2-0x%3 using only "
                        "read-only/restorative requests. No routine is started "
                        "and no actuator is seized. Proceed?")
                    .arg(svcTarget_, 4, 16, QChar('0'))
                    .arg(svcStart_, 4, 16, QChar('0'))
                    .arg(svcEnd_, 4, 16, QChar('0')),
                "Yes, run"))
            return;
        uint16_t tgt = (uint16_t)svcTarget_;
        int start = svcStart_, end = svcEnd_;
        bool dids = svcScanDIDs_, routines = svcScanRoutines_, io = svcScanIO_;
        bool ext = svcExtendedSess_, susp = svcSuspendDTC_, restore = svcRestoreAfter_;
        startWorker([this, tgt, start, end, dids, routines, io, ext, susp, restore] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::string e;
            if (ext)  uds.diagnosticSessionControl(tgt, UdsSession::Extended, e);
            if (susp) uds.controlDTCSetting(tgt, false, e);
            std::vector<uint16_t> touchedIo;
            auto record = [this](uint8_t svc, uint16_t id, int ex, const std::string& note) {
                std::lock_guard<std::mutex> g(mutex_);
                svcResults_.push_back({svc, id, ex, note});
            };
            int found = 0;
            for (int id = start; id <= end && client_.isConnected(); ++id) {
                std::vector<uint8_t> resp; std::string le;
                if (dids) { int r = uds.probeDID(tgt, (uint16_t)id, resp, le);
                    if (r >= 0) { record(0x22, (uint16_t)id, r,
                        r==1?toHex(resp.data(),resp.size()):("exists ("+le+")")); ++found; } }
                if (routines) { int r = uds.probeRoutine(tgt, (uint16_t)id, resp, le);
                    if (r >= 0) { record(0x31, (uint16_t)id, r,
                        r==1?toHex(resp.data(),resp.size()):("exists ("+le+")")); ++found; } }
                if (io) { int r = uds.probeIOControl(tgt, (uint16_t)id, resp, le);
                    if (r >= 0) { record(0x2F, (uint16_t)id, r,
                        r==1?toHex(resp.data(),resp.size()):("exists ("+le+")"));
                        touchedIo.push_back((uint16_t)id); ++found; } }
            }
            if (restore) { std::string summary; uds.restoreSafeState(tgt, touchedIo, summary); }
            else if (susp) { uds.controlDTCSetting(tgt, true, e); }
            Logger::instance().info("Service discovery complete: " + std::to_string(found) +
                " identifier(s) on 0x" + byteHex((tgt>>8)&0xFF) + byteHex(tgt&0xFF));
        });
    });
    connect(restoreBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        uint16_t tgt = (uint16_t)svcTarget_;
        std::vector<uint16_t> touched;
        { std::lock_guard<std::mutex> g(mutex_);
          for (auto& s : svcResults_) if (s.service == 0x2F) touched.push_back(s.id); }
        startWorker([this, tgt, touched] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::string summary; uds.restoreSafeState(tgt, touched, summary);
        });
    });
    connect(clearBtn, &QPushButton::clicked, this, [this] {
        std::lock_guard<std::mutex> g(mutex_); svcResults_.clear();
    });

    return page;
}

// ==========================================================================
// Protocol / advanced page - standard DoIP & UDS services for
// diagnostics and programming. Read-only DoIP checks run freely; UDS
// operations that can change ECU state are gated behind confirmations.
// ==========================================================================
void Gui::protoLine(const std::string& s) {
    std::lock_guard<std::mutex> g(mutex_);
    protoLog_ += s;
    protoLog_ += "\n";
    ++protoLogRev_;
}

void Gui::refreshProtocol() {
    std::string snapshot;
    size_t rev;
    { std::lock_guard<std::mutex> g(mutex_); snapshot = protoLog_; rev = protoLogRev_; }
    if (rev == protoViewRev_) return;
    protoViewRev_ = rev;
    if (protoView_) {
        protoView_->setPlainText(QString::fromStdString(snapshot));
        protoView_->verticalScrollBar()->setValue(
            protoView_->verticalScrollBar()->maximum());
    }
}

QWidget* Gui::buildProtocolPage() {
    auto* page = new QWidget;
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* inner = new QWidget;
    scroll->setWidget(inner);
    auto* pageLay = new QVBoxLayout(page);
    pageLay->setContentsMargins(0, 0, 0, 0);
    pageLay->addWidget(scroll);

    auto* outer = new QVBoxLayout(inner);
    outer->setContentsMargins(18, 18, 18, 18);
    outer->setSpacing(12);

    auto* intro = new QLabel(
        "<b>Protocol toolbox.</b> Standard ISO 13400 (DoIP) and ISO 14229 (UDS) "
        "services for diagnostics and programming. DoIP status checks are "
        "read-only; UDS writes/routines change ECU state and ask to confirm.");
    intro->setWordWrap(true);
    outer->addWidget(intro);

    auto* row = new QHBoxLayout;
    row->setSpacing(12);

    // ---- DoIP entity checks (left column) ----
    auto* doipCard = card("DoIP entity (UDP, read-only)");
    auto* dl = new QVBoxLayout(doipCard);
    auto* doipNote = new QLabel(
        "Queries the gateway over UDP - no diagnostic session needed.");
    doipNote->setWordWrap(true);
    dl->addWidget(doipNote);
    auto* db = new QHBoxLayout;
    auto* statusBtn = new QPushButton("Entity status (0x4001)");
    auto* powerBtn  = new QPushButton("Power mode (0x4003)");
    db->addWidget(statusBtn); db->addWidget(powerBtn); db->addStretch(1);
    dl->addLayout(db);
    dl->addStretch(1);
    row->addWidget(doipCard, 1);

    // ---- target for UDS operations (right column) ----
    auto* tgtCard = card("UDS target");
    auto* tf = new QFormLayout(tgtCard);
    edProtoTarget_ = hexEdit("1003", 4);
    tf->addRow("ECU logical addr", edProtoTarget_);
    auto* tgtNote = new QLabel("Applies to every UDS action below.");
    tgtNote->setWordWrap(true);
    tf->addRow(tgtNote);
    row->addWidget(tgtCard, 1);
    outer->addLayout(row);

    // ---- UDS read services ----
    auto* readCard = card("UDS read (ISO 14229)");
    auto* rl = new QFormLayout(readCard);
    edProtoMemAddr_ = hexEdit("00000000", 8);
    sbProtoMemSize_ = new QSpinBox; sbProtoMemSize_->setRange(1, 4096); sbProtoMemSize_->setValue(16);
    sbProtoAddrBytes_ = new QSpinBox; sbProtoAddrBytes_->setRange(1, 4); sbProtoAddrBytes_->setValue(4);
    sbProtoSizeBytes_ = new QSpinBox; sbProtoSizeBytes_->setRange(1, 4); sbProtoSizeBytes_->setValue(1);
    auto* memRow = new QHBoxLayout;
    memRow->addWidget(new QLabel("Addr")); memRow->addWidget(edProtoMemAddr_);
    memRow->addWidget(new QLabel("Size")); memRow->addWidget(sbProtoMemSize_);
    memRow->addWidget(new QLabel("addrB")); memRow->addWidget(sbProtoAddrBytes_);
    memRow->addWidget(new QLabel("sizeB")); memRow->addWidget(sbProtoSizeBytes_);
    auto* memBtn = new QPushButton("Read memory (0x23)");
    memRow->addWidget(memBtn); memRow->addStretch(1);
    rl->addRow("ReadMemoryByAddress", memRow);

    edProtoDtc_    = hexEdit("000000", 6);
    edProtoDtcRec_ = hexEdit("FF", 2);
    auto* extRow = new QHBoxLayout;
    extRow->addWidget(new QLabel("DTC")); extRow->addWidget(edProtoDtc_);
    extRow->addWidget(new QLabel("Record")); extRow->addWidget(edProtoDtcRec_);
    auto* extBtn = new QPushButton("Extended data (0x19 06)");
    auto* fdcBtn = new QPushButton("Fault counters (0x19 14)");
    extRow->addWidget(extBtn); extRow->addWidget(fdcBtn); extRow->addStretch(1);
    rl->addRow("DTC detail", extRow);

    auto* idRow = new QHBoxLayout;
    auto* idBtn  = new QPushButton("Read standard ID block (ISO 14229 F1xx)");
    auto* obdBtn = new QPushButton("OBD-II VIN (mode 09)");
    idRow->addWidget(idBtn); idRow->addWidget(obdBtn); idRow->addStretch(1);
    rl->addRow("Standard identifiers", idRow);
    outer->addWidget(readCard);

    // ---- UDS write / control services ----
    auto* wrCard = card("UDS write / control (confirm required)");
    auto* wl = new QFormLayout(wrCard);

    edProtoWriteDid_  = hexEdit("F190", 4);
    edProtoWriteData_ = new QLineEdit; edProtoWriteData_->setPlaceholderText("hex bytes, e.g. 01 02 AB");
    auto* wrRow = new QHBoxLayout;
    wrRow->addWidget(new QLabel("DID")); wrRow->addWidget(edProtoWriteDid_);
    wrRow->addWidget(edProtoWriteData_, 1);
    auto* wrBtn = new QPushButton("Write (0x2E)");
    wrRow->addWidget(wrBtn);
    wl->addRow("WriteDataByIdentifier", wrRow);

    edProtoRid_       = hexEdit("0203", 4);
    edProtoRidParams_ = new QLineEdit; edProtoRidParams_->setPlaceholderText("optional hex params");
    cbProtoRoutine_   = new QComboBox; cbProtoRoutine_->addItems({"Start (01)", "Stop (02)", "Results (03)"});
    auto* rcRow = new QHBoxLayout;
    rcRow->addWidget(new QLabel("RID")); rcRow->addWidget(edProtoRid_);
    rcRow->addWidget(cbProtoRoutine_);
    rcRow->addWidget(edProtoRidParams_, 1);
    auto* rcBtn = new QPushButton("Run (0x31)");
    rcRow->addWidget(rcBtn);
    wl->addRow("RoutineControl", rcRow);

    cbProtoComm_     = new QComboBox;
    cbProtoComm_->addItems({"Enable Rx+Tx (00)", "Enable Rx, disable Tx (01)",
                            "Disable Rx, enable Tx (02)", "Disable Rx+Tx (03)"});
    edProtoCommType_ = hexEdit("01", 2);
    auto* ccRow = new QHBoxLayout;
    ccRow->addWidget(cbProtoComm_);
    ccRow->addWidget(new QLabel("commType")); ccRow->addWidget(edProtoCommType_);
    auto* ccBtn = new QPushButton("Apply (0x28)");
    ccRow->addWidget(ccBtn); ccRow->addStretch(1);
    wl->addRow("CommunicationControl", ccRow);
    outer->addWidget(wrCard);

    // ---- BMS crash-data / HV-lockout reset -------------------------------
    auto* crashCard = card("BMS crash data / HV-lockout reset (post-collision)");
    auto* xl = new QVBoxLayout(crashCard);
    auto* crashIntro = new QLabel(
        "After an airbag/collision event the BMS latches a crash record and "
        "opens the HV contactors (lockout). Dealers clear it over OBD-II to "
        "restore the pack. This runs the standard sequence: Extended session "
        "-> optional SecurityAccess -> RoutineControl start (crash-reset RID) "
        "-> ClearDiagnosticInformation -> read-back. ONLY do this once the "
        "vehicle and HV system have been inspected and confirmed safe.");
    crashIntro->setWordWrap(true);
    xl->addWidget(crashIntro);
    edCrashTarget_   = hexEdit("1003", 4);
    edCrashSecLevel_ = hexEdit("09", 2);
    edCrashKey_      = new QLineEdit; edCrashKey_->setPlaceholderText("key hex for current seed (blank = skip security)");
    edCrashRid_      = hexEdit("FF01", 4);
    edCrashDtc_      = hexEdit("FFFFFF", 6);
    auto* xform = new QFormLayout;
    xform->setLabelAlignment(Qt::AlignRight);
    auto* xr1 = new QHBoxLayout;
    xr1->addWidget(new QLabel("BMS addr")); xr1->addWidget(edCrashTarget_);
    xr1->addSpacing(12);
    xr1->addWidget(new QLabel("Sec level")); xr1->addWidget(edCrashSecLevel_);
    xr1->addSpacing(12);
    xr1->addWidget(new QLabel("Crash RID")); xr1->addWidget(edCrashRid_);
    xr1->addSpacing(12);
    xr1->addWidget(new QLabel("DTC/group")); xr1->addWidget(edCrashDtc_);
    xr1->addStretch(1);
    xform->addRow("Parameters", xr1);
    edCrashKey_->setMinimumWidth(320);
    xform->addRow("Security key", edCrashKey_);
    xl->addLayout(xform);
    auto* xr2 = new QHBoxLayout;
    auto* crashSeedBtn  = new QPushButton("Request seed (0x27)");
    auto* crashResetBtn = new QPushButton("Clear crash data"); crashResetBtn->setObjectName("primary");
    xr2->addWidget(crashSeedBtn); xr2->addWidget(crashResetBtn); xr2->addStretch(1);
    xl->addLayout(xr2);
    outer->addWidget(crashCard);

    // ---- Periodic / dynamic data (0x2A / 0x2C) -------------------------
    auto* dynCard = card("Periodic & dynamic data (0x2A / 0x2C)");
    auto* dyl = new QVBoxLayout(dynCard);
    auto* dynIntro = new QLabel(
        "ReadDataByPeriodicIdentifier (0x2A) asks the ECU to push a DID on a "
        "schedule; DynamicallyDefineDataIdentifier (0x2C) packs several source "
        "DIDs into one identifier you can read with a single 0x22. The live "
        "page uses 0x2C automatically when \"Bundle\" is ticked.");
    dynIntro->setWordWrap(true);
    dyl->addWidget(dynIntro);

    cbProtoPeriodicMode_ = new QComboBox;
    cbProtoPeriodicMode_->addItems({"Slow (01)", "Medium (02)", "Fast (03)", "Stop (04)"});
    edProtoPdid_ = new QLineEdit; edProtoPdid_->setPlaceholderText("periodic DIDs, e.g. 90 91");
    edProtoPdid_->setText("90");
    auto* perRow = new QHBoxLayout;
    perRow->addWidget(new QLabel("Mode")); perRow->addWidget(cbProtoPeriodicMode_);
    perRow->addWidget(new QLabel("PDID(s)")); perRow->addWidget(edProtoPdid_, 1);
    auto* perBtn = new QPushButton("Schedule (0x2A)");
    perRow->addWidget(perBtn);
    dyl->addLayout(perRow);

    edProtoDddid_  = hexEdit("F300", 4);
    edProtoDddSrc_ = new QLineEdit;
    edProtoDddSrc_->setPlaceholderText("sources: DID:pos:size, e.g. F190:1:3 F195:1:2");
    edProtoDddSrc_->setText("F190:1:3 F195:1:2");
    auto* dddRow = new QHBoxLayout;
    dddRow->addWidget(new QLabel("DDDID")); dddRow->addWidget(edProtoDddid_);
    dddRow->addWidget(edProtoDddSrc_, 1);
    auto* defBtn  = new QPushButton("Define (0x2C 01)");
    auto* rdBtn   = new QPushButton("Read (0x22)");
    auto* clrBtn  = new QPushButton("Clear (0x2C 03)");
    dddRow->addWidget(defBtn); dddRow->addWidget(rdBtn); dddRow->addWidget(clrBtn);
    dyl->addLayout(dddRow);
    outer->addWidget(dynCard);

    protoView_ = new QPlainTextEdit;
    protoView_->setReadOnly(true);
    protoView_->setMaximumHeight(150);
    protoView_->setPlaceholderText("Results appear here (full hex also in the Log page).");
    outer->addWidget(protoView_, 1);

    // ---------------- handlers ----------------
    connect(statusBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        std::string ip = gatewayIp_; int port = port_;
        startWorker([this, ip, port] {
            doip::EntityStatus st; std::string err;
            if (client_.entityStatus(ip, port, 2000, st, err)) {
                protoLine("Entity status from " + st.ip + ": " +
                    std::string(st.nodeType == 0 ? "gateway" : "node") +
                    ", sockets " + std::to_string(st.openSockets) + "/" +
                    std::to_string(st.maxOpenSockets) +
                    (st.hasMaxDataSize ? ", maxData " + std::to_string(st.maxDataSize) + "B" : ""));
            } else protoLine("Entity status: " + err);
        });
    });
    connect(powerBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        std::string ip = gatewayIp_; int port = port_;
        startWorker([this, ip, port] {
            uint8_t mode = 0; std::string err;
            if (client_.diagnosticPowerMode(ip, port, 2000, mode, err)) {
                const char* t = mode == 0 ? "NOT ready" : mode == 1 ? "ready"
                               : mode == 2 ? "not supported" : "reserved";
                protoLine(std::string("Diagnostic power mode: 0x") +
                    QString::number(mode, 16).toStdString() + " (" + t + ")");
            } else protoLine("Power mode: " + err);
        });
    });
    connect(memBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint32_t addr = (uint32_t)edProtoMemAddr_->text().toULong(nullptr, 16);
        uint32_t size = (uint32_t)sbProtoMemSize_->value();
        uint8_t ab = (uint8_t)sbProtoAddrBytes_->value();
        uint8_t sb = (uint8_t)sbProtoSizeBytes_->value();
        startWorker([this, tgt, addr, size, ab, sb] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("ReadMemory: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.readMemoryByAddress(tgt, addr, size, ab, sb, out, err))
                protoLine("ReadMemory 0x" + byteHex((tgt>>8)&0xFF) + byteHex(tgt&0xFF) +
                          ": " + toHex(out.data(), out.size()));
            else protoLine("ReadMemory: " + err);
        });
    });
    connect(extBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint32_t dtc = (uint32_t)edProtoDtc_->text().toULong(nullptr, 16);
        uint8_t rec = (uint8_t)parseHex16(edProtoDtcRec_->text(), 0xFF);
        startWorker([this, tgt, dtc, rec] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("DTC extended: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::vector<uint8_t> raw;
            if (uds.readDTCExtendedData(tgt, dtc, rec, raw, err))
                protoLine("DTC extended " + decodeDtc(dtc) + ": " + toHex(raw.data(), raw.size()));
            else protoLine("DTC extended: " + err);
        });
    });
    connect(fdcBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        startWorker([this, tgt] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Fault counters: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::vector<Dtc> dtcs;
            if (uds.readDTCFaultDetectionCounter(tgt, dtcs, err)) {
                protoLine("Fault detection counters: " + std::to_string(dtcs.size()) + " DTC(s)");
                for (auto& d : dtcs)
                    protoLine("  " + d.text + " counter=" + std::to_string((int)(int8_t)d.status));
            } else protoLine("Fault counters: " + err);
        });
    });
    connect(idBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        startWorker([this, tgt] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Std ID block: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            protoLine("Standard identification block (ISO 14229) on 0x" +
                      byteHex((tgt>>8)&0xFF) + byteHex(tgt&0xFF) + ":");
            int got = 0;
            for (const auto& d : kStandardDids) {
                std::string e;
                auto v = uds.readDataByIdentifier(tgt, d.did, e);
                if (!v || v->empty()) continue;
                ++got;
                std::string out;
                if (d.ascii) {
                    for (uint8_t b : *v) out += (b >= 0x20 && b < 0x7F) ? (char)b : '.';
                } else {
                    out = toHex(v->data(), v->size());
                }
                protoLine(std::string("  ") + d.name + " (0x" +
                          byteHex((d.did>>8)&0xFF) + byteHex(d.did&0xFF) + "): " + out);
            }
            protoLine("  -> " + std::to_string(got) + " standard DID(s) present");
        });
    });
    connect(obdBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        startWorker([this, tgt] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("OBD-II VIN: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            // SAE J1979 mode 0x09 PID 0x02 = VIN. Positive reply: 0x49 0x02 ...
            std::vector<uint8_t> resp;
            if (uds.obdRequest(tgt, {0x09, 0x02}, resp, err) && resp.size() > 2) {
                std::string vin;
                for (size_t i = 2; i < resp.size(); ++i)
                    if (resp[i] >= 0x20 && resp[i] < 0x7F) vin += (char)resp[i];
                protoLine("OBD-II mode 09 VIN: " + vin);
            } else {
                protoLine("OBD-II mode 09: " + err);
            }
        });
    });
    connect(wrBtn, &QPushButton::clicked, this, [this, wrBtn] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint16_t did = parseHex16(edProtoWriteDid_->text(), 0);
        auto data = parseHexBytes(edProtoWriteData_->text().toStdString());
        if (data.empty()) { protoLine("Write: enter hex data bytes"); return; }
        if (!confirmPopup(wrBtn, "Write data by identifier",
                QString("Write %1 byte(s) to DID 0x%2 on ECU 0x%3? This changes "
                        "stored ECU configuration.")
                    .arg(data.size()).arg(did, 4, 16, QChar('0')).arg(tgt, 4, 16, QChar('0')),
                "Yes, write"))
            return;
        startWorker([this, tgt, did, data] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Write: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            if (uds.writeDataByIdentifier(tgt, did, data, err))
                protoLine("WriteDataByIdentifier DID 0x" + byteHex((did>>8)&0xFF) +
                          byteHex(did&0xFF) + ": accepted");
            else protoLine("Write: " + err);
        });
    });
    connect(rcBtn, &QPushButton::clicked, this, [this, rcBtn] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint16_t rid = parseHex16(edProtoRid_->text(), 0);
        int subIdx = cbProtoRoutine_->currentIndex();
        RoutineCtrl sub = subIdx == 0 ? RoutineCtrl::Start
                        : subIdx == 1 ? RoutineCtrl::Stop : RoutineCtrl::Results;
        auto params = parseHexBytes(edProtoRidParams_->text().toStdString());
        if (sub != RoutineCtrl::Results) {
            if (!confirmPopup(rcBtn, "Routine control",
                    QString("%1 routine 0x%2 on ECU 0x%3? Routines can move "
                            "actuators or alter ECU state.")
                        .arg(sub == RoutineCtrl::Start ? "START" : "STOP")
                        .arg(rid, 4, 16, QChar('0')).arg(tgt, 4, 16, QChar('0')),
                    "Yes, run"))
                return;
        }
        startWorker([this, tgt, sub, rid, params] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Routine: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.routineControl(tgt, sub, rid, params, out, err))
                protoLine("RoutineControl 0x" + byteHex((rid>>8)&0xFF) + byteHex(rid&0xFF) +
                          ": accepted" + (out.empty() ? "" : " status " + toHex(out.data(), out.size())));
            else protoLine("Routine: " + err);
        });
    });
    connect(ccBtn, &QPushButton::clicked, this, [this, ccBtn] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        CommCtrl ctrl = (CommCtrl)cbProtoComm_->currentIndex();
        uint8_t commType = (uint8_t)parseHex16(edProtoCommType_->text(), 0x01);
        if (!confirmPopup(ccBtn, "Communication control",
                QString("Apply control 0x%1 (commType 0x%2) on ECU 0x%3? This can "
                        "silence normal bus communication.")
                    .arg((int)ctrl, 2, 16, QChar('0')).arg(commType, 2, 16, QChar('0'))
                    .arg(tgt, 4, 16, QChar('0')),
                "Yes, apply"))
            return;
        startWorker([this, tgt, ctrl, commType] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("CommControl: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            if (uds.communicationControl(tgt, ctrl, commType, err))
                protoLine("CommunicationControl: accepted");
            else protoLine("CommControl: " + err);
        });
    });

    // ---- BMS crash-data / HV-lockout reset handlers ----
    connect(crashSeedBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edCrashTarget_->text(), 0x1003);
        uint8_t  lvl = (uint8_t)parseHex16(edCrashSecLevel_->text(), 0x09);
        startWorker([this, tgt, lvl] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Crash seed: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::string e;
            uds.diagnosticSessionControl(tgt, UdsSession::Extended, e);
            auto seed = uds.requestSeed(tgt, lvl, err);
            if (!seed) { protoLine("Crash seed (level 0x" + byteHex(lvl) + "): " + err); return; }
            if (seed->empty()) { protoLine("BMS security already unlocked (level 0x" + byteHex(lvl) + ")."); return; }
            protoLine("BMS seed (level 0x" + byteHex(lvl) + "): " + toHex(seed->data(), seed->size()) +
                      "  -> compute key with the dealer/seed-key algorithm, paste it, then Clear crash data.");
        });
    });
    connect(crashResetBtn, &QPushButton::clicked, this, [this, crashResetBtn] {
        uint16_t tgt = parseHex16(edCrashTarget_->text(), 0x1003);
        uint8_t  lvl = (uint8_t)parseHex16(edCrashSecLevel_->text(), 0x09);
        uint16_t rid = parseHex16(edCrashRid_->text(), 0);
        uint32_t dtc = (uint32_t)std::strtoul(
            QString(edCrashDtc_->text()).remove(' ').toStdString().c_str(), nullptr, 16);
        auto key = parseHexBytes(edCrashKey_->text().toStdString());
        bool hasRid = !edCrashRid_->text().trimmed().isEmpty() && rid != 0;
        if (!confirmPopup(crashResetBtn, "Clear BMS crash data",
                QString("Reset the BMS crash/HV-lockout on ECU 0x%1?\n\n"
                        "This re-arms the high-voltage system. Only proceed after the "
                        "vehicle, battery pack and HV interlocks have been inspected "
                        "and confirmed safe. You are responsible for this action.")
                    .arg(tgt, 4, 16, QChar('0')),
                "Yes, clear crash data"))
            return;
        startWorker([this, tgt, lvl, rid, dtc, key, hasRid] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Crash reset: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::string e;

            protoLine("Crash reset: entering Extended session on 0x" +
                      byteHex((tgt>>8)&0xFF) + byteHex(tgt&0xFF) + "...");
            if (!uds.diagnosticSessionControl(tgt, UdsSession::Extended, e)) {
                protoLine("Crash reset: session failed: " + e); return;
            }

            // 1) SecurityAccess (only if a key was supplied).
            if (!key.empty()) {
                auto seed = uds.requestSeed(tgt, lvl, err);
                if (!seed) { protoLine("Crash reset: requestSeed failed: " + err); return; }
                if (seed->empty()) {
                    protoLine("Crash reset: already unlocked, skipping key.");
                } else if (!uds.sendKey(tgt, lvl, key, err)) {
                    protoLine("Crash reset: sendKey rejected: " + err +
                              " (key must match THIS seed " + toHex(seed->data(), seed->size()) + ")");
                    return;
                } else {
                    protoLine("Crash reset: security unlocked (level 0x" + byteHex(lvl) + ").");
                }
            } else {
                protoLine("Crash reset: no key supplied, skipping SecurityAccess "
                          "(BMS may reject the clear if it requires unlock).");
            }

            // 2) RoutineControl start of the crash-reset routine (if given).
            if (hasRid) {
                std::vector<uint8_t> out;
                if (uds.routineControl(tgt, RoutineCtrl::Start, rid, {}, out, err))
                    protoLine("Crash reset: routine 0x" + byteHex((rid>>8)&0xFF) + byteHex(rid&0xFF) +
                              " started" + (out.empty() ? "" : ", status " + toHex(out.data(), out.size())));
                else
                    protoLine("Crash reset: routine 0x" + byteHex((rid>>8)&0xFF) + byteHex(rid&0xFF) +
                              " rejected: " + err);
            }

            // 3) ClearDiagnosticInformation for the crash DTC / group.
            if (uds.clearDiagnosticInformation(tgt, dtc, err))
                protoLine("Crash reset: ClearDiagnosticInformation 0x" +
                          byteHex((dtc>>16)&0xFF) + byteHex((dtc>>8)&0xFF) + byteHex(dtc&0xFF) + " accepted.");
            else
                protoLine("Crash reset: clear rejected: " + err);

            // 4) Read-back of confirmed DTCs as a sanity check.
            std::vector<Dtc> remaining;
            if (uds.readDTCByStatusMask(tgt, 0x08, remaining, e)) {
                if (remaining.empty())
                    protoLine("Crash reset: read-back OK - no confirmed DTCs remain.");
                else
                    protoLine("Crash reset: " + std::to_string(remaining.size()) +
                              " confirmed DTC(s) still present (cycle ignition / re-check).");
            }
            protoLine("Crash reset: sequence complete.");
        });
    });

    // ---- Periodic (0x2A) ----
    connect(perBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        int modeIdx = cbProtoPeriodicMode_->currentIndex();
        std::vector<uint8_t> pdids;
        for (const QString& tok : edProtoPdid_->text().split(' ', Qt::SkipEmptyParts)) {
            bool ok = false; uint v = tok.toUInt(&ok, 16);
            if (ok && v <= 0xFF) pdids.push_back((uint8_t)v);
        }
        startWorker([this, tgt, modeIdx, pdids] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Periodic: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            auto mode = (PeriodicMode)(modeIdx + 1);  // combo 0..3 -> 0x01..0x04
            if (uds.readDataByPeriodicIdentifier(tgt, mode, pdids, err)) {
                if (mode == PeriodicMode::StopSending)
                    protoLine("Periodic: stopped scheduled transmission.");
                else
                    protoLine("Periodic: scheduled " + std::to_string(pdids.size()) +
                              " PDID(s) at rate 0x0" + std::to_string(modeIdx + 1) + ".");
            } else protoLine("Periodic: " + err);
        });
    });

    // ---- Dynamically define (0x2C) ----
    connect(defBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt   = parseHex16(edProtoTarget_->text(), 0x1003);
        uint16_t dddid = parseHex16(edProtoDddid_->text(), 0xF300);
        std::vector<DddSource> srcs;
        for (const QString& tok : edProtoDddSrc_->text().split(' ', Qt::SkipEmptyParts)) {
            QStringList p = tok.split(':');
            if (p.isEmpty()) continue;
            bool okd = false; uint did = p[0].toUInt(&okd, 16);
            if (!okd) continue;
            uint pos = (p.size() > 1) ? p[1].toUInt(nullptr, 10) : 1;
            uint sz  = (p.size() > 2) ? p[2].toUInt(nullptr, 10) : 1;
            if (pos < 1) pos = 1; if (sz < 1) sz = 1;
            srcs.push_back({(uint16_t)did, (uint8_t)pos, (uint8_t)sz});
        }
        startWorker([this, tgt, dddid, srcs] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Define DDDID: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            if (uds.defineDynamicDataIdentifier(tgt, dddid, srcs, err))
                protoLine("Define DDDID 0x" + byteHex((dddid>>8)&0xFF) + byteHex(dddid&0xFF) +
                          ": OK (" + std::to_string(srcs.size()) + " source DID(s)).");
            else protoLine("Define DDDID: " + err);
        });
    });
    connect(rdBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt   = parseHex16(edProtoTarget_->text(), 0x1003);
        uint16_t dddid = parseHex16(edProtoDddid_->text(), 0xF300);
        startWorker([this, tgt, dddid] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Read DDDID: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            auto v = uds.readDataByIdentifier(tgt, dddid, err);
            if (v) protoLine("Read DDDID 0x" + byteHex((dddid>>8)&0xFF) + byteHex(dddid&0xFF) +
                             ": " + toHex(v->data(), v->size()));
            else protoLine("Read DDDID: " + err);
        });
    });
    connect(clrBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt   = parseHex16(edProtoTarget_->text(), 0x1003);
        uint16_t dddid = parseHex16(edProtoDddid_->text(), 0xF300);
        startWorker([this, tgt, dddid] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Clear DDDID: " + err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            if (uds.clearDynamicDataIdentifier(tgt, dddid, err))
                protoLine("Clear DDDID 0x" + byteHex((dddid>>8)&0xFF) + byteHex(dddid&0xFF) + ": OK.");
            else protoLine("Clear DDDID: " + err);
        });
    });

    return page;
}

// ==========================================================================
// Cloud page - VinFast connected-car API (reverse-engineered, community)
// ==========================================================================
void Gui::cloudLine(const std::string& s) {
    std::lock_guard<std::mutex> g(mutex_);
    cloudLog_ += s;
    cloudLog_ += "\n";
    ++cloudLogRev_;
}

void Gui::refreshCloud() {
    std::string snapshot;
    size_t rev;
    { std::lock_guard<std::mutex> g(mutex_); snapshot = cloudLog_; rev = cloudLogRev_; }
    if (rev == cloudViewRev_) return;
    cloudViewRev_ = rev;
    if (cloudView_) {
        cloudView_->setPlainText(QString::fromStdString(snapshot));
        cloudView_->verticalScrollBar()->setValue(
            cloudView_->verticalScrollBar()->maximum());
    }
}

QWidget* Gui::buildCloudPage() {
    auto* page = new QWidget;
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* inner = new QWidget;
    scroll->setWidget(inner);
    auto* pageLay = new QVBoxLayout(page);
    pageLay->setContentsMargins(0, 0, 0, 0);
    pageLay->addWidget(scroll);

    auto* outer = new QVBoxLayout(inner);
    outer->setContentsMargins(18, 18, 18, 18);
    outer->setSpacing(12);

    outer->addWidget(new QLabel(
        "<b>VinFast connected-car cloud.</b> Talks to VinFast's app back-end "
        "(Auth0 + signed REST + AWS IoT) the same way the phone app does. This "
        "uses <i>community reverse-engineered</i> endpoints, not an official "
        "SDK - they may change without notice. Credentials are kept in memory, "
        "sent only over HTTPS to VinFast, and never logged or written to disk."));

    // ---- account / login -------------------------------------------------
    auto* acctCard = card("Account");
    auto* af = new QFormLayout(acctCard);
    cbCloudRegion_ = new QComboBox;
    for (const auto& r : cloud::kCloudRegions)
        cbCloudRegion_->addItem(QString("%1  (%2)").arg(r.label).arg(r.code));
    af->addRow("Region", cbCloudRegion_);
    edCloudEmail_ = new QLineEdit;
    edCloudEmail_->setPlaceholderText("email");
    af->addRow("Email", edCloudEmail_);
    edCloudPass_ = new QLineEdit;
    edCloudPass_->setEchoMode(QLineEdit::Password);
    edCloudPass_->setPlaceholderText("password (not stored)");
    af->addRow("Password", edCloudPass_);
    auto* loginRow = new QHBoxLayout;
    auto* loginBtn  = new QPushButton("Log in"); loginBtn->setObjectName("primary");
    auto* logoutBtn = new QPushButton("Log out");
    auto* vehBtn    = new QPushButton("Get vehicles");
    loginRow->addWidget(loginBtn); loginRow->addWidget(logoutBtn);
    loginRow->addWidget(vehBtn); loginRow->addStretch(1);
    af->addRow(loginRow);
    cloudVehLabel_ = new QLabel("Not logged in.");
    cloudVehLabel_->setWordWrap(true);
    af->addRow("Vehicle", cloudVehLabel_);
    outer->addWidget(acctCard);

    // ---- remote commands -------------------------------------------------
    auto* cmdCard = card("Remote commands (confirm required)");
    auto* cmdGrid = new QGridLayout(cmdCard);
    cmdGrid->setSpacing(8);
    int col = 0, rowi = 0;
    for (const auto& rc : cloud::kRemoteCommands) {
        auto* b = new QPushButton(rc.label);
        int type = rc.type; QString label = rc.label;
        connect(b, &QPushButton::clicked, this, [this, type, label, b] {
            if (!confirmPopup(b, "Send remote command",
                              QString("Send \"%1\" to the vehicle over the cloud?").arg(label),
                              "Send"))
                return;
            startWorker([this, type, label] {
                std::string reqId, err;
                if (cloud_.sendCommand(type, reqId, err))
                    cloudLine(label.toStdString() + ": accepted" +
                              (reqId.empty() ? "" : " (req " + reqId + ")"));
                else
                    cloudLine(label.toStdString() + ": " + err);
            });
        });
        cmdGrid->addWidget(b, rowi, col);
        if (++col == 4) { col = 0; ++rowi; }
    }
    auto* wakeBtn = new QPushButton("Wake T-Box");
    connect(wakeBtn, &QPushButton::clicked, this, [this] {
        startWorker([this] {
            std::string err;
            if (cloud_.wakeup(err)) cloudLine("Wakeup: accepted");
            else cloudLine("Wakeup: " + err);
        });
    });
    cmdGrid->addWidget(wakeBtn, rowi, col);
    outer->addWidget(cmdCard);

    // ---- telemetry / charging -------------------------------------------
    auto* dataCard = card("Telemetry & charging");
    auto* dl = new QHBoxLayout(dataCard);
    auto* teleBtn    = new QPushButton("Request telemetry");
    auto* activeBtn  = new QPushButton("Active charging");
    auto* historyBtn = new QPushButton("Charging history");
    dl->addWidget(teleBtn); dl->addWidget(activeBtn);
    dl->addWidget(historyBtn); dl->addStretch(1);
    outer->addWidget(dataCard);

    connect(teleBtn, &QPushButton::clicked, this, [this] {
        startWorker([this] {
            std::string body, err;
            if (cloud_.requestTelemetry(body, err))
                cloudLine("Telemetry requested - live values arrive via MQTT.");
            else cloudLine("Telemetry: " + err);
        });
    });
    connect(activeBtn, &QPushButton::clicked, this, [this] {
        startWorker([this] {
            cloud::ActiveCharge ac; std::string err;
            if (!cloud_.fetchActiveCharge(ac, err)) { cloudLine("Active charging: " + err); return; }
            if (!ac.active) { cloudLine("Active charging: none in progress."); return; }
            char buf[160];
            std::snprintf(buf, sizeof buf,
                "Charging: %.1f kW, SOC %.0f%% -> target %.0f%%%s",
                ac.powerKw, ac.soc, ac.targetSoc,
                ac.remainMin > 0 ? (" (" + std::to_string(ac.remainMin) + " min left)").c_str() : "");
            cloudLine(buf);
        });
    });
    connect(historyBtn, &QPushButton::clicked, this, [this] {
        startWorker([this] {
            std::vector<cloud::ChargeSession> hist; std::string err;
            if (!cloud_.fetchChargeHistory(hist, err)) { cloudLine("Charging history: " + err); return; }
            if (hist.empty()) { cloudLine("Charging history: no sessions."); return; }
            cloudLine("Charging history (" + std::to_string(hist.size()) + " sessions):");
            int n = 0;
            for (const auto& s : hist) {
                if (n++ >= 10) { cloudLine("  ..."); break; }
                char buf[220];
                std::snprintf(buf, sizeof buf,
                    "  %s  %.1f kWh  %.0f%%->%.0f%%  %s",
                    s.startTime.empty() ? "(date?)" : s.startTime.c_str(),
                    s.energyKwh, s.startSoc, s.endSoc,
                    s.location.c_str());
                cloudLine(buf);
            }
        });
    });

    // ---- MQTT real-time --------------------------------------------------
    auto* mqttCard = card("Real-time (AWS IoT MQTT)");
    auto* ml = new QVBoxLayout(mqttCard);
    ml->addWidget(new QLabel(
        "Builds a presigned wss:// AWS IoT URL (Cognito identity + SigV4). The "
        "scanner generates and shows the endpoint; opening the MQTT socket is "
        "not done here. Only available where the region's Cognito pool is known."));
    auto* mqttBtn = new QPushButton("Build presigned MQTT URL");
    auto* mqttRow = new QHBoxLayout;
    mqttRow->addWidget(mqttBtn); mqttRow->addStretch(1);
    ml->addLayout(mqttRow);
    outer->addWidget(mqttCard);

    connect(mqttBtn, &QPushButton::clicked, this, [this] {
        startWorker([this] {
            std::string url, err;
            if (cloud_.buildMqttUrl(url, err)) {
                cloudLine("MQTT endpoint (presigned):");
                cloudLine("  " + url);
            } else cloudLine("MQTT: " + err);
        });
    });

    // ---- BMS characterization (bus <-> cloud correlation) ----------------
    auto* bmsCard = card("BMS characterization (bus <-> cloud)");
    auto* bl = new QVBoxLayout(bmsCard);
    bl->addWidget(new QLabel(
        "The CATL BMS exposes no public CAN/UDS map, so identify battery DIDs "
        "empirically: sweep the BMS's read-only 0x22 DIDs, timestamp the raw "
        "values, and capture the cloud SOC/charging at the same instant. Take "
        "two snapshots at different battery states (e.g. before/after charging), "
        "then compare - DIDs whose raw value tracks the cloud SOC delta are "
        "battery-data candidates. Read-only; nothing is written to the ECU."));
    auto* bf = new QHBoxLayout;
    edBmsTarget_ = hexEdit("1003", 4);
    edBmsStart_  = hexEdit("0000", 4);
    edBmsEnd_    = hexEdit("00FF", 4);
    bf->addWidget(new QLabel("BMS addr")); bf->addWidget(edBmsTarget_);
    bf->addWidget(new QLabel("Start"));    bf->addWidget(edBmsStart_);
    bf->addWidget(new QLabel("End"));      bf->addWidget(edBmsEnd_);
    bf->addStretch(1);
    bl->addLayout(bf);
    auto* bb = new QHBoxLayout;
    auto* snapBtn    = new QPushButton("Capture snapshot"); snapBtn->setObjectName("primary");
    auto* compareBtn = new QPushButton("Compare last two");
    auto* clearSnapBtn = new QPushButton("Clear snapshots");
    bb->addWidget(snapBtn); bb->addWidget(compareBtn);
    bb->addWidget(clearSnapBtn); bb->addStretch(1);
    bl->addLayout(bb);
    outer->addWidget(bmsCard);

    connect(snapBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt   = parseHex16(edBmsTarget_->text(), 0x1003);
        int      start = parseHex16(edBmsStart_->text(), 0x0000);
        int      end   = parseHex16(edBmsEnd_->text(), 0x00FF);
        if (end < start || (end - start) > 4096) {
            cloudLine("BMS snapshot: pick a valid 1..4096 DID range.");
            return;
        }
        startWorker([this, tgt, start, end] {
            std::string err;
            if (!ensureConnected(err)) { cloudLine("BMS snapshot: " + err); return; }

            BmsSnapshot snap;
            snap.tWallMs = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

            // Cloud ground-truth (best effort; SOC is reliable while charging).
            if (cloud_.loggedIn()) {
                cloud::ActiveCharge ac; std::string e2;
                if (cloud_.fetchActiveCharge(ac, e2)) {
                    snap.cloudCharging = ac.active;
                    if (ac.active) { snap.cloudSoc = ac.soc; snap.cloudPower = ac.powerKw; }
                }
            }

            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::string e;
            uds.diagnosticSessionControl(tgt, UdsSession::Extended, e);
            int n = 0;
            for (int id = start; id <= end && client_.isConnected(); ++id) {
                std::vector<uint8_t> resp; std::string le;
                if (uds.probeDID(tgt, (uint16_t)id, resp, le) == 1) {
                    snap.dids.emplace_back((uint16_t)id, resp);
                    ++n;
                }
            }

            size_t count;
            double snapSoc = snap.cloudSoc;
            bool   loggedIn = cloud_.loggedIn();
            {
                std::lock_guard<std::mutex> g(mutex_);
                bmsSnapshots_.push_back(std::move(snap));
                if (bmsSnapshots_.size() > 8) bmsSnapshots_.erase(bmsSnapshots_.begin());
                count = bmsSnapshots_.size();
            }
            std::string socNote;
            if (!loggedIn)        socNote = " | no cloud login";
            else if (snapSoc >= 0) socNote = " | cloud SOC " + std::to_string((int)snapSoc) + "%";
            else                  socNote = " | cloud SOC n/a (not charging)";
            char buf[160];
            std::snprintf(buf, sizeof buf,
                "BMS snapshot #%zu: %d readable DID(s) on 0x%04X%s.",
                count, n, tgt, socNote.c_str());
            cloudLine(buf);
        });
    });

    connect(compareBtn, &QPushButton::clicked, this, [this] {
        BmsSnapshot a, b;
        {
            std::lock_guard<std::mutex> g(mutex_);
            if (bmsSnapshots_.size() < 2) {
                cloudLine("BMS compare: need at least two snapshots.");
                return;
            }
            a = bmsSnapshots_[bmsSnapshots_.size() - 2];
            b = bmsSnapshots_.back();
        }

        auto asU = [](const std::vector<uint8_t>& v) -> long long {
            long long x = 0; size_t n = v.size() > 8 ? 8 : v.size();
            for (size_t i = 0; i < n; ++i) x = (x << 8) | v[i];
            return x;
        };

        double dtSec = (double)(b.tWallMs - a.tWallMs) / 1000.0;
        cloudLine("---- BMS compare (snapshot A -> B) ----");
        {
            char hdr[200];
            std::string socStr = "n/a";
            if (a.cloudSoc >= 0 && b.cloudSoc >= 0)
                socStr = std::to_string((int)a.cloudSoc) + "% -> " +
                         std::to_string((int)b.cloudSoc) + "% (d " +
                         std::to_string((int)(b.cloudSoc - a.cloudSoc)) + ")";
            std::snprintf(hdr, sizeof hdr,
                "dt %.0fs | cloud SOC %s | charging %s->%s",
                dtSec, socStr.c_str(),
                a.cloudCharging ? "yes" : "no", b.cloudCharging ? "yes" : "no");
            cloudLine(hdr);
        }

        // Index B's DIDs for lookup.
        int changed = 0, same = 0;
        for (const auto& pa : a.dids) {
            const std::vector<uint8_t>* pb = nullptr;
            for (const auto& q : b.dids) if (q.first == pa.first) { pb = &q.second; break; }
            if (!pb) continue;
            if (*pb == pa.second) { ++same; continue; }
            ++changed;
            long long va = asU(pa.second), vb = asU(*pb);
            char buf[220];
            std::snprintf(buf, sizeof buf,
                "  DID %04X: %s -> %s  (uint %lld -> %lld, d %+lld)",
                pa.first,
                toHex(pa.second.data(), pa.second.size()).c_str(),
                toHex(pb->data(), pb->size()).c_str(),
                va, vb, vb - va);
            cloudLine(buf);
        }
        char tail[160];
        std::snprintf(tail, sizeof tail,
            "%d DID(s) changed, %d unchanged. Changed DIDs that move with the "
            "SOC delta are battery-data candidates.", changed, same);
        cloudLine(tail);
    });

    connect(clearSnapBtn, &QPushButton::clicked, this, [this] {
        std::lock_guard<std::mutex> g(mutex_);
        bmsSnapshots_.clear();
        cloudLine("BMS snapshots cleared.");
    });

    // ---- account handlers ------------------------------------------------
    connect(cbCloudRegion_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int idx) {
        if (idx >= 0 && idx < (int)cloud::kCloudRegions.size())
            cloud_.setRegion(cloud::kCloudRegions[idx].code);
    });
    connect(loginBtn, &QPushButton::clicked, this, [this] {
        int idx = cbCloudRegion_ ? cbCloudRegion_->currentIndex() : 0;
        if (idx >= 0 && idx < (int)cloud::kCloudRegions.size())
            cloud_.setRegion(cloud::kCloudRegions[idx].code);
        std::string email = edCloudEmail_->text().toStdString();
        std::string pass  = edCloudPass_->text().toStdString();
        if (email.empty() || pass.empty()) { cloudLine("Login: enter email and password."); return; }
        startWorker([this, email, pass] {
            std::string err;
            if (cloud_.login(email, pass, err)) cloudLine("Logged in.");
            else cloudLine("Login: " + err);
        });
    });
    connect(logoutBtn, &QPushButton::clicked, this, [this] {
        cloud_.logout();
        if (cloudVehLabel_) cloudVehLabel_->setText("Not logged in.");
        cloudLine("Logged out.");
    });
    connect(vehBtn, &QPushButton::clicked, this, [this] {
        startWorker([this] {
            std::vector<cloud::Vehicle> vs; std::string err;
            if (!cloud_.getVehicles(vs, err)) { cloudLine("Vehicles: " + err); return; }
            if (vs.empty()) { cloudLine("Vehicles: none returned."); return; }
            cloudLine("Vehicles (" + std::to_string(vs.size()) + "):");
            for (const auto& v : vs)
                cloudLine("  " + v.vin + "  " + v.model +
                          (v.plate.empty() ? "" : "  [" + v.plate + "]"));
            QString summary = QString("%1  ·  %2%3")
                .arg(QString::fromStdString(vs[0].vin))
                .arg(QString::fromStdString(vs[0].model))
                .arg(vs[0].plate.empty() ? "" : QString("  ·  %1").arg(QString::fromStdString(vs[0].plate)));
            QMetaObject::invokeMethod(this, [this, summary] {
                if (cloudVehLabel_) cloudVehLabel_->setText(summary);
            });
        });
    });

    // ---- output ----------------------------------------------------------
    cloudView_ = new QPlainTextEdit;
    cloudView_->setReadOnly(true);
    cloudView_->setMinimumHeight(150);
    cloudView_->setPlaceholderText("Cloud responses appear here.");
    outer->addWidget(cloudView_, 1);

    return page;
}

QWidget* Gui::buildReferencePage() {
    auto* page = new QWidget;
    auto* lay = new QVBoxLayout(page);
    lay->setContentsMargins(18, 18, 18, 18);
    lay->setSpacing(10);

    int total = 0;
    for (const auto& s : kVF8ReferenceScan) total += (int)s.dtcs.size();
    lay->addWidget(new QLabel(QString(
        "<b>Reference scan</b> (Autel MaxiCOM) - %1 systems, %2 DTCs stored for "
        "this VIN. Expand a system to compare against a live scan.")
        .arg((int)kVF8ReferenceScan.size()).arg(total)));

    refTree_ = new QTreeWidget;
    refTree_->setColumnCount(3);
    refTree_->setHeaderLabels({"DTC / System", "Status", "Description"});
    refTree_->setColumnWidth(0, 240);
    refTree_->setColumnWidth(1, 90);
    for (const auto& sys : kVF8ReferenceScan) {
        auto* top = new QTreeWidgetItem(refTree_);
        top->setText(0, QString("%1 - %2").arg(sys.code).arg(sys.name));
        top->setText(1, QString("%1 DTC").arg(sys.dtcs.size()));
        top->setFirstColumnSpanned(false);
        for (const auto& d : sys.dtcs) {
            auto* it = new QTreeWidgetItem(top);
            it->setText(0, d.dtc);
            it->setText(1, d.status);
            std::string desc = (d.desc && d.desc[0]) ? d.desc : vf8DtcDescribe(d.dtc);
            it->setText(2, QString::fromStdString(desc));
            if (std::strcmp(d.status, "Current") == 0)
                it->setForeground(1, QColor(0xff, 0x7a, 0x7a));
        }
    }

    // ---- Protocol standards (manufacturer-independent, valid on the VF8) ----
    auto* stdTop = new QTreeWidgetItem(refTree_);
    stdTop->setText(0, "Protocol standards (ISO 14229 / SAE J1979 / ISO 13400)");
    stdTop->setText(1, "reference");
    stdTop->setText(2, "VinFast-private IDs are not public; these standardized "
                       "ones apply to the VF8's UDS/DoIP stack.");

    auto* didTop = new QTreeWidgetItem(stdTop);
    didTop->setText(0, "Standard identification DIDs (0x22)");
    didTop->setText(1, QString("%1").arg((int)kStandardDids.size()));
    for (const auto& d : kStandardDids) {
        auto* it = new QTreeWidgetItem(didTop);
        it->setText(0, QString("0x%1").arg(d.did, 4, 16, QChar('0')).toUpper());
        it->setText(1, d.ascii ? "text" : "bytes");
        it->setText(2, d.name);
    }

    auto* obdTop = new QTreeWidgetItem(stdTop);
    obdTop->setText(0, "Legislated OBD-II services (SAE J1979)");
    obdTop->setText(1, QString("%1").arg((int)kObdServices.size()));
    for (const auto& o : kObdServices) {
        auto* it = new QTreeWidgetItem(obdTop);
        it->setText(0, QString("mode 0x%1").arg(o.sid, 2, 16, QChar('0')).toUpper());
        it->setText(2, o.name);
    }

    auto* rngTop = new QTreeWidgetItem(stdTop);
    rngTop->setText(0, "DoIP logical-address ranges (ISO 13400-2)");
    rngTop->setText(1, QString("%1").arg((int)kDoipAddrRanges.size()));
    for (const auto& r : kDoipAddrRanges) {
        auto* it = new QTreeWidgetItem(rngTop);
        it->setText(0, QString("0x%1-0x%2")
            .arg(r.first, 4, 16, QChar('0')).arg(r.last, 4, 16, QChar('0')).toUpper());
        it->setText(2, r.meaning);
    }

    lay->addWidget(refTree_, 1);
    return page;
}

QWidget* Gui::buildLogPage() {
    auto* page = new QWidget;
    auto* lay = new QVBoxLayout(page);
    lay->setContentsMargins(18, 18, 18, 18);
    lay->setSpacing(10);

    auto* bar = new QHBoxLayout;
    auto* clearBtn = new QPushButton("Clear log");
    auto* saveBtn  = new QPushButton("Save to file");
    cbAutoScroll_ = new QCheckBox("Auto-scroll"); cbAutoScroll_->setChecked(true);
    logSaved_ = new QLabel;
    bar->addWidget(clearBtn);
    bar->addWidget(saveBtn);
    bar->addWidget(cbAutoScroll_);
    bar->addStretch(1);
    bar->addWidget(logSaved_);
    lay->addLayout(bar);

    logView_ = new QPlainTextEdit;
    logView_->setReadOnly(true);
    logView_->setObjectName("log");
    QFont mono("Menlo"); mono.setStyleHint(QFont::Monospace); mono.setPointSize(11);
    logView_->setFont(mono);
    logView_->setMaximumBlockCount(8000);
    lay->addWidget(logView_, 1);

    connect(clearBtn, &QPushButton::clicked, this, [this] {
        Logger::instance().clear();
        logView_->clear();
        lastLogCount_ = 0;
    });
    connect(saveBtn, &QPushButton::clicked, this, [this] {
        std::time_t now = std::time(nullptr); std::tm tmv{};
#ifdef _WIN32
        localtime_s(&tmv, &now);
#else
        localtime_r(&now, &tmv);
#endif
        char fname[96];
        std::strftime(fname, sizeof fname, "vf8-scan-%Y%m%d-%H%M%S.log", &tmv);
        std::string err;
        if (Logger::instance().saveToFile(fname, err)) {
            char cwd[1024];
            std::string full = (getcwd(cwd, sizeof cwd) ? std::string(cwd) + "/" : "") + fname;
            logSaved_->setText(QString("Saved: %1").arg(QString::fromStdString(full)));
            Logger::instance().info("Log saved to " + full);
        } else Logger::instance().error("Save failed: " + err);
    });

    return page;
}

void Gui::applyStyle() {
    setStyleSheet(R"(
        QWidget { background: #161a21; color: #dfe4ea; font-size: 13px; }
        QLabel { background: transparent; }
        QFrame#header { background: #11202e;
                        border-bottom: 2px solid #2e7dd1; }
        QLabel#title { font-size: 20px; font-weight: 700; color: #ffffff; }
        QLabel#subtitle { color: #9fb0c0; font-size: 11px; }
        QLabel#dotGood { color: #43d17a; font-size: 16px; }
        QLabel#dotBad  { color: #e0556a; font-size: 16px; }
        QLabel#dotIdle { color: #6a7686; font-size: 16px; }
        QLabel#dotBusy { color: #f2b134; font-size: 16px; }
        QListWidget#nav { background: #11151c; border: none; outline: none; }
        QListWidget#nav::item { color: #aeb9c6; border-radius: 6px; margin: 2px 8px; }
        QListWidget#nav::item:selected { background: #2e7dd1; color: #ffffff; }
        QListWidget#nav::item:hover { background: #1d2530; }
        QGroupBox#card { background: #1c222c; border: 1px solid #29313d;
                         border-radius: 10px; margin-top: 14px; padding: 12px; }
        QGroupBox#card::title { subcontrol-origin: margin; left: 12px;
                                padding: 0 6px; color: #7fa8d6; font-weight: 600; }
        QPushButton { background: #232b37; border: 1px solid #323c4a;
                      border-radius: 6px; padding: 7px 14px; }
        QPushButton:hover { background: #2b3543; }
        QPushButton#primary { background: #2e7dd1; border: none; color: #fff; font-weight: 600; }
        QPushButton#primary:hover { background: #3a8ce0; }
        QPushButton#danger { background: #b23a4a; border: none; color: #fff; }
        QPushButton#danger:hover { background: #c8485a; }
        QToolButton#tile { background: #1c222c; border: 1px solid #29313d;
                           border-radius: 10px; font-weight: 600; }
        QToolButton#tile:hover { background: #243042; border-color: #2e7dd1; }
        QLineEdit, QSpinBox, QComboBox { background: #11151c; border: 1px solid #323c4a;
                          border-radius: 5px; padding: 5px; }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border-color: #2e7dd1; }
        QTableWidget, QTreeWidget, QPlainTextEdit#log { background: #11151c;
                          border: 1px solid #29313d; border-radius: 8px; gridline-color: #232c38; }
        QHeaderView::section { background: #1c222c; color: #9fb0c0; border: none;
                          padding: 6px; }
        QScrollBar:vertical { background: #11151c; width: 12px; }
        QScrollBar::handle:vertical { background: #323c4a; border-radius: 6px; }
    )");
}

// ==========================================================================
// Periodic refresh
// ==========================================================================
void Gui::onTick() {
    refreshHeader();
    if (pages_->currentIndex() == 2) { rebuildEcuTiles(); refreshEcuTiles(); }
    if (pages_->currentIndex() == 3) refreshLive();
    if (pages_->currentIndex() == 4) refreshServiceResults();
    if (pages_->currentIndex() == 5) refreshProtocol();
    if (pages_->currentIndex() == 6) refreshCloud();
    if (pages_->currentIndex() == 8) refreshLog();

    // keep the seed label and conn button text current
    if (seedLabel_) {
        std::lock_guard<std::mutex> g(mutex_);
        if (!lastSeedHex_.empty())
            seedLabel_->setText(QString("seed: %1").arg(QString::fromStdString(lastSeedHex_)));
    }
}

void Gui::refreshHeader() {
    bool busy = busy_.load();
    busyDot_->setObjectName(busy ? "dotBusy" : "dotIdle");
    busyText_->setText(busy ? "Working..." : "Ready");

    bool conn = client_.isConnected();
    connDot_->setObjectName(conn ? "dotGood" : "dotBad");
    {
        std::lock_guard<std::mutex> g(mutex_);
        connText_->setText(QString::fromStdString(connStatus_));
    }
    connectBtn_->setText(conn ? "Disconnect" : "Connect");
    // re-polish so objectName-based colors update
    busyDot_->style()->unpolish(busyDot_); busyDot_->style()->polish(busyDot_);
    connDot_->style()->unpolish(connDot_); connDot_->style()->polish(connDot_);
}

void Gui::rebuildEcuTiles() {
    size_t count;
    { std::lock_guard<std::mutex> g(mutex_); count = ecus_.size(); }
    if ((int)count == ecuTileCount_) return;   // no structural change
    ecuTileCount_ = (int)count;

    for (auto* b : ecuTiles_) { ecuTileGrid_->removeWidget(b); b->deleteLater(); }
    ecuTiles_.clear();

    const int cols = 3;
    for (size_t i = 0; i < count; ++i) {
        auto* b = new QToolButton(ecuTileHost_);
        b->setObjectName("tile");
        b->setMinimumSize(220, 70);
        b->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        b->setToolButtonStyle(Qt::ToolButtonTextOnly);
        int idx = (int)i;
        connect(b, &QToolButton::clicked, this, [this, idx, b] { openEcuDialog(idx, b); });
        ecuTileGrid_->addWidget(b, (int)i / cols, (int)i % cols);
        ecuTiles_.push_back(b);
    }
}

void Gui::refreshEcuTiles() {
    std::lock_guard<std::mutex> g(mutex_);
    for (size_t i = 0; i < ecuTiles_.size() && i < ecus_.size(); ++i) {
        const EcuRow& r = ecus_[i];
        QString shortName = QString::fromStdString(r.name);
        int dash = shortName.indexOf(" - ");
        QString code = dash > 0 ? shortName.left(dash) : shortName;
        QString badge = r.dtcs.empty() ? "" : QString("  ●%1").arg(r.dtcs.size());
        QString dot = r.reachable == 1 ? "●  " : r.reachable == 0 ? "○  " : "·  ";
        ecuTiles_[i]->setText(QString("%1%2%3\n0x%4\n%5")
            .arg(dot).arg(code).arg(badge)
            .arg(r.logicalAddr, 4, 16, QChar('0'))
            .arg(QString::fromStdString(r.statusMsg)));
        ecuTiles_[i]->setToolTip(shortName);
        // Connected ECUs are tinted green, unreachable red, unknown neutral.
        QString border, bg, hover, text = "#dfe4ea";
        if (r.reachable == 1)      { border = "#43d17a"; bg = "#16331f"; hover = "#1d4429"; }
        else if (r.reachable == 0) { border = "#e0556a"; bg = "#3a1a20"; hover = "#4a222a"; }
        else                       { border = "#29313d"; bg = "#1c222c"; hover = "#243042"; }
        QString accentBar = r.dtcs.empty() ? border : "#f2b134";
        ecuTiles_[i]->setStyleSheet(QString(
            "QToolButton#tile{background:%1;border:1px solid %2;"
            "border-left:5px solid %3;border-radius:10px;color:%4;font-weight:600;}"
            "QToolButton#tile:hover{background:%5;}")
            .arg(bg).arg(border).arg(accentBar).arg(text).arg(hover));
    }
}

void Gui::refreshLive() {
    std::lock_guard<std::mutex> g(mutex_);
    if (liveTable_->rowCount() != (int)liveSignals_.size())
        liveTable_->setRowCount((int)liveSignals_.size());
    for (size_t i = 0; i < liveSignals_.size(); ++i) {
        const LiveSignal& s = liveSignals_[i];
        auto set = [&](int col, const QString& txt, const QColor* fg = nullptr) {
            auto* it = liveTable_->item((int)i, col);
            if (!it) { it = new QTableWidgetItem; liveTable_->setItem((int)i, col, it); }
            it->setText(txt);
            if (fg) it->setForeground(*fg);
        };
        QColor green(0x43,0xd1,0x7a), red(0xe0,0x55,0x6a), grey(0x9f,0xb0,0xc0);
        const QColor* dotc = s.ok==1 ? &green : s.ok==0 ? &red : &grey;
        set(0, s.ok==1?"●":s.ok==0?"○":"·", dotc);
        set(1, QString::fromStdString(s.name));
        set(2, QString("%1/%2").arg(s.target,4,16,QChar('0')).arg(s.did,4,16,QChar('0')));
        set(3, QString::fromStdString(s.value));
        set(4, QString::fromStdString(s.rawHex), &grey);
    }
    livePollBtn_->setText(liveRun_.load() ? "Stop polling" : "Start polling");
}

void Gui::refreshServiceResults() {
    std::lock_guard<std::mutex> g(mutex_);
    if (svcTable_->rowCount() != (int)svcResults_.size())
        svcTable_->setRowCount((int)svcResults_.size());
    for (size_t i = 0; i < svcResults_.size(); ++i) {
        const DiscoveredService& s = svcResults_[i];
        auto set = [&](int col, const QString& txt, const QColor* fg=nullptr) {
            auto* it = svcTable_->item((int)i, col);
            if (!it) { it = new QTableWidgetItem; svcTable_->setItem((int)i, col, it); }
            it->setText(txt); if (fg) it->setForeground(*fg);
        };
        const char* sv = s.service==0x22?"DID 0x22":s.service==0x31?"Routine 0x31":"I/O 0x2F";
        QColor green(0x43,0xd1,0x7a), amber(0xf2,0xb1,0x34);
        set(0, sv);
        set(1, QString("%1").arg(s.id,4,16,QChar('0')));
        set(2, s.exists==1?"pos":"nrc", s.exists==1?&green:&amber);
        set(3, QString::fromStdString(s.note));
    }
}

void Gui::refreshLog() {
    auto entries = Logger::instance().snapshot();
    if (entries.size() < lastLogCount_) { logView_->clear(); lastLogCount_ = 0; }
    for (size_t i = lastLogCount_; i < entries.size(); ++i)
        logView_->appendPlainText(QString::fromStdString(Logger::format(entries[i])));
    lastLogCount_ = entries.size();
    if (cbAutoScroll_->isChecked())
        logView_->verticalScrollBar()->setValue(logView_->verticalScrollBar()->maximum());
}

// ==========================================================================
// Popups (positioned relative to the triggering widget)
// ==========================================================================
bool Gui::confirmPopup(QWidget* anchor, const QString& title,
                       const QString& body, const QString& okText) {
    QMessageBox box(this);
    box.setIcon(QMessageBox::Warning);
    box.setWindowTitle(title);
    box.setText(QString("<b>%1</b>").arg(title));
    box.setInformativeText(body);
    auto* ok = box.addButton(okText, QMessageBox::AcceptRole);
    box.addButton("Cancel", QMessageBox::RejectRole);
    box.setDefaultButton(qobject_cast<QPushButton*>(box.buttons().last()));
    if (anchor) box.move(anchor->mapToGlobal(QPoint(0, anchor->height() + 4)));
    box.exec();
    return box.clickedButton() == ok;
}

void Gui::openAddSignalDialog(QWidget* anchor) {
    auto* dlg = new QDialog(this);
    dlg->setWindowTitle("Add live signal");
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    auto* f = new QFormLayout(dlg);
    auto* edTarget = hexEdit("1003", 4);
    auto* edDid    = hexEdit("F190", 4);
    auto* edName   = new QLineEdit("Signal");
    auto* cbInterp = new QComboBox;
    cbInterp->addItems({"Raw hex", "Unsigned", "Signed", "ASCII"});
    auto* edScale  = new QLineEdit("1.0");
    auto* edOffset = new QLineEdit("0.0");
    auto* edUnit   = new QLineEdit;
    f->addRow("Target", edTarget);
    f->addRow("DID", edDid);
    f->addRow("Name", edName);
    f->addRow("Interpretation", cbInterp);
    f->addRow("Scale", edScale);
    f->addRow("Offset", edOffset);
    f->addRow("Unit", edUnit);
    auto* row = new QHBoxLayout;
    auto* ok = new QPushButton("Add"); ok->setObjectName("primary");
    auto* cancel = new QPushButton("Cancel");
    row->addStretch(1); row->addWidget(cancel); row->addWidget(ok);
    f->addRow(row);

    connect(cancel, &QPushButton::clicked, dlg, &QDialog::reject);
    connect(ok, &QPushButton::clicked, this, [=] {
        LiveSignal s;
        s.target = parseHex16(edTarget->text(), 0x1003);
        s.did    = parseHex16(edDid->text(), 0xF190);
        s.name   = edName->text().toStdString();
        s.interp = cbInterp->currentIndex();
        s.scale  = edScale->text().toDouble();
        s.offset = edOffset->text().toDouble();
        s.unit   = edUnit->text().toStdString();
        s.value  = "(waiting)";
        { std::lock_guard<std::mutex> g(mutex_); liveSignals_.push_back(std::move(s)); }
        dlg->accept();
    });

    if (anchor) dlg->move(anchor->mapToGlobal(QPoint(0, anchor->height() + 4)));
    dlg->show();
}

void Gui::openEcuDialog(int idx, QWidget* anchor) {
    EcuRow snapshot;
    { std::lock_guard<std::mutex> g(mutex_);
      if (idx < 0 || idx >= (int)ecus_.size()) return;
      snapshot = ecus_[idx]; }

    auto* dlg = new QDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowTitle(QString::fromStdString(snapshot.name));
    dlg->setMinimumWidth(560);
    auto* lay = new QVBoxLayout(dlg);

    // editable name + address
    auto* idRow = new QHBoxLayout;
    auto* edName = new QLineEdit(QString::fromStdString(snapshot.name));
    auto* edAddr = hexEdit(QString("%1").arg(snapshot.logicalAddr,4,16,QChar('0')), 4);
    idRow->addWidget(new QLabel("Name")); idRow->addWidget(edName, 1);
    idRow->addWidget(new QLabel("Addr")); idRow->addWidget(edAddr);
    lay->addLayout(idRow);
    connect(edName, &QLineEdit::editingFinished, this, [this, idx, edName] {
        std::lock_guard<std::mutex> g(mutex_);
        if (idx < (int)ecus_.size()) ecus_[idx].name = edName->text().toStdString();
    });
    connect(edAddr, &QLineEdit::editingFinished, this, [this, idx, edAddr] {
        std::lock_guard<std::mutex> g(mutex_);
        if (idx < (int)ecus_.size())
            ecus_[idx].logicalAddr = parseHex16(edAddr->text(), ecus_[idx].logicalAddr);
    });

    // action buttons (two rows)
    auto* r1 = new QHBoxLayout;
    auto* bRead = new QPushButton("Read DTCs");
    auto* bClear= new QPushButton("Clear DTCs"); bClear->setObjectName("danger");
    auto* bVin  = new QPushButton("Read ID (F190)");
    auto* bFull = new QPushButton("Full info");
    r1->addWidget(bRead); r1->addWidget(bClear); r1->addWidget(bVin); r1->addWidget(bFull);
    lay->addLayout(r1);
    auto* r2 = new QHBoxLayout;
    auto* bCount = new QPushButton("DTC count");
    auto* bSupp  = new QPushButton("Supported");
    auto* bLogOn = new QPushButton("Log on");
    auto* bLogOff= new QPushButton("Log off");
    auto* bReset = new QPushButton("ECU reset");
    r2->addWidget(bCount); r2->addWidget(bSupp); r2->addWidget(bLogOn);
    r2->addWidget(bLogOff); r2->addWidget(bReset);
    lay->addLayout(r2);

    auto* statusLbl = new QLabel; statusLbl->setWordWrap(true);
    auto* idLbl     = new QLabel; idLbl->setWordWrap(true);
    lay->addWidget(statusLbl);
    lay->addWidget(idLbl);

    auto* dtcTable = new QTableWidget(0, 4);
    dtcTable->setHorizontalHeaderLabels({"DTC", "Status", "Description", ""});
    dtcTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    dtcTable->setColumnWidth(0, 130);
    dtcTable->setColumnWidth(3, 90);
    dtcTable->verticalHeader()->setVisible(false);
    dtcTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    lay->addWidget(dtcTable, 1);

    auto targetOf = [this, idx]() -> uint16_t {
        syncSettingsFromUi();
        std::lock_guard<std::mutex> g(mutex_);
        if (useFunctional_) return (uint16_t)functionalAddr_;
        return idx < (int)ecus_.size() ? ecus_[idx].logicalAddr : 0;
    };

    // dialog refresh: status, id info, DTC table (rebuilt when size changes)
    auto* dtimer = new QTimer(dlg);
    auto refresh = [this, idx, statusLbl, idLbl, dtcTable, dlg, targetOf] {
        EcuRow r;
        { std::lock_guard<std::mutex> g(mutex_);
          if (idx >= (int)ecus_.size()) return;
          r = ecus_[idx]; }
        statusLbl->setText(QString("<b>status:</b> %1").arg(QString::fromStdString(r.statusMsg)));
        idLbl->setText(r.idInfo.empty() ? QString()
                       : QString("<pre style='white-space:pre-wrap'>%1</pre>")
                             .arg(QString::fromStdString(r.idInfo)));
        if (dtcTable->rowCount() != (int)r.dtcs.size())
            dtcTable->setRowCount((int)r.dtcs.size());
        for (size_t di = 0; di < r.dtcs.size(); ++di) {
            const Dtc& d = r.dtcs[di];
            auto set = [&](int c, const QString& t) {
                auto* it = dtcTable->item((int)di, c);
                if (!it) { it = new QTableWidgetItem; dtcTable->setItem((int)di, c, it); }
                it->setText(t);
            };
            char codebuf[16]; std::snprintf(codebuf, sizeof codebuf, "%06X", d.code);
            set(0, QString("%1 (%2)").arg(QString::fromStdString(d.text)).arg(codebuf));
            set(1, QString::fromStdString(decodeDtcStatus(d.status)));
            set(2, QString::fromStdString(dtcDescription(d.code)));
            if (!dtcTable->cellWidget((int)di, 3)) {
                auto* snap = new QPushButton("Snapshot");
                uint32_t code = d.code;
                connect(snap, &QPushButton::clicked, this, [this, idx, code, targetOf] {
                    uint16_t target = targetOf();
                    startWorker([this, idx, code, target] {
                        std::string err;
                        if (!ensureConnected(err)) { Logger::instance().error(err); return; }
                        UDSClient uds(client_, (uint16_t)testerAddr_);
                        std::vector<uint8_t> raw;
                        if (uds.readDTCSnapshot(target, code, 0xFF, raw, err)) {
                            std::lock_guard<std::mutex> g(mutex_);
                            if (idx < (int)ecus_.size())
                                ecus_[idx].statusMsg = "snapshot " +
                                    byteHex((code>>16)&0xFF)+byteHex((code>>8)&0xFF)+byteHex(code&0xFF) +
                                    ": " + toHex(raw.data(), raw.size());
                        } else { std::lock_guard<std::mutex> g(mutex_);
                            if (idx < (int)ecus_.size()) ecus_[idx].statusMsg = "snapshot failed: " + err; }
                    });
                });
                dtcTable->setCellWidget((int)di, 3, snap);
            }
        }
    };
    connect(dtimer, &QTimer::timeout, dlg, refresh);
    dtimer->start(250);
    refresh();

    // ---- wire actions ----
    connect(bRead, &QPushButton::clicked, this, [this, idx, targetOf] {
        uint16_t target = targetOf();
        startWorker([this, idx, target] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::vector<Dtc> dtcs;
            if (uds.readDTCByStatusMask(target, (uint8_t)statusMask_, dtcs, err)) {
                std::lock_guard<std::mutex> g(mutex_);
                if (idx < (int)ecus_.size()) {
                    ecus_[idx].dtcs = std::move(dtcs);
                    ecus_[idx].statusMsg = "read OK (" + std::to_string(ecus_[idx].dtcs.size()) + " DTC)";
                }
            } else { std::lock_guard<std::mutex> g(mutex_);
                if (idx < (int)ecus_.size()) ecus_[idx].statusMsg = "read failed: " + err;
                Logger::instance().error(err); }
        });
    });
    connect(bClear, &QPushButton::clicked, this, [this, idx, dlg, targetOf] {
        if (!confirmPopup(dlg, "Clear DTCs",
                "Erases stored fault history for this ECU. Record the codes "
                "first. Proceed?", "Yes, clear"))
            return;
        uint16_t target = targetOf();
        bool autoExt = autoExtendedOnClear_;
        startWorker([this, idx, target, autoExt] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            if (autoExt) { std::string se;
                if (uds.diagnosticSessionControl(target, UdsSession::Extended, se))
                    Logger::instance().info("Extended session for clear");
                else Logger::instance().warn("Extended session refused: " + se); }
            bool ok = uds.clearDiagnosticInformation(target, 0xFFFFFFu, err);
            std::lock_guard<std::mutex> g(mutex_);
            if (idx >= (int)ecus_.size()) return;
            if (ok) { ecus_[idx].dtcs.clear(); ecus_[idx].statusMsg = "DTCs cleared"; }
            else { ecus_[idx].statusMsg = "clear failed: " + err; Logger::instance().error(err); }
        });
    });
    connect(bVin, &QPushButton::clicked, this, [this, idx, targetOf] {
        uint16_t target = targetOf();
        startWorker([this, idx, target] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            auto data = uds.readDataByIdentifier(target, 0xF190, err);
            std::lock_guard<std::mutex> g(mutex_);
            if (idx >= (int)ecus_.size()) return;
            if (data) { std::string v(data->begin(), data->end()); ecus_[idx].idInfo = "VIN/F190: " + v; }
            else ecus_[idx].idInfo = "F190 failed: " + err;
        });
    });
    connect(bFull, &QPushButton::clicked, this, [this, idx, targetOf] {
        uint16_t target = targetOf();
        startWorker([this, idx, target] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            bool ok = false; std::string info = uds.readEcuIdentification(target, ok);
            std::lock_guard<std::mutex> g(mutex_);
            if (idx >= (int)ecus_.size()) return;
            ecus_[idx].idInfo = info; if (ok) ecus_[idx].reachable = 1;
        });
    });
    connect(bCount, &QPushButton::clicked, this, [this, idx, targetOf] {
        uint16_t target = targetOf(); uint8_t mask = (uint8_t)statusMask_;
        startWorker([this, idx, target, mask] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            uint16_t cnt = 0; uint8_t fmt = 0;
            std::lock_guard<std::mutex> g(mutex_);
            if (idx >= (int)ecus_.size()) return;
            if (uds.readNumberOfDTCByStatusMask(target, mask, cnt, fmt, err))
                ecus_[idx].statusMsg = std::to_string(cnt) + " DTC(s) for mask 0x" + byteHex(mask);
            else ecus_[idx].statusMsg = "count failed: " + err;
        });
    });
    connect(bSupp, &QPushButton::clicked, this, [this, idx, targetOf] {
        uint16_t target = targetOf();
        startWorker([this, idx, target] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            std::vector<Dtc> dtcs;
            if (uds.readSupportedDTC(target, dtcs, err)) {
                std::lock_guard<std::mutex> g(mutex_);
                if (idx >= (int)ecus_.size()) return;
                ecus_[idx].dtcs = std::move(dtcs);
                ecus_[idx].statusMsg = "supported list (" + std::to_string(ecus_[idx].dtcs.size()) + " DTC)";
            } else { std::lock_guard<std::mutex> g(mutex_);
                if (idx < (int)ecus_.size()) ecus_[idx].statusMsg = "supported-DTC failed: " + err; }
        });
    });
    connect(bLogOn, &QPushButton::clicked, this, [this, targetOf] {
        uint16_t target = targetOf();
        startWorker([this, target] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            if (!uds.controlDTCSetting(target, true, err)) Logger::instance().error(err);
        });
    });
    connect(bLogOff, &QPushButton::clicked, this, [this, targetOf] {
        uint16_t target = targetOf();
        startWorker([this, target] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            if (!uds.controlDTCSetting(target, false, err)) Logger::instance().error(err);
        });
    });
    connect(bReset, &QPushButton::clicked, this, [this, idx, dlg, targetOf] {
        QMessageBox box(dlg);
        box.setWindowTitle("ECU reset");
        box.setText("<b>ECU reset</b>");
        box.setInformativeText("Reset reboots the ECU and briefly drops "
            "communication. Do not reset a safety ECU while moving. Pick a type:");
        auto* hard = box.addButton("Hard (0x01)", QMessageBox::AcceptRole);
        auto* keyo = box.addButton("Key off/on (0x02)", QMessageBox::AcceptRole);
        auto* soft = box.addButton("Soft (0x03)", QMessageBox::AcceptRole);
        box.addButton("Cancel", QMessageBox::RejectRole);
        box.move(dlg->mapToGlobal(QPoint(20, 60)));
        box.exec();
        EcuResetType rt;
        if (box.clickedButton() == hard) rt = EcuResetType::HardReset;
        else if (box.clickedButton() == keyo) rt = EcuResetType::KeyOffOnReset;
        else if (box.clickedButton() == soft) rt = EcuResetType::SoftReset;
        else return;
        uint16_t target = targetOf();
        startWorker([this, idx, target, rt] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(client_, (uint16_t)testerAddr_);
            bool ok = uds.ecuReset(target, rt, err);
            std::lock_guard<std::mutex> g(mutex_);
            if (idx < (int)ecus_.size())
                ecus_[idx].statusMsg = ok ? "ECU reset issued" : ("reset failed: " + err);
        });
    });

    if (anchor) dlg->move(anchor->mapToGlobal(QPoint(anchor->width() + 8, 0)));
    dlg->show();
}

// ==========================================================================
// Settings sync + network helpers
// ==========================================================================
void Gui::syncSettingsFromUi() {
    if (edBroadcast_)  broadcastIp_ = edBroadcast_->text().toStdString();
    if (edGateway_)    gatewayIp_   = edGateway_->text().toStdString();
    if (sbPort_)       port_        = sbPort_->value();
    if (edTester_)     testerAddr_  = parseHex16(edTester_->text(), 0x0E80);
    if (edGwAddr_)     gatewayAddr_ = parseHex16(edGwAddr_->text(), 0x1001);
    if (edActivation_) activationType_ = parseHex16(edActivation_->text(), 0x00);
    if (edFunctional_) functionalAddr_ = parseHex16(edFunctional_->text(), 0xE400);
    if (cbFunctional_) useFunctional_  = cbFunctional_->isChecked();
    if (edStatusMask_) statusMask_   = parseHex16(edStatusMask_->text(), 0x08);
    if (cbSession_)    sessionType_  = cbSession_->currentIndex() + 1;
    if (cbAutoExt_)    autoExtendedOnClear_ = cbAutoExt_->isChecked();
    if (cbKeepAlive_)  keepAlive_    = cbKeepAlive_->isChecked();
    if (edSeedLevel_)  securityLevel_= parseHex16(edSeedLevel_->text(), 0x01);
    if (edKey_)        securityKeyHex_ = edKey_->text().toStdString();
    if (edSweepStart_) sweepStart_   = parseHex16(edSweepStart_->text(), 0x1000);
    if (edSweepEnd_)   sweepEnd_     = parseHex16(edSweepEnd_->text(), 0x10FF);
    if (cbSweepAdd_)   sweepAddDiscovered_ = cbSweepAdd_->isChecked();
    if (edSvcTarget_)  svcTarget_    = parseHex16(edSvcTarget_->text(), 0x1003);
    if (edSvcStart_)   svcStart_     = parseHex16(edSvcStart_->text(), 0x0000);
    if (edSvcEnd_)     svcEnd_       = parseHex16(edSvcEnd_->text(), 0x00FF);
    if (cbSvcDIDs_)    svcScanDIDs_  = cbSvcDIDs_->isChecked();
    if (cbSvcRoutines_)svcScanRoutines_ = cbSvcRoutines_->isChecked();
    if (cbSvcIO_)      svcScanIO_    = cbSvcIO_->isChecked();
    if (cbSvcSuspend_) svcSuspendDTC_= cbSvcSuspend_->isChecked();
    if (cbSvcExt_)     svcExtendedSess_ = cbSvcExt_->isChecked();
    if (cbSvcRestore_) svcRestoreAfter_ = cbSvcRestore_->isChecked();
    if (edSovdUrl_)    sovdBaseUrl_  = edSovdUrl_->text().toStdString();
    if (edSovdToken_)  sovdToken_    = edSovdToken_->text().toStdString();
    sovd_.setBaseUrl(sovdBaseUrl_);
    sovd_.setBearerToken(sovdToken_);
}

// Derive a SOVD component id from a free-text ECU name. SOVD uses lowercase
// string ids (e.g. "bms") where DoIP uses 16-bit logical addresses, so map the
// common VinFast modules and fall back to a sanitized first word.
std::string Gui::deriveSovdId(const std::string& ecuName) {
    std::string low;
    for (char c : ecuName) low += (char)std::tolower((unsigned char)c);
    auto has = [&](const char* s) { return low.find(s) != std::string::npos; };
    if (has("bms") || has("battery"))            return "bms";
    if (has("vcu") || has("vehicle control"))    return "vcu";
    if (has("gateway") || has("xgw") || has("gw")) return "gateway";
    // Fallback: first alphanumeric token, lowercased.
    std::string id;
    for (char c : low) {
        if (std::isalnum((unsigned char)c)) id += c;
        else if (!id.empty()) break;
    }
    return id;
}

// Probe an ECU's reachability over the SOVD backup endpoint by confirming the
// component is listed. Returns true and sets `detail` (e.g. "via SOVD (...)")
// when reachable. Runs on the worker thread; libcurl I/O is synchronous.
bool Gui::sovdProbe(const std::string& componentId, std::string& detail) {
    if (!sovd_.configured()) { detail = "SOVD not configured"; return false; }
    if (componentId.empty()) { detail = "no SOVD component id"; return false; }
    std::vector<sovd::Component> comps;
    std::string e;
    if (!sovd_.listComponents(comps, e)) { detail = "SOVD unreachable: " + e; return false; }
    for (const auto& c : comps)
        if (c.id == componentId) { detail = "via SOVD (" + c.name + ")"; return true; }
    detail = "SOVD endpoint has no component '" + componentId + "'";
    return false;
}


void Gui::startKeepAlive() {
    if (keepAliveRun_) return;
    keepAliveRun_ = true;
    keepAliveThread_ = std::thread([this] {
        while (keepAliveRun_) {
            if (client_.isConnected() && !busy_) {
                std::lock_guard<std::mutex> n(netMutex_);
                UDSClient uds(client_, (uint16_t)testerAddr_);
                std::string err;
                uds.testerPresent((uint16_t)gatewayAddr_, err, /*suppress=*/true);
            }
            for (int i = 0; i < 20 && keepAliveRun_; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}

void Gui::stopKeepAlive() {
    keepAliveRun_ = false;
    if (keepAliveThread_.joinable()) keepAliveThread_.join();
}

void Gui::startLivePoll() {
    if (liveRun_) return;
    liveRun_ = true;
    bool bundle = liveBundle_;
    liveThread_ = std::thread([this, bundle] {
        // Each live signal maps to a slice [off, off+len) of its target's
        // dynamic-DID response when bundling is active.
        struct SigRef { size_t idx; uint16_t target; uint16_t did; size_t off; size_t len; };
        struct TargetBundle { uint16_t target; uint16_t dddid; bool active; std::vector<SigRef> sigs; size_t total; };
        std::vector<TargetBundle> bundles;
        const uint16_t kDddBase = 0xF300;

        // ---- setup: define one dynamic DID per target (0x2C) ----
        if (bundle && client_.isConnected()) {
            std::vector<std::tuple<size_t, uint16_t, uint16_t>> snap;
            {
                std::lock_guard<std::mutex> g(mutex_);
                for (size_t i = 0; i < liveSignals_.size(); ++i)
                    snap.emplace_back(i, liveSignals_[i].target, liveSignals_[i].did);
            }
            std::lock_guard<std::mutex> n(netMutex_);
            UDSClient uds(client_, (uint16_t)testerAddr_);
            for (auto& [idx, tgt, did] : snap) {
                TargetBundle* tb = nullptr;
                for (auto& b : bundles) if (b.target == tgt) { tb = &b; break; }
                if (!tb) {
                    bundles.push_back({tgt, (uint16_t)(kDddBase + bundles.size()), false, {}, 0});
                    tb = &bundles.back();
                }
                // Learn each signal's byte length with a one-off 0x22.
                std::string e;
                auto r = uds.readDataByIdentifier(tgt, did, e);
                size_t len = r ? r->size() : 0;
                if (len == 0 || len > 0xFF) continue;
                tb->sigs.push_back({idx, tgt, did, tb->total, len});
                tb->total += len;
            }
            for (auto& b : bundles) {
                if (b.sigs.empty() || b.total == 0 || b.total > 0xFF) continue;
                std::vector<DddSource> srcs;
                for (auto& s : b.sigs) srcs.push_back({s.did, 1, (uint8_t)s.len});
                std::string e;
                std::string tgtHex = byteHex((b.target >> 8) & 0xFF) + byteHex(b.target & 0xFF);
                std::string didHex = byteHex((b.dddid >> 8) & 0xFF) + byteHex(b.dddid & 0xFF);
                if (uds.defineDynamicDataIdentifier(b.target, b.dddid, srcs, e)) {
                    b.active = true;
                    Logger::instance().info("Live: bundled " + std::to_string(b.sigs.size()) +
                        " signal(s) on 0x" + tgtHex + " into dynamic DID 0x" + didHex +
                        " (" + std::to_string(b.total) + " bytes/cycle)");
                } else {
                    Logger::instance().warn("Live: dynamic-DID bundle on 0x" + tgtHex +
                        " unavailable (" + e + "); using per-signal reads");
                }
            }
        }

        while (liveRun_) {
            if (!client_.isConnected() || busy_) {
                for (int i = 0; i < livePollMs_ / 20 + 1 && liveRun_; ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                continue;
            }

            // 1) Active bundles: one 0x22 reads the whole bundle, then split.
            std::set<size_t> covered;
            for (auto& b : bundles) {
                if (!b.active || !liveRun_) continue;
                std::vector<uint8_t> data; bool ok = false;
                {
                    std::lock_guard<std::mutex> n(netMutex_);
                    UDSClient uds(client_, (uint16_t)testerAddr_);
                    std::string err;
                    auto r = uds.readDataByIdentifier(b.target, b.dddid, err);
                    if (r) { data = std::move(*r); ok = true; }
                }
                std::lock_guard<std::mutex> g(mutex_);
                for (auto& s : b.sigs) {
                    covered.insert(s.idx);
                    if (s.idx >= liveSignals_.size()) continue;
                    LiveSignal& sig = liveSignals_[s.idx];
                    if (sig.target != s.target || sig.did != s.did) continue;
                    if (ok && data.size() >= s.off + s.len) {
                        std::vector<uint8_t> slice(data.begin() + s.off, data.begin() + s.off + s.len);
                        sig.rawHex = toHex(slice.data(), slice.size());
                        sig.value  = decodeLiveValue(slice, sig.interp, sig.scale, sig.offset, sig.unit);
                        sig.ok = 1;
                    } else sig.ok = 0;
                }
            }

            // 2) Remaining (unbundled) signals: per-signal 0x22.
            std::vector<std::pair<uint16_t, uint16_t>> items;
            {
                std::lock_guard<std::mutex> g(mutex_);
                items.reserve(liveSignals_.size());
                for (const auto& s : liveSignals_) items.emplace_back(s.target, s.did);
            }
            for (size_t i = 0; i < items.size() && liveRun_; ++i) {
                if (covered.count(i)) continue;
                if (!client_.isConnected() || busy_) break;
                std::vector<uint8_t> data; bool ok = false;
                {
                    std::lock_guard<std::mutex> n(netMutex_);
                    UDSClient uds(client_, (uint16_t)testerAddr_);
                    std::string err;
                    auto r = uds.readDataByIdentifier(items[i].first, items[i].second, err);
                    if (r) { data = std::move(*r); ok = true; }
                }
                std::lock_guard<std::mutex> g(mutex_);
                if (i >= liveSignals_.size()) break;
                LiveSignal& s = liveSignals_[i];
                if (s.target != items[i].first || s.did != items[i].second) continue;
                if (ok) {
                    s.rawHex = toHex(data.data(), data.size());
                    s.value  = decodeLiveValue(data, s.interp, s.scale, s.offset, s.unit);
                    s.ok = 1;
                } else s.ok = 0;
            }

            for (int i = 0; i < livePollMs_ / 20 + 1 && liveRun_; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        // ---- teardown: release the dynamic DIDs we defined ----
        if (client_.isConnected()) {
            std::lock_guard<std::mutex> n(netMutex_);
            UDSClient uds(client_, (uint16_t)testerAddr_);
            for (auto& b : bundles) {
                if (!b.active) continue;
                std::string e;
                uds.clearDynamicDataIdentifier(b.target, b.dddid, e);
            }
        }
    });
}

void Gui::stopLivePoll() {
    liveRun_ = false;
    if (liveThread_.joinable()) liveThread_.join();
}

void Gui::startWorker(std::function<void()> fn) {
    if (busy_) return;
    if (worker_.joinable()) worker_.join();
    busy_ = true;
    worker_ = std::thread([this, fn] { fn(); busy_ = false; });
}

bool Gui::ensureConnected(std::string& err) {
    if (client_.isConnected()) return true;
    if (!client_.connectTcp(gatewayIp_, (uint16_t)port_, err)) return false;
    if (!client_.routingActivation((uint16_t)testerAddr_, (uint8_t)activationType_, err)) {
        client_.disconnect();
        return false;
    }
    if (keepAlive_) startKeepAlive();
    return true;
}
