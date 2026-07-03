#include "Gui.hpp"
#include "BtDiscovery.hpp"
#include "Logger.hpp"
#include "VF8Data.hpp"
#include "CloudData.hpp"

#include <QStackedWidget>
#include <QListWidget>
#include <QListWidgetItem>
#include <QLabel>
#include <QPushButton>
#include <QToolButton>
#include <QDateTimeEdit>
#include <QDateTime>
#include <QTimeZone>
#include <QLineEdit>
#include <QSpinBox>
#include <QComboBox>
#include <QCheckBox>
#include <QFileDialog>
#include <QFile>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QProgressBar>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QScrollArea>
#include <QDialog>
#include <QMenu>
#include <QMessageBox>
#include <QTimer>
#include <QFont>
#include <QFrame>
#include <QScrollBar>
#include <QStyle>
#include <QColor>
#include <QSizePolicy>
#include <QAbstractItemView>
#include <QPainter>
#include <QPixmap>
#include <QPainterPath>
#include <QLinearGradient>
#include <QFontMetrics>
#include <QMouseEvent>
#include <QResizeEvent>

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <algorithm>
#include <set>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <mutex>

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

static std::string trimCopy(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace((unsigned char)s[b])) ++b;
    size_t e = s.size();
    while (e > b && std::isspace((unsigned char)s[e - 1])) --e;
    return s.substr(b, e - b);
}

static std::string extractDidValue(const std::string& idInfo, const char* label) {
    const std::string key = std::string(label) + " (";
    size_t pos = 0;
    while (pos < idInfo.size()) {
        size_t nl = idInfo.find('\n', pos);
        if (nl == std::string::npos) nl = idInfo.size();
        std::string line = trimCopy(idInfo.substr(pos, nl - pos));
        if (!line.empty() && line.rfind(key, 0) == 0) {
            size_t c = line.find(':');
            if (c != std::string::npos) return trimCopy(line.substr(c + 1));
        }
        pos = nl + 1;
    }
    return "";
}

static std::string extractScannedVin(const std::string& idInfo) {
    std::string v = extractDidValue(idInfo, "VIN");
    if (!v.empty()) return v;
    const std::string key = "VIN/F190:";
    size_t p = idInfo.find(key);
    if (p == std::string::npos) return "";
    return trimCopy(idInfo.substr(p + key.size()));
}

static std::string decodeVinModelYear(const std::string& vin) {
    if (vin.size() < 10) return "";
    static const char* code = "123456789ABCDEFGHJKLMNPRSTVWXY";
    char c = (char)std::toupper((unsigned char)vin[9]);
    const char* p = std::strchr(code, c);
    if (!p) return "";
    int year = 2001 + (int)(p - code);
    char out[8];
    std::snprintf(out, sizeof out, "%d", year);
    return out;
}

// ==========================================================================
// Engineering-menu TOTP candidate generation
//
// The VF8 engineering menu shows a 6-digit seed and uses a 30s time window.
// The real algorithm is not published, so we generate the most plausible
// 6-digit codes for a given (seed, time-step): the standard RFC 6238 TOTP
// (HMAC-SHA1, the canonical "TOTP" definition) under a few seed encodings,
// plus common ad-hoc arithmetic schemes. Self-contained SHA-1/HMAC so the GUI
// does not depend on CloudClient's internal (SHA-256-only) crypto.
// ==========================================================================
namespace {

struct Sha1Ctx { uint32_t h[5]; };
static uint32_t rol32(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }

static void sha1Block(Sha1Ctx& s, const uint8_t* p) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 80; ++i)
        w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint32_t a = s.h[0], b = s.h[1], c = s.h[2], d = s.h[3], e = s.h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
        uint32_t t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d; s.h[4] += e;
}

static std::string sha1Raw(const std::string& msg) {
    Sha1Ctx s = {{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}};
    size_t len = msg.size(), full = len / 64;
    for (size_t i = 0; i < full; ++i)
        sha1Block(s, (const uint8_t*)msg.data() + i * 64);
    uint8_t block[64] = {0};
    size_t rem = len - full * 64;
    std::memcpy(block, msg.data() + full * 64, rem);
    block[rem] = 0x80;
    if (rem >= 56) { sha1Block(s, block); std::memset(block, 0, 64); }
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; ++i) block[63 - i] = (uint8_t)(bits >> (i * 8));
    sha1Block(s, block);
    std::string out(20, '\0');
    for (int i = 0; i < 5; ++i) {
        out[i*4]   = (char)(s.h[i] >> 24); out[i*4+1] = (char)(s.h[i] >> 16);
        out[i*4+2] = (char)(s.h[i] >> 8);  out[i*4+3] = (char)(s.h[i]);
    }
    return out;
}

static std::string hmacSha1Raw(const std::string& keyIn, const std::string& msg) {
    std::string k = keyIn;
    if (k.size() > 64) k = sha1Raw(k);
    k.resize(64, '\0');
    std::string ipad(64, '\0'), opad(64, '\0');
    for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    return sha1Raw(opad + sha1Raw(ipad + msg));
}

// RFC 4226 / 6238 dynamic truncation to `digits` decimal digits.
static QString hotp(const std::string& keyRaw, uint64_t counter, int digits) {
    uint8_t msg[8];
    for (int i = 0; i < 8; ++i) msg[7 - i] = (uint8_t)(counter >> (i * 8));
    std::string hs = hmacSha1Raw(keyRaw, std::string((const char*)msg, 8));
    int off = hs[19] & 0x0f;
    uint32_t bin = (((uint32_t)(hs[off] & 0x7f)) << 24) |
                   ((uint32_t)(uint8_t)hs[off+1] << 16) |
                   ((uint32_t)(uint8_t)hs[off+2] << 8)  |
                   ((uint32_t)(uint8_t)hs[off+3]);
    uint32_t mod = 1; for (int i = 0; i < digits; ++i) mod *= 10;
    char buf[16]; std::snprintf(buf, sizeof buf, "%0*u", digits, bin % mod);
    return buf;
}

static QString to6(uint64_t v) {
    char buf[8];
    std::snprintf(buf, sizeof buf, "%06llu", (unsigned long long)(v % 1000000ULL));
    return buf;
}

// All candidate (method, 6-digit code) pairs for one 30s time-step.
// dtTs is the adjusted (region-offset) unix time for this step, used to build
// the broken-down UTC datetime values the engineering menu actually keys off.
static std::vector<std::pair<QString, QString>>
totpCandidates(uint64_t seed, const QString& seedStr, uint64_t step, long long dtTs) {
    std::vector<std::pair<QString, QString>> out;

    // RFC 6238 standard TOTP (HMAC-SHA1) - the canonical, most-likely method.
    // Try the plausible encodings of the 6-digit seed as the shared secret.
    auto beBytes = [](uint64_t v, int n) {
        std::string s((size_t)n, '\0');
        for (int i = 0; i < n; ++i) s[n - 1 - i] = (char)(v >> (i * 8));
        return s;
    };
    out.push_back({"RFC6238 TOTP (seed ASCII)",  hotp(seedStr.toStdString(), step, 6)});
    out.push_back({"RFC6238 TOTP (seed u32 BE)", hotp(beBytes(seed, 4), step, 6)});
    out.push_back({"RFC6238 TOTP (seed u64 BE)", hotp(beBytes(seed, 8), step, 6)});

    // Ad-hoc arithmetic schemes against the 30s step (speculative but cheap).
    uint64_t key = seed;
    struct M { QString name; uint64_t val; };
    const std::vector<M> arith = {
        {"key + step",                        key + step},
        {"key * step",                        key * step},
        {"key ^ step",                        key ^ step},
        {"(key*step) ^ (key+step)",           (key * step) ^ (key + step)},
        {"key*step + step",                   key * step + step},
        {"(key+step)*1234567 % 999999",       (key + step) * 1234567ULL % 999999ULL},
        {"key*1234567 % 999999",              key * 1234567ULL % 999999ULL},
        {"key*31 + step",                     key * 31 + step},
        {"step*131 + key",                    step * 131 + key},
        {"(key<<5) ^ step",                   (key << 5) ^ step},
        {"step ^ (key*17)",                   step ^ (key * 17)},
        {"(key ^ 0xAAAAAAAA) + step",         (key ^ 0xAAAAAAAAULL) + step},
        {"key*step % 999983",                 key * step % 999983ULL},
        {"(key + step*step) % 1000000",       (key + step * step) % 1000000ULL},
        {"key*6364136223846793005 ^ step",    (key * 6364136223846793005ULL) ^ step},
    };
    for (const auto& m : arith) out.push_back({m.name, to6(m.val)});

    // Datetime-based schemes: the engineering menu keys off a UTC datetime
    // value (broken-down calendar fields), not the raw 30s counter.
    std::time_t tt = (std::time_t)dtTs;
    std::tm g{};
#ifdef _WIN32
    gmtime_s(&g, &tt);
#else
    gmtime_r(&tt, &g);
#endif
    uint64_t Y  = (uint64_t)(g.tm_year + 1900);
    uint64_t Mo = (uint64_t)(g.tm_mon + 1);
    uint64_t D  = (uint64_t)g.tm_mday;
    uint64_t H  = (uint64_t)g.tm_hour;
    uint64_t Mi = (uint64_t)g.tm_min;
    uint64_t S  = (uint64_t)g.tm_sec;

    uint64_t ymdhms = ((((Y * 100 + Mo) * 100 + D) * 100 + H) * 100 + Mi) * 100 + S; // YYYYMMDDHHMMSS
    uint64_t ymdhm  = (((Y * 100 + Mo) * 100 + D) * 100 + H) * 100 + Mi;             // YYYYMMDDHHMM
    uint64_t ymdh   = ((Y * 100 + Mo) * 100 + D) * 100 + H;                          // YYYYMMDDHH
    uint64_t ymd    = (Y * 100 + Mo) * 100 + D;                                      // YYYYMMDD
    uint64_t hms    = (H * 100 + Mi) * 100 + S;                                      // HHMMSS
    uint64_t hm     = H * 100 + Mi;                                                  // HHMM

    const std::vector<M> dt = {
        {"YYYYMMDDHHMM (raw)",                ymdhm},
        {"key + YYYYMMDDHHMM",                key + ymdhm},
        {"key * YYYYMMDDHHMM % 1000000",      key * ymdhm % 1000000ULL},
        {"key ^ YYYYMMDDHHMM",                key ^ ymdhm},
        {"(key + YYYYMMDDHHMM) % 1000000",    (key + ymdhm) % 1000000ULL},
        {"key + YYYYMMDDHH",                  key + ymdh},
        {"key ^ YYYYMMDDHH",                  key ^ ymdh},
        {"key + YYYYMMDDHHMMSS",              key + ymdhms},
        {"key ^ YYYYMMDDHHMMSS",              key ^ ymdhms},
        {"key + YYYYMMDD",                    key + ymd},
        {"(key * YYYYMMDD) % 999999",         key * ymd % 999999ULL},
        {"key + HHMMSS",                      key + hms},
        {"key + HHMM",                        key + hm},
        {"key ^ HHMM",                        key ^ hm},
        {"(key + HHMM) * 1234567 % 999999",   (key + hm) * 1234567ULL % 999999ULL},
    };
    for (const auto& m : dt) out.push_back({m.name, to6(m.val)});

    // RFC 6238 with the datetime value used as the moving counter.
    out.push_back({"RFC6238(YYYYMMDDHHMM ctr, ASCII)", hotp(seedStr.toStdString(), ymdhm, 6)});
    out.push_back({"RFC6238(YYYYMMDDHH ctr, ASCII)",   hotp(seedStr.toStdString(), ymdh,  6)});
    return out;
}

} // namespace

// ==========================================================================
// EcuTopologyView - Autel-style "module topology" diagram.
//
// Each module is drawn as a coloured node that hangs off one of three coloured
// communication buses (drive / comfort / information). The buses fan out from
// the gateway beside the OBD connector, exactly like a vehicle network map.
// Faulted modules turn orange and carry a red fault-count badge; clicking a
// node opens that ECU's diagnostics dialog.
// ==========================================================================
class EcuTopologyView : public QWidget {
public:
    struct Node {
        QString code;
        QString addr;
        QString fullName;
        int     state    = 0;   // 0 not scanned, 1 pass, 2 fault, 3 no response
        int     faults   = 0;
        int     ecuIndex = -1;
        int     bus      = 1;   // 0 drive, 1 comfort, 2 information
        int     col      = 0;   // column within its band row
        bool    below    = false;
        bool    gateway  = false;
        QRect   rect;           // computed in relayout(), used for hit-testing
    };

    explicit EcuTopologyView(QWidget* parent = nullptr) : QWidget(parent) {
        setMinimumSize(760, 500);
        setMouseTracking(true);
        setCursor(Qt::PointingHandCursor);

        // Separate animation repaint cadence from data refresh cadence so
        // scanning sweeps stay fluid.
        animTimer_.setInterval(33);
        connect(&animTimer_, &QTimer::timeout, this, [this] {
            if (hasScanningNodes_) update();
        });
        animTimer_.start();
    }

    std::function<void(int, QWidget*)> onClick;

    void setNodes(std::vector<Node> nodes) {
        nodes_ = std::move(nodes);
        hasScanningNodes_ = false;
        for (const auto& n : nodes_) {
            if (n.state == 4) { hasScanningNodes_ = true; break; }
        }
        relayout();
        update();
    }

protected:
    void resizeEvent(QResizeEvent*) override { relayout(); }
    void mousePressEvent(QMouseEvent* e) override {
        for (const auto& n : nodes_)
            if (n.ecuIndex >= 0 && n.rect.contains(e->pos())) {
                if (onClick) onClick(n.ecuIndex, this);
                return;
            }
    }
    void mouseMoveEvent(QMouseEvent* e) override {
        QString tip;
        for (const auto& n : nodes_)
            if (n.rect.contains(e->pos())) { tip = n.fullName; break; }
        setToolTip(tip);
    }
    void paintEvent(QPaintEvent*) override;

private:
    static QColor stateFill(int s) {
        switch (s) {
            case 1:  return QColor(0x20, 0xc5, 0x5a); // pass
            case 2:  return QColor(0xf4, 0x87, 0x20); // fault
            case 3:  return QColor(0x7e, 0x87, 0x94); // no response
            case 4:  return QColor(0x2e, 0x7d, 0xd1); // scanning
            default: return QColor(0x1f, 0x7b, 0xd6); // not scanned
        }
    }
    static QColor busColor(int b) {
        switch (b) {
            case 0:  return QColor(0x3f, 0x8a, 0xe0); // drive (blue)
            case 2:  return QColor(0xb1, 0x5c, 0xd0); // information (purple)
            default: return QColor(0xe0, 0x55, 0x6a); // comfort (red)
        }
    }

    void drawNode(QPainter& p, const Node& n);

    void relayout() {
        const int W = width();
        for (int b = 0; b < 3; ++b)
            trunkY_[b] = marginTop_ + b * bandPitch_ + nodeH_ + dropGap_;
        const int cy = trunkY_[1];

        obdRect_ = QRect(12, cy - 34, 68, 68);
        gwRect_  = QRect(98, cy - nodeH_ / 2, 62, nodeH_);
        spineX_  = 166;

        const int contentLeft  = 180;
        const int contentRight = W - 56;
        const int span  = std::max(contentRight - contentLeft, 7 * 70);
        const int cellW = span / 7;

        int cnt[3][2] = {{0,0},{0,0},{0,0}};
        for (const auto& n : nodes_)
            if (!n.gateway) cnt[n.bus][n.below ? 1 : 0]++;

        for (auto& n : nodes_) {
            if (n.gateway) { n.rect = gwRect_; continue; }
            const int k = cnt[n.bus][n.below ? 1 : 0];
            const int rowW = k * cellW;
            const int startX = contentLeft + (span - rowW) / 2;
            const int nodeW = std::min(cellW - 12, 116);
            const int x = startX + n.col * cellW + (cellW - nodeW) / 2;
            const int y = n.below ? (trunkY_[n.bus] + dropGap_)
                                  : (trunkY_[n.bus] - dropGap_ - nodeH_);
            n.rect = QRect(x, y, nodeW, nodeH_);
        }

        setMinimumHeight(marginTop_ + 3 * bandPitch_ + 12);
    }

    std::vector<Node> nodes_;
    QPixmap obdPixmap_{QStringLiteral(":/images/obd-connector.png")};
    int   marginTop_ = 18;
    int   nodeH_     = 46;
    int   dropGap_   = 26;
    int   bandPitch_ = 46 + 26 + 26 + 46 + 30; // nodeH + drop + drop + nodeH + gap
    int   trunkY_[3] = {0, 0, 0};
    int   spineX_    = 154;
    QRect gwRect_;
    QRect obdRect_;
    QTimer animTimer_;
    bool hasScanningNodes_ = false;
};

void EcuTopologyView::drawNode(QPainter& p, const Node& n) {
    const QColor fill = stateFill(n.state);
    p.setPen(QPen(fill.lighter(125), 1.5));
    p.setBrush(fill);
    p.drawRoundedRect(n.rect, 6, 6);

    if (n.state == 4) {
        // Animated scan halo and clear left-to-right sweep for in-progress scans.
        const qint64 t = QDateTime::currentMSecsSinceEpoch();
        const int periodMs = 900;
        const int tick = (int)((t + (qint64)n.ecuIndex * 70) % periodMs);
        const int pad = (tick * 6) / periodMs;
        const QRect halo = n.rect.adjusted(-4 - pad, -4 - pad, 4 + pad, 4 + pad);
        const int a = 140 - pad * 14;
        p.setPen(QPen(QColor(0x2e, 0x7d, 0xd1, a > 30 ? a : 30), 2));
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(halo, 7 + pad, 7 + pad);

        const int trail = 16;
        const int span = n.rect.width() + trail * 2;
        const int sx = n.rect.left() - trail + (tick * span) / periodMs;

        // trailing beam body
        QRect sweepBody(sx - trail, n.rect.top() + 4, trail, n.rect.height() - 8);
        sweepBody = sweepBody.intersected(n.rect.adjusted(2, 3, -2, -3));
        if (!sweepBody.isEmpty()) {
            p.fillRect(sweepBody, QColor(0xff, 0xff, 0xff, 85));
        }

        // bright scan head
        p.setPen(QPen(QColor(0xff, 0xff, 0xff, 210), 2));
        p.drawLine(sx, n.rect.top() + 4, sx, n.rect.bottom() - 4);
    }

    QFont f = p.font();
    f.setBold(true);
    f.setPointSize(n.gateway ? 11 : 10);
    p.setFont(f);
    p.setPen(QColor(0xff, 0xff, 0xff));

    if (n.gateway || n.addr.isEmpty()) {
        const QString label =
            QFontMetrics(f).elidedText(n.code, Qt::ElideRight, n.rect.width() - 8);
        p.drawText(n.rect, Qt::AlignCenter, label);
    } else {
        // code on top, address on a dimmer second line
        QRect top(n.rect.left(), n.rect.top() + 5, n.rect.width(), n.rect.height() / 2 - 1);
        QRect bot(n.rect.left(), n.rect.center().y() + 1, n.rect.width(), n.rect.height() / 2 - 3);
        const QString code =
            QFontMetrics(f).elidedText(n.code, Qt::ElideRight, n.rect.width() - 8);
        p.drawText(top, Qt::AlignHCenter | Qt::AlignVCenter, code);
        QFont af = f; af.setBold(false); af.setPointSize(8); p.setFont(af);
        p.setPen(QColor(0xff, 0xff, 0xff, 200));
        const QString addr =
            QFontMetrics(af).elidedText(n.addr, Qt::ElideRight, n.rect.width() - 8);
        p.drawText(bot, Qt::AlignHCenter | Qt::AlignVCenter, addr);
    }

    if (n.faults > 0) {
        const int r = 10;
        const QPoint c(n.rect.right() - 2, n.rect.top() + 2);
        const QRect br(c.x() - r, c.y() - r, 2 * r, 2 * r);
        p.setPen(QPen(QColor(0xff, 0xff, 0xff), 1.5));
        p.setBrush(QColor(0xe2, 0x3a, 0x2c));
        p.drawEllipse(br);
        QFont bf = f; bf.setPointSize(8); p.setFont(bf);
        p.setPen(QColor(0xff, 0xff, 0xff));
        p.drawText(br, Qt::AlignCenter, QString::number(n.faults));
    }
}

void EcuTopologyView::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    QLinearGradient bg(0, 0, width(), height());
    bg.setColorAt(0.0, QColor(0xff, 0xff, 0xff));
    bg.setColorAt(0.5, QColor(0xfd, 0xff, 0xff));
    bg.setColorAt(1.0, QColor(0xf8, 0xfb, 0xff));
    p.fillRect(rect(), bg);

    const int contentRight = width() - 56;
    const int cy = trunkY_[1];

    // neutral left riser linking the three coloured trunks
    p.setPen(QPen(QColor(0x4a, 0x6f, 0x96), 2));
    p.drawLine(spineX_, trunkY_[0], spineX_, trunkY_[2]);

    // three coloured bus trunks, each ending in a chassis-ground symbol
    static const char* kBusName[3] = {"drive", "comfort", "information"};
    for (int b = 0; b < 3; ++b) {
        p.setPen(QPen(busColor(b), 3));
        p.drawLine(spineX_, trunkY_[b], contentRight, trunkY_[b]);
        const int gx = contentRight + 6, gy = trunkY_[b];
        p.drawLine(gx, gy, gx + 10, gy);
        p.drawLine(gx + 10, gy - 7, gx + 10, gy + 7);
        p.drawLine(gx + 13, gy - 4, gx + 13, gy + 4);
        p.drawLine(gx + 16, gy - 2, gx + 16, gy + 2);

        // bus name label sitting just above the trunk start
        QFont nf = p.font(); nf.setBold(true); nf.setPointSize(8); p.setFont(nf);
        p.setPen(busColor(b).lighter(135));
        p.drawText(QRect(spineX_ + 6, trunkY_[b] - 16, 120, 14),
                   Qt::AlignLeft | Qt::AlignVCenter, kBusName[b]);
    }

    // vertical drop from each node to its trunk
    for (const auto& n : nodes_) {
        if (n.gateway) continue;
        p.setPen(QPen(busColor(n.bus), 2));
        const int xc = n.rect.center().x();
        if (n.below) p.drawLine(xc, n.rect.top(), xc, trunkY_[n.bus]);
        else         p.drawLine(xc, n.rect.bottom(), xc, trunkY_[n.bus]);
    }

    // OBD connector -> gateway -> spine (comfort-bus colour)
    p.setPen(QPen(busColor(1), 3));
    p.drawLine(obdRect_.right(), cy, gwRect_.left(), cy);
    p.drawLine(gwRect_.right(), cy, spineX_, cy);

    // OBD connector glyph
    const QRect ob = obdRect_;
    if (!obdPixmap_.isNull()) {
        const QPixmap scaled = obdPixmap_.scaled(
            ob.size(), Qt::KeepAspectRatio, Qt::SmoothTransformation);
        const QPoint at(ob.left() + (ob.width() - scaled.width()) / 2,
                        ob.top() + (ob.height() - scaled.height()) / 2);
        p.drawPixmap(at, scaled);
    } else {
        p.setPen(QPen(QColor(0x4a, 0x5f, 0x78), 2));
        p.setBrush(QColor(0xe8, 0xf0, 0xf9));
        p.drawRoundedRect(ob, 6, 6);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(0x5f, 0x75, 0x8f));
        for (int i = 0; i < 4; ++i) p.drawRect(ob.left() + 8 + i * 8, ob.top() + 12, 4, 8);
        for (int i = 0; i < 3; ++i) p.drawRect(ob.left() + 12 + i * 8, ob.top() + 30, 4, 8);
    }
    p.setPen(QColor(0x3a, 0x4e, 0x66));
    QFont lf = p.font(); lf.setPointSize(10); lf.setBold(true); p.setFont(lf);
    p.drawText(QRect(ob.left() - 2, ob.top() - 20, 70, 16),
               Qt::AlignLeft | Qt::AlignVCenter, "OBD");

    for (const auto& n : nodes_) drawNode(p, n);
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

    // Wire CAN as optional fallback for OpenXC transport failures.
    transport_.setCanBackup(&canBackup_);

    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, &Gui::onTick);
    timer_->start(200);

    setWindowTitle("VinFast VF8 - OpenXC USB/Bluetooth UDS Scanner");
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
    const char* items[] = {"Dashboard", "Connection", "ECU Topology",
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
    hdrSubtitle_ = new QLabel(QString("VIN %1   ·   %2")
                                  .arg(vf8::kVin).arg(vf8::kFirmware));
    hdrSubtitle_->setObjectName("subtitle");
    auto* titleCol = new QVBoxLayout();
    titleCol->setSpacing(0);
    titleCol->addWidget(title);
    titleCol->addWidget(hdrSubtitle_);
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
        if (transport_.isConnected() || canBackup_.isConnected()) {
            stopLivePoll();
            stopKeepAlive();
            transport_.disconnect();
            canBackup_.disconnect();
            std::lock_guard<std::mutex> g(mutex_);
            connStatus_ = "Disconnected";
            return;
        }
        syncSettingsFromUi();
        startWorker([this] {
            std::string err;
            if (ensureConnected(err)) {
                std::lock_guard<std::mutex> g(mutex_);
                connStatus_ = "Connected to OpenXC " + gatewayIp_;
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
    dashModel_ = new QLabel("-");
    dashVin_ = new QLabel("-");
    dashMarket_ = new QLabel("-");
    dashMhuSw_ = new QLabel("-");
    dashTbox_ = new QLabel("-");
    dashModules_ = new QLabel("-");
    dashVin_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    dashMhuSw_->setWordWrap(true);
    dashTbox_->setWordWrap(true);
    dashModules_->setWordWrap(false);
    form->addRow("Model", dashModel_);
    form->addRow("VIN", dashVin_);
    form->addRow("Market", dashMarket_);
    form->addRow("MHU SW", dashMhuSw_);
    form->addRow("TBOX", dashTbox_);
    form->addRow("Modules", dashModules_);
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
    addTile(0, 0, "OpenXC link\nstatus check", [this] {
        syncSettingsFromUi();
        startWorker([this] {
            std::string err;
            if (ensureConnected(err)) Logger::instance().info("OpenXC Bluetooth link ready");
            else Logger::instance().warn("OpenXC link: " + err);
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
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* inner = new QWidget;
    scroll->setWidget(inner);
    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->addWidget(scroll);

    auto* lay = new QVBoxLayout(inner);
    lay->setContentsMargins(18, 18, 18, 18);
    lay->setSpacing(14);

    // --- transport ---
    auto* net = card("OpenXC USB/Bluetooth Transport");
    auto* nf = new QFormLayout(net);
    edGateway_   = new QLineEdit(QString::fromStdString(gatewayIp_));
    edGateway_->setPlaceholderText("/dev/ttyUSB0, /dev/cu.usbmodem*, COM3, or Bluetooth MAC");
    usbScanBtn_  = new QPushButton("Scan USB");
    usbScanBtn_->setToolTip(
        "List available USB/serial ports that may host an OpenXC VI.\n"
        "USB is preferred because Bluetooth RFCOMM is only reliable on Linux.");
    usbScanBtn_->setFixedWidth(72);
    btScanBtn_   = new QPushButton("Scan BT");
    btScanBtn_->setToolTip(
        "Query macOS Bluetooth for paired OpenXC VI devices.\n"
        "Selects the device path automatically if exactly one is found.");
    btScanBtn_->setFixedWidth(72);

    auto* devRow = new QHBoxLayout;
    devRow->setContentsMargins(0, 0, 0, 0);
    devRow->addWidget(edGateway_);
    devRow->addWidget(usbScanBtn_);
    devRow->addWidget(btScanBtn_);

    // USB scan: enumerate serial ports and present a popup menu.
    connect(usbScanBtn_, &QPushButton::clicked, this, [this] {
        auto ports = openxc::Client::enumerateUsbSerialPorts();
        if (ports.empty()) {
            QMessageBox::information(
                this, "USB serial scan",
                "No USB serial ports found.\n\n"
                "Connect the OpenXC VI via USB and ensure its driver is loaded,\n"
                "then click Scan USB again.");
            return;
        }
        if (ports.size() == 1) {
            edGateway_->setText(QString::fromStdString(ports[0]));
            Logger::instance().info("Auto-selected USB serial port: " + ports[0]);
            return;
        }
        auto* menu = new QMenu(usbScanBtn_);
        for (const auto& p : ports) {
            auto* act = menu->addAction(QString::fromStdString(p));
            connect(act, &QAction::triggered, this,
                    [this, p] { edGateway_->setText(QString::fromStdString(p)); });
        }
        menu->popup(usbScanBtn_->mapToGlobal(usbScanBtn_->rect().bottomLeft()));
    });

    // Bluetooth scan: enumerate paired SPP devices via IOBluetooth and populate
    // a popup menu so the user can pick (or auto-fill if only one found).
    connect(btScanBtn_, &QPushButton::clicked, this, [this] {
        btScanBtn_->setEnabled(false);
        btScanBtn_->setText("…");

        startWorker([this] {
            auto devices = bt::pairedSppDevices();

            // Post back to the UI thread.
            QMetaObject::invokeMethod(this, [this, devices = std::move(devices)]() mutable {
                btScanBtn_->setEnabled(true);
                btScanBtn_->setText("Scan BT");

                if (devices.empty()) {
                    QMessageBox::information(
                        this, "Bluetooth scan",
                        "No paired OpenXC VI devices found.\n\n"
                        "Pair the device in macOS Bluetooth settings first,\n"
                        "then click Scan BT again.");
                    return;
                }

                if (devices.size() == 1) {
                    // Auto-fill: use devPath if available, else MAC address.
                    const auto& d = devices[0];
                    QString val = QString::fromStdString(
                        d.devPath.empty() ? d.address : d.devPath);
                    edGateway_->setText(val);
                    Logger::instance().info(
                        "Auto-selected OpenXC Bluetooth device: " + d.name +
                        " → " + val.toStdString());
                    return;
                }

                // Multiple devices: show a popup menu.
                auto* menu = new QMenu(btScanBtn_);
                for (const auto& d : devices) {
                    QString label = QString::fromStdString(d.name);
                    if (!d.address.empty())
                        label += "  [" + QString::fromStdString(d.address) + "]";
                    if (!d.devPath.empty())
                        label += "  " + QString::fromStdString(d.devPath);
                    else if (d.connected)
                        label += "  (connected)";
                    auto* act = menu->addAction(label);
                    QString val = QString::fromStdString(
                        d.devPath.empty() ? d.address : d.devPath);
                    connect(act, &QAction::triggered, this,
                            [this, val] { edGateway_->setText(val); });
                }
                menu->popup(btScanBtn_->mapToGlobal(btScanBtn_->rect().bottomLeft()));
            }, Qt::QueuedConnection);
        });
    });

    nf->addRow("OpenXC device", devRow);
    edTester_    = hexEdit("0E80", 4);
    edGwAddr_    = hexEdit("1001", 4);
    nf->addRow("Tester source addr", edTester_);
    nf->addRow("Default target addr", edGwAddr_);
    sbOpenxcBus_ = new QSpinBox; sbOpenxcBus_->setRange(1, 2); sbOpenxcBus_->setValue(openxcBus_);
    nf->addRow("OpenXC CAN bus", sbOpenxcBus_);
    edCanIdBase_ = new QLineEdit(QString::asprintf("0x%X", canIdBase_));
    edCanIdBase_->setPlaceholderText("0x700");
    edCanRespOffset_ = new QLineEdit(QString::asprintf("0x%X", canRespOffset_));
    edCanRespOffset_->setPlaceholderText("0x8");
    auto* canIdRow = new QHBoxLayout;
    canIdRow->addWidget(new QLabel("Base req ID")); canIdRow->addWidget(edCanIdBase_);
    canIdRow->addWidget(new QLabel("Resp offset")); canIdRow->addWidget(edCanRespOffset_);
    canIdRow->addStretch(1);
    nf->addRow("CAN ID mapping", canIdRow);
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
    edKeepAliveTarget_ = hexEdit("1001", 4);
    auto* kaRow = new QHBoxLayout;
    kaRow->addWidget(cbKeepAlive_);
    kaRow->addSpacing(10);
    kaRow->addWidget(new QLabel("Keep-alive target"));
    kaRow->addWidget(edKeepAliveTarget_);
    kaRow->addStretch(1);
    sf->addRow(kaRow);
    connect(cbKeepAlive_, &QCheckBox::toggled, this, [this](bool on) {
        keepAlive_ = on;
        if (on && transport_.isConnected()) startKeepAlive();
        if (!on) stopKeepAlive();
    });

    auto* sbtns = new QHBoxLayout;
    auto* enterBtn = new QPushButton("Enter session");
    auto* tpBtn    = new QPushButton("Tester present");
    sbtns->addWidget(enterBtn); sbtns->addWidget(tpBtn); sbtns->addStretch(1);
    sf->addRow(sbtns);

    edSecurityTarget_ = hexEdit("1001", 4);
    sf->addRow("Session/Security target", edSecurityTarget_);
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
    auto* disc = card("Address Sweep");
    auto* df = new QVBoxLayout(disc);
    auto* discBtn = new QPushButton("OpenXC link check");
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
    auto* discNote = new QLabel(
        "<i>OpenXC transport uses Bluetooth RFCOMM to the VI. Use sweep/enumeration "
        "to find responsive diagnostic addresses.</i>");
    discNote->setWordWrap(true);
    df->addWidget(discNote);
    lay->addWidget(disc);


    // --- CAN backup (UDS over ISO 15765 via mvci32.dll, used if OpenXC fails) ---
    auto* canc = card("CAN Backup  (UDS over ISO 15765, used if OpenXC fails)");
    auto* cvf = new QFormLayout(canc);
    cbCanEnabled_ = new QCheckBox("Enable CAN fallback");
    cbCanEnabled_->setChecked(canEnabled_);
    edCanDll_ = new QLineEdit(QString::fromStdString(canDll_));
    edCanDll_->setPlaceholderText("mvci32.dll  (MVCI D-PDU API)");
    auto* btnCanDll = new QPushButton("Browse...");
    auto* dllRow = new QHBoxLayout();
    dllRow->setContentsMargins(0, 0, 0, 0);
    dllRow->addWidget(edCanDll_, 1);
    dllRow->addWidget(btnCanDll);
    auto* dllRowW = new QWidget();
    dllRowW->setLayout(dllRow);
    edCanBaud_ = new QLineEdit(QString::number(canBaud_));
    edCanBaud_->setPlaceholderText("500000");
    edCanReqId_ = new QLineEdit(QString::asprintf("0x%X", canReqId_));
    edCanReqId_->setPlaceholderText("0x7E0");
    edCanRespId_ = new QLineEdit(QString::asprintf("0x%X", canRespId_));
    edCanRespId_->setPlaceholderText("0x7E8");
    cbCanExt_ = new QCheckBox("29-bit (extended) identifiers");
    cbCanExt_->setChecked(canExtended_);
    cvf->addRow(cbCanEnabled_);
    cvf->addRow("D-PDU API DLL", dllRowW);
    cvf->addRow("Baud rate", edCanBaud_);
    cvf->addRow("Request CAN ID", edCanReqId_);
    cvf->addRow("Response CAN ID", edCanRespId_);
    cvf->addRow(cbCanExt_);
    connect(btnCanDll, &QPushButton::clicked, this, [this] {
        QString start = edCanDll_->text().trimmed();
        QString fn = QFileDialog::getOpenFileName(
            this, "Select MVCI D-PDU API library", start,
            "Dynamic libraries (*.dll *.so *.dylib);;All files (*)");
        if (!fn.isEmpty()) edCanDll_->setText(fn);
    });
    auto* canNote = new QLabel(
        "<i>Windows only. When an OpenXC exchange fails, requests are retried over "
        "CAN using the MVCI D-PDU API (mvci32.dll). ISO-TP segmentation is "
        "handled by the VCI.</i>");
    canNote->setWordWrap(true);
    cvf->addRow(canNote);
    auto* btnCanScan = new QPushButton("CAN Bus Scan...");
    btnCanScan->setToolTip("Probe every protocol, baud rate, addressing mode "
                           "and ID the MVCI supports to find responding ECUs.");
    cvf->addRow(btnCanScan);
    connect(btnCanScan, &QPushButton::clicked, this,
            [this, btnCanScan] { syncSettingsFromUi(); openCanScanDialog(btnCanScan); });
    lay->addWidget(canc);

    lay->addStretch(1);

    // ---- wiring ----
    connect(enterBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        int s = sessionType_;
        startWorker([this, s] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            if (uds.diagnosticSessionControl((uint16_t)securityTarget_, (UdsSession)s, err))
                Logger::instance().info("Session 0x" + byteHex((uint8_t)s) + " active");
            else Logger::instance().error("SessionControl: " + err);
        });
    });
    connect(tpBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        startWorker([this] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            auto seed = uds.requestSeed((uint16_t)securityTarget_, (uint8_t)lvl, err);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            if (uds.sendKey((uint16_t)securityTarget_, (uint8_t)lvl, key, err))
                Logger::instance().info("Security unlocked (level 0x" + byteHex((uint8_t)lvl) + ")");
            else Logger::instance().error("SendKey: " + err);
        });
    });
    connect(discBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        startWorker([this] {
            std::string err;
            if (ensureConnected(err)) Logger::instance().info("OpenXC Bluetooth link ready");
            else Logger::instance().warn("OpenXC link: " + err);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            int found = 0;
            for (int a = start; a <= end && transport_.isConnected(); ++a) {
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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

    auto* title = new QLabel("MODULE TOPOLOGY");
    title->setObjectName("ecuTitle");
    auto* subtitle = new QLabel(
        "Displays a system distribution diagram of vehicle control modules. "
        "Modules with active faults are highlighted in orange.");
    subtitle->setObjectName("ecuSubtitle");
    subtitle->setWordWrap(true);
    lay->addWidget(title);
    lay->addWidget(subtitle);

    auto* toolbar = new QHBoxLayout;
    auto* scanBtn  = new QPushButton("Scan all (read DTCs)");
    auto* clearBtn = new QPushButton("Clear DTCs on ALL"); clearBtn->setObjectName("danger");
    auto* addBtn   = new QPushButton("Add ECU");
    toolbar->addWidget(scanBtn);
    toolbar->addWidget(clearBtn);
    toolbar->addStretch(1);
    toolbar->addWidget(addBtn);
    lay->addLayout(toolbar);

    auto* row = new QHBoxLayout;
    row->setSpacing(12);

    auto* canvas = new QFrame;
    canvas->setObjectName("ecuCanvas");
    auto* canvasLay = new QVBoxLayout(canvas);
    canvasLay->setContentsMargins(14, 14, 14, 14);
    canvasLay->setSpacing(8);

    auto* ecuHint = new QLabel(
        "Tap a module for diagnostics and actions. Placeholder addresses can be "
        "edited inside each module dialog.");
    ecuHint->setObjectName("ecuCanvasHint");
    ecuHint->setWordWrap(true);
    canvasLay->addWidget(ecuHint);

    topology_ = new EcuTopologyView;
    topology_->onClick = [this](int idx, QWidget* anchor) { openEcuDialog(idx, anchor); };
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setStyleSheet(
        "QScrollArea{background:transparent;border:none;}"
        "QScrollArea>QWidget>QWidget{background:transparent;}");
    scroll->setWidget(topology_);
    canvasLay->addWidget(scroll, 1);
    row->addWidget(canvas, 1);

    auto* legend = new QFrame;
    legend->setObjectName("ecuLegend");
    legend->setFixedWidth(220);
    auto* legendLay = new QVBoxLayout(legend);
    legendLay->setContentsMargins(12, 12, 12, 12);
    legendLay->setSpacing(10);

    auto* lgTitle = new QLabel("Status");
    lgTitle->setObjectName("ecuLegendTitle");
    legendLay->addWidget(lgTitle);

    auto addLegendItem = [legendLay](const QString& color, const QString& text) {
        auto* item = new QWidget;
        auto* hl = new QHBoxLayout(item);
        hl->setContentsMargins(0, 0, 0, 0);
        hl->setSpacing(8);
        auto* swatch = new QFrame;
        swatch->setFixedSize(14, 14);
        swatch->setStyleSheet(QString("background:%1;border-radius:4px;").arg(color));
        auto* lbl = new QLabel(text);
        hl->addWidget(swatch);
        hl->addWidget(lbl, 1);
        legendLay->addWidget(item);
    };

    addLegendItem("#1f7bd6", "Not scanned");
    addLegendItem("#2e7dd1", "Scanning");
    addLegendItem("#20c55a", "Pass");
    addLegendItem("#ff8a00", "Fault");
    addLegendItem("#7e8794", "No response");

    auto* div = new QFrame;
    div->setFrameShape(QFrame::HLine);
    div->setStyleSheet("color:#2c4a6b; background:#2c4a6b; max-height:1px;");
    legendLay->addWidget(div);

    auto addBusItem = [legendLay](const QString& color, const QString& text) {
        auto* item = new QWidget;
        auto* hl = new QHBoxLayout(item);
        hl->setContentsMargins(0, 0, 0, 0);
        hl->setSpacing(8);
        auto* line = new QFrame;
        line->setFixedSize(22, 4);
        line->setStyleSheet(QString("background:%1; border-radius:2px;").arg(color));
        auto* wrap = new QWidget;
        wrap->setFixedWidth(22);
        auto* wl = new QVBoxLayout(wrap);
        wl->setContentsMargins(0, 0, 0, 0);
        wl->addStretch(1); wl->addWidget(line); wl->addStretch(1);
        auto* lbl = new QLabel(text);
        hl->addWidget(wrap);
        hl->addWidget(lbl, 1);
        legendLay->addWidget(item);
    };
    addBusItem("#b15cd0", "information");
    addBusItem("#e0556a", "comfort");
    addBusItem("#3f8ae0", "drive");

    auto* legendNote = new QLabel(
        "Fault count appears on each node after scanning. Scan all now probes "
        "addresses and runs DID identification automatically.");
    legendNote->setWordWrap(true);
    legendNote->setObjectName("ecuLegendNote");
    legendLay->addSpacing(4);
    legendLay->addWidget(legendNote);
    legendLay->addStretch(1);

    row->addWidget(legend);
    lay->addLayout(row, 1);

    connect(scanBtn, &QPushButton::clicked, this, [this] {
        syncSettingsFromUi();
        uint8_t mask = (uint8_t)statusMask_;
        bool functional = useFunctional_;
        uint16_t funcAddr = (uint16_t)functionalAddr_;
        startWorker([this, mask, functional, funcAddr] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            size_t count; { std::lock_guard<std::mutex> g(mutex_); count = ecus_.size(); }

            int reachable = 0;
            int identified = 0;
            for (size_t i = 0; i < count; ++i) {
                uint16_t addr, alt;
                std::string name;
                {
                    std::lock_guard<std::mutex> g(mutex_);
                    addr = ecus_[i].logicalAddr;
                    alt = ecus_[i].altAddr;
                    name = ecus_[i].name;
                    
                    ecus_[i].statusMsg = "scanning module " + std::to_string(i + 1) +
                                         "/" + std::to_string(count) + "...";
                }

                // Intentional pacing so the topology animation clearly shows each ECU sweep.
                std::this_thread::sleep_for(std::chrono::milliseconds(480));

                uint16_t target = functional ? funcAddr : addr;

                // 1) Probe address first, trying alternative routing.
                bool probed = false;
                std::string probeErr;
                if (uds.probe(target, probeErr)) {
                    probed = true;
                } else if (!functional && alt != 0 && alt != addr) {
                    std::string e2;
                    if (uds.probe(alt, e2)) {
                        std::lock_guard<std::mutex> g(mutex_);
                        if (i < ecus_.size()) ecus_[i].logicalAddr = alt;
                        target = alt;
                        probed = true;
                    }
                }

                if (!probed) {
                    std::lock_guard<std::mutex> g(mutex_);
                    if (i < ecus_.size()) {
                        ecus_[i].reachable = 0;
                        ecus_[i].statusMsg = "no response: " + probeErr;
                    }
                    continue;
                }

                ++reachable;

                // 2) Identify module via DID sweep.
                int answered = 0;
                auto fields = uds.sweepIdentificationDids(target, answered);
                std::string idInfo;
                if (answered > 0) {
                    for (const auto& f : fields) {
                        char did[8]; std::snprintf(did, sizeof did, "%04X", f.did);
                        idInfo += f.label + " (" + did + "): " + f.value + "\n";
                    }
                    ++identified;
                }

                // 3) Read DTCs for the requested status mask.
                std::vector<Dtc> dtcs; std::string e;
                if (uds.readDTCByStatusMask(target, mask, dtcs, e)) {
                    std::lock_guard<std::mutex> g(mutex_);
                    if (i < ecus_.size()) {
                        ecus_[i].reachable = 1;
                        if (!idInfo.empty()) ecus_[i].idInfo = idInfo;
                        ecus_[i].dtcs = std::move(dtcs);
                        ecus_[i].statusMsg = "scan OK (" + std::to_string(answered) + " DID, " +
                                             std::to_string(ecus_[i].dtcs.size()) + " DTC)";
                    }
                } else {
                    std::lock_guard<std::mutex> g(mutex_);
                    if (i < ecus_.size()) {
                        ecus_[i].reachable = 1;
                        if (!idInfo.empty()) ecus_[i].idInfo = idInfo;
                        ecus_[i].statusMsg = "read failed: " + e;
                    }
                }

                if (functional) break;
            }
            Logger::instance().info("Scan All complete: " + std::to_string(reachable) +
                                    "/" + std::to_string(count) + " reachable, " +
                                    std::to_string(identified) + " identified");
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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

    auto* svcIntro = new QLabel(
        "<b>Safe service enumerator.</b> Finds which DIDs / routines / I/O "
        "channels an ECU implements <i>without executing anything</i> - only "
        "read-only or restorative sub-functions are sent (0x22 read, 0x31 0x03 "
        "request-results, 0x2F 0x00 return-control).");
    svcIntro->setWordWrap(true);
    lay->addWidget(svcIntro);

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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::string e;
            if (ext)  uds.diagnosticSessionControl(tgt, UdsSession::Extended, e);
            if (susp) uds.controlDTCSetting(tgt, false, e);
            std::vector<uint16_t> touchedIo;
            auto record = [this](uint8_t svc, uint16_t id, int ex, const std::string& note) {
                std::lock_guard<std::mutex> g(mutex_);
                svcResults_.push_back({svc, id, ex, note});
            };
            int found = 0;
            for (int id = start; id <= end && transport_.isConnected(); ++id) {
                std::vector<uint8_t> resp; std::string le;
                if (dids) { int r = uds.probeDID(tgt, (uint16_t)id, resp, le);
                    if (r >= 0) { record(0x22, (uint16_t)id, r,
                        r==1?toHex(resp.data(),resp.size()):("exists ("+le+")"));
                        found++;
                    }
                }
                if (routines) { int r = uds.probeRoutine(tgt, (uint16_t)id, resp, le);
                    if (r >= 0) { record(0x31, (uint16_t)id, r,
                        r==1?toHex(resp.data(),resp.size()):("exists ("+le+")"));
                        found++;
                    }
                }
                if (io) { int r = uds.probeIOControl(tgt, (uint16_t)id, resp, le);
                    if (r >= 0) { record(0x2F, (uint16_t)id, r,
                        r==1?toHex(resp.data(),resp.size()):("exists ("+le+")"));
                        touchedIo.push_back((uint16_t)id); found++;
                    }
                }
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::string summary; uds.restoreSafeState(tgt, touched, summary);
        });
    });
    connect(clearBtn, &QPushButton::clicked, this, [this] {
        std::lock_guard<std::mutex> g(mutex_); svcResults_.clear();
    });

    return page;
}

// ==========================================================================
// Protocol / advanced page - standard UDS services for
// diagnostics and programming. UDS
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
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* inner = new QWidget;
    scroll->setWidget(inner);
    auto* pageLay = new QVBoxLayout(page);
    pageLay->setContentsMargins(0, 0, 0, 0);
    pageLay->addWidget(scroll);

    auto* outer = new QVBoxLayout(inner);
    outer->setContentsMargins(18, 18, 18, 18);
    outer->setSpacing(12);

    auto* intro = new QLabel(
        "<b>Protocol toolbox.</b> Standard ISO 14229 (UDS) "
        "services for diagnostics and programming. "
        "read-only; UDS writes/routines change ECU state and ask to confirm.");
    intro->setWordWrap(true);
    outer->addWidget(intro);

    auto* row = new QHBoxLayout;
    row->setSpacing(12);

    // ---- target for UDS operations ----
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
    memRow->addWidget(memBtn);
    memRow->addStretch(1);
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
    connect(memBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint32_t addr = (uint32_t)edProtoMemAddr_->text().toULong(nullptr, 16);
        uint32_t size = (uint32_t)sbProtoMemSize_->value();
        uint8_t ab = (uint8_t)sbProtoAddrBytes_->value();
        uint8_t sb = (uint8_t)sbProtoSizeBytes_->value();
        startWorker([this, tgt, addr, size, ab, sb] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("ReadMemory: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            if (uds.clearDynamicDataIdentifier(tgt, dddid, err))
                protoLine("Clear DDDID 0x" + byteHex((dddid>>8)&0xFF) + byteHex(dddid&0xFF) + ": OK.");
            else protoLine("Clear DDDID: " + err);
        });
    });

    // ---- Actuator control / active tests (0x2F) ----
    auto* ioCard = card("Actuator control / active test (0x2F, confirm required)");
    auto* iol = new QFormLayout(ioCard);
    auto* ioNote = new QLabel(
        "InputOutputControlByIdentifier drives an actuator directly (open a "
        "valve, cycle a relay, command a value). Often needs an extended/diagnostic "
        "session and security unlock first. <b>Always</b> hand control back to the "
        "ECU when finished.");
    ioNote->setWordWrap(true);
    iol->addRow(ioNote);
    edProtoIoDid_    = hexEdit("F010", 4);
    cbProtoIoOption_ = new QComboBox;
    cbProtoIoOption_->addItems({"shortTermAdjustment (03)", "freezeCurrentState (02)",
                                "resetToDefault (01)", "returnControlToECU (00)"});
    edProtoIoState_  = new QLineEdit; edProtoIoState_->setPlaceholderText("control state, hex e.g. 01 FF");
    edProtoIoMask_   = new QLineEdit; edProtoIoMask_->setPlaceholderText("optional enable mask, hex");
    auto* ioRow = new QHBoxLayout;
    ioRow->addWidget(new QLabel("DID")); ioRow->addWidget(edProtoIoDid_);
    ioRow->addWidget(cbProtoIoOption_);
    iol->addRow("Identifier / option", ioRow);
    iol->addRow("Control state", edProtoIoState_);
    iol->addRow("Enable mask", edProtoIoMask_);
    auto* ioBtnRow = new QHBoxLayout;
    auto* ioRunBtn = new QPushButton("Execute (0x2F)"); ioRunBtn->setObjectName("primary");
    auto* ioRetBtn = new QPushButton("Return control to ECU");
    ioBtnRow->addWidget(ioRunBtn); ioBtnRow->addWidget(ioRetBtn); ioBtnRow->addStretch(1);
    iol->addRow(ioBtnRow);
    outer->addWidget(ioCard);

    connect(ioRunBtn, &QPushButton::clicked, this, [this, ioRunBtn] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint16_t did = parseHex16(edProtoIoDid_->text(), 0xF010);
        int optIdx = cbProtoIoOption_->currentIndex();   // 0..3 -> ShortTerm..Return
        auto state = parseHexBytes(edProtoIoState_->text().toStdString());
        auto mask  = parseHexBytes(edProtoIoMask_->text().toStdString());
        static const IoControlOption kOpt[] = {
            IoControlOption::ShortTermAdjustment, IoControlOption::FreezeCurrentState,
            IoControlOption::ResetToDefault, IoControlOption::ReturnControlToECU};
        IoControlOption opt = kOpt[optIdx];
        if (opt != IoControlOption::ReturnControlToECU &&
            !confirmPopup(ioRunBtn, "Actuator control",
                          QString("Drive actuator DID 0x%1 on ECU 0x%2? This physically "
                                  "actuates a component - keep clear and be ready to "
                                  "return control.")
                              .arg(did, 4, 16, QChar('0')).arg(tgt, 4, 16, QChar('0')),
                          "Execute"))
            return;
        startWorker([this, tgt, did, opt, state, mask] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Actuator: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.inputOutputControl(tgt, did, opt, state, mask, out, err))
                protoLine("Actuator 0x" + byteHex((did>>8)&0xFF) + byteHex(did&0xFF) +
                          ": OK" + (out.empty() ? "" : " status " + toHex(out.data(), out.size())));
            else protoLine("Actuator 0x" + byteHex((did>>8)&0xFF) + byteHex(did&0xFF) + ": " + err);
        });
    });
    connect(ioRetBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint16_t did = parseHex16(edProtoIoDid_->text(), 0xF010);
        startWorker([this, tgt, did] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Return control: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.inputOutputControl(tgt, did, IoControlOption::ReturnControlToECU, {}, {}, out, err))
                protoLine("Return control 0x" + byteHex((did>>8)&0xFF) + byteHex(did&0xFF) + ": OK.");
            else protoLine("Return control 0x" + byteHex((did>>8)&0xFF) + byteHex(did&0xFF) + ": " + err);
        });
    });

    // ---- Memory & scaling (0x3D / 0x24 / 0x35) ----
    auto* memCard = card("Memory & scaling (0x3D write / 0x24 scaling / 0x35 upload)");
    auto* ml = new QFormLayout(memCard);
    auto* memNote = new QLabel(
        "WriteMemoryByAddress and memory upload read/modify raw ECU memory - "
        "use only with a confirmed memory map. ReadScalingData describes how to "
        "interpret a DID's raw bytes (type, length, unit, formula).");
    memNote->setWordWrap(true);
    ml->addRow(memNote);

    edProtoScalingDid_ = hexEdit("F190", 4);
    auto* scRow = new QHBoxLayout;
    scRow->addWidget(new QLabel("DID")); scRow->addWidget(edProtoScalingDid_);
    auto* scBtn = new QPushButton("Read scaling (0x24)");
    scRow->addWidget(scBtn); scRow->addStretch(1);
    ml->addRow("ReadScalingData", scRow);

    edProtoWmbaAddr_  = hexEdit("00000000", 8);
    edProtoWmbaData_  = new QLineEdit; edProtoWmbaData_->setPlaceholderText("hex bytes to write");
    sbProtoWmbaAddrB_ = new QSpinBox; sbProtoWmbaAddrB_->setRange(1, 4); sbProtoWmbaAddrB_->setValue(4);
    sbProtoWmbaSizeB_ = new QSpinBox; sbProtoWmbaSizeB_->setRange(1, 4); sbProtoWmbaSizeB_->setValue(1);
    auto* wmRow = new QHBoxLayout;
    wmRow->addWidget(new QLabel("Addr")); wmRow->addWidget(edProtoWmbaAddr_);
    wmRow->addWidget(new QLabel("addrB")); wmRow->addWidget(sbProtoWmbaAddrB_);
    wmRow->addWidget(new QLabel("sizeB")); wmRow->addWidget(sbProtoWmbaSizeB_);
    wmRow->addWidget(edProtoWmbaData_, 1);
    auto* wmBtn = new QPushButton("Write memory (0x3D)");
    wmRow->addWidget(wmBtn);
    ml->addRow("WriteMemoryByAddress", wmRow);

    edProtoUpAddr_ = hexEdit("00000000", 8);
    sbProtoUpSize_ = new QSpinBox; sbProtoUpSize_->setRange(1, 65536); sbProtoUpSize_->setValue(256);
    auto* upRow = new QHBoxLayout;
    upRow->addWidget(new QLabel("Addr")); upRow->addWidget(edProtoUpAddr_);
    upRow->addWidget(new QLabel("Size")); upRow->addWidget(sbProtoUpSize_);
    auto* upBtn = new QPushButton("Upload memory (0x35)");
    upRow->addWidget(upBtn); upRow->addStretch(1);
    ml->addRow("RequestUpload", upRow);
    outer->addWidget(memCard);

    connect(scBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint16_t did = parseHex16(edProtoScalingDid_->text(), 0xF190);
        startWorker([this, tgt, did] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Scaling: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.readScalingDataByIdentifier(tgt, did, out, err))
                protoLine("Scaling 0x" + byteHex((did>>8)&0xFF) + byteHex(did&0xFF) +
                          ": " + toHex(out.data(), out.size()));
            else protoLine("Scaling 0x" + byteHex((did>>8)&0xFF) + byteHex(did&0xFF) + ": " + err);
        });
    });
    connect(wmBtn, &QPushButton::clicked, this, [this, wmBtn] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint32_t addr = (uint32_t)edProtoWmbaAddr_->text().toUInt(nullptr, 16);
        auto data = parseHexBytes(edProtoWmbaData_->text().toStdString());
        int addrB = sbProtoWmbaAddrB_->value(), sizeB = sbProtoWmbaSizeB_->value();
        if (data.empty()) { protoLine("Write memory: no data bytes given."); return; }
        if (!confirmPopup(wmBtn, "Write memory",
                          QString("Write %1 byte(s) to address 0x%2 on ECU 0x%3? This "
                                  "modifies raw ECU memory and can be irreversible.")
                              .arg(data.size()).arg(addr, 0, 16).arg(tgt, 4, 16, QChar('0')),
                          "Write"))
            return;
        startWorker([this, tgt, addr, data, addrB, sizeB] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Write memory: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            if (uds.writeMemoryByAddress(tgt, addr, data, addrB, sizeB, err))
                protoLine("Write memory 0x" + std::to_string(addr) + ": OK (" +
                          std::to_string(data.size()) + " byte(s)).");
            else protoLine("Write memory: " + err);
        });
    });
    connect(upBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint32_t addr = (uint32_t)edProtoUpAddr_->text().toUInt(nullptr, 16);
        uint32_t size = (uint32_t)sbProtoUpSize_->value();
        startWorker([this, tgt, addr, size] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Upload: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::vector<uint8_t> image;
            if (uds.uploadBlock(tgt, addr, size, 4, 4, 0x00, image, nullptr, err)) {
                protoLine("Upload 0x" + std::to_string(addr) + ": " +
                          std::to_string(image.size()) + " byte(s) received.");
                size_t show = (std::min)((size_t)64, image.size());
                if (show) protoLine("  " + toHex(image.data(), show) +
                                    (show < image.size() ? " ..." : ""));
            } else protoLine("Upload: " + err);
        });
    });

    // ---- Full memory dump to .bin (chunked 0x35 upload) ----
    auto* dumpCard = card("Full memory dump to .bin (0x35 upload)");
    auto* dmpl = new QFormLayout(dumpCard);
    auto* dumpNote = new QLabel(
        "Reads a memory range in chunks via RequestUpload (0x35) and streams it "
        "straight to a .bin file you can edit and reflash. Most production ECUs "
        "require a programming session + SecurityAccess first, and many reject "
        "0x35 entirely or only expose permitted regions - so a true full-flash "
        "dump is often partial. Enter the start address and total size from the "
        "ECU's memory map; the file is written incrementally so a partial dump "
        "is still saved.");
    dumpNote->setWordWrap(true);
    dmpl->addRow(dumpNote);

    edDumpAddr_  = hexEdit("00000000", 8);
    edDumpSize_  = hexEdit("00100000", 8);   // 1 MiB default
    edDumpChunk_ = hexEdit("0400", 4);        // 1 KiB request granularity
    sbDumpAddrB_ = new QSpinBox; sbDumpAddrB_->setRange(1, 4); sbDumpAddrB_->setValue(4);
    sbDumpSizeB_ = new QSpinBox; sbDumpSizeB_->setRange(1, 4); sbDumpSizeB_->setValue(4);
    auto* dmpRow = new QHBoxLayout;
    dmpRow->addWidget(new QLabel("Start")); dmpRow->addWidget(edDumpAddr_);
    dmpRow->addWidget(new QLabel("Total"));  dmpRow->addWidget(edDumpSize_);
    dmpRow->addWidget(new QLabel("Chunk"));  dmpRow->addWidget(edDumpChunk_);
    dmpRow->addWidget(new QLabel("addrB")); dmpRow->addWidget(sbDumpAddrB_);
    dmpRow->addWidget(new QLabel("sizeB")); dmpRow->addWidget(sbDumpSizeB_);
    dmpl->addRow("Range", dmpRow);
    auto* dumpBtn = new QPushButton("Dump to .bin file"); dumpBtn->setObjectName("primary");
    auto* dmpBtnRow = new QHBoxLayout;
    dmpBtnRow->addWidget(dumpBtn); dmpBtnRow->addStretch(1);
    dmpl->addRow(dmpBtnRow);
    outer->addWidget(dumpCard);

    connect(dumpBtn, &QPushButton::clicked, this, [this, dumpBtn] {
        uint16_t tgt   = parseHex16(edProtoTarget_->text(), 0x1003);
        uint32_t addr  = (uint32_t)edDumpAddr_->text().toUInt(nullptr, 16);
        uint32_t total = (uint32_t)edDumpSize_->text().toUInt(nullptr, 16);
        uint32_t chunk = (uint32_t)edDumpChunk_->text().toUInt(nullptr, 16);
        uint8_t  addrB = (uint8_t)sbDumpAddrB_->value();
        uint8_t  sizeB = (uint8_t)sbDumpSizeB_->value();
        if (total == 0) { protoLine("Dump: total size must be non-zero."); return; }
        if (chunk == 0) chunk = 0x400;

        QString path = QFileDialog::getSaveFileName(this, "Save memory dump", "ecu-dump.bin",
                                                    "Binary image (*.bin);;All files (*)");
        if (path.isEmpty()) return;
        if (!confirmPopup(dumpBtn, "Dump ECU memory",
                          QString("Read %1 byte(s) from 0x%2 on ECU 0x%3 and save to a file?\n\n"
                                  "The ECU must permit RequestUpload (0x35); enter a programming "
                                  "session and unlock SecurityAccess first if required.")
                              .arg(total).arg(addr, 0, 16).arg(tgt, 4, 16, QChar('0')),
                          "Start dump"))
            return;

        std::string file = path.toStdString();
        startWorker([this, tgt, addr, total, chunk, addrB, sizeB, file] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Dump: " + err); return; }

            FILE* fp = std::fopen(file.c_str(), "wb");
            if (!fp) { protoLine("Dump: cannot open output file."); return; }

            UDSClient uds(transport_, (uint16_t)testerAddr_);
            protoLine("Dump: reading " + std::to_string(total) + " byte(s) from 0x" +
                      std::to_string(addr) + " in " + std::to_string(chunk) + "-byte chunks...");

            uint32_t done = 0;
            uint32_t nextReport = 0;
            bool ok = true;
            while (done < total && transport_.isConnected()) {
                uint32_t want = (std::min)(chunk, total - done);
                std::vector<uint8_t> part;
                std::string e;
                if (!uds.uploadBlock(tgt, addr + done, want, addrB, sizeB, 0x00, part, nullptr, e)) {
                    protoLine("Dump: stopped at 0x" + std::to_string(addr + done) + ": " + e);
                    ok = false;
                    break;
                }
                if (std::fwrite(part.data(), 1, part.size(), fp) != part.size()) {
                    protoLine("Dump: file write error."); ok = false; break;
                }
                done += (uint32_t)part.size();
                if (done >= nextReport) {
                    protoLine("  dumped " + std::to_string(done) + "/" +
                              std::to_string(total) + " byte(s)");
                    nextReport = done + 64u * 1024u;
                }
            }
            std::fclose(fp);
            protoLine(std::string(ok ? "Dump complete: " : "Dump partial: ") +
                      std::to_string(done) + " byte(s) saved to " + file +
                      ". Edit it, then use the flash panel to reupload (0x34).");
        });
    });

    // ---- Link, timing & authentication (0x87 / 0x83 / 0x29) ----
    auto* linkCard = card("Link, timing & authentication (0x87 / 0x83 / 0x29)");
    auto* ll = new QFormLayout(linkCard);

    cbProtoLinkSub_ = new QComboBox;
    cbProtoLinkSub_->addItems({"verifyFixedBaudrate (01)", "verifySpecificBaudrate (02)",
                               "transitionBaudrate (03)"});
    edProtoLinkParam_ = new QLineEdit; edProtoLinkParam_->setPlaceholderText("baudrate id/value, hex");
    auto* lkRow = new QHBoxLayout;
    lkRow->addWidget(cbProtoLinkSub_); lkRow->addWidget(edProtoLinkParam_, 1);
    auto* lkBtn = new QPushButton("Run (0x87)");
    lkRow->addWidget(lkBtn);
    ll->addRow("LinkControl", lkRow);

    cbProtoTimingSub_ = new QComboBox;
    cbProtoTimingSub_->addItems({"readExtendedSet (01)", "setToDefault (02)",
                                 "readCurrentlyActive (03)", "setToGivenValues (04)"});
    edProtoTimingVals_ = new QLineEdit; edProtoTimingVals_->setPlaceholderText("timing values for set (hex)");
    auto* tmRow = new QHBoxLayout;
    tmRow->addWidget(cbProtoTimingSub_); tmRow->addWidget(edProtoTimingVals_, 1);
    auto* tmBtn = new QPushButton("Run (0x83)");
    tmRow->addWidget(tmBtn);
    ll->addRow("AccessTimingParameter", tmRow);

    edProtoAuthSub_  = hexEdit("08", 2);
    edProtoAuthData_ = new QLineEdit; edProtoAuthData_->setPlaceholderText("sub-function payload, hex");
    auto* auRow = new QHBoxLayout;
    auRow->addWidget(new QLabel("Sub")); auRow->addWidget(edProtoAuthSub_);
    auRow->addWidget(edProtoAuthData_, 1);
    auto* auBtn = new QPushButton("Run (0x29)");
    auRow->addWidget(auBtn);
    ll->addRow("Authentication", auRow);
    outer->addWidget(linkCard);

    connect(lkBtn, &QPushButton::clicked, this, [this, lkBtn] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        int subIdx = cbProtoLinkSub_->currentIndex();   // 0..2 -> 0x01..0x03
        auto param = parseHexBytes(edProtoLinkParam_->text().toStdString());
        auto sub = (LinkControlType)(subIdx + 1);
        if (sub == LinkControlType::TransitionMode &&
            !confirmPopup(lkBtn, "Link control",
                          "Transition the diagnostic link to the verified baudrate? "
                          "An unsupported rate can drop the connection.", "Transition"))
            return;
        startWorker([this, tgt, sub, param] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("LinkControl: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            if (uds.linkControl(tgt, sub, param, err))
                protoLine("LinkControl sub 0x" + byteHex((uint8_t)sub) + ": OK.");
            else protoLine("LinkControl: " + err);
        });
    });
    connect(tmBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        int subIdx = cbProtoTimingSub_->currentIndex();   // 0..3 -> 0x01..0x04
        auto vals = parseHexBytes(edProtoTimingVals_->text().toStdString());
        auto sub = (TimingParamAccess)(subIdx + 1);
        startWorker([this, tgt, sub, vals] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Timing: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.accessTimingParameter(tgt, sub, vals, out, err))
                protoLine("AccessTimingParameter sub 0x" + byteHex((uint8_t)sub) + ": OK" +
                          (out.empty() ? "" : " " + toHex(out.data(), out.size())));
            else protoLine("AccessTimingParameter: " + err);
        });
    });
    connect(auBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint8_t sub = (uint8_t)parseHex16(edProtoAuthSub_->text(), 0x08);
        auto data = parseHexBytes(edProtoAuthData_->text().toStdString());
        startWorker([this, tgt, sub, data] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Authentication: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.authentication(tgt, sub, data, out, err))
                protoLine("Authentication sub 0x" + byteHex(sub) + ": OK" +
                          (out.empty() ? "" : " " + toHex(out.data(), out.size())));
            else protoLine("Authentication: " + err);
        });
    });

    // ---- Secured transport, response-on-event, file transfer (0x84 / 0x86 / 0x38) ----
    auto* secEvtCard = card("Secured transport & event/file services (0x84 / 0x86 / 0x38)");
    auto* se = new QFormLayout(secEvtCard);

    edProtoSecData_ = new QLineEdit;
    edProtoSecData_->setPlaceholderText("secured payload record (hex)");
    auto* secRow = new QHBoxLayout;
    secRow->addWidget(edProtoSecData_, 1);
    auto* secBtn = new QPushButton("Send (0x84)");
    secRow->addWidget(secBtn);
    se->addRow("SecuredDataTransmission", secRow);

    edProtoRoeEventType_ = hexEdit("01", 2);
    edProtoRoeWindow_ = hexEdit("00", 2);
    edProtoRoeEventRec_ = new QLineEdit;
    edProtoRoeEventRec_->setPlaceholderText("eventTypeRecord (hex, optional)");
    edProtoRoeSvcRec_ = new QLineEdit;
    edProtoRoeSvcRec_->setPlaceholderText("serviceToRespondTo record (hex)");
    auto* roeTop = new QHBoxLayout;
    roeTop->addWidget(new QLabel("eventType")); roeTop->addWidget(edProtoRoeEventType_);
    roeTop->addWidget(new QLabel("window")); roeTop->addWidget(edProtoRoeWindow_);
    auto* roeBtn = new QPushButton("Configure (0x86)");
    roeTop->addWidget(roeBtn); roeTop->addStretch(1);
    se->addRow("ResponseOnEvent", roeTop);
    se->addRow("Event record", edProtoRoeEventRec_);
    se->addRow("Service record", edProtoRoeSvcRec_);

    cbProtoFileMode_ = new QComboBox;
    cbProtoFileMode_->addItems({"Add file (01)", "Delete file (02)", "Replace file (03)",
                                "Read file (04)", "Read directory (05)", "Resume file (06)"});
    edProtoFilePath_ = new QLineEdit;
    edProtoFilePath_->setPlaceholderText("ECU file path, e.g. /logs/diag.bin");
    edProtoFileFmt_ = hexEdit("00", 2);
    edProtoFileSizeU_ = new QLineEdit("0");
    edProtoFileSizeC_ = new QLineEdit("0");
    auto* ftRow = new QHBoxLayout;
    ftRow->addWidget(cbProtoFileMode_);
    ftRow->addWidget(new QLabel("fmt")); ftRow->addWidget(edProtoFileFmt_);
    ftRow->addWidget(new QLabel("sizeU")); ftRow->addWidget(edProtoFileSizeU_);
    ftRow->addWidget(new QLabel("sizeC")); ftRow->addWidget(edProtoFileSizeC_);
    auto* ftBtn = new QPushButton("Run (0x38)");
    ftRow->addWidget(ftBtn);
    se->addRow("RequestFileTransfer", ftRow);
    se->addRow("Path", edProtoFilePath_);
    outer->addWidget(secEvtCard);

    connect(secBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        auto data = parseHexBytes(edProtoSecData_->text().toStdString());
        startWorker([this, tgt, data] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("SecuredDataTransmission: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.securedDataTransmission(tgt, data, out, err))
                protoLine("SecuredDataTransmission: OK" +
                          (out.empty() ? "" : " " + toHex(out.data(), out.size())));
            else
                protoLine("SecuredDataTransmission: " + err);
        });
    });

    connect(roeBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint8_t eventType = (uint8_t)parseHex16(edProtoRoeEventType_->text(), 0x01);
        uint8_t window = (uint8_t)parseHex16(edProtoRoeWindow_->text(), 0x00);
        auto eventRec = parseHexBytes(edProtoRoeEventRec_->text().toStdString());
        auto svcRec = parseHexBytes(edProtoRoeSvcRec_->text().toStdString());
        if (svcRec.empty()) { protoLine("ResponseOnEvent: service record cannot be empty."); return; }
        startWorker([this, tgt, eventType, window, eventRec, svcRec] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("ResponseOnEvent: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.responseOnEvent(tgt, eventType, window, eventRec, svcRec, out, err))
                protoLine("ResponseOnEvent: OK" +
                          (out.empty() ? "" : " " + toHex(out.data(), out.size())));
            else
                protoLine("ResponseOnEvent: " + err);
        });
    });

    connect(ftBtn, &QPushButton::clicked, this, [this, ftBtn] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        auto mode = (FileTransferMode)(cbProtoFileMode_->currentIndex() + 1);
        std::string path = edProtoFilePath_->text().toStdString();
        uint8_t fmt = (uint8_t)parseHex16(edProtoFileFmt_->text(), 0x00);
        uint64_t sizeU = std::strtoull(edProtoFileSizeU_->text().trimmed().toStdString().c_str(), nullptr, 0);
        uint64_t sizeC = std::strtoull(edProtoFileSizeC_->text().trimmed().toStdString().c_str(), nullptr, 0);
        if (path.empty()) { protoLine("RequestFileTransfer: file path is required."); return; }

        bool invasive = (mode == FileTransferMode::AddFile ||
                         mode == FileTransferMode::DeleteFile ||
                         mode == FileTransferMode::ReplaceFile ||
                         mode == FileTransferMode::ResumeFile);
        if (invasive &&
            !confirmPopup(ftBtn, "RequestFileTransfer",
                          QString("Run file-transfer mode 0x%1 for path '%2' on ECU 0x%3? "
                                  "This can modify ECU storage.")
                              .arg((int)mode, 2, 16, QChar('0'))
                              .arg(QString::fromStdString(path))
                              .arg(tgt, 4, 16, QChar('0')),
                          "Run"))
            return;

        startWorker([this, tgt, mode, path, fmt, sizeU, sizeC] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("RequestFileTransfer: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::vector<uint8_t> out;
            if (uds.requestFileTransfer(tgt, mode, path, fmt, sizeU, sizeC, out, err))
                protoLine("RequestFileTransfer: OK" +
                          (out.empty() ? "" : " " + toHex(out.data(), out.size())));
            else
                protoLine("RequestFileTransfer: " + err);
        });
    });

    // ---- Reprogramming / flash (0x34 -> 0x36 -> 0x37) ----
    auto* flashCard = card("Reprogramming / flash download (0x34/0x36/0x37, confirm required)");
    auto* fl = new QFormLayout(flashCard);
    auto* flashNote = new QLabel(
        "<b>Invasive.</b> Downloads a binary image to ECU memory using the "
        "RequestDownload -> TransferData -> RequestTransferExit sequence. The ECU "
        "must already be in a <i>programming session</i> with security unlocked "
        "(use the UDS write/control and Security panels first). A wrong or "
        "interrupted flash can brick the module.");
    flashNote->setWordWrap(true);
    fl->addRow(flashNote);
    edProtoFlashAddr_ = hexEdit("00000000", 8);
    edProtoFlashFile_ = new QLineEdit; edProtoFlashFile_->setReadOnly(true);
    edProtoFlashFile_->setPlaceholderText("no file selected");
    auto* flBrowse = new QPushButton("Browse...");
    auto* flRow = new QHBoxLayout;
    flRow->addWidget(new QLabel("Addr")); flRow->addWidget(edProtoFlashAddr_);
    flRow->addWidget(edProtoFlashFile_, 1); flRow->addWidget(flBrowse);
    fl->addRow("Image", flRow);
    auto* flBtnRow = new QHBoxLayout;
    auto* flProgBtn  = new QPushButton("Enter programming session (0x10 02)");
    auto* flFlashBtn = new QPushButton("Flash image"); flFlashBtn->setObjectName("primary");
    flBtnRow->addWidget(flProgBtn); flBtnRow->addWidget(flFlashBtn); flBtnRow->addStretch(1);
    fl->addRow(flBtnRow);
    outer->addWidget(flashCard);

    connect(flBrowse, &QPushButton::clicked, this, [this] {
        QString f = QFileDialog::getOpenFileName(this, "Select firmware image", QString(),
                                                 "Firmware (*.bin *.hex *.s19 *.srec *.fls);;All files (*)");
        if (!f.isEmpty()) edProtoFlashFile_->setText(f);
    });
    connect(flProgBtn, &QPushButton::clicked, this, [this] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        startWorker([this, tgt] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Programming session: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            if (uds.diagnosticSessionControl(tgt, UdsSession::Programming, err))
                protoLine("Programming session on 0x" + byteHex((tgt>>8)&0xFF) + byteHex(tgt&0xFF) +
                          ": active. Unlock security before flashing.");
            else protoLine("Programming session: " + err);
        });
    });
    connect(flFlashBtn, &QPushButton::clicked, this, [this, flFlashBtn] {
        uint16_t tgt = parseHex16(edProtoTarget_->text(), 0x1003);
        uint32_t addr = (uint32_t)edProtoFlashAddr_->text().toUInt(nullptr, 16);
        QString path = edProtoFlashFile_->text();
        if (path.isEmpty()) { protoLine("Flash: select an image file first."); return; }
        QFile imgFile(path);
        if (!imgFile.open(QIODevice::ReadOnly)) {
            protoLine("Flash: cannot open " + path.toStdString()); return;
        }
        QByteArray raw = imgFile.readAll();
        imgFile.close();
        std::vector<uint8_t> image(raw.begin(), raw.end());
        if (image.empty()) { protoLine("Flash: image is empty."); return; }
        if (!confirmPopup(flFlashBtn, "Flash firmware",
                          QString("Download %1 byte(s) to address 0x%2 on ECU 0x%3? "
                                  "The module must be in a programming session with security "
                                  "unlocked. An interrupted flash can brick the ECU.")
                              .arg(image.size()).arg(addr, 0, 16).arg(tgt, 4, 16, QChar('0')),
                          "Flash now"))
            return;
        startWorker([this, tgt, addr, image] {
            std::string err;
            if (!ensureConnected(err)) { protoLine("Flash: " + err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            protoLine("Flash: starting download of " + std::to_string(image.size()) +
                      " byte(s) to 0x" + std::to_string(addr) + " ...");
            auto progress = [this](size_t done, size_t total) {
                if (total && (done == total || done % (64 * 1024) < 4096))
                    protoLine("  flashed " + std::to_string(done) + "/" +
                              std::to_string(total) + " byte(s)");
            };
            if (uds.downloadBlock(tgt, addr, image, 4, 4, 0x00, progress, err))
                protoLine("Flash: download complete. Run any required check routine, then reset the ECU.");
            else protoLine("Flash: " + err);
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
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* inner = new QWidget;
    scroll->setWidget(inner);
    auto* pageLay = new QVBoxLayout(page);
    pageLay->setContentsMargins(0, 0, 0, 0);
    pageLay->addWidget(scroll);

    auto* outer = new QVBoxLayout(inner);
    outer->setContentsMargins(18, 18, 18, 18);
    outer->setSpacing(12);

    auto* introLabel = new QLabel(
        "<b>VinFast connected-car cloud.</b> Talks to VinFast's app back-end "
        "(Auth0 + signed REST + AWS IoT) the same way the phone app does. This "
        "uses <i>community reverse-engineered</i> endpoints, not an official "
        "SDK - they may change without notice. Credentials are kept in memory, "
        "sent only over HTTPS to VinFast, and never logged or written to disk.");
    introLabel->setWordWrap(true);
    outer->addWidget(introLabel);

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
    auto* mqttInfo = new QLabel(
        "Builds a presigned wss:// AWS IoT URL (Cognito identity + SigV4). The "
        "scanner generates and shows the endpoint; opening the MQTT socket is "
        "not done here. Only available where the region's Cognito pool is known.");
    mqttInfo->setWordWrap(true);
    ml->addWidget(mqttInfo);
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
    auto* bmsInfo = new QLabel(
        "The CATL BMS exposes no public CAN/UDS map, so identify battery DIDs "
        "empirically: sweep the BMS's read-only 0x22 DIDs, timestamp the raw "
        "values, and capture the cloud SOC/charging at the same instant. Take "
        "two snapshots at different battery states (e.g. before/after charging), "
        "then compare - DIDs whose raw value tracks the cloud SOC delta are "
        "battery-data candidates. Read-only; nothing is written to the ECU.");
    bmsInfo->setWordWrap(true);
    bl->addWidget(bmsInfo);
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

            UDSClient uds(transport_, (uint16_t)testerAddr_);
            std::string e;
            uds.diagnosticSessionControl(tgt, UdsSession::Extended, e);
            int n = 0;
            for (int id = start; id <= end && transport_.isConnected(); ++id) {
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

    // ---- Engineering-menu TOTP candidate generator -----------------------
    auto* totpCard = card("Engineering menu TOTP (candidate generator)");
    auto* tv = new QVBoxLayout(totpCard);
    auto* totpInfo = new QLabel(
        "The engineering menu shows a 6-digit <b>seed</b> and uses a 30-second "
        "time window. The real key derivation is not published, so this lists "
        "the most likely 6-digit codes for the seed + timestamp - standard "
        "RFC&nbsp;6238 TOTP (HMAC-SHA1) plus common arithmetic schemes - and "
        "includes the neighbouring 30s steps for clock skew. Enter the UTC "
        "date/time the menu is showing (defaults to now). Nothing is "
        "sent to the car; enter the candidates one at a time in the menu.");
    totpInfo->setWordWrap(true);
    tv->addWidget(totpInfo);
    auto* tf = new QHBoxLayout;
    edTotpSeed_ = new QLineEdit;
    edTotpSeed_->setMaxLength(6);
    edTotpSeed_->setPlaceholderText("6-digit seed");
    edTotpSeed_->setMaximumWidth(120);
    edTotpTs_ = new QDateTimeEdit;
    edTotpTs_->setDisplayFormat("MM/dd/yyyy - HH:mm");
    edTotpTs_->setTimeZone(QTimeZone::UTC);
    edTotpTs_->setCalendarPopup(true);
    edTotpTs_->setDateTime(QDateTime::currentDateTimeUtc());
    edTotpTsText_ = new QLineEdit;
    edTotpTsText_->setPlaceholderText("e.g. 06/02/2026 - 12:01 (UTC)");
    edTotpTsText_->setToolTip("Optional: type a UTC date/time string and press "
                              "Enter to set the picker. Accepts forms like "
                              "'06/02/2026 - 12:01', 'Wed May 20 20:24:05 2026', "
                              "or '2026-05-20 20:24:05'.");
    edTotpTsText_->setMinimumWidth(260);
    tf->addWidget(new QLabel("Seed"));              tf->addWidget(edTotpSeed_);
    tf->addWidget(new QLabel("UTC date/time"));     tf->addWidget(edTotpTs_);
    tf->addStretch(1);
    tv->addLayout(tf);
    auto* tf2 = new QHBoxLayout;
    tf2->addWidget(new QLabel("or type UTC"));      tf2->addWidget(edTotpTsText_);
    tf2->addStretch(1);
    tv->addLayout(tf2);
    auto* tb = new QHBoxLayout;
    auto* totpBtn = new QPushButton("Generate candidates");
    totpBtn->setObjectName("primary");
    tb->addWidget(totpBtn); tb->addStretch(1);
    tv->addLayout(tb);
    outer->addWidget(totpCard);

    // Parse a typed UTC string into a QDateTime (UTC). Accepts the current
    // engineering-menu timestamp format and a few legacy/ISO-ish variants.
    auto parseUtcText = [](const QString& raw) -> QDateTime {
        QString s = raw.simplified();   // collapse runs of whitespace
        if (s.isEmpty()) return QDateTime();
        static const char* fmts[] = {
            "MM/dd/yyyy - HH:mm",       // 06/02/2026 - 12:01
            "ddd MMM d HH:mm:ss yyyy",   // Wed May 20 20:24:05 2026 (asctime)
            "ddd MMM d yyyy HH:mm:ss",   // Wed May 20 2026 20:24:05
            "yyyy-MM-dd HH:mm:ss",       // 2026-05-20 20:24:05
            "yyyy-MM-ddTHH:mm:ss",       // 2026-05-20T20:24:05
            "yyyy-MM-dd HH:mm",          // 2026-05-20 20:24
        };
        for (const char* f : fmts) {
            QDateTime dt = QDateTime::fromString(s, QString::fromLatin1(f));
            if (dt.isValid()) { dt.setTimeZone(QTimeZone::UTC); return dt; }
        }
        QDateTime iso = QDateTime::fromString(s, Qt::ISODate);
        if (iso.isValid()) { iso.setTimeZone(QTimeZone::UTC); return iso; }
        return QDateTime();
    };

    // Typing a UTC string and committing it updates the picker.
    connect(edTotpTsText_, &QLineEdit::editingFinished, this,
            [this, parseUtcText] {
        const QString raw = edTotpTsText_->text().trimmed();
        if (raw.isEmpty()) return;
        QDateTime dt = parseUtcText(raw);
        if (dt.isValid()) {
            edTotpTs_->setDateTime(dt);
        } else {
            cloudLine("TOTP: could not parse UTC date/time '" +
                      raw.toStdString() + "'. Try '06/02/2026 - 12:01'.");
        }
    });

    connect(totpBtn, &QPushButton::clicked, this, [this, parseUtcText] {
        QString seedStr = edTotpSeed_->text().trimmed();
        bool okSeed = false;
        uint64_t seed = seedStr.toULongLong(&okSeed);
        if (seedStr.isEmpty() || !okSeed) {
            cloudLine("TOTP: enter the 6-digit seed shown by the car.");
            return;
        }
        // Prefer a freshly typed UTC string if present; else use the picker.
        const QString typed = edTotpTsText_->text().trimmed();
        QDateTime dt;
        if (!typed.isEmpty()) {
            dt = parseUtcText(typed);
            if (!dt.isValid()) {
                cloudLine("TOTP: could not parse UTC date/time '" +
                          typed.toStdString() +
                          "'. Try '06/02/2026 - 12:01'.");
                return;
            }
            edTotpTs_->setDateTime(dt);
        } else {
            dt = edTotpTs_->dateTime();
        }
        dt.setTimeZone(QTimeZone::UTC);
        long long ts = (long long)dt.toSecsSinceEpoch();
        long long adjTs = ts;   // datetime is already UTC; no offset needed
        uint64_t baseStep = (uint64_t)(adjTs / 30);

        std::time_t att = (std::time_t)adjTs;
        std::tm ag{};
#ifdef _WIN32
        gmtime_s(&ag, &att);
#else
        gmtime_r(&att, &ag);
#endif
        char dtbuf[32];
        std::strftime(dtbuf, sizeof dtbuf, "%Y-%m-%d %H:%M:%S", &ag);

        cloudLine("==== Engineering-menu TOTP candidates ====");
        cloudLine(QString("seed %1 | ts %2 | datetime %3 UTC | base step %4")
                      .arg(seedStr).arg(ts)
                      .arg(dtbuf)
                      .arg((qulonglong)baseStep)
                      .toStdString());
        for (int skew = -1; skew <= 1; ++skew) {
            uint64_t step = baseStep + skew;
            long long stepTs = adjTs + (long long)skew * 30;
            cloudLine(QString("---- step %1 (%2) ----")
                          .arg((qulonglong)step)
                          .arg(skew == 0 ? "current"
                                         : (skew < 0 ? "previous 30s" : "next 30s"))
                          .toStdString());
            for (const auto& c : totpCandidates(seed, seedStr, step, stepTs))
                cloudLine(("  " + c.first.leftJustified(34, ' ') + c.second).toStdString());
        }
        cloudLine("Try each code in the engineering menu within its 30s window.");
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
    auto* refIntro = new QLabel(QString(
        "<b>Reference scan</b> (Autel MaxiCOM) - %1 systems, %2 DTCs stored for "
        "this VIN. Expand a system to compare against a live scan.")
        .arg((int)kVF8ReferenceScan.size()).arg(total));
    refIntro->setWordWrap(true);
    lay->addWidget(refIntro);

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
                       "ones apply to the VF8's UDS stack.");

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
    rngTop->setText(0, "UDS logical-address ranges (ISO 13400-2)");
    rngTop->setText(1, QString("%1").arg((int)kUdsAddrRanges.size()));
    for (const auto& r : kUdsAddrRanges) {
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
        QWidget { background: #f4f7fb; color: #1f2a37; font-size: 13px; }
        QLabel { background: transparent; }
        QLabel#ecuTitle { font-size: 38px; font-weight: 800; color: #10233d; letter-spacing: 1px; }
        QLabel#ecuSubtitle { color: #50657d; font-size: 16px; font-weight: 600; }
        QFrame#header { background: #ffffff;
                        border-bottom: 2px solid #2e7dd1; }
        QLabel#title { font-size: 20px; font-weight: 700; color: #10233d; }
        QLabel#subtitle { color: #63758a; font-size: 11px; }
        QLabel#dotGood { color: #43d17a; font-size: 16px; }
        QLabel#dotBad  { color: #e0556a; font-size: 16px; }
        QLabel#dotIdle { color: #8a97a8; font-size: 16px; }
        QLabel#dotBusy { color: #f2b134; font-size: 16px; }
        QListWidget#nav { background: #ebf1f7; border: none; outline: none; }
        QListWidget#nav::item { color: #304255; border-radius: 6px; margin: 2px 8px; }
        QListWidget#nav::item:selected { background: #2e7dd1; color: #ffffff; }
        QListWidget#nav::item:hover { background: #dbe7f3; }
        QGroupBox#card { background: #ffffff; border: 1px solid #d6e0ea;
                         border-radius: 10px; margin-top: 14px; padding: 12px; }
        QGroupBox#card::title { subcontrol-origin: margin; left: 12px;
                                padding: 0 6px; color: #2f6fbf; font-weight: 600; }
        QPushButton { background: #f7f9fc; border: 1px solid #cfd9e4;
                      border-radius: 6px; padding: 7px 14px; }
        QPushButton:hover { background: #edf3f8; }
        QPushButton#primary { background: #2e7dd1; border: none; color: #fff; font-weight: 600; }
        QPushButton#primary:hover { background: #3a8ce0; }
        QPushButton#danger { background: #b23a4a; border: none; color: #fff; }
        QPushButton#danger:hover { background: #c8485a; }
        QFrame#ecuCanvas {
            background: #ffffff;
            border: 1px solid #c7d8ea;
            border-radius: 12px;
        }
        QLabel#ecuCanvasHint { color: #5f7287; font-size: 12px; }
        QFrame#ecuLegend {
            background: rgba(255, 255, 255, 0.96);
            border: 1px solid #c7d8ea;
            border-radius: 12px;
        }
        QLabel#ecuLegendTitle { font-size: 17px; font-weight: 700; color: #10233d; }
        QLabel#ecuLegendNote { color: #5f7287; font-size: 12px; }
        QToolButton#tile { background: #ffffff; border: 1px solid #d1dbe6;
                           border-radius: 10px; font-weight: 600; }
        QToolButton#tile:hover { background: #eef4f9; border-color: #2e7dd1; }
        QLineEdit, QSpinBox, QComboBox { background: #ffffff; border: 1px solid #cfd9e4;
                          border-radius: 5px; padding: 5px; }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border-color: #2e7dd1; }
        QTableWidget, QTreeWidget, QPlainTextEdit#log { background: #ffffff;
                          border: 1px solid #d6e0ea; border-radius: 8px; gridline-color: #e2eaf2; }
        QHeaderView::section { background: #edf3f8; color: #425466; border: none;
                          padding: 6px; }
        QScrollBar:vertical { background: #eef3f8; width: 12px; }
        QScrollBar::handle:vertical { background: #c2cfdb; border-radius: 6px; }
    )");
}

// ==========================================================================
// Periodic refresh
// ==========================================================================
void Gui::onTick() {
    refreshHeader();
    refreshDashboard();
    if (pages_->currentIndex() == 2) refreshEcuTiles();
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

    bool conn = transport_.isConnected() || canBackup_.isConnected();
    connDot_->setObjectName(conn ? "dotGood" : "dotBad");
    {
        std::lock_guard<std::mutex> g(mutex_);
        connText_->setText(QString::fromStdString(connStatus_));
    }
    connectBtn_->setText(conn ? "Disconnect" : "Connect");

    if (hdrSubtitle_) {
        std::string vin = vf8::kVin;
        int identified = 0;
        int total = 0;
        {
            std::lock_guard<std::mutex> g(mutex_);
            total = (int)ecus_.size();
            for (const auto& r : ecus_) {
                if (!r.idInfo.empty()) ++identified;
                std::string cand = extractScannedVin(r.idInfo);
                if (!cand.empty()) vin = cand;
            }
        }
        hdrSubtitle_->setText(QString("VIN %1   ·   Modules %2/%3 identified")
                                  .arg(QString::fromStdString(vin))
                                  .arg(identified)
                                  .arg(total));
    }

    // re-polish so objectName-based colors update
    busyDot_->style()->unpolish(busyDot_); busyDot_->style()->polish(busyDot_);
    connDot_->style()->unpolish(connDot_); connDot_->style()->polish(connDot_);
}

void Gui::refreshDashboard() {
    if (!dashModel_ || !dashVin_ || !dashMarket_ || !dashMhuSw_ || !dashTbox_ || !dashModules_)
        return;

    std::string vin = vf8::kVin;
    std::string mhuSw;
    std::string tboxSw;
    int reachable = 0;
    int identified = 0;
    int faulted = 0;
    int total = 0;

    {
        std::lock_guard<std::mutex> g(mutex_);
        total = (int)ecus_.size();
        for (const auto& r : ecus_) {
            if (r.reachable == 1) ++reachable;
            if (!r.dtcs.empty()) ++faulted;
            if (!r.idInfo.empty()) {
                ++identified;
                std::string candVin = extractScannedVin(r.idInfo);
                if (!candVin.empty()) vin = candVin;
            }

            std::string code = r.name;
            size_t sep = code.find(" - ");
            if (sep != std::string::npos) code = code.substr(0, sep);
            if (mhuSw.empty() && code == "MHU") {
                mhuSw = extractDidValue(r.idInfo, "SW Version Number");
                if (mhuSw.empty()) mhuSw = extractDidValue(r.idInfo, "SW Version");
                if (mhuSw.empty()) mhuSw = extractDidValue(r.idInfo, "ECU SW Version");
                if (mhuSw.empty()) mhuSw = extractDidValue(r.idInfo, "System Supplier SW Version");
            }
            if (tboxSw.empty() && code == "TBOX") {
                tboxSw = extractDidValue(r.idInfo, "SW Version Number");
                if (tboxSw.empty()) tboxSw = extractDidValue(r.idInfo, "SW Version");
                if (tboxSw.empty()) tboxSw = extractDidValue(r.idInfo, "ECU SW Version");
                if (tboxSw.empty()) tboxSw = extractDidValue(r.idInfo, "System Supplier SW Version");
            }
        }
    }

    if (identified == 0) {
        dashModel_->setText("-");
        dashVin_->setText("-");
        dashMarket_->setText("-");
        dashMhuSw_->setText("-");
        dashTbox_->setText("-");
        dashModules_->setText("-");
    } else {
        std::string year = decodeVinModelYear(vin);
        dashModel_->setText(year.empty()
            ? QString(vf8::kModel)
            : QString("%1 (%2)").arg(vf8::kModel).arg(QString::fromStdString(year)));
        dashVin_->setText(QString::fromStdString(vin));
        dashMarket_->setText(QString("%1   ·   %2").arg(vf8::kMarket).arg(vf8::kVariant));
        dashMhuSw_->setText(QString::fromStdString(mhuSw.empty() ? std::string(vf8::kMhuSoftware) : mhuSw));
        dashTbox_->setText(QString::fromStdString(tboxSw.empty() ? std::string(vf8::kTboxProject) : tboxSw));
        dashModules_->setText(QString("ID %1/%2   |   Reach %3   |   DTC %4")
                                  .arg(identified).arg(total).arg(reachable).arg(faulted));
    }
}

void Gui::refreshEcuTiles() {
    if (!topology_) return;

    // Map each ECU code to one of the three communication buses
    // (0 = drive, 1 = comfort, 2 = information).
    static const std::vector<std::pair<const char*, int>> kBus = {
        {"VCU",0},{"MCU",0},{"BMS",0},{"EDS_F",0},{"EDS_R",0},{"DCDC",0},
        {"DDC",0},{"APM",0},{"PSM_D",0},{"SHVU_F",0},{"BCM_BPM",0},
        {"BCM",1},{"CCU",1},{"MHU",1},{"RLS",1},{"TBOX",1},{"HUD",1},{"IDR",1},
        {"ESC",2},{"EPS",2},{"ADAS",2},{"ACM",2},{"MRGEN",2},{"SCAM",2},{"RCU",2},
        {"SRR_FR",2},{"SRR_FL",2},{"SRR_RR",2},{"SRR_RL",2},{"OCS",2},
    };
    auto busOf = [](const QString& code) -> int {
        for (const auto& kv : kBus)
            if (code == QString::fromUtf8(kv.first)) return kv.second;
        return 1;   // unknown / discovered modules default to the comfort bus
    };

    std::vector<EcuTopologyView::Node> nodes;
    std::lock_guard<std::mutex> g(mutex_);

    std::vector<QString> code(ecus_.size());
    std::vector<int> band[3];
    int gwIdx = -1;
    for (size_t i = 0; i < ecus_.size(); ++i) {
        QString full = QString::fromStdString(ecus_[i].name);
        int dash = full.indexOf(" - ");
        code[i] = (dash > 0 ? full.left(dash) : full).trimmed();
        if (code[i] == "XGW") { gwIdx = (int)i; continue; }
        band[busOf(code[i])].push_back((int)i);
    }

    auto makeNode = [&](int i, int bus, int col, bool below, bool gw) {
        const EcuRow& r = ecus_[i];
        EcuTopologyView::Node n;
        n.code     = code[i];
        n.addr     = QString("0x%1").arg(r.logicalAddr, 4, 16, QChar('0')).toUpper();
        n.fullName = QString::fromStdString(r.name);
        n.ecuIndex = i;
        n.bus = bus; n.col = col; n.below = below; n.gateway = gw;
        n.faults = (int)r.dtcs.size();
        if (r.statusMsg.rfind("scanning module ", 0) == 0) n.state = 4; // scanning
        else if (r.reachable == 0)      n.state = 3;   // no response
        else if (!r.dtcs.empty())  n.state = 2;   // fault
        else if (r.reachable == 1) n.state = 1;   // pass
        else                       n.state = 0;   // not scanned
        return n;
    };

    if (gwIdx >= 0) nodes.push_back(makeNode(gwIdx, 1, 0, false, true));

    // Split each bus's modules into a row above and a row below its trunk.
    for (int b = 0; b < 3; ++b) {
        const int total = (int)band[b].size();
        const int aboveCount = (total + 1) / 2;
        for (int k = 0; k < total; ++k) {
            const bool below = k >= aboveCount;
            const int col = below ? (k - aboveCount) : k;
            nodes.push_back(makeNode(band[b][k], b, col, below, false));
        }
    }

    topology_->setNodes(std::move(nodes));
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
// ----- CAN bus discovery scan ---------------------------------------------
namespace {

// A single CAN diagnostic target (one request/response identifier pair).
struct CanTarget {
    uint32_t req  = 0;
    uint32_t resp = 0;
    bool     functional = false;
    QString  label;
};

// A UDS/OBD probe service sent to each target. Any reply (even a negative
// 0x7F response) proves the ECU is alive on that protocol/baud/id.
struct CanProbe {
    const char*          name;
    std::vector<uint8_t> bytes;
};

// One responder discovered during the scan (queued for the UI thread).
struct CanHit {
    uint32_t baud = 0;
    bool     ext  = false;
    uint32_t req  = 0;
    uint32_t resp = 0;
    QString  service;
    QString  response;
};

// Shared state between the scan worker thread and the dialog's UI timer.
struct CanScanState {
    std::atomic<bool> cancel{false};
    std::atomic<bool> running{false};
    std::atomic<bool> done{false};
    std::atomic<int>  progress{0};   // 0..1000 (per-mille for smoothness)
    std::atomic<int>  found{0};
    std::mutex        mtx;
    std::string       status;
    std::vector<CanHit> pending;     // drained by the UI timer
};

// Builds the list of identifier targets for one addressing width / scope.
static std::vector<CanTarget> buildCanTargets(bool ext, bool sweep) {
    std::vector<CanTarget> t;
    if (!ext) {
        // ISO 15765-4 11-bit OBD-II.
        t.push_back({0x7DF, 0x7E8, true,  "11b OBD functional"});
        for (uint32_t i = 0; i < 8; ++i)
            t.push_back({0x7E0 + i, 0x7E8 + i, false,
                         QString::asprintf("11b phys %03X", 0x7E0 + i)});
        if (sweep) {
            // Manufacturer-specific 11-bit range, resp = req + 8 heuristic.
            for (uint32_t id = 0x700; id <= 0x7FF; ++id) {
                if (id >= 0x7DF && id <= 0x7EF) continue;  // already covered
                t.push_back({id, id + 8, false,
                             QString::asprintf("11b sweep %03X", id)});
            }
        }
    } else {
        // ISO 15765-4 29-bit OBD-II.
        t.push_back({0x18DB33F1u, 0x18DAF111u, true, "29b OBD functional"});
        uint32_t maxTa = sweep ? 0xFF : 0x3F;
        for (uint32_t ta = 0; ta <= maxTa; ++ta) {
            uint32_t req  = 0x18DA0000u | (ta << 8) | 0xF1u;
            uint32_t resp = 0x18DAF100u | ta;
            t.push_back({req, resp, false,
                         QString::asprintf("29b phys TA=%02X", ta)});
        }
    }
    return t;
}

// The probe services tried against every target.
static std::vector<CanProbe> canProbeSet() {
    return {
        {"TesterPresent (3E 00)",      {0x3E, 0x00}},
        {"DefaultSession (10 01)",     {0x10, 0x01}},
        {"OBD PIDs (01 00)",           {0x01, 0x00}},
        {"Read VIN DID (22 F1 90)",    {0x22, 0xF1, 0x90}},
        {"OBD VIN (09 02)",            {0x09, 0x02}},
    };
}

static QString hexBytes(const std::vector<uint8_t>& v) {
    QString s;
    for (uint8_t b : v) s += QString::asprintf("%02X ", b);
    return s.trimmed();
}

} // namespace

void Gui::openCanScanDialog(QWidget* anchor) {
    auto* dlg = new QDialog(this);
    dlg->setWindowTitle("CAN / OBD-II Bus Scan - Toyota Mini-VCI (J2534)");
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setMinimumSize(760, 620);
    auto* root = new QVBoxLayout(dlg);

    auto* intro = new QLabel(
        "<b>Extensive CAN discovery.</b> Probes every selected baud rate, "
        "addressing width and identifier with a battery of UDS/OBD services "
        "via the Toyota Mini-VCI (J2534 PassThru, mvci32.dll). Any reply - "
        "positive or negative - proves the vehicle answers on that protocol/ID.");
    intro->setWordWrap(true);
    root->addWidget(intro);

    if (!can::Client::platformSupported()) {
        auto* warn = new QLabel(
            "<span style='color:#c0392b'><b>CAN scanning requires Windows</b> "
            "with the Toyota Mini-VCI J2534 driver (mvci32.dll). This platform "
            "will report the API as unavailable.</span>");
        warn->setWordWrap(true);
        root->addWidget(warn);
    }

    // =====================================================================
    //  OBD-II protocol discovery - figure out HOW the vehicle communicates
    // =====================================================================
    // We don't yet know whether the VF8 uses CAN, K-line or J1850, so this
    // sweeps every standard OBD-II protocol the Mini-VCI can attempt and
    // reports which one(s) the vehicle actually answers on.
    struct ProtoState {
        std::mutex                 mtx;
        std::vector<can::ProtocolProbe> pending;
        std::atomic<int>           progress{0};   // 0..1000
        std::atomic<bool>          running{false};
        std::atomic<bool>          cancel{false};
        std::atomic<bool>          done{false};
        std::string                status;
    };
    auto ps = std::make_shared<ProtoState>();
    auto pThreadHolder = std::make_shared<std::thread*>(nullptr);

    auto* discBox = new QGroupBox("Step 1 - Discover OBD-II protocol");
    auto* dl = new QVBoxLayout(discBox);
    auto* discIntro = new QLabel(
        "Sweeps ISO 15765-4 CAN (11/29-bit @ 500k & 250k), a passive raw-CAN "
        "sniff, SAE J1850 PWM/VPW and ISO 9141-2 / ISO 14230-4 KWP (K-line) to "
        "find which transport the vehicle responds on.");
    discIntro->setWordWrap(true);
    dl->addWidget(discIntro);

    auto* discBar = new QProgressBar();
    discBar->setRange(0, 1000); discBar->setValue(0);
    discBar->setTextVisible(true); discBar->setFormat("%p%");
    dl->addWidget(discBar);
    auto* discStatus = new QLabel("Idle. Press \"Discover protocol\" to begin.");
    discStatus->setWordWrap(true);
    dl->addWidget(discStatus);

    auto* discTable = new QTableWidget(0, 3);
    discTable->setHorizontalHeaderLabels({"Protocol", "Result", "Detail"});
    discTable->horizontalHeader()->setStretchLastSection(true);
    discTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    discTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    discTable->verticalHeader()->setVisible(false);
    discTable->setMinimumHeight(150);
    dl->addWidget(discTable);

    auto* discBtnRow = new QHBoxLayout();
    auto* btnDiscover = new QPushButton("Discover protocol");
    btnDiscover->setObjectName("primary");
    auto* btnDiscStop = new QPushButton("Stop"); btnDiscStop->setEnabled(false);
    discBtnRow->addWidget(btnDiscover);
    discBtnRow->addWidget(btnDiscStop);
    discBtnRow->addStretch(1);
    dl->addLayout(discBtnRow);
    root->addWidget(discBox);

    std::string protoDll = canDll_;
    auto* discTimer = new QTimer(dlg);
    discTimer->setInterval(120);
    QObject::connect(discTimer, &QTimer::timeout, dlg,
                     [ps, discBar, discStatus, discTable, btnDiscover, btnDiscStop] {
        std::vector<can::ProtocolProbe> rows;
        std::string s;
        {
            std::lock_guard<std::mutex> g(ps->mtx);
            rows.swap(ps->pending);
            s = ps->status;
        }
        discBar->setValue(ps->progress.load());
        if (!s.empty()) discStatus->setText(QString::fromStdString(s));
        for (const auto& p : rows) {
            int r = discTable->rowCount();
            discTable->insertRow(r);
            discTable->setItem(r, 0, new QTableWidgetItem(QString::fromStdString(p.protocol)));
            QString result = !p.linkUp ? "link failed"
                                       : (p.responded ? "RESPONDED" : "no reply");
            auto* it = new QTableWidgetItem(result);
            if (p.responded) it->setForeground(QColor("#1e8449"));
            else if (!p.linkUp) it->setForeground(QColor("#7f8c8d"));
            discTable->setItem(r, 1, it);
            discTable->setItem(r, 2, new QTableWidgetItem(QString::fromStdString(p.detail)));
            discTable->scrollToBottom();
        }
        if (ps->done.load() && !ps->running.load()) {
            btnDiscover->setEnabled(true);
            btnDiscStop->setEnabled(false);
        }
    });
    discTimer->start();

    QObject::connect(btnDiscover, &QPushButton::clicked, dlg,
        [=]() mutable {
            if (ps->running.load()) return;
            discTable->setRowCount(0);
            ps->cancel = false; ps->done = false; ps->progress = 0;
            { std::lock_guard<std::mutex> g(ps->mtx); ps->pending.clear(); ps->status = "Scanning protocols..."; }
            ps->running = true;
            btnDiscover->setEnabled(false);
            btnDiscStop->setEnabled(true);

            if (*pThreadHolder) {
                if ((*pThreadHolder)->joinable()) (*pThreadHolder)->join();
                delete *pThreadHolder;
                *pThreadHolder = nullptr;
            }
            *pThreadHolder = new std::thread([ps, protoDll]() {
                can::Client scanner;
                std::string err;
                bool ok = scanner.scanObdProtocols(
                    protoDll,
                    [ps](float f) { ps->progress = (int)(f * 1000); },
                    [ps](const can::ProtocolProbe& p) {
                        std::lock_guard<std::mutex> g(ps->mtx);
                        ps->pending.push_back(p);
                    },
                    ps->cancel,
                    err);
                {
                    std::lock_guard<std::mutex> g(ps->mtx);
                    if (!ok)
                        ps->status = "Protocol discovery failed: " + err;
                    else if (ps->cancel.load())
                        ps->status = "Protocol discovery stopped.";
                    else
                        ps->status = "Protocol discovery complete. Check the "
                                     "\"RESPONDED\" rows for the vehicle's transport.";
                }
                ps->progress = 1000;
                ps->running = false;
                ps->done = true;
            });
        });

    QObject::connect(btnDiscStop, &QPushButton::clicked, dlg,
                     [ps, btnDiscStop]() { ps->cancel = true; btnDiscStop->setEnabled(false); });
    QObject::connect(dlg, &QObject::destroyed, dlg, [ps, pThreadHolder]() {
        ps->cancel = true;
        if (*pThreadHolder) {
            if ((*pThreadHolder)->joinable()) (*pThreadHolder)->join();
            delete *pThreadHolder;
            *pThreadHolder = nullptr;
        }
    });

    // --- scan scope options ---
    auto* opt = new QGroupBox("Step 2 - CAN ID / service sweep (ISO 15765)");
    auto* og = new QGridLayout(opt);
    auto* cb500  = new QCheckBox("500 kbit/s");  cb500->setChecked(true);
    auto* cb250  = new QCheckBox("250 kbit/s");  cb250->setChecked(true);
    auto* cb125  = new QCheckBox("125 kbit/s");
    auto* cb1m   = new QCheckBox("1 Mbit/s");
    auto* cb11   = new QCheckBox("11-bit IDs");  cb11->setChecked(true);
    auto* cb29   = new QCheckBox("29-bit IDs");  cb29->setChecked(true);
    auto* cbSweep= new QCheckBox("Thorough sweep (slow: scans full ID space)");
    og->addWidget(new QLabel("<b>Baud rates</b>"), 0, 0);
    og->addWidget(cb500, 1, 0); og->addWidget(cb250, 1, 1);
    og->addWidget(cb125, 1, 2); og->addWidget(cb1m, 1, 3);
    og->addWidget(new QLabel("<b>Addressing</b>"), 2, 0);
    og->addWidget(cb11, 3, 0); og->addWidget(cb29, 3, 1);
    og->addWidget(cbSweep, 4, 0, 1, 4);
    root->addWidget(opt);

    // --- progress + status ---
    auto* bar = new QProgressBar();
    bar->setRange(0, 1000);
    bar->setValue(0);
    bar->setTextVisible(true);
    bar->setFormat("%p%");
    root->addWidget(bar);
    auto* status = new QLabel("Idle. Choose a scope and press Start.");
    status->setWordWrap(true);
    root->addWidget(status);

    // --- results table ---
    auto* table = new QTableWidget(0, 6);
    table->setHorizontalHeaderLabels(
        {"Baud", "Width", "Req ID", "Resp ID", "Service", "Response"});
    table->horizontalHeader()->setStretchLastSection(true);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->verticalHeader()->setVisible(false);
    root->addWidget(table, 1);

    // --- buttons ---
    auto* btnRow = new QHBoxLayout();
    auto* btnStart = new QPushButton("Start scan");
    btnStart->setObjectName("primary");
    auto* btnStop  = new QPushButton("Stop");
    btnStop->setEnabled(false);
    auto* btnClose = new QPushButton("Close");
    btnRow->addWidget(btnStart);
    btnRow->addWidget(btnStop);
    btnRow->addStretch(1);
    btnRow->addWidget(btnClose);
    root->addLayout(btnRow);

    auto st = std::make_shared<CanScanState>();
    auto threadHolder = std::make_shared<std::thread*>(nullptr);
    std::string dll = canDll_;

    // Drain worker output into the widgets on the UI thread.
    auto* timer = new QTimer(dlg);
    timer->setInterval(120);
    QObject::connect(timer, &QTimer::timeout, dlg,
                     [st, bar, status, table, btnStart, btnStop] {
        std::vector<CanHit> hits;
        std::string s;
        {
            std::lock_guard<std::mutex> g(st->mtx);
            hits.swap(st->pending);
            s = st->status;
        }
        bar->setValue(st->progress.load());
        status->setText(QString::fromStdString(s));
        for (const auto& h : hits) {
            int r = table->rowCount();
            table->insertRow(r);
            table->setItem(r, 0, new QTableWidgetItem(
                QString::number(h.baud) + " bps"));
            table->setItem(r, 1, new QTableWidgetItem(h.ext ? "29-bit" : "11-bit"));
            table->setItem(r, 2, new QTableWidgetItem(
                QString::asprintf("0x%X", h.req)));
            table->setItem(r, 3, new QTableWidgetItem(
                QString::asprintf("0x%X", h.resp)));
            table->setItem(r, 4, new QTableWidgetItem(h.service));
            table->setItem(r, 5, new QTableWidgetItem(h.response));
            table->scrollToBottom();
        }
        if (st->done.load() && !st->running.load()) {
            btnStart->setEnabled(true);
            btnStop->setEnabled(false);
        }
    });
    timer->start();

    QObject::connect(btnStart, &QPushButton::clicked, dlg,
        [=]() mutable {
            if (st->running.load()) return;
            std::vector<uint32_t> bauds;
            if (cb500->isChecked()) bauds.push_back(500000);
            if (cb250->isChecked()) bauds.push_back(250000);
            if (cb125->isChecked()) bauds.push_back(125000);
            if (cb1m->isChecked())  bauds.push_back(1000000);
            std::vector<bool> widths;
            if (cb11->isChecked()) widths.push_back(false);
            if (cb29->isChecked()) widths.push_back(true);
            if (bauds.empty() || widths.empty()) {
                status->setText("Select at least one baud rate and addressing width.");
                return;
            }
            bool sweep = cbSweep->isChecked();

            // Clear previous run.
            table->setRowCount(0);
            st->cancel = false;
            st->done = false;
            st->found = 0;
            st->progress = 0;
            { std::lock_guard<std::mutex> g(st->mtx); st->pending.clear(); st->status = "Starting..."; }
            st->running = true;
            btnStart->setEnabled(false);
            btnStop->setEnabled(true);

            // Join any finished previous thread before launching a new one.
            if (*threadHolder) {
                if ((*threadHolder)->joinable()) (*threadHolder)->join();
                delete *threadHolder;
                *threadHolder = nullptr;
            }

            *threadHolder = new std::thread([st, dll, bauds, widths, sweep]() {
                auto probes = canProbeSet();

                // Precompute total probe count for the progress bar.
                long total = 0;
                for (bool ext : widths)
                    total += (long)buildCanTargets(ext, sweep).size() *
                             (long)probes.size() * (long)bauds.size();
                if (total <= 0) total = 1;
                long step = 0;
                auto bump = [&] {
                    ++step;
                    st->progress = (int)std::min<long>(1000, (step * 1000) / total);
                };

                can::Client scanner;
                for (uint32_t baud : bauds) {
                    if (st->cancel.load()) break;
                    for (bool ext : widths) {
                        if (st->cancel.load()) break;
                        auto targets = buildCanTargets(ext, sweep);
                        if (targets.empty()) continue;

                        can::Config cfg;
                        cfg.dllPath    = dll;
                        cfg.baudrate   = (uint32_t)baud;
                        cfg.extendedId = ext;
                        cfg.reqId      = targets.front().req;
                        cfg.respId     = targets.front().resp;
                        {
                            std::lock_guard<std::mutex> g(st->mtx);
                            st->status = "Opening link @ " + std::to_string(baud) +
                                         " bps, " + (ext ? "29-bit" : "11-bit") + "...";
                        }
                        std::string err;
                        if (!scanner.connect(cfg, err)) {
                            {
                                std::lock_guard<std::mutex> g(st->mtx);
                                st->status = "Link unavailable @ " + std::to_string(baud) +
                                             " bps (" + err + ")";
                            }
                            // Skip this whole (baud,width) block; advance progress.
                            for (size_t i = 0; i < targets.size() * probes.size(); ++i) bump();
                            continue;
                        }

                        for (const auto& tgt : targets) {
                            if (st->cancel.load()) break;
                            std::string e2;
                            scanner.setAddressing(tgt.req, tgt.resp, e2);
                            {
                                std::lock_guard<std::mutex> g(st->mtx);
                                st->status = "Probing " + tgt.label.toStdString() +
                                             " @ " + std::to_string(baud) + " bps";
                            }
                            for (const auto& pr : probes) {
                                if (st->cancel.load()) break;
                                std::vector<uint8_t> resp;
                                std::string e3;
                                int timeout = tgt.functional ? 250 : 120;
                                bool ok = scanner.sendDiagnostic(
                                    0, 0, pr.bytes, resp, timeout, e3, tgt.functional);
                                bump();
                                if (ok && !resp.empty()) {
                                    st->found = st->found.load() + 1;
                                    CanHit hit;
                                    hit.baud = baud;
                                    hit.ext  = ext;
                                    hit.req  = tgt.req;
                                    hit.resp = tgt.resp;
                                    hit.service  = QString::fromUtf8(pr.name);
                                    hit.response = hexBytes(resp);
                                    std::lock_guard<std::mutex> g(st->mtx);
                                    st->pending.push_back(std::move(hit));
                                }
                            }
                        }
                        scanner.disconnect();
                    }
                }

                {
                    std::lock_guard<std::mutex> g(st->mtx);
                    if (st->cancel.load())
                        st->status = "Scan stopped. " + std::to_string(st->found.load()) +
                                     " responder(s) found.";
                    else
                        st->status = "Scan complete. " + std::to_string(st->found.load()) +
                                     " responder(s) found.";
                }
                st->progress = 1000;
                st->running = false;
                st->done = true;
            });
        });

    QObject::connect(btnStop, &QPushButton::clicked, dlg,
                     [st, btnStop]() { st->cancel = true; btnStop->setEnabled(false); });
    QObject::connect(btnClose, &QPushButton::clicked, dlg, [dlg]() { dlg->close(); });

    // Ensure the worker is stopped and joined when the dialog is destroyed.
    QObject::connect(dlg, &QObject::destroyed, dlg,
                     [st, threadHolder]() {
        st->cancel = true;
        if (*threadHolder) {
            if ((*threadHolder)->joinable()) (*threadHolder)->join();
            delete *threadHolder;
            *threadHolder = nullptr;
        }
    });

    if (anchor) dlg->move(anchor->mapToGlobal(QPoint(0, anchor->height() + 6)));
    dlg->show();
}

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
    connect(ok, &QPushButton::clicked, this, [=, this] {
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

    auto* dtcTable = new QTableWidget(0, 5);
    dtcTable->setHorizontalHeaderLabels({"DTC", "Code status", "Status", "Description", ""});
    dtcTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    dtcTable->setColumnWidth(0, 130);
    dtcTable->setColumnWidth(1, 110);
    dtcTable->setColumnWidth(4, 90);
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
            set(1, QString::fromStdString(dtcLifecycle(d.status)));
            set(2, QString::fromStdString(decodeDtcStatus(d.status)));
            set(3, QString::fromStdString(dtcDescription(d.code)));
            if (!dtcTable->cellWidget((int)di, 4)) {
                auto* snap = new QPushButton("Snapshot");
                uint32_t code = d.code;
                connect(snap, &QPushButton::clicked, this, [this, idx, code, targetOf] {
                    uint16_t target = targetOf();
                    startWorker([this, idx, code, target] {
                        std::string err;
                        if (!ensureConnected(err)) { Logger::instance().error(err); return; }
                        UDSClient uds(transport_, (uint16_t)testerAddr_);
                        std::vector<uint8_t> raw;
                        if (uds.readDTCSnapshot(target, code, 0xFF, raw, err)) {
                            std::lock_guard<std::mutex> g(mutex_);
                            if (idx < (int)ecus_.size())
                                ecus_[idx].statusMsg = "snapshot " +
                                    byteHex((code>>16)&0xFF) + byteHex((code>>8)&0xFF) + byteHex(code&0xFF) +
                                    ": " + toHex(raw.data(), raw.size());
                        } else { std::lock_guard<std::mutex> g(mutex_);
                            if (idx < (int)ecus_.size()) ecus_[idx].statusMsg = "snapshot failed: " + err; }
                    });
                });
                dtcTable->setCellWidget((int)di, 4, snap);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
            if (!uds.controlDTCSetting(target, true, err)) Logger::instance().error(err);
        });
    });
    connect(bLogOff, &QPushButton::clicked, this, [this, targetOf] {
        uint16_t target = targetOf();
        startWorker([this, target] {
            std::string err;
            if (!ensureConnected(err)) { Logger::instance().error(err); return; }
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
    if (edGateway_)    gatewayIp_   = edGateway_->text().toStdString();
    if (edTester_)     testerAddr_  = parseHex16(edTester_->text(), 0x0E80);
    if (edGwAddr_)     gatewayAddr_ = parseHex16(edGwAddr_->text(), 0x1001);
    if (sbOpenxcBus_)  openxcBus_   = sbOpenxcBus_->value();
    if (edFunctional_) functionalAddr_ = parseHex16(edFunctional_->text(), 0xE400);
    if (cbFunctional_) useFunctional_  = cbFunctional_->isChecked();
    if (edStatusMask_) statusMask_   = parseHex16(edStatusMask_->text(), 0x08);
    if (cbSession_)    sessionType_  = cbSession_->currentIndex() + 1;
    if (cbAutoExt_)    autoExtendedOnClear_ = cbAutoExt_->isChecked();
    if (cbKeepAlive_)  keepAlive_    = cbKeepAlive_->isChecked();
    if (edKeepAliveTarget_) keepAliveTarget_ = parseHex16(edKeepAliveTarget_->text(), 0x1001);
    if (edSecurityTarget_) securityTarget_ = parseHex16(edSecurityTarget_->text(), 0x1001);
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
    if (cbCanEnabled_) canEnabled_   = cbCanEnabled_->isChecked();
    if (edCanDll_)     canDll_       = edCanDll_->text().toStdString();
    if (edCanBaud_) {
        const int parsed = edCanBaud_->text().toInt();
        // VF8 diagnostics are expected on HS-CAN 500 kbps.
        canBaud_ = parsed > 0 ? parsed : 500000;
    }
    auto parseHex32 = [](const QString& s, int def) -> int {
        QString t = s.trimmed();
        if (t.startsWith("0x", Qt::CaseInsensitive)) t = t.mid(2);
        bool ok = false;
        uint v = t.toUInt(&ok, 16);
        return ok ? (int)v : def;
    };
    if (edCanReqId_)   canReqId_     = parseHex32(edCanReqId_->text(), 0x7E0);
    if (edCanRespId_)  canRespId_    = parseHex32(edCanRespId_->text(), 0x7E8);
    if (cbCanExt_)     canExtended_  = cbCanExt_->isChecked();
    if (edCanIdBase_)     canIdBase_     = parseHex32(edCanIdBase_->text(), 0x700);
    if (edCanRespOffset_) canRespOffset_ = parseHex32(edCanRespOffset_->text(), 0x08);
    // Clamp to 11-bit arbitration IDs.
    canIdBase_     &= 0x7FF;
    canRespOffset_ &= 0x7FF;
}

void Gui::startKeepAlive() {
    if (keepAliveRun_) return;
    keepAliveRun_ = true;
    keepAliveThread_ = std::thread([this] {
        while (keepAliveRun_) {
            if (transport_.isConnected() && !busy_) {
                std::lock_guard<std::mutex> n(netMutex_);
                UDSClient uds(transport_, (uint16_t)testerAddr_);
                std::string err;
                uint16_t tgt = (uint16_t)(keepAliveTarget_ ? keepAliveTarget_ : gatewayAddr_);
                uds.testerPresent(tgt, err, /*suppress=*/true);
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
        if (bundle && transport_.isConnected()) {
            std::vector<std::tuple<size_t, uint16_t, uint16_t>> snap;
            {
                std::lock_guard<std::mutex> g(mutex_);
                for (size_t i = 0; i < liveSignals_.size(); ++i)
                    snap.emplace_back(i, liveSignals_[i].target, liveSignals_[i].did);
            }
            std::lock_guard<std::mutex> n(netMutex_);
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
            if (!transport_.isConnected() || busy_) {
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
                    UDSClient uds(transport_, (uint16_t)testerAddr_);
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
                if (!transport_.isConnected() || busy_) break;
                std::vector<uint8_t> data; bool ok = false;
                {
                    std::lock_guard<std::mutex> n(netMutex_);
                    UDSClient uds(transport_, (uint16_t)testerAddr_);
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
        if (transport_.isConnected()) {
            std::lock_guard<std::mutex> n(netMutex_);
            UDSClient uds(transport_, (uint16_t)testerAddr_);
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
    // Bring up the optional CAN backup transport first so it is available the
    // moment an OpenXC exchange fails. A CAN failure here is non-fatal.
    if (canEnabled_ && !canBackup_.isConnected()) {
        if (can::Client::platformSupported()) {
            can::Config cfg;
            cfg.dllPath    = canDll_;
            const int safeBaud = canBaud_ > 0 ? canBaud_ : 500000;
            cfg.baudrate   = (uint32_t)safeBaud;
            cfg.reqId      = (uint32_t)canReqId_;
            cfg.respId     = (uint32_t)canRespId_;
            cfg.extendedId = canExtended_;
            std::string canErr;
            if (!canBackup_.connect(cfg, canErr)) {
                Logger::instance().warn("CAN backup unavailable: " + canErr);
            } else {
                Logger::instance().info("CAN backup transport ready");
            }
        } else {
            Logger::instance().warn("CAN backup enabled but not supported on this platform");
        }
    }

    // Apply the latest OpenXC settings before opening the link.
    transport_.setBus(openxcBus_);
    transport_.setCanIdMapping((uint32_t)canIdBase_, (uint32_t)canRespOffset_);

    if (transport_.isConnected()) return true;
    if (!transport_.connect(gatewayIp_, err)) {
        // OpenXC link could not be established. If the CAN backup is up we can
        // still operate purely over CAN.
        if (canBackup_.isConnected()) {
            Logger::instance().warn("OpenXC connect failed (" + err +
                                    "); continuing over CAN backup");
            err.clear();
            return true;
        }
        return false;
    }
    if (keepAlive_) startKeepAlive();
    return true;
}
