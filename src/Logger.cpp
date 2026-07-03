#include "Logger.hpp"

#include <cstdio>
#include <ctime>
#include <fstream>

Logger& Logger::instance() {
    static Logger l;
    return l;
}

Logger::Logger() : start_(std::chrono::steady_clock::now()) {}

void Logger::log(LogLevel lvl, const std::string& m) {
    using namespace std::chrono;
    auto now = steady_clock::now();
    double mono = duration_cast<duration<double>>(now - start_).count();
    long long wall = duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
    std::lock_guard<std::mutex> g(m_);
    entries_.push_back({lvl, m, mono, wall});
    // Cap the ring so a long session does not grow unbounded.
    if (entries_.size() > 5000)
        entries_.erase(entries_.begin(), entries_.begin() + 1000);
}

void Logger::info(const std::string& m)  { log(LogLevel::Info, m); }
void Logger::warn(const std::string& m)  { log(LogLevel::Warn, m); }
void Logger::error(const std::string& m) { log(LogLevel::Error, m); }
void Logger::tx(const std::string& m)    { log(LogLevel::Tx, m); }
void Logger::rx(const std::string& m)    { log(LogLevel::Rx, m); }

void Logger::hexDump(LogLevel lvl, const std::string& prefix,
                     const uint8_t* data, size_t len) {
    log(lvl, prefix + " [" + std::to_string(len) + "]: " + toHex(data, len));
}

std::vector<LogEntry> Logger::snapshot() {
    std::lock_guard<std::mutex> g(m_);
    return entries_;
}

void Logger::clear() {
    std::lock_guard<std::mutex> g(m_);
    entries_.clear();
}

size_t Logger::count() {
    std::lock_guard<std::mutex> g(m_);
    return entries_.size();
}

const char* Logger::levelTag(LogLevel l) {
    switch (l) {
        case LogLevel::Info:  return "INFO ";
        case LogLevel::Tx:    return "TX   ";
        case LogLevel::Rx:    return "RX   ";
        case LogLevel::Warn:  return "WARN ";
        case LogLevel::Error: return "ERROR";
    }
    return "?????";
}

std::string Logger::format(const LogEntry& e) {
    // Wall-clock HH:MM:SS.mmm in local time.
    std::time_t secs = (std::time_t)(e.tWallMs / 1000);
    int ms = (int)(e.tWallMs % 1000);
    std::tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &secs);
#else
    localtime_r(&secs, &tmv);
#endif
    char buf[160];
    std::snprintf(buf, sizeof buf, "[+%9.3fs | %02d:%02d:%02d.%03d] %s | %s",
                  e.tMonotonic, tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ms,
                  levelTag(e.level), e.text.c_str());
    return buf;
}

bool Logger::saveToFile(const std::string& path, std::string& err) {
    std::vector<LogEntry> snap = snapshot();
    std::ofstream f(path, std::ios::out | std::ios::trunc);
    if (!f) { err = "Could not open file for writing: " + path; return false; }

    std::time_t now = std::time(nullptr);
    std::tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    char hdr[128];
    std::strftime(hdr, sizeof hdr, "%Y-%m-%d %H:%M:%S", &tmv);

    f << "===========================================================\n";
    f << " VinFast VF8 OpenXC/UDS Scanner - session log\n";
    f << " Exported: " << hdr << "\n";
    f << " Entries:  " << snap.size() << "\n";
    f << "===========================================================\n\n";
    for (const auto& e : snap)
        f << format(e) << "\n";
    if (!f) { err = "Write failed (disk full or permissions?)"; return false; }
    return true;
}

std::string toHex(const uint8_t* data, size_t len) {
    static const char* h = "0123456789ABCDEF";
    std::string s;
    s.reserve(len * 3);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(h[data[i] >> 4]);
        s.push_back(h[data[i] & 0xF]);
        if (i + 1 < len) s.push_back(' ');
    }
    return s;
}

std::string byteHex(uint8_t b) {
    static const char* h = "0123456789ABCDEF";
    std::string s;
    s.push_back(h[b >> 4]);
    s.push_back(h[b & 0xF]);
    return s;
}
