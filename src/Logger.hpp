#pragma once
//
// Logger.hpp - Thread-safe in-memory logger used by the DoIP/UDS stack and GUI.
//
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <cstddef>

enum class LogLevel { Info, Tx, Rx, Warn, Error };

struct LogEntry {
    LogLevel    level;
    std::string text;
    double      tMonotonic;  // seconds since logger start (high-res)
    long long   tWallMs;     // wall-clock epoch milliseconds
};

class Logger {
public:
    static Logger& instance();

    void log(LogLevel level, const std::string& msg);
    void info(const std::string& m);
    void warn(const std::string& m);
    void error(const std::string& m);
    void tx(const std::string& m);
    void rx(const std::string& m);

    // Logs "prefix [len]: AA BB CC ..."
    void hexDump(LogLevel level, const std::string& prefix,
                 const uint8_t* data, size_t len);

    std::vector<LogEntry> snapshot();
    void clear();

    // Formats a single entry as "[+12.345s | HH:MM:SS.mmm] LEVEL: text".
    static std::string format(const LogEntry& e);

    // Short uppercase tag for a level (INFO/TX/RX/WARN/ERROR).
    static const char* levelTag(LogLevel l);

    // Writes the whole session log (with a header) to a UTF-8 text file.
    // Returns false and sets err on failure.
    bool saveToFile(const std::string& path, std::string& err);

    size_t count();

private:
    Logger();
    std::mutex            m_;
    std::vector<LogEntry> entries_;
    std::chrono::steady_clock::time_point start_;
};

// Free helpers.
std::string toHex(const uint8_t* data, size_t len);
std::string byteHex(uint8_t b);
