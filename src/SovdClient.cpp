#include "SovdClient.hpp"
#include "Logger.hpp"

#include <curl/curl.h>

#include <cstdio>

namespace sovd {
namespace {

// --- Minimal JSON parser (objects/arrays/strings/numbers/bool/null) --------
// SOVD payloads are arbitrary JSON; this is a compact tolerant parser used to
// pull out the few fields the client needs (items[].id/name/code/status).
struct Json {
    enum Type { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool                                      b = false;
    double                                    num = 0;
    std::string                               str;
    std::vector<Json>                         arr;
    std::vector<std::pair<std::string, Json>> obj;

    const Json* find(const std::string& key) const {
        if (type != Obj) return nullptr;
        for (const auto& kv : obj) if (kv.first == key) return &kv.second;
        return nullptr;
    }
    std::string asString() const {
        if (type == Str) return str;
        if (type == Num) { char buf[32]; std::snprintf(buf, sizeof buf, "%g", num); return buf; }
        if (type == Bool) return b ? "true" : "false";
        return {};
    }
};

struct JsonParser {
    const char* p; const char* e;
    explicit JsonParser(const std::string& s) : p(s.data()), e(s.data() + s.size()) {}
    void ws() { while (p < e && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p; }
    bool parse(Json& out) { ws(); return value(out); }

    bool string(std::string& s) {
        if (p >= e || *p != '"') return false; ++p;
        while (p < e && *p != '"') {
            char c = *p++;
            if (c == '\\' && p < e) {
                char esc = *p++;
                switch (esc) {
                    case 'n': s.push_back('\n'); break;
                    case 't': s.push_back('\t'); break;
                    case 'r': s.push_back('\r'); break;
                    case 'b': s.push_back('\b'); break;
                    case 'f': s.push_back('\f'); break;
                    case '/': s.push_back('/');  break;
                    case '\\': s.push_back('\\'); break;
                    case '"': s.push_back('"');  break;
                    case 'u': {  // keep it simple: emit the 4 hex digits raw
                        for (int i = 0; i < 4 && p < e; ++i) s.push_back(*p++);
                        break;
                    }
                    default: s.push_back(esc); break;
                }
            } else {
                s.push_back(c);
            }
        }
        if (p < e && *p == '"') { ++p; return true; }
        return false;
    }

    bool value(Json& v) {
        ws(); if (p >= e) return false;
        char c = *p;
        if (c == '"') { v.type = Json::Str; return string(v.str); }
        if (c == '{') return object(v);
        if (c == '[') return array(v);
        if (c == 't' || c == 'f') {  // bool
            v.type = Json::Bool;
            if (e - p >= 4 && std::string(p, p + 4) == "true")  { v.b = true;  p += 4; return true; }
            if (e - p >= 5 && std::string(p, p + 5) == "false") { v.b = false; p += 5; return true; }
            return false;
        }
        if (c == 'n') { if (e - p >= 4) { p += 4; v.type = Json::Null; return true; } return false; }
        // number
        const char* start = p;
        while (p < e && (*p == '-' || *p == '+' || *p == '.' || *p == 'e' || *p == 'E' ||
                         (*p >= '0' && *p <= '9'))) ++p;
        if (p == start) return false;
        v.type = Json::Num; v.num = std::strtod(std::string(start, p).c_str(), nullptr);
        return true;
    }

    bool array(Json& v) {
        v.type = Json::Arr; ++p; ws();
        if (p < e && *p == ']') { ++p; return true; }
        while (p < e) {
            Json el; if (!value(el)) return false;
            v.arr.push_back(std::move(el)); ws();
            if (p < e && *p == ',') { ++p; continue; }
            if (p < e && *p == ']') { ++p; return true; }
            return false;
        }
        return false;
    }

    bool object(Json& v) {
        v.type = Json::Obj; ++p; ws();
        if (p < e && *p == '}') { ++p; return true; }
        while (p < e) {
            ws(); if (p >= e || *p != '"') return false;
            std::string key; string(key); ws();
            if (p >= e || *p != ':') return false; ++p;
            Json val; if (!value(val)) return false;
            v.obj.emplace_back(std::move(key), std::move(val)); ws();
            if (p < e && *p == ',') { ++p; continue; }
            if (p < e && *p == '}') { ++p; return true; }
            return false;
        }
        return false;
    }
};

bool parseJson(const std::string& s, Json& out) { JsonParser jp(s); return jp.parse(out); }

size_t writeCb(char* ptr, size_t sz, size_t nm, void* ud) {
    ((std::string*)ud)->append(ptr, sz * nm);
    return sz * nm;
}

// SOVD responses put collections under "items" (ASAM) but some gateways use
// the bare array; accept either.
const Json* itemsArray(const Json& root) {
    if (root.type == Json::Arr) return &root;
    if (const Json* it = root.find("items"); it && it->type == Json::Arr) return it;
    return nullptr;
}

} // namespace

void SovdClient::setBaseUrl(const std::string& u) {
    base_ = u;
    while (!base_.empty() && base_.back() == '/') base_.pop_back();  // trim trailing /
}

void SovdClient::setBearerToken(const std::string& t) { token_ = t; }

std::string SovdClient::url(const std::string& path) const {
    if (path.empty() || path.front() == '/') return base_ + path;
    return base_ + "/" + path;
}

bool SovdClient::httpRequest(const std::string& method, const std::string& u,
                             const std::string& body, HttpResult& out, std::string& err) {
    CURL* curl = curl_easy_init();
    if (!curl) { err = "curl init failed"; return false; }

    struct curl_slist* hl = nullptr;
    hl = curl_slist_append(hl, "Accept: application/json");
    if (!body.empty()) hl = curl_slist_append(hl, "Content-Type: application/json");
    if (!token_.empty())
        hl = curl_slist_append(hl, ("Authorization: Bearer " + token_).c_str());

    out.body.clear();
    curl_easy_setopt(curl, CURLOPT_URL, u.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "vinfast-scanner-sovd/1.0");
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    } else if (method != "GET") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    }

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.status);
    else
        err = curl_easy_strerror(rc);

    curl_slist_free_all(hl);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK;
}

bool SovdClient::checkAvailability(long& httpStatus, std::string& err) {
    if (!configured()) { err = "SOVD base URL not set"; return false; }
    HttpResult r;
    if (!httpRequest("GET", url("/components"), {}, r, err)) {
        Logger::instance().log(LogLevel::Warn, "SOVD unavailable: " + err);
        return false;
    }
    httpStatus = r.status;
    bool ok = r.status >= 200 && r.status < 300;
    Logger::instance().log(ok ? LogLevel::Info : LogLevel::Warn,
        "SOVD availability check " + base_ + " -> HTTP " + std::to_string(r.status));
    if (!ok) err = "SOVD endpoint returned HTTP " + std::to_string(r.status);
    return ok;
}

bool SovdClient::listComponents(std::vector<Component>& out, std::string& err) {
    if (!configured()) { err = "SOVD base URL not set"; return false; }
    HttpResult r;
    if (!httpRequest("GET", url("/components"), {}, r, err)) return false;
    if (r.status < 200 || r.status >= 300) {
        err = "SOVD /components HTTP " + std::to_string(r.status); return false;
    }
    Json root;
    if (!parseJson(r.body, root)) { err = "SOVD /components: invalid JSON"; return false; }
    const Json* items = itemsArray(root);
    if (!items) { err = "SOVD /components: no item array"; return false; }
    out.clear();
    for (const auto& it : items->arr) {
        Component c;
        if (const Json* id = it.find("id"))   c.id   = id->asString();
        if (const Json* nm = it.find("name")) c.name = nm->asString();
        if (c.name.empty()) c.name = c.id;
        if (!c.id.empty()) out.push_back(std::move(c));
    }
    Logger::instance().log(LogLevel::Info,
        "SOVD listComponents: " + std::to_string(out.size()) + " component(s)");
    return true;
}

bool SovdClient::readData(const std::string& component, const std::string& resource,
                          std::string& jsonBody, std::string& err) {
    if (!configured()) { err = "SOVD base URL not set"; return false; }
    HttpResult r;
    if (!httpRequest("GET", url("/components/" + component + "/data/" + resource),
                     {}, r, err)) return false;
    if (r.status < 200 || r.status >= 300) {
        err = "SOVD data " + component + "/" + resource + " HTTP " + std::to_string(r.status);
        return false;
    }
    jsonBody = r.body;
    Logger::instance().log(LogLevel::Info,
        "SOVD readData " + component + "/" + resource + ": " +
        std::to_string(jsonBody.size()) + " byte(s)");
    return true;
}

std::string SovdClient::didToResource(uint16_t did) {
    // Maps the standard ISO 14229 identification DIDs the stack already reads to
    // conventional SOVD data-resource names.
    switch (did) {
        case 0xF190: return "vin";
        case 0xF18C: return "ecu_serial_number";
        case 0xF195: return "ecu_software_version";
        case 0xF194: return "ecu_software_number";
        case 0xF193: return "ecu_hardware_version";
        case 0xF191: return "ecu_hardware_number";
        case 0xF1A0: return "active_software";       // running-software state
        case 0xF187: return "spare_part_number";
        case 0xF18A: return "system_supplier_id";
        default:     return {};
    }
}

bool SovdClient::readDataByDid(const std::string& component, uint16_t did,
                               std::string& jsonBody, std::string& err) {
    std::string res = didToResource(did);
    if (res.empty()) {
        char buf[48];
        std::snprintf(buf, sizeof buf, "No SOVD resource mapping for DID 0x%04X", did);
        err = buf;
        return false;
    }
    return readData(component, res, jsonBody, err);
}

bool SovdClient::readFaults(const std::string& component, std::vector<Fault>& out,
                            std::string& err) {
    if (!configured()) { err = "SOVD base URL not set"; return false; }
    HttpResult r;
    if (!httpRequest("GET", url("/components/" + component + "/faults"), {}, r, err))
        return false;
    if (r.status < 200 || r.status >= 300) {
        err = "SOVD faults " + component + " HTTP " + std::to_string(r.status); return false;
    }
    Json root;
    if (!parseJson(r.body, root)) { err = "SOVD faults: invalid JSON"; return false; }
    const Json* items = itemsArray(root);
    if (!items) { err = "SOVD faults: no item array"; return false; }
    out.clear();
    for (const auto& it : items->arr) {
        Fault f;
        if (const Json* c = it.find("code"))     f.code     = c->asString();
        if (const Json* s = it.find("status"))   f.status   = s->asString();
        if (const Json* v = it.find("severity")) f.severity = v->asString();
        if (!f.code.empty()) out.push_back(std::move(f));
    }
    Logger::instance().log(LogLevel::Info,
        "SOVD readFaults " + component + ": " + std::to_string(out.size()) + " fault(s)");
    return true;
}

bool SovdClient::executeOperation(const std::string& component, const std::string& op,
                                  const std::string& jsonRequest, std::string& jsonResponse,
                                  std::string& err) {
    if (!configured()) { err = "SOVD base URL not set"; return false; }
    HttpResult r;
    if (!httpRequest("POST",
                     url("/components/" + component + "/operations/" + op + "/executions"),
                     jsonRequest, r, err)) return false;
    if (r.status < 200 || r.status >= 300) {
        err = "SOVD operation " + component + "/" + op + " HTTP " + std::to_string(r.status);
        return false;
    }
    jsonResponse = r.body;
    Logger::instance().log(LogLevel::Info,
        "SOVD executeOperation " + component + "/" + op + " accepted (HTTP " +
        std::to_string(r.status) + ")");
    return true;
}

} // namespace sovd
