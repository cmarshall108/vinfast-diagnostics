//
// CloudClient.cpp - VinFast connected-car cloud client (libcurl + self-contained crypto).
//
#include "CloudClient.hpp"
#include "CloudData.hpp"
#include "Logger.hpp"

#include <curl/curl.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace cloud {
namespace {

// ===========================================================================
//  SHA-256 (FIPS 180-4) - self-contained, public-domain style implementation.
// ===========================================================================
struct Sha256 {
    uint32_t s[8];
    uint64_t len = 0;
    uint8_t  buf[64];
    size_t   n = 0;

    Sha256() {
        s[0]=0x6a09e667; s[1]=0xbb67ae85; s[2]=0x3c6ef372; s[3]=0xa54ff53a;
        s[4]=0x510e527f; s[5]=0x9b05688c; s[6]=0x1f83d9ab; s[7]=0x5be0cd19;
    }
    static uint32_t ror(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }

    void block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15]>>3);
            uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
    }
    void update(const uint8_t* p, size_t l) {
        len += l;
        while (l) {
            size_t k = 64 - n; if (k > l) k = l;
            std::memcpy(buf + n, p, k); n += k; p += k; l -= k;
            if (n == 64) { block(buf); n = 0; }
        }
    }
    void finish(uint8_t out[32]) {
        uint64_t bits = len * 8;
        uint8_t pad = 0x80; update(&pad, 1);
        uint8_t z = 0; while (n != 56) update(&z, 1);
        uint8_t lb[8];
        for (int i = 0; i < 8; ++i) lb[i] = (uint8_t)(bits >> (56 - i*8));
        update(lb, 8);
        for (int i = 0; i < 8; ++i) {
            out[i*4]   = (uint8_t)(s[i] >> 24);
            out[i*4+1] = (uint8_t)(s[i] >> 16);
            out[i*4+2] = (uint8_t)(s[i] >> 8);
            out[i*4+3] = (uint8_t)(s[i]);
        }
    }
};

std::string sha256Raw(const std::string& m) {
    Sha256 h; h.update((const uint8_t*)m.data(), m.size());
    uint8_t d[32]; h.finish(d);
    return std::string((char*)d, 32);
}
std::string toHexLower(const std::string& b) {
    static const char* hx = "0123456789abcdef";
    std::string o; o.reserve(b.size() * 2);
    for (unsigned char c : b) { o.push_back(hx[c >> 4]); o.push_back(hx[c & 15]); }
    return o;
}
std::string sha256Hex(const std::string& m) { return toHexLower(sha256Raw(m)); }

std::string hmacSha256Raw(const std::string& key, const std::string& msg) {
    uint8_t k[64]; std::memset(k, 0, 64);
    if (key.size() > 64) { std::string kh = sha256Raw(key); std::memcpy(k, kh.data(), 32); }
    else std::memcpy(k, key.data(), key.size());
    uint8_t ip[64], op[64];
    for (int i = 0; i < 64; ++i) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
    Sha256 h1; h1.update(ip, 64); h1.update((const uint8_t*)msg.data(), msg.size());
    uint8_t inner[32]; h1.finish(inner);
    Sha256 h2; h2.update(op, 64); h2.update(inner, 32);
    uint8_t d[32]; h2.finish(d);
    return std::string((char*)d, 32);
}
std::string hmacSha256Hex(const std::string& key, const std::string& msg) {
    return toHexLower(hmacSha256Raw(key, msg));
}

std::string base64(const std::string& in) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o; size_t i = 0;
    while (i + 2 < in.size()) {
        uint32_t v = ((uint8_t)in[i] << 16) | ((uint8_t)in[i+1] << 8) | (uint8_t)in[i+2];
        o.push_back(t[(v>>18)&63]); o.push_back(t[(v>>12)&63]);
        o.push_back(t[(v>>6)&63]);  o.push_back(t[v&63]); i += 3;
    }
    if (i + 1 == in.size()) {
        uint32_t v = (uint8_t)in[i] << 16;
        o.push_back(t[(v>>18)&63]); o.push_back(t[(v>>12)&63]); o.push_back('='); o.push_back('=');
    } else if (i + 2 == in.size()) {
        uint32_t v = ((uint8_t)in[i] << 16) | ((uint8_t)in[i+1] << 8);
        o.push_back(t[(v>>18)&63]); o.push_back(t[(v>>12)&63]); o.push_back(t[(v>>6)&63]); o.push_back('=');
    }
    return o;
}

std::string toLower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}
std::string nowMs() {
    using namespace std::chrono;
    auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    return std::to_string((long long)ms);
}

// RFC3986 strict percent-encoding (used for SigV4 query strings).
std::string uriEncode(const std::string& s, bool encodeSlash) {
    static const char* hx = "0123456789ABCDEF";
    std::string o;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c=='-' || c=='_' || c=='.' || c=='~') {
            o.push_back((char)c);
        } else if (c == '/' && !encodeSlash) {
            o.push_back('/');
        } else {
            o.push_back('%'); o.push_back(hx[c >> 4]); o.push_back(hx[c & 15]);
        }
    }
    return o;
}

std::string jsonEscape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o.push_back(c);
        }
    }
    return o;
}

// ===========================================================================
//  Minimal JSON parser (objects/arrays/strings/numbers/bool/null).
// ===========================================================================
struct Json {
    enum Type { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool        b = false;
    double      num = 0;
    std::string str;
    std::vector<Json> arr;
    std::vector<std::pair<std::string, Json>> obj;

    const Json* find(const std::string& key) const {
        if (type != Obj) return nullptr;
        for (auto& kv : obj) if (kv.first == key) return &kv.second;
        return nullptr;
    }
    // Dotted-path lookup: find("data.content").
    const Json* path(const std::string& dotted) const {
        const Json* cur = this; std::string seg;
        for (size_t i = 0; i <= dotted.size(); ++i) {
            if (i == dotted.size() || dotted[i] == '.') {
                if (!seg.empty()) { if (!cur) return nullptr; cur = cur->find(seg); seg.clear(); }
            } else seg.push_back(dotted[i]);
        }
        return cur;
    }
    std::string asStr() const {
        if (type == Str)  return str;
        if (type == Bool) return b ? "true" : "false";
        if (type == Num)  { char x[40]; std::snprintf(x, sizeof x, "%g", num); return x; }
        return "";
    }
    double asNum() const {
        if (type == Num) return num;
        if (type == Str) return std::atof(str.c_str());
        if (type == Bool) return b ? 1 : 0;
        return 0;
    }
};

struct JsonParser {
    const char* p; const char* e;
    explicit JsonParser(const std::string& s) : p(s.data()), e(s.data() + s.size()) {}
    void ws() { while (p < e && (*p==' '||*p=='\t'||*p=='\n'||*p=='\r')) ++p; }
    bool parse(Json& out) { ws(); return value(out); }
    bool value(Json& v) {
        ws(); if (p >= e) return false;
        char c = *p;
        if (c == '{') return object(v);
        if (c == '[') return array(v);
        if (c == '"') { v.type = Json::Str; return string(v.str); }
        if (c == 't' || c == 'f') return boolean(v);
        if (c == 'n') { if (e - p >= 4 && !std::strncmp(p,"null",4)) { p += 4; v.type = Json::Null; return true; } return false; }
        return number(v);
    }
    bool string(std::string& out) {
        if (*p != '"') return false; ++p;
        while (p < e && *p != '"') {
            char c = *p++;
            if (c == '\\' && p < e) {
                char x = *p++;
                switch (x) {
                    case 'n': out.push_back('\n'); break;
                    case 't': out.push_back('\t'); break;
                    case 'r': out.push_back('\r'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case '/': out.push_back('/');  break;
                    case '"': out.push_back('"');  break;
                    case '\\':out.push_back('\\'); break;
                    case 'u': {
                        if (e - p >= 4) {
                            int code = (int)std::strtol(std::string(p, p+4).c_str(), nullptr, 16);
                            p += 4;
                            if (code < 0x80) out.push_back((char)code);
                            else if (code < 0x800) {
                                out.push_back((char)(0xC0 | (code >> 6)));
                                out.push_back((char)(0x80 | (code & 0x3F)));
                            } else {
                                out.push_back((char)(0xE0 | (code >> 12)));
                                out.push_back((char)(0x80 | ((code >> 6) & 0x3F)));
                                out.push_back((char)(0x80 | (code & 0x3F)));
                            }
                        }
                        break;
                    }
                    default: out.push_back(x);
                }
            } else out.push_back(c);
        }
        if (p < e && *p == '"') ++p;
        return true;
    }
    bool number(Json& v) {
        const char* s = p;
        while (p < e && (std::isdigit((unsigned char)*p) || *p=='-'||*p=='+'||*p=='.'||*p=='e'||*p=='E')) ++p;
        if (p == s) return false;
        v.type = Json::Num; v.num = std::atof(std::string(s, p).c_str());
        return true;
    }
    bool boolean(Json& v) {
        if (e - p >= 4 && !std::strncmp(p,"true",4))  { p += 4; v.type = Json::Bool; v.b = true;  return true; }
        if (e - p >= 5 && !std::strncmp(p,"false",5)) { p += 5; v.type = Json::Bool; v.b = false; return true; }
        return false;
    }
    bool array(Json& v) {
        v.type = Json::Arr; ++p; ws();
        if (p < e && *p == ']') { ++p; return true; }
        while (p < e) {
            Json item; if (!value(item)) return false;
            v.arr.push_back(std::move(item)); ws();
            if (p < e && *p == ',') { ++p; ws(); continue; }
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

// libcurl write callback.
size_t writeCb(char* ptr, size_t sz, size_t nm, void* ud) {
    ((std::string*)ud)->append(ptr, sz * nm);
    return sz * nm;
}

} // namespace

// ===========================================================================
//  HTTP
// ===========================================================================
bool CloudClient::httpRequest(const std::string& method, const std::string& url,
                              const std::vector<std::string>& headers,
                              const std::string& body, HttpResult& out, std::string& err) {
    CURL* curl = curl_easy_init();
    if (!curl) { err = "curl init failed"; return false; }

    struct curl_slist* hl = nullptr;
    for (const auto& h : headers) hl = curl_slist_append(hl, h.c_str());

    out.body.clear();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "vinfast-scanner/1.0");
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

// ===========================================================================
//  Signing
// ===========================================================================
std::vector<std::string> CloudClient::signedHeaders(const std::string& method,
                                                    const std::string& apiPath,
                                                    bool withVin) const {
    std::string ts = nowMs();
    std::string p = apiPath;
    auto q = p.find('?'); if (q != std::string::npos) p = p.substr(0, q);
    if (p.empty() || p[0] != '/') p = "/" + p;

    // X-HASH
    std::string m1;
    {
        std::vector<std::string> parts;
        parts.push_back(method); parts.push_back(p);
        if (withVin) parts.push_back(vin_);
        parts.push_back("Vinfast@2025"); parts.push_back(ts);
        for (size_t i = 0; i < parts.size(); ++i) { if (i) m1 += "_"; m1 += parts[i]; }
        m1 = toLower(m1);
    }
    std::string xHash = base64(hmacSha256Raw("Vinfast@2025", m1));

    // X-HASH-2
    std::string norm;
    {
        std::string t = p;
        while (!t.empty() && t.front() == '/') t.erase(t.begin());
        while (!t.empty() && t.back()  == '/') t.pop_back();
        for (char c : t) norm.push_back(c == '/' ? '_' : c);
    }
    std::string m2;
    {
        std::vector<std::string> parts;
        parts.push_back("android");
        if (withVin) parts.push_back(vin_);
        parts.push_back(kDeviceId); parts.push_back(norm);
        parts.push_back(method); parts.push_back(ts);
        for (size_t i = 0; i < parts.size(); ++i) { if (i) m2 += "_"; m2 += parts[i]; }
        m2 = toLower(m2);
    }
    std::string xHash2 = base64(hmacSha256Raw("ConnectedCar@6521", m2));

    std::vector<std::string> h;
    h.push_back("Authorization: Bearer " + accessToken_);
    h.push_back("x-service-name: CAPP");
    h.push_back(std::string("x-app-version: ") + kAppVersion);
    h.push_back("x-device-platform: android");
    h.push_back(std::string("x-device-identifier: ") + kDeviceId);
    h.push_back("Content-Type: application/json");
    h.push_back("X-HASH: "   + xHash);
    h.push_back("X-HASH-2: " + xHash2);
    h.push_back("X-TIMESTAMP: " + ts);
    if (!vin_.empty())    h.push_back("x-vin-code: " + vin_);
    if (!userId_.empty()) h.push_back("x-player-identifier: " + userId_);
    return h;
}

// ===========================================================================
//  Public API
// ===========================================================================
void CloudClient::setRegion(const std::string& code) {
    std::lock_guard<std::mutex> g(mutex_);
    regionCode_ = cloudRegion(code).code;
}
std::string CloudClient::region() const {
    std::lock_guard<std::mutex> g(mutex_); return regionCode_;
}
bool CloudClient::loggedIn() const {
    std::lock_guard<std::mutex> g(mutex_); return !accessToken_.empty();
}
void CloudClient::logout() {
    std::lock_guard<std::mutex> g(mutex_);
    accessToken_.clear(); vin_.clear(); userId_.clear(); model_.clear(); plate_.clear();
}
std::string CloudClient::vin()    const { std::lock_guard<std::mutex> g(mutex_); return vin_; }
std::string CloudClient::userId() const { std::lock_guard<std::mutex> g(mutex_); return userId_; }
std::string CloudClient::model()  const { std::lock_guard<std::mutex> g(mutex_); return model_; }

bool CloudClient::login(const std::string& email, const std::string& password, std::string& err) {
    CloudRegion reg;
    { std::lock_guard<std::mutex> g(mutex_); reg = cloudRegion(regionCode_); }

    std::string url = std::string("https://") + reg.auth0Domain + "/oauth/token";
    std::string body =
        std::string("{\"client_id\":\"") + kAuth0ClientId + "\","
        "\"grant_type\":\"password\","
        "\"username\":\"" + jsonEscape(email) + "\","
        "\"password\":\"" + jsonEscape(password) + "\","
        "\"scope\":\"openid profile email offline_access\","
        "\"audience\":\"" + reg.apiBase + "\"}";

    Logger::instance().info(std::string("Cloud: Auth0 login as ") + email + " (" + reg.code + ")");
    HttpResult r;
    if (!httpRequest("POST", url, {"Content-Type: application/json"}, body, r, err)) {
        Logger::instance().error("Cloud: login transport error: " + err);
        return false;
    }
    if (r.status != 200) {
        err = "login HTTP " + std::to_string(r.status);
        Json j; if (parseJson(r.body, j)) { if (auto* d = j.find("error_description")) err += ": " + d->asStr(); }
        Logger::instance().error("Cloud: " + err);
        return false;
    }
    Json j;
    if (!parseJson(r.body, j) || !j.find("access_token")) {
        err = "login: no access_token in response";
        Logger::instance().error("Cloud: " + err);
        return false;
    }
    {
        std::lock_guard<std::mutex> g(mutex_);
        accessToken_ = j.find("access_token")->asStr();
    }
    Logger::instance().info("Cloud: login OK (token acquired)");
    return true;
}

bool CloudClient::getVehicles(std::vector<Vehicle>& out, std::string& err) {
    if (!loggedIn()) { err = "not logged in"; return false; }
    CloudRegion reg; { std::lock_guard<std::mutex> g(mutex_); reg = cloudRegion(regionCode_); }
    std::string path = "ccarusermgnt/api/v1/user-vehicle";
    std::string url  = std::string(reg.apiBase) + "/" + path;

    Logger::instance().info("Cloud: GET user-vehicle");
    HttpResult r;
    if (!httpRequest("GET", url, signedHeaders("GET", path, false), "", r, err)) return false;
    if (r.status != 200) { err = "user-vehicle HTTP " + std::to_string(r.status); return false; }

    Json j; if (!parseJson(r.body, j)) { err = "user-vehicle: bad JSON"; return false; }
    const Json* data = j.find("data");
    if (!data) data = &j;
    if (data->type != Json::Arr) { err = "user-vehicle: no vehicle array"; return false; }

    out.clear();
    for (const auto& v : data->arr) {
        Vehicle veh;
        if (auto* x = v.find("vinCode"))        veh.vin    = x->asStr();
        if (auto* x = v.find("userId"))         veh.userId = x->asStr();
        if (auto* x = v.find("marketingName"))  veh.model  = x->asStr();
        if (veh.model.empty()) if (auto* x = v.find("dmsVehicleModel")) veh.model = x->asStr();
        if (auto* x = v.find("licensePlate"))   veh.plate  = x->asStr();
        if (veh.plate.empty()) if (auto* x = v.find("customizedVehicleName")) veh.plate = x->asStr();
        out.push_back(veh);
    }
    if (!out.empty()) {
        std::lock_guard<std::mutex> g(mutex_);
        vin_ = out[0].vin; userId_ = out[0].userId; model_ = out[0].model; plate_ = out[0].plate;
    }
    Logger::instance().info("Cloud: " + std::to_string(out.size()) + " vehicle(s)");
    return true;
}

bool CloudClient::sendCommand(int commandType, std::string& reqId, std::string& err) {
    if (!loggedIn()) { err = "not logged in"; return false; }
    if (vin().empty()) { err = "no vehicle selected"; return false; }
    CloudRegion reg; std::string vinc;
    { std::lock_guard<std::mutex> g(mutex_); reg = cloudRegion(regionCode_); vinc = vin_; }

    std::string path = "ccaraccessmgmt/api/v2/remote/app/command";
    std::string url  = std::string(reg.apiBase) + "/" + path;
    std::string body = "{\"commandType\":" + std::to_string(commandType) +
                       ",\"vinCode\":\"" + jsonEscape(vinc) + "\",\"params\":{}}";

    Logger::instance().tx("Cloud: command " + std::to_string(commandType));
    HttpResult r;
    if (!httpRequest("POST", url, signedHeaders("POST", path, true), body, r, err)) return false;
    if (r.status != 200 && r.status != 201 && r.status != 202) {
        err = "command HTTP " + std::to_string(r.status) + " " + r.body;
        return false;
    }
    Json j; if (parseJson(r.body, j)) {
        if (auto* d = j.path("data.requestId")) reqId = d->asStr();
        else if (auto* d2 = j.find("requestId")) reqId = d2->asStr();
    }
    Logger::instance().rx("Cloud: command accepted" + (reqId.empty() ? "" : " (req " + reqId + ")"));
    return true;
}

bool CloudClient::wakeup(std::string& err) {
    if (!loggedIn()) { err = "not logged in"; return false; }
    CloudRegion reg; { std::lock_guard<std::mutex> g(mutex_); reg = cloudRegion(regionCode_); }
    std::string path = "ccaraccessmgmt/api/v1/remote/app/wakeup";
    std::string url  = std::string(reg.apiBase) + "/" + path;
    Logger::instance().tx("Cloud: wakeup");
    HttpResult r;
    if (!httpRequest("POST", url, signedHeaders("POST", path, true), "{}", r, err)) return false;
    if (r.status < 200 || r.status >= 300) { err = "wakeup HTTP " + std::to_string(r.status); return false; }
    Logger::instance().rx("Cloud: wakeup accepted");
    return true;
}

bool CloudClient::requestTelemetry(std::string& bodyOut, std::string& err) {
    if (!loggedIn()) { err = "not logged in"; return false; }
    if (vin().empty()) { err = "no vehicle selected"; return false; }
    CloudRegion reg; std::string vinc;
    { std::lock_guard<std::mutex> g(mutex_); reg = cloudRegion(regionCode_); vinc = vin_; }

    // Subscribe to the full VF8 resource map (the community OMA-LWM2M dictionary
    // mirrored in kVF8Telemetry), de-duplicated by object/instance/resource so
    // codes that share a triplet are only requested once.
    std::string arr = "[";
    std::vector<std::string> seen;
    size_t emitted = 0;
    for (const auto& t : kVF8Telemetry) {
        std::string c = t.code;
        if (c.size() != 17) continue;                 // expect NNNNN_NNNNN_NNNNN
        int oid = std::atoi(c.substr(0,5).c_str());
        int iid = std::atoi(c.substr(6,5).c_str());
        int rid = std::atoi(c.substr(12,5).c_str());
        std::string key = std::to_string(oid) + "/" + std::to_string(iid) +
                          "/" + std::to_string(rid);
        if (std::find(seen.begin(), seen.end(), key) != seen.end()) continue;
        seen.push_back(key);
        if (emitted++) arr += ",";
        arr += "{\"objectId\":" + std::to_string(oid) +
               ",\"instanceId\":" + std::to_string(iid) +
               ",\"resourceId\":" + std::to_string(rid) + "}";
    }
    arr += "]";

    std::string path = "ccaraccessmgmt/api/v1/telemetry/" + vinc + "/list_resource";
    std::string url  = std::string(reg.apiBase) + "/" + path;
    Logger::instance().tx("Cloud: telemetry list_resource (" +
                          std::to_string(emitted) + " resources)");
    HttpResult r;
    if (!httpRequest("POST", url, signedHeaders("POST", path, true), arr, r, err)) return false;
    bodyOut = r.body;
    if (r.status < 200 || r.status >= 300) { err = "telemetry HTTP " + std::to_string(r.status); return false; }
    Logger::instance().rx("Cloud: telemetry request accepted (values arrive via MQTT)");
    return true;
}

bool CloudClient::fetchActiveCharge(ActiveCharge& out, std::string& err) {
    if (!loggedIn()) { err = "not logged in"; return false; }
    CloudRegion reg; { std::lock_guard<std::mutex> g(mutex_); reg = cloudRegion(regionCode_); }
    std::string path = "ccarcharging/api/v1/charging-sessions/active";
    std::string url  = std::string(reg.apiBase) + "/" + path;
    HttpResult r;
    if (!httpRequest("GET", url, signedHeaders("GET", path, true), "", r, err)) return false;
    if (r.status == 204) { out = ActiveCharge{}; return true; }   // no active session
    if (r.status < 200 || r.status >= 300) { err = "active-charge HTTP " + std::to_string(r.status); return false; }
    Json j; if (!parseJson(r.body, j)) { err = "active-charge: bad JSON"; return false; }
    const Json* d = j.find("data"); if (!d) d = &j;
    if (d->type != Json::Obj) { out = ActiveCharge{}; return true; }
    out.active = true;
    if (auto* x = d->find("chargingPower"))      out.powerKw   = x->asNum();
    if (auto* x = d->find("targetBatteryLevel")) out.targetSoc = x->asNum();
    if (auto* x = d->find("currentBatteryLevel"))out.soc       = x->asNum();
    if (auto* x = d->find("remainingTime"))      out.remainMin = (int)x->asNum();
    return true;
}

bool CloudClient::fetchChargeHistory(std::vector<ChargeSession>& out, std::string& err) {
    if (!loggedIn()) { err = "not logged in"; return false; }
    CloudRegion reg; { std::lock_guard<std::mutex> g(mutex_); reg = cloudRegion(regionCode_); }
    std::string path = "ccarcharging/api/v1/charging-sessions/search?page=0&size=20";
    std::string url  = std::string(reg.apiBase) + "/" + path;
    long long now = std::atoll(nowMs().c_str());
    long long start = now - 90LL * 24 * 3600 * 1000;       // last 90 days
    std::string body = "{\"orderStatus\":[3,5,7],\"startTime\":" + std::to_string(start) +
                       ",\"endTime\":" + std::to_string(now) + "}";
    HttpResult r;
    if (!httpRequest("POST", url, signedHeaders("POST", path, true), body, r, err)) return false;
    if (r.status < 200 || r.status >= 300) { err = "charge-history HTTP " + std::to_string(r.status); return false; }
    Json j; if (!parseJson(r.body, j)) { err = "charge-history: bad JSON"; return false; }
    const Json* content = j.path("data.content");
    if (!content || content->type != Json::Arr) { out.clear(); return true; }
    out.clear();
    for (const auto& s : content->arr) {
        ChargeSession cs;
        if (auto* x = s.find("pluggedTime"))            cs.startTime  = x->asStr();
        if (auto* x = s.find("chargingStationAddress")) cs.location   = x->asStr();
        if (auto* x = s.find("totalKWCharged"))         cs.energyKwh  = x->asNum();
        if (auto* x = s.find("startBatteryLevel"))      cs.startSoc   = x->asNum();
        if (auto* x = s.find("endBatteryLevel"))        cs.endSoc     = x->asNum();
        if (auto* x = s.find("chargingDuration"))       cs.durationMin= (int)x->asNum();
        out.push_back(cs);
    }
    return true;
}

// ===========================================================================
//  AWS IoT MQTT presigned URL (Cognito identity + SigV4)
// ===========================================================================
bool CloudClient::buildMqttUrl(std::string& url, std::string& err) {
    if (!loggedIn()) { err = "not logged in"; return false; }
    CloudRegion reg; std::string token;
    { std::lock_guard<std::mutex> g(mutex_); reg = cloudRegion(regionCode_); token = accessToken_; }
    if (!reg.cognitoPool[0]) {
        err = std::string("MQTT presign unavailable for region ") + reg.code +
              " (Cognito identity pool not published).";
        return false;
    }

    std::string cognitoUrl = std::string("https://cognito-identity.") + reg.awsRegion + ".amazonaws.com/";
    std::string loginKey = reg.auth0Domain;   // Auth0 domain is the Logins provider key

    // 1) GetId
    std::string getIdBody = std::string("{\"IdentityPoolId\":\"") + reg.cognitoPool +
        "\",\"Logins\":{\"" + loginKey + "\":\"" + jsonEscape(token) + "\"}}";
    HttpResult r1;
    if (!httpRequest("POST", cognitoUrl,
            {"Content-Type: application/x-amz-json-1.1",
             "X-Amz-Target: AWSCognitoIdentityService.GetId"},
            getIdBody, r1, err)) return false;
    if (r1.status != 200) { err = "Cognito GetId HTTP " + std::to_string(r1.status) + " " + r1.body; return false; }
    Json j1; if (!parseJson(r1.body, j1) || !j1.find("IdentityId")) { err = "Cognito GetId: no IdentityId"; return false; }
    std::string identityId = j1.find("IdentityId")->asStr();

    // 2) GetCredentialsForIdentity
    std::string credBody = std::string("{\"IdentityId\":\"") + identityId +
        "\",\"Logins\":{\"" + loginKey + "\":\"" + jsonEscape(token) + "\"}}";
    HttpResult r2;
    if (!httpRequest("POST", cognitoUrl,
            {"Content-Type: application/x-amz-json-1.1",
             "X-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity"},
            credBody, r2, err)) return false;
    if (r2.status != 200) { err = "Cognito GetCredentials HTTP " + std::to_string(r2.status); return false; }
    Json j2; if (!parseJson(r2.body, j2)) { err = "Cognito GetCredentials: bad JSON"; return false; }
    const Json* cr = j2.find("Credentials");
    if (!cr) { err = "Cognito GetCredentials: no Credentials"; return false; }
    std::string ak, sk, st;
    if (auto* x = cr->find("AccessKeyId"))  ak = x->asStr();
    if (auto* x = cr->find("SecretKey"))    sk = x->asStr();
    if (auto* x = cr->find("SessionToken")) st = x->asStr();
    if (ak.empty() || sk.empty()) { err = "Cognito GetCredentials: incomplete credentials"; return false; }

    // 3) SigV4 presign a GET on /mqtt for service iotdevicegateway.
    std::string host    = reg.iotEndpoint;
    std::string service = "iotdevicegateway";
    std::string awsReg  = reg.awsRegion;

    // amz date stamps
    std::time_t t = std::time(nullptr);
    std::tm gm; 
#ifdef _WIN32
    gmtime_s(&gm, &t);
#else
    gmtime_r(&t, &gm);
#endif
    char amzDate[20], dateStamp[10];
    std::strftime(amzDate, sizeof amzDate, "%Y%m%dT%H%M%SZ", &gm);
    std::strftime(dateStamp, sizeof dateStamp, "%Y%m%d", &gm);

    std::string credScope = std::string(dateStamp) + "/" + awsReg + "/" + service + "/aws4_request";

    // Canonical query string (sorted by key, values URI-encoded).
    std::string canonicalQuery =
        "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=" + uriEncode(ak + "/" + credScope, true) +
        "&X-Amz-Date=" + std::string(amzDate) +
        "&X-Amz-Expires=86400"
        "&X-Amz-SignedHeaders=host";

    std::string canonicalHeaders = "host:" + host + "\n";
    std::string signedHdrs = "host";
    std::string payloadHash = sha256Hex("");   // empty body
    std::string canonicalRequest =
        "GET\n/mqtt\n" + canonicalQuery + "\n" + canonicalHeaders + "\n" + signedHdrs + "\n" + payloadHash;

    std::string stringToSign =
        "AWS4-HMAC-SHA256\n" + std::string(amzDate) + "\n" + credScope + "\n" + sha256Hex(canonicalRequest);

    // Derive signing key.
    std::string kDate    = hmacSha256Raw("AWS4" + sk, dateStamp);
    std::string kRegion  = hmacSha256Raw(kDate, awsReg);
    std::string kService = hmacSha256Raw(kRegion, service);
    std::string kSigning = hmacSha256Raw(kService, "aws4_request");
    std::string signature = hmacSha256Hex(kSigning, stringToSign);

    url = "wss://" + host + "/mqtt?" + canonicalQuery + "&X-Amz-Signature=" + signature;
    if (!st.empty()) url += "&X-Amz-Security-Token=" + uriEncode(st, true);

    Logger::instance().info("Cloud: built presigned MQTT URL for " + host);
    return true;
}

} // namespace cloud
