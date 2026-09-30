#include "snake/c2.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include "snake/crypto.hpp"

namespace snake::c2 {

namespace {

bool parse_bool(const std::string& v, bool* out) {
    if (v == "1" || v == "t" || v == "T" || v == "true" || v == "TRUE" || v == "True") {
        *out = true;
        return true;
    }
    if (v == "0" || v == "f" || v == "F" || v == "false" || v == "FALSE" || v == "False") {
        *out = false;
        return true;
    }
    return false;
}

std::string invalid_byte_error(unsigned char b) {
    char head[64];
    std::snprintf(head, sizeof(head), "encoding/hex: invalid byte: U+%04X", b);
    std::string out = head;
    bool printable = (b >= 0x20 && b <= 0x7E) || (b >= 0xA1 && b != 0xAD);
    if (printable) {
        if (b < 0x80) {
            out += " '";
            out += static_cast<char>(b);
            out += "'";
        } else {
            out += " '";
            out += static_cast<char>(0xC0 | (b >> 6));
            out += static_cast<char>(0x80 | (b & 0x3F));
            out += "'";
        }
    }
    return out;
}

std::string row() { return std::string(60, '='); }

}  // namespace

std::string truncate(const std::string& s, size_t n) {
    return s.size() > n ? s.substr(0, n) : s;
}

std::string random_node_id() {
    std::string full = "c2-" + to_hex(random_bytes(16));
    return truncate(full, 20);
}

void log_line(const std::string& msg) {
    std::time_t now = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&now, &tmv);
    char stamp[32];
    std::strftime(stamp, sizeof(stamp), "%Y/%m/%d %H:%M:%S", &tmv);
    std::fprintf(stderr, "%s [c2] %s\n", stamp, msg.c_str());
}

std::string banner(const Config& cfg, const std::string& node_id, const Bytes& session_key,
                   bool tls_enabled) {
    Bytes prefix(session_key.begin(), session_key.begin() + std::min<size_t>(8, session_key.size()));
    std::string out = row() + "\n";
    out += "  SOLIDSNAKE - Distributed Mesh C2 Framework\n";
    out += "  Node: " + truncate(node_id, 12) + "...\n";
    out += "  Listen: " + cfg.listen + "\n";
    out += std::string("  TLS: ") + (tls_enabled ? "true" : "false") + "\n";
    out += "  Mesh: " + cfg.mesh + "\n";
    out += "  DB: " + cfg.db_path + "\n";
    out += "  SessionKey: " + to_hex(prefix) + "...\n";
    out += row() + "\n";
    return out;
}

bool decode_session_key(const std::string& hex, Bytes* key, std::string* err) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        if (i + 1 >= hex.size()) {
            *err = "bad -key hex: encoding/hex: odd length hex string";
            return false;
        }
        int hi = 0, lo = 0;
        auto nib = [](char c, int* v) -> bool {
            if (c >= '0' && c <= '9') { *v = c - '0'; return true; }
            if (c >= 'a' && c <= 'f') { *v = c - 'a' + 10; return true; }
            if (c >= 'A' && c <= 'F') { *v = c - 'A' + 10; return true; }
            return false;
        };
        if (!nib(hex[i], &hi)) {
            *err = "bad -key hex: " + invalid_byte_error(static_cast<unsigned char>(hex[i]));
            return false;
        }
        if (!nib(hex[i + 1], &lo)) {
            *err = "bad -key hex: " + invalid_byte_error(static_cast<unsigned char>(hex[i + 1]));
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    if (out.size() != 32) {
        char buf[96];
        std::snprintf(buf, sizeof(buf), "-key must decode to 32 bytes, got %zu", out.size());
        *err = buf;
        return false;
    }
    *key = std::move(out);
    return true;
}

std::string usage() {
    return
        "usage: solidsnake-c2 [flags]\n"
        "  --listen <addr>        C2 listen address (default \":4443\")\n"
        "  --mesh <addr>          Mesh P2P listen address (empty = no mesh)\n"
        "  --bootstrap <peers>    Comma-separated bootstrap mesh peers\n"
        "  --db <path>            Database path (default \"data/c2.db\")\n"
        "  --password <pw>        Operator dashboard password (plaintext or bcrypt hash)\n"
        "  --key <hex>            Session key hex (32 bytes). Omit to generate and print one\n"
        "  --cert <file>          TLS certificate file\n"
        "  --tls-key <file>       TLS key file\n"
        "  --gen-certs            Generate or reuse self-signed TLS certs\n"
        "  --gen-certs-only       Generate or reuse self-signed certs and exit\n"
        "  --force-certs          Regenerate self-signed certs even if they exist\n"
        "  --cert-sans <list>     Extra comma-separated DNS names / IPs for generated cert SANs\n"
        "  --id <id>              C2 node ID (auto if empty)\n";
}

bool parse_args(const std::vector<std::string>& argv, Config& cfg, bool& help, std::string& err) {
    help = false;
    for (size_t i = 0; i < argv.size(); ++i) {
        const std::string& raw = argv[i];
        if (raw == "-h" || raw == "--help") {
            help = true;
            continue;
        }
        if (raw.size() < 2 || raw[0] != '-') {
            break;
        }
        std::string body = raw.substr(raw[1] == '-' ? 2 : 1);
        std::string inline_value;
        bool has_inline = false;
        size_t eq = body.find('=');
        if (eq != std::string::npos) {
            inline_value = body.substr(eq + 1);
            body = body.substr(0, eq);
            has_inline = true;
        }
        auto value = [&](const std::string& flag) -> bool {
            if (has_inline) return true;
            if (i + 1 >= argv.size()) {
                err = "missing value for --" + flag;
                return false;
            }
            ++i;
            return true;
        };
        auto flag_value = [&]() -> std::string { return has_inline ? inline_value : argv[i]; };
        auto bool_flag = [&](bool* out) -> bool {
            if (!has_inline) {
                *out = true;
                return true;
            }
            if (!parse_bool(inline_value, out)) {
                err = "invalid boolean value \"" + inline_value + "\" for --" + body;
                return false;
            }
            return true;
        };

        if (body == "listen") {
            if (!value(body)) return false;
            cfg.listen = flag_value();
        } else if (body == "mesh") {
            if (!value(body)) return false;
            cfg.mesh = flag_value();
        } else if (body == "bootstrap") {
            if (!value(body)) return false;
            cfg.bootstrap = flag_value();
        } else if (body == "db") {
            if (!value(body)) return false;
            cfg.db_path = flag_value();
        } else if (body == "password") {
            if (!value(body)) return false;
            cfg.password = flag_value();
        } else if (body == "key") {
            if (!value(body)) return false;
            cfg.key_hex = flag_value();
        } else if (body == "cert") {
            if (!value(body)) return false;
            cfg.tls_cert = flag_value();
        } else if (body == "tls-key") {
            if (!value(body)) return false;
            cfg.tls_key = flag_value();
        } else if (body == "cert-sans") {
            if (!value(body)) return false;
            cfg.cert_sans = flag_value();
        } else if (body == "id") {
            if (!value(body)) return false;
            cfg.node_id = flag_value();
        } else if (body == "gen-certs") {
            if (!bool_flag(&cfg.gen_certs)) return false;
        } else if (body == "gen-certs-only") {
            if (!bool_flag(&cfg.gen_certs_only)) return false;
        } else if (body == "force-certs") {
            if (!bool_flag(&cfg.force_certs)) return false;
        } else {
            err = "unknown flag: " + raw;
            return false;
        }
    }
    return true;
}

}  // namespace snake::c2
