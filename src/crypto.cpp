#include "snake/crypto.hpp"

#include <sodium.h>

#include <cstring>
#include <ctime>

namespace snake {

namespace {
constexpr size_t kNonce = 24;
constexpr size_t kTag = 16;

bool sodium_ready() {
    static const bool ok = (sodium_init() >= 0);
    return ok;
}

const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_padded(const Bytes& b) {
    std::string out;
    size_t i = 0;
    while (i + 3 <= b.size()) {
        uint32_t v = (uint32_t(b[i]) << 16) | (uint32_t(b[i + 1]) << 8) | b[i + 2];
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
        out.push_back(kB64[v & 63]);
        i += 3;
    }
    if (i + 1 == b.size()) {
        uint32_t v = uint32_t(b[i]) << 16;
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (i + 2 == b.size()) {
        uint32_t v = (uint32_t(b[i]) << 16) | (uint32_t(b[i + 1]) << 8);
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}
}  // namespace

std::string to_hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) {
        s.push_back(d[c >> 4]);
        s.push_back(d[c & 0xf]);
    }
    return s;
}

std::optional<Bytes> from_hex(const std::string& s) {
    if (s.size() % 2) return std::nullopt;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    Bytes out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(uint8_t(hi * 16 + lo));
    }
    return out;
}

std::string to_b64_raw(const Bytes& b) {
    std::string out;
    size_t i = 0;
    while (i + 3 <= b.size()) {
        uint32_t v = (uint32_t(b[i]) << 16) | (uint32_t(b[i + 1]) << 8) | b[i + 2];
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
        out.push_back(kB64[v & 63]);
        i += 3;
    }
    if (i + 1 == b.size()) {
        uint32_t v = uint32_t(b[i]) << 16;
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
    } else if (i + 2 == b.size()) {
        uint32_t v = (uint32_t(b[i]) << 16) | (uint32_t(b[i + 1]) << 8);
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
    }
    return out;
}

std::optional<Bytes> from_b64_raw(const std::string& s) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    Bytes out;
    int buf = 0, bits = 0;
    for (char c : s) {
        int v = val(c);
        if (v < 0) return std::nullopt;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(uint8_t((buf >> bits) & 0xff));
        }
    }
    return out;
}

std::string to_b64(const Bytes& b) { return b64_padded(b); }

std::optional<Bytes> from_b64(const std::string& s) {
    std::string t;
    t.reserve(s.size());
    for (char c : s) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        t.push_back(c);
    }
    return from_b64_raw(t);
}

Bytes random_bytes(size_t n) {
    sodium_ready();
    Bytes out(n);
    randombytes_buf(out.data(), n);
    return out;
}

Bytes aead_encrypt_with_nonce(const Bytes& key, const Bytes& nonce, const Bytes& pt) {
    sodium_ready();
    if (key.size() != 32 || nonce.size() != kNonce) return {};
    Bytes out(kNonce + pt.size() + kTag);
    std::memcpy(out.data(), nonce.data(), kNonce);
    unsigned char mac[kTag];
    unsigned long long maclen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            out.data() + kNonce, mac, &maclen, pt.data(), pt.size(), nullptr, 0,
            nullptr, nonce.data(), key.data()) != 0)
        return {};
    std::memcpy(out.data() + kNonce + pt.size(), mac, kTag);
    return out;
}

Bytes aead_encrypt(const Bytes& key, const Bytes& pt) {
    Bytes nonce = random_bytes(kNonce);
    return aead_encrypt_with_nonce(key, nonce, pt);
}

std::optional<Bytes> aead_decrypt(const Bytes& key, const Bytes& blob) {
    sodium_ready();
    if (key.size() != 32 || blob.size() < kNonce + kTag) return std::nullopt;
    const size_t ctlen = blob.size() - kNonce - kTag;
    Bytes pt(ctlen ? ctlen : 1);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            pt.data(), nullptr, blob.data() + kNonce, ctlen,
            blob.data() + kNonce + ctlen, nullptr, 0, blob.data(),
            key.data()) != 0)
        return std::nullopt;
    pt.resize(ctlen);
    return pt;
}

Ed25519KeyPair ed25519_keypair_from_seed(const Bytes& seed) {
    Ed25519KeyPair kp;
    if (seed.size() != 32) return kp;
    kp.seed = seed;
    unsigned char pk[32], sk[64];
    crypto_sign_seed_keypair(pk, sk, seed.data());
    kp.pub.assign(pk, pk + 32);
    return kp;
}

Bytes ed25519_sign(const Bytes& seed, const Bytes& msg) {
    if (seed.size() != 32) return {};
    unsigned char pk[32], sk[64], sig[crypto_sign_BYTES];
    crypto_sign_seed_keypair(pk, sk, seed.data());
    unsigned long long siglen = 0;
    crypto_sign_detached(sig, &siglen, msg.data(), msg.size(), sk);
    return Bytes(sig, sig + crypto_sign_BYTES);
}

bool ed25519_verify_sig(const Bytes& pub, const Bytes& msg, const Bytes& sig) {
    if (pub.size() != 32 || sig.size() != 64) return false;
    return crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(), pub.data()) == 0;
}

Bytes sign_message(const Bytes& data, int64_t ts, const std::string& nonce_b64) {
    Bytes msg = data;
    std::string tail = std::to_string(ts) + nonce_b64;
    msg.insert(msg.end(), tail.begin(), tail.end());
    return msg;
}

bool verify_signature(const Bytes& pub, const Bytes& data, const Bytes& sig,
                      const std::string& nonce, int64_t ts, int64_t window_secs) {
    int64_t now = int64_t(std::time(nullptr));
    int64_t diff = now - ts;
    if (diff < 0) diff = -diff;
    if (diff > window_secs) return false;
    if (!nonce.empty() && nonce.size() < 8) return false;
    return ed25519_verify_sig(pub, sign_message(data, ts, nonce), sig);
}

Bytes sha256(const Bytes& d) {
    sodium_ready();
    Bytes out(32);
    crypto_hash_sha256(out.data(), d.data(), d.size());
    return out;
}

Bytes derive_session_key(const Bytes& secret, const Bytes& salt) {
    Bytes m = secret;
    m.insert(m.end(), salt.begin(), salt.end());
    return sha256(m);
}

std::string public_key_pem(const Bytes& pub) {
    if (pub.size() != 32) return "";
    static const unsigned char kPkixEd25519Prefix[] = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
    Bytes der(kPkixEd25519Prefix, kPkixEd25519Prefix + sizeof(kPkixEd25519Prefix));
    der.insert(der.end(), pub.begin(), pub.end());
    std::string b64 = b64_padded(der);
    std::string out = "-----BEGIN PUBLIC KEY-----\n";
    for (size_t i = 0; i < b64.size(); i += 64) out += b64.substr(i, 64) + "\n";
    out += "-----END PUBLIC KEY-----\n";
    return out;
}

bool constant_time_eq(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace snake
