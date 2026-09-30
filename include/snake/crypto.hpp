#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace snake {

using Bytes = std::vector<uint8_t>;

std::string to_hex(const Bytes& b);
std::optional<Bytes> from_hex(const std::string& s);

std::string to_b64_raw(const Bytes& b);
std::optional<Bytes> from_b64_raw(const std::string& s);

std::string to_b64(const Bytes& b);
std::optional<Bytes> from_b64(const std::string& s);

Bytes aead_encrypt(const Bytes& key, const Bytes& plaintext);
Bytes aead_encrypt_with_nonce(const Bytes& key, const Bytes& nonce, const Bytes& plaintext);
std::optional<Bytes> aead_decrypt(const Bytes& key, const Bytes& blob);

struct Ed25519KeyPair {
    Bytes seed;
    Bytes pub;
};
Ed25519KeyPair ed25519_keypair_from_seed(const Bytes& seed);
Bytes ed25519_sign(const Bytes& seed, const Bytes& msg);
bool ed25519_verify_sig(const Bytes& pub, const Bytes& msg, const Bytes& sig);

Bytes sign_message(const Bytes& data, int64_t ts, const std::string& nonce_b64);
bool verify_signature(const Bytes& pub, const Bytes& data, const Bytes& sig,
                      const std::string& nonce, int64_t ts, int64_t window_secs = 300);

Bytes sha256(const Bytes& data);
Bytes derive_session_key(const Bytes& secret, const Bytes& salt);
std::string public_key_pem(const Bytes& pub);
Bytes random_bytes(size_t n);
bool constant_time_eq(const Bytes& a, const Bytes& b);

}  // namespace snake
