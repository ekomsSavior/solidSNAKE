#ifndef SNAKE_PAYLOADS_SSH_CLIENT_HPP
#define SNAKE_PAYLOADS_SSH_CLIENT_HPP

#ifndef _WIN32

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace sshdet {

inline void put_u32(std::string& b, uint32_t v) {
    b.push_back((char)((v >> 24) & 0xff));
    b.push_back((char)((v >> 16) & 0xff));
    b.push_back((char)((v >> 8) & 0xff));
    b.push_back((char)(v & 0xff));
}

inline void put_str(std::string& b, const std::string& s) {
    put_u32(b, (uint32_t)s.size());
    b += s;
}

inline uint32_t get_u32(const std::string& b, size_t off) {
    return ((uint32_t)(unsigned char)b[off] << 24) | ((uint32_t)(unsigned char)b[off + 1] << 16) |
           ((uint32_t)(unsigned char)b[off + 2] << 8) | (uint32_t)(unsigned char)b[off + 3];
}

inline bool get_u32_at(const std::string& b, size_t& off, uint32_t& out) {
    if (off + 4 > b.size()) return false;
    out = get_u32(b, off);
    off += 4;
    return true;
}

inline bool get_str(const std::string& b, size_t& off, std::string& out) {
    if (off + 4 > b.size()) return false;
    uint32_t n = get_u32(b, off);
    off += 4;
    if (off + n > b.size()) return false;
    out.assign(b, off, n);
    off += n;
    return true;
}

inline std::string mpint_of(const Bytes& v) {
    size_t i = 0;
    while (i < v.size() && v[i] == 0) ++i;
    std::string body((const char*)v.data() + i, v.size() - i);
    if (body.empty()) {
        body = std::string(1, '\0');
    } else if ((unsigned char)body[0] & 0x80) {
        body.insert(body.begin(), '\0');
    }
    std::string out;
    put_str(out, body);
    return out;
}

inline Bytes sha256(const std::string& data) {
    Bytes out(32);
    unsigned int n = 0;
    EVP_Digest(data.data(), data.size(), out.data(), &n, EVP_sha256(), nullptr);
    out.resize(n);
    return out;
}

inline std::string now_rfc3339_utc() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

inline std::string local_stamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &tm);
    return buf;
}

inline std::string temp_dir() {
    const char* t = getenv("TMPDIR");
    if (t != nullptr && *t != '\0') return t;
    return "/tmp";
}

const char* const kClientVersion = "SSH-2.0-solidSNAKE_1.0";
const char* const kHostKeyAlgos =
    "ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ssh-rsa";

constexpr unsigned char MSG_SERVICE_REQUEST = 5;
constexpr unsigned char MSG_SERVICE_ACCEPT = 6;
constexpr unsigned char MSG_EXT_INFO = 7;
constexpr unsigned char MSG_IGNORE = 2;
constexpr unsigned char MSG_DEBUG = 4;
constexpr unsigned char MSG_CHANNEL_OPEN = 90;
constexpr unsigned char MSG_CHANNEL_OPEN_CONFIRMATION = 91;
constexpr unsigned char MSG_CHANNEL_OPEN_FAILURE = 92;
constexpr unsigned char MSG_CHANNEL_WINDOW_ADJUST = 93;
constexpr unsigned char MSG_CHANNEL_DATA = 94;
constexpr unsigned char MSG_CHANNEL_EXTENDED_DATA = 95;
constexpr unsigned char MSG_CHANNEL_EOF = 96;
constexpr unsigned char MSG_CHANNEL_CLOSE = 97;
constexpr unsigned char MSG_CHANNEL_REQUEST = 98;
constexpr unsigned char MSG_CHANNEL_SUCCESS = 99;
constexpr unsigned char MSG_CHANNEL_FAILURE = 100;
constexpr unsigned char MSG_KEXINIT = 20;
constexpr unsigned char MSG_NEWKEYS = 21;
constexpr unsigned char MSG_KEX_ECDH_INIT = 30;
constexpr unsigned char MSG_KEX_ECDH_REPLY = 31;
constexpr unsigned char MSG_USERAUTH_REQUEST = 50;
constexpr unsigned char MSG_USERAUTH_FAILURE = 51;
constexpr unsigned char MSG_USERAUTH_SUCCESS = 52;
constexpr unsigned char MSG_USERAUTH_BANNER = 53;

class SshClient {
  public:
    ~SshClient() { reset(); }
    SshClient(const SshClient&) = delete;
    SshClient& operator=(const SshClient&) = delete;
    SshClient() = default;

    bool auth_password(const std::string& host, uint16_t port, const std::string& user,
                       const std::string& pass, int timeout_sec) {
        timeout_ms_ = (timeout_sec > 0) ? timeout_sec * 1000 : 0;
        if (!open_conn(host, port)) return false;

        std::string v_s;
        if (!exchange_versions(v_s)) return false;

        std::string i_c;
        if (!send_kexinit(i_c)) return false;
        std::string i_s;
        if (!recv_packet(i_s) || i_s.empty() || (unsigned char)i_s[0] != MSG_KEXINIT) return false;

        Bytes pub(32), priv(32);
        if (!x25519_keypair(pub, priv)) return false;

        std::string init;
        init.push_back((char)MSG_KEX_ECDH_INIT);
        put_str(init, std::string((const char*)pub.data(), pub.size()));
        if (!send_packet(init)) return false;

        std::string reply;
        if (!recv_packet(reply) || reply.empty() || (unsigned char)reply[0] != MSG_KEX_ECDH_REPLY)
            return false;
        std::string k_s, q_s, sig;
        size_t off = 1;
        if (!get_str(reply, off, k_s) || !get_str(reply, off, q_s) || !get_str(reply, off, sig))
            return false;
        if (q_s.size() != 32) return false;

        Bytes shared;
        if (!x25519_shared(priv, Bytes(q_s.begin(), q_s.end()), shared)) return false;

        std::string h_input;
        put_str(h_input, kClientVersion);
        put_str(h_input, v_s);
        put_str(h_input, i_c);
        put_str(h_input, i_s);
        put_str(h_input, k_s);
        put_str(h_input, std::string((const char*)pub.data(), pub.size()));
        put_str(h_input, q_s);
        std::string k_mpint = mpint_of(shared);
        h_input += k_mpint;
        Bytes h = sha256(h_input);

        if (!init_keys(h, k_mpint)) return false;

        std::string newkeys;
        newkeys.push_back((char)MSG_NEWKEYS);
        if (!send_packet(newkeys)) return false;
        out_encrypted_ = true;

        for (;;) {
            std::string p;
            if (!recv_packet(p) || p.empty()) return false;
            unsigned char t = (unsigned char)p[0];
            if (t == MSG_NEWKEYS) break;
            if (t != MSG_IGNORE && t != MSG_DEBUG) return false;
        }
        in_encrypted_ = true;

        std::string svc;
        svc.push_back((char)MSG_SERVICE_REQUEST);
        put_str(svc, "ssh-userauth");
        if (!send_packet(svc)) return false;

        for (;;) {
            std::string p;
            if (!recv_packet(p) || p.empty()) return false;
            unsigned char t = (unsigned char)p[0];
            if (t == MSG_SERVICE_ACCEPT) break;
            if (t == MSG_EXT_INFO || t == MSG_IGNORE || t == MSG_DEBUG) continue;
            return false;
        }

        std::string auth;
        auth.push_back((char)MSG_USERAUTH_REQUEST);
        put_str(auth, user);
        put_str(auth, "ssh-connection");
        put_str(auth, "password");
        auth.push_back('\0');
        put_str(auth, pass);
        if (!send_packet(auth)) return false;

        for (;;) {
            std::string p;
            if (!recv_packet(p) || p.empty()) return false;
            unsigned char t = (unsigned char)p[0];
            if (t == MSG_USERAUTH_SUCCESS) return true;
            if (t == MSG_USERAUTH_FAILURE) return false;
            if (t == MSG_USERAUTH_BANNER || t == MSG_EXT_INFO || t == MSG_IGNORE ||
                t == MSG_DEBUG)
                continue;
            return false;
        }
    }

    bool exec_session(const std::string& cmd) {
        uint32_t local_chan = next_chan_++;
        std::string open;
        open.push_back((char)MSG_CHANNEL_OPEN);
        put_str(open, "session");
        put_u32(open, local_chan);
        put_u32(open, 2 * 1024 * 1024);
        put_u32(open, 32768);
        if (!send_packet(open)) return false;

        uint32_t remote_chan = 0;
        for (;;) {
            std::string r;
            if (!recv_packet(r) || r.empty()) return false;
            unsigned char t = (unsigned char)r[0];
            if (t == MSG_CHANNEL_OPEN_CONFIRMATION) {
                size_t off = 1;
                uint32_t recipient = 0, sender = 0, window = 0, maxpkt = 0;
                if (!get_u32_at(r, off, recipient) || !get_u32_at(r, off, sender) ||
                    !get_u32_at(r, off, window) || !get_u32_at(r, off, maxpkt))
                    return false;
                remote_chan = sender;
                break;
            }
            if (t == MSG_CHANNEL_OPEN_FAILURE) return false;
            if (t == MSG_IGNORE || t == MSG_DEBUG) continue;
            return false;
        }

        std::string req;
        req.push_back((char)MSG_CHANNEL_REQUEST);
        put_u32(req, remote_chan);
        put_str(req, "exec");
        req.push_back('\1');
        put_str(req, cmd);
        if (!send_packet(req)) return false;

        for (int n = 0; n < 32; ++n) {
            std::string r;
            if (!recv_packet(r) || r.empty()) break;
            unsigned char t = (unsigned char)r[0];
            if (t == MSG_CHANNEL_EOF || t == MSG_CHANNEL_CLOSE) break;
        }
        return true;
    }

  private:
    void reset() {
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
        if (enc_ctx_ != nullptr) EVP_CIPHER_CTX_free(enc_ctx_);
        if (dec_ctx_ != nullptr) EVP_CIPHER_CTX_free(dec_ctx_);
        enc_ctx_ = nullptr;
        dec_ctx_ = nullptr;
    }

    bool open_conn(const std::string& host, uint16_t port) {
        char portbuf[8];
        std::snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);
        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), portbuf, &hints, &res) != 0 || res == nullptr) return false;

        int fd = -1;
        for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
            fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (fd < 0) continue;
            if (timeout_ms_ > 0 && !connect_timeout(fd, ai, timeout_ms_)) {
                ::close(fd);
                fd = -1;
                continue;
            }
            if (timeout_ms_ == 0 && ::connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
                ::close(fd);
                fd = -1;
                continue;
            }
            break;
        }
        freeaddrinfo(res);
        if (fd < 0) return false;
        if (timeout_ms_ > 0) {
            struct timeval tv;
            tv.tv_sec = timeout_ms_ / 1000;
            tv.tv_usec = (timeout_ms_ % 1000) * 1000;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        fd_ = fd;
        return true;
    }

    static bool connect_timeout(int fd, struct addrinfo* ai, int timeout_ms) {
        int flags = fcntl_fd(fd);
        set_nonblock(fd, true);
        int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        bool ok = (rc == 0);
        if (!ok && errno_is_inprogress()) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            int pr = ::poll(&pfd, 1, timeout_ms);
            if (pr > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) ok = true;
            }
        }
        set_nonblock(fd, false);
        (void)flags;
        return ok;
    }

    static int fcntl_fd(int fd) {
        return fcntl(fd, F_GETFL, 0);
    }

    static void set_nonblock(int fd, bool on) {
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl < 0) return;
        if (on)
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        else
            fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }

    static bool errno_is_inprogress() {
        return errno == EINPROGRESS;
    }

    bool write_all(const void* buf, size_t n) {
        const char* p = (const char*)buf;
        size_t left = n;
        while (left > 0) {
            ssize_t w = ::send(fd_, p, left, MSG_NOSIGNAL);
            if (w <= 0) {
                if (w < 0 && (errno == EINTR)) continue;
                return false;
            }
            p += w;
            left -= (size_t)w;
        }
        return true;
    }

    bool read_exact(void* buf, size_t n) {
        char* p = (char*)buf;
        size_t left = n;
        while (left > 0) {
            struct pollfd pfd;
            pfd.fd = fd_;
            pfd.events = POLLIN;
            int pr = (timeout_ms_ > 0) ? ::poll(&pfd, 1, timeout_ms_) : 1;
            if (pr <= 0) return false;
            ssize_t r = ::recv(fd_, p, left, 0);
            if (r == 0) return false;
            if (r < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                return false;
            }
            p += r;
            left -= (size_t)r;
        }
        return true;
    }

    bool send_packet(const std::string& payload) {
        std::string pkt;
        size_t blk = out_encrypted_ ? 16 : 8;
        unsigned char pad = (unsigned char)(blk - ((4 + 1 + payload.size()) % blk));
        if (pad < 4) pad = (unsigned char)(pad + blk);
        uint32_t plen = (uint32_t)(1 + payload.size() + pad);
        put_u32(pkt, plen);
        pkt.push_back((char)pad);
        pkt += payload;
        std::string padding(pad, '\0');
        if (RAND_bytes((unsigned char*)&padding[0], (int)pad) != 1) {
            for (size_t i = 0; i < padding.size(); ++i) padding[i] = (char)(i + 1);
        }
        pkt += padding;

        if (!out_encrypted_) {
            out_seq_++;
            return write_all(pkt.data(), pkt.size());
        }
        Bytes mac = hmac_sha256(mac_key_out_, seq_prefix(out_seq_) + pkt);
        out_seq_++;
        std::string ciphered = pkt;
        if (!ctr_crypt(enc_ctx_, ciphered, false)) return false;
        if (!write_all(ciphered.data(), ciphered.size())) return false;
        return write_all(mac.data(), mac.size());
    }

    bool recv_packet(std::string& payload) {
        if (!in_encrypted_) {
            std::string head(4, '\0');
            if (!read_exact(&head[0], 4)) return false;
            uint32_t plen = get_u32(head, 0);
            if (plen < 5 || plen > 35000) return false;
            std::string body(plen, '\0');
            if (!read_exact(&body[0], plen)) return false;
            size_t pad = (unsigned char)body[0];
            if ((size_t)plen < 1 + pad) return false;
            payload.assign(body, 1, plen - 1 - pad);
            in_seq_++;
            return true;
        }

        std::string first(16, '\0');
        if (!read_exact(&first[0], 16)) return false;
        if (!ctr_crypt(dec_ctx_, first, true)) return false;
        uint32_t plen = get_u32(first, 0);
        if (plen < 5 || plen > 35000) return false;
        if (4 + plen < 16) return false;
        size_t rest = 4 + (size_t)plen - 16;
        std::string body;
        if (rest > 0) {
            body.assign(rest, '\0');
            if (!read_exact(&body[0], rest)) return false;
            if (!ctr_crypt(dec_ctx_, body, true)) return false;
        }
        Bytes mac(32);
        if (!read_exact(mac.data(), mac.size())) return false;

        std::string plain = first + body;
        std::string want = seq_prefix(in_seq_) + plain;
        Bytes got = hmac_sha256(mac_key_in_, want);
        if (got.size() != mac.size() || !constant_time_eq(got, mac)) return false;
        size_t pad = (unsigned char)plain[4];
        if ((size_t)plen < 1 + pad) return false;
        in_seq_++;
        payload.assign(plain, 5, plen - 1 - pad);
        return true;
    }

    static std::string seq_prefix(uint32_t seq) {
        std::string s;
        put_u32(s, seq);
        return s;
    }

    static Bytes hmac_sha256(const Bytes& key, const std::string& data) {
        Bytes out(32);
        unsigned int n = 0;
        HMAC(EVP_sha256(), key.data(), (int)key.size(), (const unsigned char*)data.data(),
             data.size(), out.data(), &n);
        out.resize(n);
        return out;
    }

    static bool ctr_crypt(EVP_CIPHER_CTX* ctx, std::string& buf, bool decrypt) {
        if (ctx == nullptr || buf.empty()) return ctx != nullptr;
        int outl = 0;
        int rc = decrypt ? EVP_DecryptUpdate(ctx, (unsigned char*)&buf[0], &outl,
                                             (const unsigned char*)buf.data(),
                                             (int)buf.size())
                         : EVP_EncryptUpdate(ctx, (unsigned char*)&buf[0], &outl,
                                             (const unsigned char*)buf.data(),
                                             (int)buf.size());
        if (rc != 1) return false;
        return outl == (int)buf.size();
    }

    bool exchange_versions(std::string& v_s) {
        std::string line = std::string(kClientVersion) + "\r\n";
        if (!write_all(line.data(), line.size())) return false;
        std::string pending;
        for (int i = 0; i < 64; ++i) {
            char c;
            if (!read_exact(&c, 1)) return false;
            if (c == '\n') {
                std::string l = pending;
                if (!l.empty() && l.back() == '\r') l.pop_back();
                pending.clear();
                if (l.rfind("SSH-", 0) == 0) {
                    v_s = l;
                    server_version_ = l;
                    return true;
                }
                continue;
            }
            pending.push_back(c);
            if (pending.size() > 512) return false;
        }
        return false;
    }

    bool send_kexinit(std::string& i_c) {
        std::string p;
        p.push_back((char)MSG_KEXINIT);
        unsigned char cookie[16];
        if (RAND_bytes(cookie, 16) != 1) {
            for (size_t i = 0; i < sizeof(cookie); ++i) cookie[i] = (unsigned char)(i * 7 + 1);
        }
        p.append((const char*)cookie, 16);
        put_str(p, "curve25519-sha256");
        put_str(p, kHostKeyAlgos);
        put_str(p, "aes128-ctr");
        put_str(p, "aes128-ctr");
        put_str(p, "hmac-sha2-256");
        put_str(p, "hmac-sha2-256");
        put_str(p, "none");
        put_str(p, "none");
        put_str(p, "");
        put_str(p, "");
        p.push_back('\0');
        put_u32(p, 0);
        i_c = p;
        return send_packet(p);
    }

    static bool x25519_keypair(Bytes& pub, Bytes& priv) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (ctx == nullptr) return false;
        bool ok = EVP_PKEY_keygen_init(ctx) == 1;
        EVP_PKEY* pkey = nullptr;
        if (ok) ok = EVP_PKEY_keygen(ctx, &pkey) == 1;
        if (ok) {
            pub.resize(32);
            priv.resize(32);
            size_t plen = 32, klen = 32;
            ok = EVP_PKEY_get_raw_public_key(pkey, pub.data(), &plen) == 1;
            if (ok) ok = EVP_PKEY_get_raw_private_key(pkey, priv.data(), &klen) == 1;
            if (ok) {
                pub.resize(plen);
                priv.resize(klen);
            }
        }
        if (pkey != nullptr) EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return ok;
    }

    static bool x25519_shared(const Bytes& priv, const Bytes& peer_pub, Bytes& shared) {
        if (priv.size() != 32 || peer_pub.size() != 32) return false;
        EVP_PKEY* mine = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), 32);
        EVP_PKEY* theirs =
            EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), 32);
        if (mine == nullptr || theirs == nullptr) {
            if (mine != nullptr) EVP_PKEY_free(mine);
            if (theirs != nullptr) EVP_PKEY_free(theirs);
            return false;
        }
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(mine, nullptr);
        bool ok = ctx != nullptr && EVP_PKEY_derive_init(ctx) == 1;
        size_t len = 32;
        if (ok) ok = EVP_PKEY_derive_set_peer(ctx, theirs) == 1;
        shared.resize(32);
        if (ok) ok = EVP_PKEY_derive(ctx, shared.data(), &len) == 1;
        if (ok) shared.resize(len);
        if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(mine);
        EVP_PKEY_free(theirs);
        return ok && shared.size() == 32;
    }

    bool init_keys(const Bytes& h, const std::string& k_mpint) {
        Bytes session_id = h;
        Bytes k = Bytes(k_mpint.begin(), k_mpint.end());
        Bytes iv_c2s = key_material(k, h, session_id, 'A');
        Bytes key_c2s = key_material(k, h, session_id, 'C');
        Bytes mac_c2s = key_material(k, h, session_id, 'E');
        Bytes iv_s2c = key_material(k, h, session_id, 'B');
        Bytes key_s2c = key_material(k, h, session_id, 'D');
        Bytes mac_s2c = key_material(k, h, session_id, 'F');
        (void)iv_s2c;
        (void)key_s2c;
        if (key_c2s.size() < 16 || iv_c2s.size() < 16) return false;
        mac_key_out_ = mac_c2s;
        mac_key_in_ = mac_s2c;

        enc_ctx_ = EVP_CIPHER_CTX_new();
        dec_ctx_ = EVP_CIPHER_CTX_new();
        if (enc_ctx_ == nullptr || dec_ctx_ == nullptr) return false;
        if (EVP_EncryptInit_ex(enc_ctx_, EVP_aes_128_ctr(), nullptr, key_c2s.data(),
                               iv_c2s.data()) != 1)
            return false;
        if (EVP_DecryptInit_ex(dec_ctx_, EVP_aes_128_ctr(), nullptr, key_s2c.data(),
                               iv_s2c.data()) != 1)
            return false;
        return true;
    }

    static Bytes key_material(const Bytes& k, const Bytes& h, const Bytes& session_id, char tag) {
        Bytes out;
        Bytes so_far;
        while (out.size() < 32) {
            std::string in;
            in.append((const char*)k.data(), k.size());
            in.append((const char*)h.data(), h.size());
            if (so_far.empty()) {
                in.push_back(tag);
                in.append((const char*)session_id.data(), session_id.size());
            } else {
                in.append((const char*)so_far.data(), so_far.size());
            }
            Bytes d = sha256(in);
            so_far = d;
            size_t take = std::min((size_t)32, (size_t)32 - out.size());
            out.insert(out.end(), d.begin(), d.begin() + take);
        }
        return out;
    }

    int fd_ = -1;
    int timeout_ms_ = 0;
    bool out_encrypted_ = false;
    bool in_encrypted_ = false;
    uint32_t out_seq_ = 0;
    uint32_t in_seq_ = 0;
    EVP_CIPHER_CTX* enc_ctx_ = nullptr;
    EVP_CIPHER_CTX* dec_ctx_ = nullptr;
    Bytes mac_key_out_;
    Bytes mac_key_in_;
    std::string server_version_;
    uint32_t next_chan_ = 0;
};

}  // namespace sshdet
}  // namespace snake::payloads

#endif  // _WIN32
#endif  // SNAKE_PAYLOADS_SSH_CLIENT_HPP
