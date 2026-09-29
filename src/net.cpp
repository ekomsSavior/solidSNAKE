#include "snake/net.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <cctype>
#include <cstdlib>
#include <cstring>

#include "snake/sys.hpp"

namespace snake::net {

#if defined(_WIN32)
constexpr int kMsgNoSignal = 0;
#else
constexpr int kMsgNoSignal = MSG_NOSIGNAL;
#endif

namespace {

bool looks_like_ip(const std::string& h) {
    if (h.empty()) return false;
    if (h.find(':') != std::string::npos) return true;
    for (char c : h) {
        if (!(c == '.' || (c >= '0' && c <= '9'))) return false;
    }
    return true;
}

std::string lower(std::string s) {
    for (auto& c : s) c = char(std::tolower((unsigned char)c));
    return s;
}

std::string trim(std::string s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return s.substr(a, b - a + 1);
}

std::string normalize_fp(const std::string& fp) {
    std::string out;
    for (char c : fp) {
        if (c == ':' || c == ' ' || c == '\t') continue;
        out.push_back(char(std::tolower((unsigned char)c)));
    }
    return out;
}

std::string ssl_err() {
    unsigned long e = ERR_get_error();
    if (!e) return "";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf;
}

std::string decode_chunked(const std::string& in) {
    std::string out;
    size_t p = 0;
    while (p < in.size()) {
        size_t eol = in.find("\r\n", p);
        if (eol == std::string::npos) break;
        std::string szline = in.substr(p, eol - p);
        size_t semi = szline.find(';');
        if (semi != std::string::npos) szline = szline.substr(0, semi);
        size_t sz = strtoul(szline.c_str(), nullptr, 16);
        p = eol + 2;
        if (sz == 0) break;
        if (p + sz > in.size()) { out.append(in, p, in.size() - p); break; }
        out.append(in, p, sz);
        p += sz;
        if (in.compare(p, 2, "\r\n") == 0) p += 2;
    }
    return out;
}

template <typename F>
void for_each_header_line(const std::string& head, F fn) {
    size_t pos = head.find("\r\n");
    if (pos == std::string::npos) return;
    size_t start = pos + 2;
    while (start <= head.size()) {
        size_t next = head.find("\r\n", start);
        std::string line =
            head.substr(start, (next == std::string::npos ? head.size() : next) - start);
        if (!line.empty()) fn(line);
        if (next == std::string::npos) break;
        start = next + 2;
    }
}

std::optional<HttpResponse> parse_http_response(const std::string& raw) {
    size_t he = raw.find("\r\n\r\n");
    if (he == std::string::npos) return std::nullopt;
    std::string head = raw.substr(0, he);
    std::string rest = raw.substr(he + 4);

    HttpResponse resp;
    size_t sp1 = head.find(' ');
    size_t sp2 = (sp1 == std::string::npos) ? std::string::npos : head.find(' ', sp1 + 1);
    if (sp1 == std::string::npos) return std::nullopt;
    resp.status = std::atoi(head.substr(sp1 + 1, sp2 - sp1 - 1).c_str());

    for_each_header_line(head, [&](const std::string& line) {
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            resp.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
        }
    });

    auto te = resp.headers.find("transfer-encoding");
    if (te != resp.headers.end() && lower(te->second).find("chunked") != std::string::npos) {
        resp.body = decode_chunked(rest);
    } else {
        resp.body = rest;
    }
    return resp;
}

}  // namespace

struct TlsClient::Impl {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    rr_socket_t fd = sys::kInvalidSocket;
};

TlsClient::TlsClient() {
    sys::net_init();
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    impl_ = new Impl();
}

TlsClient::~TlsClient() {
    close();
    delete impl_;
}

bool TlsClient::connect(const std::string& host, uint16_t port, const TlsOptions& opts) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    std::string ps = std::to_string(port);
    if (getaddrinfo(host.c_str(), ps.c_str(), &hints, &res) != 0 || res == nullptr) {
        err_ = "resolve failed: " + host;
        return false;
    }
    rr_socket_t fd = sys::kInvalidSocket;
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == sys::kInvalidSocket) continue;
        sys::set_socket_timeout(fd, opts.timeout_seconds);
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        sys::close_socket(fd);
        fd = sys::kInvalidSocket;
    }
    freeaddrinfo(res);
    if (fd == sys::kInvalidSocket) {
        err_ = "tcp connect failed: " + host + ":" + ps;
        return false;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        sys::close_socket(fd);
        err_ = "SSL_CTX_new failed";
        return false;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_default_verify_paths(ctx);
    if (!opts.ca_file.empty() &&
        SSL_CTX_load_verify_locations(ctx, opts.ca_file.c_str(), nullptr) != 1) {
        SSL_CTX_free(ctx);
        sys::close_socket(fd);
        err_ = "load ca failed: " + opts.ca_file;
        return false;
    }
    bool pin = !opts.fingerprint_hex.empty();
    SSL_CTX_set_verify(ctx, (opts.skip_verify || pin) ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, nullptr);

    static const unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn));

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        sys::close_socket(fd);
        err_ = "SSL_new failed";
        return false;
    }
    SSL_set_fd(ssl, (int)fd);
    if (!looks_like_ip(host)) SSL_set_tlsext_host_name(ssl, host.c_str());
    if (!opts.skip_verify && !pin) {
        X509_VERIFY_PARAM* vp = SSL_get0_param(ssl);
        if (looks_like_ip(host)) {
            X509_VERIFY_PARAM_set1_ip_asc(vp, host.c_str());
        } else {
            X509_VERIFY_PARAM_set1_host(vp, host.c_str(), 0);
        }
    }
    if (SSL_connect(ssl) != 1) {
        std::string e = ssl_err();
        err_ = "tls handshake failed" + (e.empty() ? "" : (": " + e));
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        sys::close_socket(fd);
        return false;
    }
    if (!opts.skip_verify && !pin) {
        long vr = SSL_get_verify_result(ssl);
        if (vr != X509_V_OK) {
            err_ = "cert verify failed: " + std::to_string(vr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            sys::close_socket(fd);
            return false;
        }
    }
    if (pin) {
        X509* cert = SSL_get1_peer_certificate(ssl);
        bool ok = false;
        std::string got;
        if (cert) {
            unsigned char md[EVP_MAX_MD_SIZE];
            unsigned int n = 0;
            X509_digest(cert, EVP_sha256(), md, &n);
            char b[4];
            for (unsigned int i = 0; i < n; i++) {
                std::snprintf(b, sizeof(b), "%02x", md[i]);
                got += b;
            }
            X509_free(cert);
            ok = (normalize_fp(opts.fingerprint_hex) == got);
        }
        if (!ok) {
            err_ = "certificate fingerprint mismatch (got " + got + ")";
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            sys::close_socket(fd);
            return false;
        }
    }

    impl_->ctx = ctx;
    impl_->ssl = ssl;
    impl_->fd = fd;
    return true;
}

bool TlsClient::write_all(const uint8_t* data, size_t len) {
    if (!impl_->ssl) return false;
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(impl_->ssl, data + off, (int)(len - off));
        if (n <= 0) {
            std::string e = ssl_err();
            err_ = "tls write failed" + (e.empty() ? "" : (": " + e));
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

bool TlsClient::write_all(const Bytes& b) { return write_all(b.data(), b.size()); }

long TlsClient::read_some(uint8_t* buf, size_t len) {
    if (!impl_->ssl) return -1;
    int n = SSL_read(impl_->ssl, buf, (int)len);
    if (n > 0) return n;
    int e = SSL_get_error(impl_->ssl, n);
    if (e == SSL_ERROR_ZERO_RETURN) return 0;
    if (e == SSL_ERROR_SYSCALL && n == 0) return 0;
    std::string s = ssl_err();
    err_ = "tls read failed" + (s.empty() ? "" : (": " + s));
    return -1;
}

void TlsClient::close() {
    if (!impl_) return;
    if (impl_->ssl) {
        SSL_shutdown(impl_->ssl);
        SSL_free(impl_->ssl);
        impl_->ssl = nullptr;
    }
    if (impl_->ctx) {
        SSL_CTX_free(impl_->ctx);
        impl_->ctx = nullptr;
    }
    if (impl_->fd != sys::kInvalidSocket) {
        sys::close_socket(impl_->fd);
        impl_->fd = sys::kInvalidSocket;
    }
}

std::string build_request_head(const std::string& method, const std::string& host, uint16_t port,
                               const std::string& path, const HeaderList& headers,
                               const std::string& body) {
    std::string req;
    req.reserve(256 + body.size());
    req += method + " " + path + " HTTP/1.1\r\n";
    req += "Host: " + host + ":" + std::to_string(port) + "\r\n";
    for (const auto& [k, v] : headers) req += k + ": " + v + "\r\n";
    if (!body.empty()) req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    req += "Connection: close\r\n\r\n";
    req += body;
    return req;
}

std::optional<HttpResponse> http_request(TlsClient& c, const std::string& method,
                                         const std::string& host, uint16_t port,
                                         const std::string& path, const HeaderList& headers,
                                         const std::string& body) {
    std::string req = build_request_head(method, host, port, path, headers, body);
    if (!c.write_all((const uint8_t*)req.data(), req.size())) return std::nullopt;

    std::string raw;
    uint8_t tmp[8192];
    for (;;) {
        long n = c.read_some(tmp, sizeof(tmp));
        if (n > 0) {
            raw.append((char*)tmp, (size_t)n);
            if (raw.size() > (16u << 20)) return std::nullopt;
            continue;
        }
        break;
    }
    return parse_http_response(raw);
}

std::optional<HttpResponse> http_get_plain(const std::string& host, uint16_t port,
                                           const std::string& path, const HeaderList& headers,
                                           int timeout_seconds) {
    sys::net_init();
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    std::string ps = std::to_string(port);
    if (getaddrinfo(host.c_str(), ps.c_str(), &hints, &res) != 0 || res == nullptr) {
        return std::nullopt;
    }
    rr_socket_t fd = sys::kInvalidSocket;
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == sys::kInvalidSocket) continue;
        sys::set_socket_timeout(fd, timeout_seconds);
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        sys::close_socket(fd);
        fd = sys::kInvalidSocket;
    }
    freeaddrinfo(res);
    if (fd == sys::kInvalidSocket) return std::nullopt;

    std::string req = build_request_head("GET", host, port, path, headers, "");

    size_t off = 0;
    while (off < req.size()) {
        int n = (int)::send(fd, req.data() + off, (int)(req.size() - off), kMsgNoSignal);
        if (n <= 0) {
            sys::close_socket(fd);
            return std::nullopt;
        }
        off += (size_t)n;
    }

    std::string raw;
    char tmp[8192];
    for (;;) {
        int n = (int)::recv(fd, tmp, (int)sizeof(tmp), 0);
        if (n > 0) {
            raw.append(tmp, (size_t)n);
            if (raw.size() > (16u << 20)) {
                sys::close_socket(fd);
                return std::nullopt;
            }
            continue;
        }
        break;
    }
    sys::close_socket(fd);
    return parse_http_response(raw);
}

bool WsClient::fill(size_t need) {
    uint8_t tmp[8192];
    while (pending_.size() < need) {
        long n = c_->read_some(tmp, sizeof(tmp));
        if (n <= 0) {
            err_ = "socket closed during read";
            return false;
        }
        pending_.insert(pending_.end(), tmp, tmp + n);
        if (pending_.size() > (64u << 20)) {
            err_ = "message too large";
            return false;
        }
    }
    return true;
}

bool WsClient::send_frame(uint8_t opcode, const Bytes& payload, bool masked) {
    Bytes frame;
    frame.reserve(payload.size() + 14);
    frame.push_back(uint8_t(0x80 | (opcode & 0x0f)));
    size_t len = payload.size();
    if (masked) {
        if (len < 126) {
            frame.push_back(uint8_t(0x80 | len));
        } else if (len <= 0xffff) {
            frame.push_back(0x80 | 126);
            frame.push_back(uint8_t((len >> 8) & 0xff));
            frame.push_back(uint8_t(len & 0xff));
        } else {
            frame.push_back(0x80 | 127);
            for (int i = 7; i >= 0; --i) frame.push_back(uint8_t((len >> (8 * i)) & 0xff));
        }
        Bytes mk = random_bytes(4);
        frame.insert(frame.end(), mk.begin(), mk.end());
        size_t hdr = frame.size();
        frame.resize(hdr + payload.size());
        for (size_t i = 0; i < payload.size(); i++) frame[hdr + i] = payload[i] ^ mk[i & 3];
    } else {
        if (len < 126) {
            frame.push_back(uint8_t(len));
        } else if (len <= 0xffff) {
            frame.push_back(126);
            frame.push_back(uint8_t((len >> 8) & 0xff));
            frame.push_back(uint8_t(len & 0xff));
        } else {
            frame.push_back(127);
            for (int i = 7; i >= 0; --i) frame.push_back(uint8_t((len >> (8 * i)) & 0xff));
        }
        frame.insert(frame.end(), payload.begin(), payload.end());
    }
    return c_->write_all(frame);
}

bool WsClient::handshake(TlsClient& c, const std::string& host, uint16_t port,
                         const std::string& path, const HeaderList& extra_headers) {
    c_ = &c;
    Bytes kb = random_bytes(16);
    std::string key = to_b64(kb);
    std::string req = "GET " + path + " HTTP/1.1\r\n";
    req += "Host: " + host + ":" + std::to_string(port) + "\r\n";
    req += "Upgrade: websocket\r\n";
    req += "Connection: Upgrade\r\n";
    req += "Sec-WebSocket-Key: " + key + "\r\n";
    req += "Sec-WebSocket-Version: 13\r\n";
    for (const auto& [k, v] : extra_headers) req += k + ": " + v + "\r\n";
    req += "\r\n";
    if (!c.write_all((const uint8_t*)req.data(), req.size())) {
        err_ = "handshake write failed";
        return false;
    }

    size_t he = std::string::npos;
    while (true) {
        std::string s((char*)pending_.data(), pending_.size());
        he = s.find("\r\n\r\n");
        if (he != std::string::npos) break;
        if (pending_.size() > 65536) {
            err_ = "handshake response too large";
            return false;
        }
        if (!fill(pending_.size() + 1)) return false;
    }
    std::string head((char*)pending_.data(), he);
    pending_.erase(pending_.begin(), pending_.begin() + he + 4);

    if (head.rfind("HTTP/1.1 101", 0) != 0 && head.rfind("HTTP/1.0 101", 0) != 0) {
        err_ = "upgrade failed: " + head.substr(0, head.find("\r\n"));
        return false;
    }
    std::string accept;
    for_each_header_line(head, [&](const std::string& line) {
        size_t colon = line.find(':');
        if (colon != std::string::npos &&
            lower(trim(line.substr(0, colon))) == "sec-websocket-accept") {
            accept = trim(line.substr(colon + 1));
        }
    });
    std::string src = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char md[20];
    unsigned int mdlen = 0;
    EVP_Digest(src.data(), src.size(), md, &mdlen, EVP_sha1(), nullptr);
    Bytes mdb(md, md + mdlen);
    std::string expected = to_b64(mdb);
    if (lower(accept) != lower(expected)) {
        err_ = "Sec-WebSocket-Accept mismatch";
        return false;
    }
    return true;
}

bool WsClient::send_binary(const Bytes& payload) { return send_frame(0x2, payload, true); }

std::optional<Bytes> WsClient::recv_message() {
    Bytes acc;
    bool started = false;
    for (;;) {
        if (!fill(2)) return std::nullopt;
        uint8_t b0 = pending_[0];
        uint8_t b1 = pending_[1];
        bool fin = (b0 & 0x80) != 0;
        uint8_t op = uint8_t(b0 & 0x0f);
        bool masked = (b1 & 0x80) != 0;
        uint64_t len = uint64_t(b1 & 0x7f);
        size_t hdr = 2;
        if (len == 126) {
            if (!fill(4)) return std::nullopt;
            len = (uint64_t(pending_[2]) << 8) | uint64_t(pending_[3]);
            hdr = 4;
        } else if (len == 127) {
            if (!fill(10)) return std::nullopt;
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | uint64_t(pending_[2 + i]);
            hdr = 10;
        }
        if (len > (64u << 20)) {
            err_ = "frame too large";
            return std::nullopt;
        }
        size_t need = hdr + (masked ? 4 : 0) + size_t(len);
        if (!fill(need)) return std::nullopt;
        const uint8_t* maskp = masked ? &pending_[hdr] : nullptr;
        const uint8_t* payload = &pending_[hdr + (masked ? 4 : 0)];
        Bytes chunk(payload, payload + size_t(len));
        if (masked) {
            for (size_t i = 0; i < chunk.size(); i++) chunk[i] ^= maskp[i & 3];
        }
        pending_.erase(pending_.begin(), pending_.begin() + need);

        if (op == 0x9) {
            if (!send_frame(0xA, chunk, true)) return std::nullopt;
            continue;
        }
        if (op == 0xA) continue;
        if (op == 0x8) {
            err_ = "closed by peer";
            return std::nullopt;
        }
        if (op == 0x1 || op == 0x2) {
            if (started) {
                err_ = "unexpected new data frame mid-message";
                return std::nullopt;
            }
            started = true;
            acc.insert(acc.end(), chunk.begin(), chunk.end());
        } else if (op == 0x0) {
            if (!started) {
                err_ = "continuation without start";
                return std::nullopt;
            }
            acc.insert(acc.end(), chunk.begin(), chunk.end());
        } else {
            err_ = "unknown opcode";
            return std::nullopt;
        }
        if (fin) return acc;
    }
}

}  // namespace snake::net
