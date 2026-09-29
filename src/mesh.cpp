#include "snake/mesh.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>

namespace snake::mesh {

namespace {

std::string openssl_err() {
    unsigned long e = ERR_get_error();
    if (e == 0) return std::string();
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

void logf(const std::string& msg) {
    std::time_t now = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&now, &tmv);
    char stamp[32];
    std::strftime(stamp, sizeof(stamp), "%Y/%m/%d %H:%M:%S", &tmv);
    std::fprintf(stderr, "%s [mesh] %s\n", stamp, msg.c_str());
}

std::string truncate8(const std::string& s) { return s.size() > 8 ? s.substr(0, 8) : s; }

int accept_any_cert(int, X509_STORE_CTX*) { return 1; }

std::string remote_addr_string(int fd) {
    sockaddr_storage ss{};
    socklen_t slen = sizeof(ss);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&ss), &slen) != 0) return "";
    char host[NI_MAXHOST] = {0};
    char serv[NI_MAXSERV] = {0};
    if (::getnameinfo(reinterpret_cast<sockaddr*>(&ss), slen, host, sizeof(host), serv,
                      sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return "";
    }
    if (ss.ss_family == AF_INET6) return "[" + std::string(host) + "]:" + serv;
    return std::string(host) + ":" + serv;
}

std::string cert_common_name(X509* cert) {
    X509_NAME* name = X509_get_subject_name(cert);
    if (!name) return "";
    char buf[512];
    int n = X509_NAME_get_text_by_NID(name, NID_commonName, buf, sizeof(buf));
    if (n <= 0) return "";
    return std::string(buf, static_cast<size_t>(n));
}

std::string cert_serial_hex(X509* cert) {
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (!serial) return "";
    const unsigned char* d = ASN1_STRING_get0_data(serial);
    int len = ASN1_STRING_length(serial);
    if (!d || len <= 0) return "";
    int off = 0;
    while (off < len && d[off] == 0) ++off;
    std::string out;
    static const char* hexd = "0123456789abcdef";
    for (int i = off; i < len; ++i) {
        out.push_back(hexd[(d[i] >> 4) & 0xF]);
        out.push_back(hexd[d[i] & 0xF]);
    }
    return out;
}

Bytes cert_ed25519_key(X509* cert) {
    Bytes out;
    EVP_PKEY* pk = X509_get_pubkey(cert);
    if (!pk) return out;
    if (EVP_PKEY_id(pk) == EVP_PKEY_ED25519) {
        unsigned char raw[32];
        size_t len = sizeof(raw);
        if (EVP_PKEY_get_raw_public_key(pk, raw, &len) == 1 && len == sizeof(raw)) {
            out.assign(raw, raw + sizeof(raw));
        }
    }
    EVP_PKEY_free(pk);
    return out;
}

SSL_CTX* make_ctx(const cert::KeyMaterial& km, std::string* err) {
    ERR_clear_error();
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        *err = "SSL_CTX_new: " + openssl_err();
        return nullptr;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    const unsigned char* p = km.cert_der.data();
    X509* x = d2i_X509(nullptr, &p, static_cast<long>(km.cert_der.size()));
    if (!x) {
        *err = "parse cert: " + openssl_err();
        SSL_CTX_free(ctx);
        return nullptr;
    }
    p = km.key_pkcs8_der.data();
    PKCS8_PRIV_KEY_INFO* p8 =
        d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(km.key_pkcs8_der.size()));
    EVP_PKEY* key = p8 ? EVP_PKCS82PKEY(p8) : nullptr;
    if (p8) PKCS8_PRIV_KEY_INFO_free(p8);
    if (!key) {
        *err = "parse key: " + openssl_err();
        X509_free(x);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_use_certificate(ctx, x) != 1 || SSL_CTX_use_PrivateKey(ctx, key) != 1) {
        *err = "load cert/key: " + openssl_err();
        X509_free(x);
        EVP_PKEY_free(key);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    X509_free(x);
    EVP_PKEY_free(key);
    return ctx;
}

bool is_ip_literal(const std::string& s) {
    unsigned char buf[16];
    if (::inet_pton(AF_INET, s.c_str(), buf) == 1) return true;
    return ::inet_pton(AF_INET6, s.c_str(), buf) == 1;
}

bool split_host_port(const std::string& addr, std::string* host, uint16_t* port, std::string* err) {
    size_t colon = addr.rfind(':');
    if (colon == std::string::npos) {
        *err = "invalid mesh listen address: " + addr;
        return false;
    }
    *host = addr.substr(0, colon);
    if ((*host).size() >= 2 && (*host).front() == '[' && (*host).back() == ']') {
        *host = host->substr(1, host->size() - 2);
    }
    long p = 0;
    try {
        p = std::stol(addr.substr(colon + 1));
    } catch (...) {
        *err = "invalid mesh listen address: " + addr;
        return false;
    }
    if (p < 0 || p > 65535) {
        *err = "invalid mesh listen address: " + addr;
        return false;
    }
    *port = static_cast<uint16_t>(p);
    return true;
}

}  // namespace

struct Node::Conn {
    SSL* ssl = nullptr;
    int fd = -1;
    bool is_server = false;
    std::mutex write_mu;

    ~Conn() { close(); }

    void shutdown_socket() {
        if (fd >= 0) ::shutdown(fd, SHUT_RDWR);
    }

    void close() {
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }

    bool write_all(const std::string& s) {
        std::lock_guard<std::mutex> lk(write_mu);
        size_t off = 0;
        while (off < s.size()) {
            int n = SSL_write(ssl, s.data() + off, static_cast<int>(s.size() - off));
            if (n <= 0) return false;
            off += static_cast<size_t>(n);
        }
        return true;
    }

    long read_some(uint8_t* buf, size_t len) {
        int n = SSL_read(ssl, buf, static_cast<int>(len));
        if (n > 0) return n;
        int e = SSL_get_error(ssl, n);
        if (e == SSL_ERROR_ZERO_RETURN) return 0;
        return -1;
    }
};

std::string heartbeat_payload(const gob::Heartbeat& hb) {
    return hb.node_id + "|" + hb.addr + "|" + std::to_string(hb.timestamp);
}

Bytes sign_heartbeat(const Bytes& seed, const gob::Heartbeat& hb) {
    if (seed.empty()) return Bytes();
    const std::string payload = heartbeat_payload(hb);
    return ed25519_sign(seed, Bytes(payload.begin(), payload.end()));
}

bool verify_heartbeat(const Bytes& pub, const gob::Heartbeat& hb) {
    if (pub.empty()) return false;
    const std::string payload = heartbeat_payload(hb);
    return ed25519_verify_sig(pub, Bytes(payload.begin(), payload.end()), hb.signature);
}

bool generate_mesh_cert(const std::string& node_id, cert::KeyMaterial* out, std::string* err) {
    cert::CertSpec spec;
    spec.common_name = node_id;
    spec.organization = "Ranger Mesh";
    spec.digital_signature = true;
    spec.key_encipherment = false;
    spec.server_auth = true;
    spec.client_auth = true;
    spec.basic_constraints_valid = true;
    spec.not_before_offset_secs = -3600;
    spec.not_after_offset_secs = 365LL * 24 * 3600;
    return cert::create_self_signed(spec, out, err);
}

struct Node::Peer {
    std::string id;
    std::shared_ptr<Conn> conn;
    gob::Encoder enc;
    gob::Decoder dec;
    std::vector<gob::Heartbeat> pending;
    Bytes peer_key;
    bool has_key = false;
    std::chrono::steady_clock::time_point last_seen;

    bool next_message(gob::Heartbeat* out) {
        for (;;) {
            if (!pending.empty()) {
                *out = pending.front();
                pending.erase(pending.begin());
                return true;
            }
            std::string err;
            if (!dec.feed(nullptr, 0, &pending, &err)) return false;
            if (!pending.empty()) continue;
            uint8_t buf[4096];
            long n = conn->read_some(buf, sizeof(buf));
            if (n <= 0) return false;
            if (!dec.feed(buf, static_cast<size_t>(n), &pending, &err)) return false;
        }
    }
};

Node::Node(Config cfg) : cfg_(std::move(cfg)) {}

Node::~Node() { stop(); }

bool Node::start(std::string* err) {
    ::signal(SIGPIPE, SIG_IGN);
    if (cfg_.tls.cert_der.empty() || cfg_.tls.key_pkcs8_der.empty()) {
        if (err) *err = "mesh: no TLS certificate configured";
        return false;
    }
    std::string e;
    SSL_CTX* ctx = make_ctx(cfg_.tls, &e);
    if (!ctx) {
        if (err) *err = e;
        return false;
    }
    ssl_ctx_ = ctx;

    std::string host;
    uint16_t port = 0;
    if (!split_host_port(cfg_.listen_addr, &host, &port, &e)) {
        if (err) *err = e;
        return false;
    }

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        if (err) *err = std::string("socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (host.empty() || host == "0.0.0.0") {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
        if (err) *err = "invalid mesh listen host: " + host;
        ::close(fd);
        return false;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
        if (err) *err = "mesh listen: bind " + cfg_.listen_addr + ": " + std::strerror(errno);
        ::close(fd);
        return false;
    }
    if (::listen(fd, 128) < 0) {
        if (err) *err = "mesh listen: listen: " + std::string(std::strerror(errno));
        ::close(fd);
        return false;
    }
    sockaddr_in bound{};
    socklen_t blen = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
        port_ = ntohs(bound.sin_port);
    } else {
        port_ = port;
    }
    listen_fd_ = fd;

    accept_thread_ = std::thread([this] { accept_loop(); });
    for (const std::string& addr : cfg_.bootstrap) {
        dial_threads_.emplace_back([this, addr] { dial_peer(addr); });
    }
    heartbeat_thread_ = std::thread([this] { heartbeat_loop(); });

    logf("node " + truncate8(cfg_.node_id) + " listening on " + cfg_.listen_addr + " with " +
         std::to_string(cfg_.bootstrap.size()) + " bootstrap peers");
    return true;
}

void Node::stop() {
    bool expected = false;
    if (!stop_.compare_exchange_strong(expected, true)) return;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    std::vector<std::shared_ptr<Conn>> conns;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& kv : peers_) conns.push_back(kv.second->conn);
    }
    for (auto& c : conns) c->shutdown_socket();

    if (accept_thread_.joinable()) accept_thread_.join();
    for (auto& t : dial_threads_) {
        if (t.joinable()) t.join();
    }
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
    if (ssl_ctx_) {
        SSL_CTX_free(static_cast<SSL_CTX*>(ssl_ctx_));
        ssl_ctx_ = nullptr;
    }
    std::lock_guard<std::mutex> lk(mu_);
    peers_.clear();
}

std::vector<std::string> Node::peers() {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::string> out;
    for (const auto& kv : peers_) out.push_back(kv.first);
    return out;
}

size_t Node::peer_count() {
    std::lock_guard<std::mutex> lk(mu_);
    return peers_.size();
}

void Node::accept_loop() {
    for (;;) {
        int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0) {
            if (stop_) return;
            logf("accept error: " + std::string(std::strerror(errno)));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        auto conn = std::make_shared<Conn>();
        conn->fd = fd;
        conn->is_server = true;
        SSL* ssl = SSL_new(static_cast<SSL_CTX*>(ssl_ctx_));
        if (!ssl) {
            conn->close();
            continue;
        }
        SSL_set_fd(ssl, fd);
        SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, accept_any_cert);
        conn->ssl = ssl;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (stop_) {
                conn->close();
                return;
            }
            workers_.emplace_back([this, conn] { handle_peer(conn); });
        }
    }
}

void Node::dial_peer(const std::string& addr) {
    std::string host = addr;
    std::string port_str = "0";
    size_t colon = addr.rfind(':');
    if (colon != std::string::npos) {
        host = addr.substr(0, colon);
        port_str = addr.substr(colon + 1);
    }
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || res == nullptr) {
        logf("dial " + addr + ": lookup " + host + ": no such host");
        return;
    }
    int fd = -1;
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    if (fd < 0) {
        logf("dial " + addr + ": " + std::string(std::strerror(errno)));
        return;
    }

    auto conn = std::make_shared<Conn>();
    conn->fd = fd;
    conn->is_server = false;
    SSL* ssl = SSL_new(static_cast<SSL_CTX*>(ssl_ctx_));
    if (!ssl) {
        conn->close();
        return;
    }
    SSL_set_fd(ssl, fd);
    if (!host.empty() && !is_ip_literal(host)) {
        SSL_set_tlsext_host_name(ssl, host.c_str());
    }
    conn->ssl = ssl;
    if (SSL_connect(ssl) != 1) {
        std::string e = openssl_err();
        logf("dial " + addr + ": tls handshake failed" + (e.empty() ? "" : (": " + e)));
        conn->close();
        return;
    }
    handle_peer(conn);
}

void Node::handle_peer(std::shared_ptr<Conn> conn) {
    SSL* ssl = conn->ssl;
    int one = 1;
    ::setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    timeval tv{};
    tv.tv_sec = 60;
    ::setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(conn->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (conn->is_server && SSL_accept(ssl) != 1) return;

    std::string peer_id = cfg_.node_id;
    Bytes peer_key;
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (cert) {
        std::string cn = cert_common_name(cert);
        if (!cn.empty()) {
            peer_id = cn;
        } else {
            peer_id = cert_serial_hex(cert);
        }
        peer_key = cert_ed25519_key(cert);
        X509_free(cert);
    }
    const std::string peer_addr = remote_addr_string(conn->fd);

    auto peer = std::make_shared<Peer>();
    peer->id = peer_id;
    peer->conn = conn;
    peer->peer_key = peer_key;
    peer->has_key = !peer_key.empty();

    gob::Heartbeat hb;
    hb.node_id = cfg_.node_id;
    hb.addr = cfg_.listen_addr;
    hb.timestamp = static_cast<int64_t>(std::time(nullptr));
    if (cfg_.signing) {
        hb.signature = sign_heartbeat(cfg_.signing_seed, hb);
    }
    if (!conn->write_all(peer->enc.encode(hb))) return;

    gob::Heartbeat peer_hb;
    if (!peer->next_message(&peer_hb)) return;
    if (!peer_hb.node_id.empty()) peer->id = peer_hb.node_id;

    const std::string final_id = peer->id;
    peer->last_seen = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (stop_) return;
        peers_[final_id] = peer;
    }

    if (cfg_.on_peer_join) {
        PeerInfo info;
        info.id = final_id;
        info.addr = peer_addr;
        info.implants = static_cast<int>(peer_hb.implants.size());
        info.version = "3.0";
        cfg_.on_peer_join(info);
    }

    gob::Heartbeat msg;
    while (peer->next_message(&msg)) {
        if (peer->has_key && !msg.signature.empty() && !verify_heartbeat(peer->peer_key, msg)) {
            logf("dropping heartbeat with bad signature from " + truncate8(final_id));
            continue;
        }
        peer->last_seen = std::chrono::steady_clock::now();
        if (cfg_.on_heartbeat) cfg_.on_heartbeat(msg);
    }

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = peers_.find(final_id);
        if (it != peers_.end() && it->second == peer) peers_.erase(it);
    }
    if (cfg_.on_peer_leave) cfg_.on_peer_leave(final_id);
}

size_t Node::broadcast_heartbeat() {
    gob::Heartbeat hb;
    hb.node_id = cfg_.node_id;
    hb.addr = cfg_.listen_addr;
    hb.timestamp = static_cast<int64_t>(std::time(nullptr));
    if (cfg_.signing) hb.signature = sign_heartbeat(cfg_.signing_seed, hb);

    std::vector<std::pair<std::string, std::shared_ptr<Peer>>> snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& kv : peers_) snapshot.push_back(kv);
    }
    size_t sent = 0;
    for (auto& kv : snapshot) {
        if (kv.second->conn->write_all(kv.second->enc.encode(hb))) {
            ++sent;
        } else {
            logf("send to " + truncate8(kv.first) + ": write failed");
        }
    }
    return sent;
}

void Node::heartbeat_loop() {
    const auto interval = std::chrono::milliseconds(cfg_.heartbeat_interval_ms > 0
                                                        ? cfg_.heartbeat_interval_ms
                                                        : 30000);
    auto next = std::chrono::steady_clock::now() + interval;
    for (;;) {
        while (!stop_ && std::chrono::steady_clock::now() < next) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (stop_) return;
        broadcast_heartbeat();
        next += interval;
    }
}

}
