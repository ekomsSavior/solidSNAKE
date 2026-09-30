#include "snake/httpd.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <sstream>

namespace snake::http {

namespace {

std::string lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return std::string();
    size_t b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}

void split_target(const std::string& target, std::string* raw_path, std::string* query) {
    size_t q = target.find('?');
    if (q == std::string::npos) {
        *raw_path = target;
        query->clear();
        return;
    }
    *raw_path = target.substr(0, q);
    *query = target.substr(q + 1);
}

std::string unescape_path(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            out.push_back(static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16)));
            i += 2;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

class PlainConn : public Conn {
  public:
    explicit PlainConn(int fd) : fd_(fd) {}
    ~PlainConn() override {
        if (fd_ >= 0) ::close(fd_);
    }
    bool write_all(const uint8_t* data, size_t len) override {
        size_t off = 0;
        while (off < len) {
            ssize_t n = ::send(fd_, data + off, len - off, MSG_NOSIGNAL);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                set_error("write failed");
                return false;
            }
            off += static_cast<size_t>(n);
        }
        return true;
    }
    long read_some(uint8_t* buf, size_t len) override {
        for (;;) {
            ssize_t n = ::recv(fd_, buf, len, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) {
                set_error("read failed");
                return -1;
            }
            return static_cast<long>(n);
        }
    }

  private:
    int fd_;
};

class TlsConn : public Conn {
  public:
    TlsConn(int fd, SSL* ssl) : ssl_(ssl) {
        fd_ = fd;
    }
    ~TlsConn() override {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        if (fd_ >= 0) ::close(fd_);
    }
    bool write_all(const uint8_t* data, size_t len) override {
        size_t off = 0;
        while (off < len) {
            int n = SSL_write(ssl_, data + off, static_cast<int>(len - off));
            if (n <= 0) {
                int e = SSL_get_error(ssl_, n);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
                set_error("tls write failed");
                return false;
            }
            off += static_cast<size_t>(n);
        }
        return true;
    }
    long read_some(uint8_t* buf, size_t len) override {
        for (;;) {
            int n = SSL_read(ssl_, buf, static_cast<int>(len));
            if (n > 0) return n;
            int e = SSL_get_error(ssl_, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
            if (e == SSL_ERROR_ZERO_RETURN) return 0;
            set_error("tls read failed");
            return -1;
        }
    }

  private:
    SSL* ssl_ = nullptr;
    int fd_ = -1;
};

}  // namespace

std::string Request::header(const std::string& name) const {
    std::string want = lower(name);
    for (const auto& h : headers) {
        if (lower(h.first) == want) return h.second;
    }
    return std::string();
}

void Response::set_header(const std::string& name, const std::string& value) {
    for (auto& h : headers) {
        if (lower(h.first) == lower(name)) {
            h.second = value;
            return;
        }
    }
    headers.emplace_back(name, value);
}

bool Conn::write_all(const std::string& s) {
    return write_all(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

bool Conn::read_exact(uint8_t* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (!pending_.empty()) {
            size_t take = std::min(len - off, pending_.size());
            std::memcpy(buf + off, pending_.data(), take);
            pending_.erase(pending_.begin(), pending_.begin() + static_cast<long>(take));
            off += take;
            continue;
        }
        long n = read_some(buf + off, len - off);
        if (n <= 0) {
            set_error(n == 0 ? "connection closed" : "read failed");
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

bool Conn::read_line(std::string* out, size_t max_len) {
    out->clear();
    for (;;) {
        size_t nl = pending_.size();
        bool found = false;
        for (size_t i = 0; i < pending_.size(); ++i) {
            if (pending_[i] == '\n') {
                nl = i;
                found = true;
                break;
            }
        }
        if (found) {
            std::string line(pending_.begin(), pending_.begin() + static_cast<long>(nl));
            pending_.erase(pending_.begin(), pending_.begin() + static_cast<long>(nl) + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            *out = line;
            return true;
        }
        if (pending_.size() > max_len) {
            set_error("header line too long");
            return false;
        }
        uint8_t buf[4096];
        long n = read_some(buf, sizeof(buf));
        if (n <= 0) {
            set_error(n == 0 ? "connection closed" : "read failed");
            return false;
        }
        pending_.insert(pending_.end(), buf, buf + n);
    }
}

const char* status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Request Entity Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 503: return "Service Unavailable";
        default: return "Status";
    }
}

std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&#34;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

Server::~Server() {
    stop();
    if (ssl_ctx_) SSL_CTX_free(static_cast<SSL_CTX*>(ssl_ctx_));
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
}

bool Server::listen(const std::string& addr, const std::string& cert_file,
                    const std::string& key_file, std::string* err) {
    std::string host = "";
    std::string port_str = addr;
    size_t colon = addr.rfind(':');
    if (colon != std::string::npos) {
        host = addr.substr(0, colon);
        port_str = addr.substr(colon + 1);
    }
    int port = 0;
    try {
        port = std::stoi(port_str);
    } catch (...) {
        if (err) *err = "invalid listen address: " + addr;
        return false;
    }
    if (port < 0 || port > 65535) {
        if (err) *err = "invalid listen address: " + addr;
        return false;
    }

    if (!cert_file.empty() && !key_file.empty()) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            if (err) *err = "SSL_CTX_new failed";
            return false;
        }
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_read_ahead(ctx, 1);
        if (SSL_CTX_use_certificate_chain_file(ctx, cert_file.c_str()) != 1) {
            if (err) *err = "load cert: " + cert_file;
            SSL_CTX_free(ctx);
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            if (err) *err = "load key: " + key_file;
            SSL_CTX_free(ctx);
            return false;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            if (err) *err = "cert/key mismatch";
            SSL_CTX_free(ctx);
            return false;
        }
        ssl_ctx_ = ctx;
    }

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        if (err) *err = "socket: " + std::string(std::strerror(errno));
        return false;
    }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(port));
    if (host.empty() || host == "0.0.0.0") {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
        if (err) *err = "invalid listen host: " + host;
        ::close(fd);
        return false;
    }

    if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
        if (err) *err = "bind " + addr + ": " + std::string(std::strerror(errno));
        ::close(fd);
        return false;
    }
    if (::listen(fd, 128) < 0) {
        if (err) *err = "listen: " + std::string(std::strerror(errno));
        ::close(fd);
        return false;
    }
    sockaddr_in bound{};
    socklen_t blen = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
        port_ = ntohs(bound.sin_port);
    } else {
        port_ = static_cast<uint16_t>(port);
    }
    listen_fd_ = fd;
    return true;
}

void Server::stop() {
    bool expected = false;
    if (!stop_.compare_exchange_strong(expected, true)) return;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
}

void Server::handle_conn(int fd) {
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    timeval tv{};
    tv.tv_sec = 30;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    Conn* conn = nullptr;
    SSL* ssl = nullptr;
    if (ssl_ctx_) {
        ssl = SSL_new(static_cast<SSL_CTX*>(ssl_ctx_));
        if (!ssl) {
            ::close(fd);
            return;
        }
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) != 1) {
            SSL_free(ssl);
            ::close(fd);
            return;
        }
        conn = new TlsConn(fd, ssl);
    } else {
        conn = new PlainConn(fd);
    }

    std::string line;
    if (!conn->read_line(&line, 8192) || line.empty()) {
        delete conn;
        return;
    }
    std::istringstream rl(line);
    Request req;
    std::string target;
    rl >> req.method >> target >> req.version;
    if (req.method.empty() || target.empty()) {
        delete conn;
        return;
    }
    split_target(target, &req.raw_path, &req.query);
    req.path = unescape_path(req.raw_path);

    bool bad = false;
    for (;;) {
        std::string hl;
        if (!conn->read_line(&hl, 8192)) {
            bad = true;
            break;
        }
        if (hl.empty()) break;
        size_t c = hl.find(':');
        if (c == std::string::npos) continue;
        req.headers.emplace_back(trim(hl.substr(0, c)), trim(hl.substr(c + 1)));
    }
    if (!bad) {
        long long clen = 0;
        std::string cls = req.header("Content-Length");
        if (!cls.empty()) {
            try {
                clen = std::stoll(cls);
            } catch (...) {
                clen = 0;
            }
        }
        if (clen > 0) {
            if (clen > 32 * 1024 * 1024) {
                bad = true;
            } else {
                req.body.resize(static_cast<size_t>(clen));
                if (!conn->read_exact(reinterpret_cast<uint8_t*>(&req.body[0]),
                                      static_cast<size_t>(clen))) {
                    bad = true;
                }
            }
        }
    }

    if (!bad) {
        dispatch(req, conn);
    }

    delete conn;
}

Response Server::dispatch(const Request& req, Conn* conn) {
    Response res;
    if (!handler_) {
        res.status = 500;
        res.body = "no handler\n";
        return res;
    }
    handler_(req, res, *conn);
    if (res.hijacked) return res;

    std::ostringstream head;
    head << "HTTP/1.1 " << res.status << " " << status_text(res.status) << "\r\n";
    bool have_len = false;
    for (const auto& h : res.headers) {
        if (lower(h.first) == "content-length") have_len = true;
        head << h.first << ": " << h.second << "\r\n";
    }
    if (!have_len) head << "Content-Length: " << res.body.size() << "\r\n";
    head << "Connection: close\r\n\r\n";
    std::string raw = head.str() + res.body;
    conn->write_all(raw);
    return res;
}

void Server::serve_forever() {
    while (!stop_.load()) {
        sockaddr_in cli{};
        socklen_t clen = sizeof(cli);
        int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&cli), &clen);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (stop_.load()) break;
            break;
        }
        std::thread t([this, fd]() { handle_conn(fd); });
        std::lock_guard<std::mutex> lk(workers_mu_);
        workers_.push_back(std::move(t));
    }
    std::lock_guard<std::mutex> lk(workers_mu_);
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
}

}  // namespace snake::http
