#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <cstdio>
#include <functional>
#include <set>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

void walk(const std::string& root, const std::function<void(const std::string&, bool)>& fn) {
    struct stat st;
    if (lstat(root.c_str(), &st) != 0) return;
    bool is_dir = S_ISDIR(st.st_mode);
    fn(root, is_dir);
    if (!is_dir) return;
    DIR* d = opendir(root.c_str());
    if (d == nullptr) return;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        std::string nm = e->d_name;
        if (nm == "." || nm == "..") continue;
        std::string child = root;
        if (child.empty() || child.back() != '/') child += '/';
        child += nm;
        walk(child, fn);
    }
    closedir(d);
}

std::string base_name(const std::string& p) {
    size_t pos = p.rfind('/');
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

OJ check_sudo_privs() {
    OJ items = OJ::array();
    CmdResult r = run_cmd("sudo -l");
    if (r.ok && r.out.find("may run") != std::string::npos) {
        OJ i;
        i["type"] = "SUDO_PRIVS";
        i["severity"] = "HIGH";
        i["description"] = "User has sudo privileges";
        i["details"] = r.out;
        items.push_back(i);
    }
    std::string data;
    if (read_file("/etc/sudoers", data)) {
        for (const auto& line : split(data, '\n')) {
            if (line.find("ALL=(ALL)") != std::string::npos && line.rfind("#", 0) != 0) {
                OJ i;
                i["type"] = "SUDOERS_ALL";
                i["severity"] = "HIGH";
                i["description"] = "User in sudoers with ALL privileges: " + line;
                items.push_back(i);
            }
        }
    }
    return items;
}

OJ find_suid() {
    OJ items = OJ::array();
    static const std::set<std::string> dangerous = {"nmap", "find", "awk",    "perl",
                                                    "python", "ruby", "bash", "sh"};
    const std::map<std::string, std::string> exploits = {
        {"nmap", "--interactive mode escape"}, {"find", "-exec command execution"},
        {"awk", "system() function"},          {"perl", "-e command execution"},
        {"python", "-c command execution"},    {"ruby", "-e command execution"},
        {"bash", "-p privilege mode"},         {"sh", "-p privilege mode"},
    };
    walk("/", [&](const std::string& path, bool is_dir) {
        if (items.size() >= 30) return;
        if (is_dir) return;
        struct stat st;
        if (lstat(path.c_str(), &st) != 0) return;
        if ((st.st_mode & S_ISUID) == 0) return;
        if (!S_ISREG(st.st_mode)) return;
        std::string base = base_name(path);
        bool is_dangerous = dangerous.count(base) > 0;
        OJ i;
        i["binary"] = path;
        i["dangerous"] = is_dangerous;
        i["writable"] = (st.st_mode & 0002) != 0;
        if (is_dangerous) {
            auto it = exploits.find(base);
            i["exploits"] = OJ::array({it->second});
        }
        i["owner"] = file_owner(path);
        items.push_back(i);
    });
    return items;
}

OJ check_writable() {
    OJ items = OJ::array();
    const char* sensitive[] = {"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab",
                               "/etc/init.d"};
    for (const char* p : sensitive) {
        struct stat st;
        if (stat(p, &st) != 0) continue;
        if ((st.st_mode & 0002) != 0) {
            OJ i;
            i["path"] = p;
            i["type"] = "sensitive_file";
            i["severity"] = "CRITICAL";
            items.push_back(i);
        }
    }
    return items;
}

OJ check_cron() {
    OJ items = OJ::array();
    std::string data;
    if (read_file("/etc/crontab", data)) {
        for (const auto& raw : split(data, '\n')) {
            std::string line = trim(raw);
            if (line.empty() || line[0] == '#') continue;
            std::vector<std::string> f;
            for (auto& p : split(line, ' '))
                if (!p.empty()) f.push_back(p);
            if (f.size() >= 6) {
                std::string script = f.back();
                struct stat st;
                if (stat(script.c_str(), &st) == 0 && (st.st_mode & 0002) != 0) {
                    OJ i;
                    i["type"] = "WRITABLE_CRON_SCRIPT";
                    i["severity"] = "CRITICAL";
                    i["description"] = "Writable cron script: " + script;
                    i["details"] = line;
                    items.push_back(i);
                }
            }
        }
    }
    return items;
}

OJ check_kernel_exploits() {
    OJ items = OJ::array();
    std::string kernel = "linux/amd64";
#if !defined(__x86_64__)
    kernel = "linux/other";
#endif
    const std::vector<std::pair<std::string, std::string>> known = {
        {"DirtyCow", "CVE-2016-5195"},
        {"PwnKit", "CVE-2021-4034"},
        {"DirtyPipe", "CVE-2022-0847"},
        {"CopyFail", "CVE-2026-31431"},
    };
    for (const auto& k : known) {
        OJ i;
        i["type"] = "KERNEL_EXPLOIT";
        i["severity"] = "MEDIUM";
        i["description"] = k.first + " (" + k.second + ") - kernel: " + kernel;
        items.push_back(i);
    }
    return items;
}

OJ check_capabilities() {
    OJ items = OJ::array();
    const char* dangerous_caps[] = {"cap_setuid", "cap_setgid", "cap_sys_admin",
                                    "cap_sys_ptrace"};
    CmdResult r = run_cmd("getcap -r /");
    if (!r.ok) return items;
    for (const auto& raw : split(r.out, '\n')) {
        std::string line = trim(raw);
        if (line.empty()) continue;
        std::vector<std::string> f;
        for (auto& p : split(line, ' '))
            if (!p.empty()) f.push_back(p);
        if (f.size() < 2) continue;
        std::string fpath = f[0];
        while (!fpath.empty() && fpath.back() == ':') fpath.pop_back();
        std::string caps = f[1];
        for (size_t i = 2; i < f.size(); ++i) caps += " " + f[i];
        bool dangerous = false;
        for (const char* dc : dangerous_caps) {
            if (caps.find(dc) != std::string::npos) {
                dangerous = true;
                break;
            }
        }
        OJ i;
        i["file"] = fpath;
        i["capabilities"] = caps;
        i["dangerous"] = dangerous;
        i["severity"] = dangerous ? "HIGH" : "LOW";
        items.push_back(i);
        if (items.size() >= 20) break;
    }
    return items;
}

class LinPEAS : public Payload {
  public:
    const char* name() const override { return "linpeas_light"; }
    const char* category() const override { return "recon"; }
    const char* description() const override {
        return "Lightweight Linux PEAS scanner (sudo perms, SUID, cron, capabilities, kernel exploits)";
    }

    Output execute(const Args&) const override {
        OJ sudo_checks = check_sudo_privs();
        OJ suid = find_suid();
        OJ writable = check_writable();
        OJ cron = check_cron();
        OJ kernel = check_kernel_exploits();
        OJ caps = check_capabilities();

        int critical = 0, dangerous_suid = 0;
        for (const auto& w : writable)
            if (w.value("severity", "") == "CRITICAL") critical++;
        for (const auto& s : suid)
            if (s.value("dangerous", false)) dangerous_suid++;

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();
        r["hostname"] = hostname_now();
        r["sudo_checks"] = sudo_checks;
        r["suid_binaries"] = suid;
        r["writable_files"] = writable;
        r["cron_vulns"] = cron;
        r["kernel_exploits"] = kernel;
        r["capabilities"] = caps;
        OJ summary = OJ::object();
        summary["critical"] = critical;
        summary["high"] = dangerous_suid + (int)cron.size();
        summary["medium"] = (int)kernel.size();
        r["summary"] = summary;

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

LinPEAS g_linpeas;

struct Reg { Reg() { Register(&g_linpeas); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
