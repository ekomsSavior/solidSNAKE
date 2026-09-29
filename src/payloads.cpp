#include "snake/payloads.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>

#include <dirent.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "snake/net.hpp"
#include "snake/sys.hpp"

namespace snake::payloads {

namespace {

std::map<std::string, Payload*>& registry() {
    static std::map<std::string, Payload*> r;
    return r;
}

std::string go_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        unsigned char c = (unsigned char)in[i];
        if (c == '<') {
            out += "\\u003c";
        } else if (c == '>') {
            out += "\\u003e";
        } else if (c == '&') {
            out += "\\u0026";
        } else {
            out.push_back((char)c);
        }
    }
    return out;
}

std::string exit_error_text(const std::string& name, int code) {
    if (code == 0) return "";
    if (code == 127) {
        if (name.find('/') != std::string::npos)
            return "fork/exec " + name + ": no such file or directory";
        return "exec: \"" + name + "\": executable file not found in $PATH";
    }
    return "exit status " + std::to_string(code);
}

#ifndef _WIN32

CmdResult run_argv_impl(const std::vector<std::string>& argv, bool merge_stderr, int timeout_seconds) {
    CmdResult r;
    if (argv.empty()) return r;

    int fd[2];
    if (pipe(fd) != 0) return r;
    pid_t pid = fork();
    if (pid < 0) {
        ::close(fd[0]);
        ::close(fd[1]);
        return r;
    }
    if (pid == 0) {
        dup2(fd[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) dup2(devnull, STDIN_FILENO);
        if (merge_stderr) {
            dup2(fd[1], STDERR_FILENO);
        } else if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
        }
        ::close(fd[0]);
        ::close(fd[1]);
        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const auto& s : argv) cargv.push_back(const_cast<char*>(s.c_str()));
        cargv.push_back(nullptr);
        execvp(cargv[0], cargv.data());
        _exit(127);
    }
    ::close(fd[1]);
    fcntl(fd[0], F_SETFL, O_NONBLOCK);

    long long budget_ms = (timeout_seconds < 0) ? 60000LL : (long long)timeout_seconds * 1000LL;
    if (budget_ms < 0) budget_ms = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
    bool timed_out = false;
    char buf[4096];
    for (;;) {
        struct pollfd pfd = {fd[0], POLLIN, 0};
        auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(
                          deadline - std::chrono::steady_clock::now())
                          .count();
        int pr = poll(&pfd, 1, remain <= 0 ? 0 : (remain > 100 ? 100 : (int)remain));
        if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = read(fd[0], buf, sizeof(buf));
            if (n > 0) {
                r.out.append(buf, (size_t)n);
                continue;
            }
            if (n == 0) break;
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
        }
        if (std::chrono::steady_clock::now() > deadline) {
            timed_out = true;
            kill(pid, SIGKILL);
            break;
        }
    }
    ::close(fd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (timed_out) {
        r.exit_code = -1;
        r.ok = false;
        r.err = "signal: killed";
        return r;
    }
    if (WIFEXITED(st)) {
        r.exit_code = WEXITSTATUS(st);
        r.ok = (r.exit_code == 0);
        r.err = exit_error_text(argv[0], r.exit_code);
    } else {
        r.exit_code = -1;
        r.ok = false;
        r.err = "signal: killed";
    }
    return r;
}

CmdResult run_argv_impl_stdin(const std::vector<std::string>& argv, const std::string& input) {
    CmdResult r;
    if (argv.empty()) return r;

    int in_fd[2];
    if (pipe(in_fd) != 0) return r;
    pid_t pid = fork();
    if (pid < 0) {
        ::close(in_fd[0]);
        ::close(in_fd[1]);
        return r;
    }
    if (pid == 0) {
        dup2(in_fd[0], STDIN_FILENO);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }
        ::close(in_fd[0]);
        ::close(in_fd[1]);
        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const auto& s : argv) cargv.push_back(const_cast<char*>(s.c_str()));
        cargv.push_back(nullptr);
        execvp(cargv[0], cargv.data());
        _exit(127);
    }

    ::close(in_fd[0]);
    size_t off = 0;
    while (off < input.size()) {
        ssize_t n = ::write(in_fd[1], input.data() + off, input.size() - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    ::close(in_fd[1]);

    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
    if (WIFEXITED(st)) {
        r.exit_code = WEXITSTATUS(st);
        r.ok = (r.exit_code == 0);
        r.err = exit_error_text(argv[0], r.exit_code);
    } else {
        r.exit_code = -1;
        r.ok = false;
        r.err = "signal: killed";
    }
    return r;
}

#else  // _WIN32

bool win_pipe_done(HANDLE h) {
    DWORD avail = 0;
    if (PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) return false;
    return GetLastError() == ERROR_BROKEN_PIPE || GetLastError() == ERROR_HANDLE_EOF;
}

void win_drain_pipe(HANDLE h, std::string& into, bool& done) {
    if (done) return;
    DWORD avail = 0;
    if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) {
        if (GetLastError() == ERROR_BROKEN_PIPE || GetLastError() == ERROR_HANDLE_EOF) done = true;
        return;
    }
    while (avail > 0) {
        char buf[4096];
        DWORD want = avail > (DWORD)sizeof(buf) ? (DWORD)sizeof(buf) : avail;
        DWORD got = 0;
        if (!ReadFile(h, buf, want, &got, nullptr) || got == 0) break;
        into.append(buf, (size_t)got);
        if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) {
            if (GetLastError() == ERROR_BROKEN_PIPE || GetLastError() == ERROR_HANDLE_EOF) done = true;
            return;
        }
    }
    if (avail == 0 && win_pipe_done(h)) done = true;
}

HANDLE win_nul_handle() {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE h = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    return h == INVALID_HANDLE_VALUE ? nullptr : h;
}

CmdResult run_argv_impl(const std::vector<std::string>& argv, bool merge_stderr, int timeout_seconds) {
    CmdResult r;
    if (argv.empty()) return r;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE out_rd = nullptr, out_wr = nullptr;
    if (CreatePipe(&out_rd, &out_wr, &sa, 0) == 0) return r;
    SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = win_nul_handle();

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul != nullptr ? nul : GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = out_wr;
    si.hStdError = merge_stderr ? out_wr : (nul != nullptr ? nul : GetStdHandle(STD_ERROR_HANDLE));

    std::string cl =
        sys::command_line(argv[0], std::vector<std::string>(argv.begin() + 1, argv.end()));
    std::vector<char> cmd(cl.begin(), cl.end());
    cmd.push_back('\0');

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                             nullptr, &si, &pi);
    CloseHandle(out_wr);
    if (nul != nullptr) CloseHandle(nul);
    if (ok == 0) {
        CloseHandle(out_rd);
        r.exit_code = 127;
        r.ok = false;
        r.err = exit_error_text(argv[0], 127);
        return r;
    }
    CloseHandle(pi.hThread);

    long long budget_ms = (timeout_seconds < 0) ? 60000LL : (long long)timeout_seconds * 1000LL;
    if (budget_ms < 0) budget_ms = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
    bool done = false;
    bool timed_out = false;
    for (;;) {
        win_drain_pipe(out_rd, r.out, done);
        if (done) break;
        if (std::chrono::steady_clock::now() > deadline) {
            timed_out = true;
            TerminateProcess(pi.hProcess, 1);
            break;
        }
        Sleep(10);
    }
    if (timed_out) win_drain_pipe(out_rd, r.out, done);
    CloseHandle(out_rd);

    DWORD code = 0;
    if (timed_out) {
        r.exit_code = -1;
        r.ok = false;
        r.err = "signal: killed";
    } else if (GetExitCodeProcess(pi.hProcess, &code) != 0) {
        r.exit_code = (int)code;
        r.ok = (r.exit_code == 0);
        r.err = exit_error_text(argv[0], r.exit_code);
    }
    CloseHandle(pi.hProcess);
    return r;
}

CmdResult run_argv_impl_stdin(const std::vector<std::string>& argv, const std::string& input) {
    CmdResult r;
    if (argv.empty()) return r;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE in_rd = nullptr, in_wr = nullptr;
    if (CreatePipe(&in_rd, &in_wr, &sa, 0) == 0) return r;
    SetHandleInformation(in_wr, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = win_nul_handle();

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_rd;
    si.hStdOutput = nul != nullptr ? nul : GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = nul != nullptr ? nul : GetStdHandle(STD_ERROR_HANDLE);

    std::string cl =
        sys::command_line(argv[0], std::vector<std::string>(argv.begin() + 1, argv.end()));
    std::vector<char> cmd(cl.begin(), cl.end());
    cmd.push_back('\0');

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                             nullptr, &si, &pi);
    CloseHandle(in_rd);
    if (nul != nullptr) CloseHandle(nul);
    if (ok == 0) {
        CloseHandle(in_wr);
        r.exit_code = 127;
        r.ok = false;
        r.err = exit_error_text(argv[0], 127);
        return r;
    }
    CloseHandle(pi.hThread);

    size_t off = 0;
    while (off < input.size()) {
        DWORD wrote = 0;
        DWORD chunk = (DWORD)((input.size() - off) > 65536 ? 65536 : (input.size() - off));
        if (WriteFile(in_wr, input.data() + off, chunk, &wrote, nullptr) == 0 || wrote == 0) break;
        off += (size_t)wrote;
    }
    CloseHandle(in_wr);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    if (GetExitCodeProcess(pi.hProcess, &code) != 0) {
        r.exit_code = (int)code;
        r.ok = (r.exit_code == 0);
        r.err = exit_error_text(argv[0], r.exit_code);
    }
    CloseHandle(pi.hProcess);
    return r;
}

#endif  // _WIN32

}  // namespace

void Register(Payload* p) { registry()[p->name()] = p; }

Payload* Get(const std::string& name) {
    auto it = registry().find(name);
    return it == registry().end() ? nullptr : it->second;
}

std::vector<Payload*> List() {
    std::vector<Payload*> out;
    out.reserve(registry().size());
    for (const auto& kv : registry()) out.push_back(kv.second);
    return out;
}

std::vector<Info> InfoList() {
    std::vector<Info> out;
    for (Payload* p : List()) out.push_back(Info{p->name(), p->category(), p->description()});
    return out;
}

std::string ExecuteByName(const std::string& name, const Args& args) {
    Payload* p = Get(name);
    if (p == nullptr) throw PayloadError("unknown payload: " + name);
    Output out = p->execute(args);
    return std::string(out.begin(), out.end());
}

Args ExecuteTaskArgs(const nlohmann::json& payload) {
    Args args;
    if (!payload.is_object()) return args;
    for (auto it = payload.begin(); it != payload.end(); ++it) {
        if (it->is_string()) {
            args[it.key()] = it->get<std::string>();
        } else {
            args[it.key()] = it->dump();
        }
    }
    return args;
}

Args ExecuteTaskArgs(const std::map<std::string, std::string>& payload) {
    Args args;
    for (const auto& kv : payload) args[kv.first] = kv.second;
    return args;
}

std::string MarshalJSON(const nlohmann::json& v) { return go_escape(v.dump(2)); }

namespace {

struct ParsedUrl {
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 80;
};

bool parse_url(const std::string& url, ParsedUrl& u) {
    size_t sep = url.find("://");
    if (sep == std::string::npos) return false;
    u.scheme = url.substr(0, sep);
    std::string rest = url.substr(sep + 3);
    size_t slash = rest.find('/');
    std::string hp = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    u.path = (slash == std::string::npos) ? "/" : rest.substr(slash);
    size_t colon = hp.rfind(':');
    if (colon == std::string::npos) {
        u.host = hp;
        u.port = (u.scheme == "https") ? 443 : 80;
    } else {
        u.host = hp.substr(0, colon);
        u.port = (uint16_t)std::atoi(hp.substr(colon + 1).c_str());
    }
    return !u.host.empty();
}

HttpResponse http_plain(const std::string& method, const ParsedUrl& u, const Headers& headers) {
    HttpResponse r;
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    std::string port = std::to_string(u.port);
    if (getaddrinfo(u.host.c_str(), port.c_str(), &hints, &res) != 0 || res == nullptr) return r;

    int fd = -1;
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
#ifdef _WIN32
        DWORD tv = 2000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv{2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return r;

    std::string req = method + " " + u.path + " HTTP/1.1\r\nHost: " + u.host + "\r\n";
    for (const auto& h : headers) req += h.first + ": " + h.second + "\r\n";
    req += "Connection: close\r\nContent-Length: 0\r\n\r\n";
    if (send(fd, req.data(), req.size(), 0) < 0) {
        ::close(fd);
        return r;
    }

    std::string raw;
    char buf[4096];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) raw.append(buf, (size_t)n);
    ::close(fd);

    size_t hdr_end = raw.find("\r\n\r\n");
    if (hdr_end == std::string::npos) return r;
    std::string head = raw.substr(0, hdr_end);
    std::string body = raw.substr(hdr_end + 4);

    size_t sp = head.find(' ');
    if (sp != std::string::npos) r.status = std::atoi(head.substr(sp + 1, 3).c_str());

    std::string lower = head;
    for (char& c : lower) c = (char)::tolower((unsigned char)c);
    if (lower.find("transfer-encoding: chunked") != std::string::npos) {
        std::string dec;
        size_t pos = 0;
        while (pos < body.size()) {
            size_t nl = body.find("\r\n", pos);
            if (nl == std::string::npos) break;
            long len = std::strtol(body.substr(pos, nl - pos).c_str(), nullptr, 16);
            pos = nl + 2;
            if (len <= 0) break;
            dec.append(body, pos, (size_t)len);
            pos += (size_t)len + 2;
        }
        body = dec;
    }
    r.body = body;
    r.ok = true;
    return r;
}

}  // namespace

HttpResponse http_request(const std::string& method, const std::string& url, const Headers& headers) {
    ParsedUrl u;
    if (!parse_url(url, u)) return HttpResponse{};
    if (u.scheme == "https") {
        net::TlsOptions opts;
        net::TlsClient tls;
        if (!tls.connect(u.host, u.port, opts)) return HttpResponse{};
        net::HeaderList hl;
        for (const auto& h : headers) hl.emplace_back(h.first, h.second);
        auto resp = net::http_request(tls, method, u.host, u.port, u.path, hl, "");
        HttpResponse r;
        if (!resp) return r;
        r.status = resp->status;
        r.body = resp->body;
        r.ok = true;
        return r;
    }
    return http_plain(method, u, headers);
}

HttpResponse http_get(const std::string& url, const Headers& headers) {
    return http_request("GET", url, headers);
}

CmdResult run_cmd(const std::string& cmd) {
    return run_argv_impl({"/bin/sh", "-c", cmd}, true, -1);
}

CmdResult run_cmd_out(const std::vector<std::string>& argv) {
    return run_argv_impl(argv, false, -1);
}

CmdResult run_cmd_ctx(const std::vector<std::string>& argv, int timeout_seconds) {
    return run_argv_impl(argv, true, timeout_seconds);
}

CmdResult run_argv_combined(const std::vector<std::string>& argv) {
    return run_argv_impl(argv, true, -1);
}

CmdResult run_argv_stdin(const std::vector<std::string>& argv, const std::string& input) {
    return run_argv_impl_stdin(argv, input);
}

std::string which_exe(const std::string& name) {
#ifdef _WIN32
    const char* path = getenv("PATH");
    if (path == nullptr) return "";
    const char* pathext = getenv("PATHEXT");
    std::string exts = (pathext != nullptr && *pathext != '\0') ? pathext : ".COM;.EXE;.BAT;.CMD";
    bool has_ext = name.find('.') != std::string::npos;
    for (const auto& dir : split(path, ';')) {
        if (dir.empty()) continue;
        std::vector<std::string> cands;
        cands.push_back(dir + "\\" + name);
        if (!has_ext) {
            for (const auto& ext : split(exts, ';')) {
                if (!ext.empty()) cands.push_back(dir + "\\" + name + ext);
            }
        }
        for (const auto& full : cands) {
            struct stat st;
            if (stat(full.c_str(), &st) == 0 && !S_ISDIR(st.st_mode)) return full;
        }
    }
    return "";
#else
    const char* path = getenv("PATH");
    if (path == nullptr) return "";
    for (const auto& dir : split(path, ':')) {
        if (dir.empty()) continue;
        std::string full = dir + "/" + name;
        struct stat st;
        if (stat(full.c_str(), &st) == 0 && !S_ISDIR(st.st_mode) && access(full.c_str(), X_OK) == 0)
            return full;
    }
    return "";
#endif
}

std::string errno_text(int err) {
    if (err == 0) return "operation not permitted";
    std::string s = std::strerror(err);
    if (!s.empty() && s[0] >= 'A' && s[0] <= 'Z') s[0] = (char)(s[0] - 'A' + 'a');
    return s;
}

std::string prog_argv0() {
#ifndef _WIN32
    std::string raw;
    if (read_file("/proc/self/cmdline", raw) && !raw.empty()) {
        size_t end = raw.find('\0');
        return raw.substr(0, end == std::string::npos ? raw.size() : end);
    }
#endif
    return "";
}

std::string now_rfc3339() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    gmtime_r(&t, &tmv);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

std::string local_rfc3339() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&t, &tmv);
    char base[32];
    std::strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tmv);
#ifdef _WIN32
    long off = (long)difftime(mktime(&tmv), _mkgmtime(&tmv));
#else
    long off = tmv.tm_gmtoff;
#endif
    if (off == 0) return std::string(base) + "Z";
    char sign = off < 0 ? '-' : '+';
    if (off < 0) off = -off;
    long hours = off / 3600;
    long mins = (off % 3600) / 60;
    char zone[8];
    zone[0] = sign;
    zone[1] = (char)('0' + (hours / 10) % 10);
    zone[2] = (char)('0' + (hours % 10));
    zone[3] = ':';
    zone[4] = (char)('0' + (mins / 10) % 10);
    zone[5] = (char)('0' + (mins % 10));
    zone[6] = '\0';
    return std::string(base) + zone;
}

bool safe_mode() {
    const char* v = getenv("SNAKE_SAFE_MODE");
    return v != nullptr && *v != '\0' && std::string(v) != "0";
}

bool path_exists(const std::string& path, bool& is_dir) {
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return false;
    is_dir = S_ISDIR(st.st_mode);
    return true;
}

bool mut_mkdir_p(const std::string& path, unsigned mode) {
    if (safe_mode()) return false;
    if (path.empty()) return false;
    std::string cur;
    for (size_t i = 0; i <= path.size(); ++i) {
#ifdef _WIN32
        bool sep = i == path.size() || path[i] == '/' || path[i] == '\\';
#else
        bool sep = i == path.size() || path[i] == '/';
#endif
        if (sep) {
            cur = path.substr(0, i);
            if (cur.empty() || cur == "/") continue;
#ifdef _WIN32
            if (cur.back() == ':') continue;
#endif
            bool is_dir = false;
            if (path_exists(cur, is_dir)) {
                if (!is_dir) return false;
                continue;
            }
            if (::mkdir(cur.c_str(), (mode_t)mode) != 0 && errno != EEXIST) return false;
        }
    }
    return true;
}

bool mut_write(const std::string& path, const std::string& data, unsigned mode) {
    if (safe_mode()) return false;
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, (mode_t)mode);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        off += (size_t)n;
    }
    ::close(fd);
    return true;
}

bool mut_append(const std::string& path, const std::string& data, unsigned mode) {
    if (safe_mode()) return false;
    int fd = ::open(path.c_str(), O_WRONLY | O_APPEND, (mode_t)mode);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        off += (size_t)n;
    }
    ::close(fd);
    return true;
}

bool mut_chmod(const std::string& path, unsigned mode) {
    if (safe_mode()) return false;
    return ::chmod(path.c_str(), (mode_t)mode) == 0;
}

bool mut_chtimes(const std::string& path, std::time_t t) {
    if (safe_mode()) return false;
    struct utimbuf times{t, t};
    return ::utime(path.c_str(), &times) == 0;
}

bool mut_truncate(const std::string& path) {
    if (safe_mode()) return false;
    return ::truncate(path.c_str(), 0) == 0;
}

CmdResult mut_run_argv(const std::vector<std::string>& argv) {
    if (safe_mode()) return CmdResult{};
    return run_cmd_out(argv);
}

CmdResult mut_run_shell(const std::string& cmd) {
    if (safe_mode()) return CmdResult{};
    return run_cmd(cmd);
}

CmdResult mut_run_argv_stdin(const std::vector<std::string>& argv, const std::string& input) {
    if (safe_mode()) {
        CmdResult r;
        r.err = "exit status 1";
        return r;
    }
    return run_argv_impl_stdin(argv, input);
}

CmdResult mut_run_argv_combined(const std::vector<std::string>& argv) {
    if (safe_mode()) {
        CmdResult r;
        r.err = "exit status 1";
        return r;
    }
    return run_argv_combined(argv);
}

static bool remove_tree(const std::string& path) {
    struct stat st;
    if (::lstat(path.c_str(), &st) != 0) return false;
    if (!S_ISDIR(st.st_mode)) return ::remove(path.c_str()) == 0;
    DIR* d = opendir(path.c_str());
    if (d != nullptr) {
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            std::string n = e->d_name;
            if (n == "." || n == "..") continue;
            remove_tree(path + "/" + n);
        }
        closedir(d);
    }
    return ::rmdir(path.c_str()) == 0;
}

bool mut_remove_all(const std::string& path) {
    if (safe_mode()) return false;
    if (path.empty()) return false;
    remove_tree(path);
    return true;
}

bool mut_remove(const std::string& path) {
    if (safe_mode()) return false;
    return ::remove(path.c_str()) == 0;
}

bool mut_kill_process(int pid) {
    if (safe_mode()) return false;
    return kill_process(pid);
}

bool mut_ptrace_attach(int pid, int& err) {
    err = 0;
    if (safe_mode()) {
        err = EPERM;
        return false;
    }
#ifndef _WIN32
    if (::ptrace(PTRACE_ATTACH, (pid_t)pid, nullptr, nullptr) != 0) {
        err = errno;
        return false;
    }
    return true;
#else
    (void)pid;
    err = ENOSYS;
    return false;
#endif
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n\v\f");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n\v\f");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    for (;;) {
        size_t pos = s.find(sep, start);
        if (pos == std::string::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

bool read_file(const std::string& path, std::string& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) return false;
    char buf[8192];
    size_t n;
    out.clear();
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
    std::fclose(f);
    return true;
}

std::string hostname_now() {
    char h[256] = {0};
    if (gethostname(h, sizeof(h) - 1) != 0) return "";
    return h;
}

}  // namespace snake::payloads
