#include "snake/sys.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#if !defined(_WIN32)

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <dirent.h>
#include <fcntl.h>
#include <time.h>

namespace snake::sys {

bool net_init() { return true; }

void net_shutdown() {}

void close_socket(rr_socket_t s) {
    if (s >= 0) ::close((int)s);
}

bool set_socket_timeout(rr_socket_t s, int seconds) {
    if (seconds <= 0) return true;
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    bool ok = ::setsockopt((int)s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
    ok = ::setsockopt((int)s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0 && ok;
    return ok;
}

int wait_readable(rr_socket_t s, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = (int)s;
    pfd.events = POLLIN;
    pfd.revents = 0;
    return ::poll(&pfd, 1, timeout_ms);
}

std::string socket_error_text(int err) {
    if (err == 0) return "socket(0)";
    return "socket(" + std::to_string(err) + "): " + std::strerror(err);
}

int socket_last_error() { return errno; }

void sleep_ms(long long ms) {
    if (ms <= 0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000);
    ts.tv_nsec = (long)((ms % 1000) * 1000000);
    while (::nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

std::string make_temp_dir(const std::string& prefix) {
    const char* tmp = std::getenv("TMPDIR");
    std::string base = (tmp && *tmp) ? tmp : "/tmp";
    while (!base.empty() && base.back() == '/') base.pop_back();
    std::string tmpl = base + "/" + prefix + "XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (::mkdtemp(buf.data()) == nullptr) return "";
    return std::string(buf.data());
}

bool write_file_exec(const std::string& path, const std::string& data) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) break;
        off += (size_t)n;
    }
    ::close(fd);
    if (off != data.size()) return false;
    return ::chmod(path.c_str(), 0755) == 0;
}

bool remove_file(const std::string& path) { return ::unlink(path.c_str()) == 0; }

bool remove_dir(const std::string& path) { return ::rmdir(path.c_str()) == 0; }

bool remove_tree(const std::string& path) {
    struct stat st;
    if (::lstat(path.c_str(), &st) != 0) return errno == ENOENT;
    if (!S_ISDIR(st.st_mode)) return ::unlink(path.c_str()) == 0;
    DIR* d = ::opendir(path.c_str());
    if (d == nullptr) return false;
    bool ok = true;
    for (struct dirent* e = ::readdir(d); e != nullptr; e = ::readdir(d)) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        if (!remove_tree(path + "/" + name)) ok = false;
    }
    ::closedir(d);
    if (!ok) return false;
    return ::rmdir(path.c_str()) == 0;
}

std::string exe_path() {
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf);
}

Spawned spawn_detached(const std::string& exe, const std::vector<std::string>& args) {
    Spawned out;
    std::vector<char*> cargv;
    cargv.push_back(const_cast<char*>(exe.c_str()));
    for (const auto& a : args) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);

    int pfd[2];
    if (::pipe(pfd) != 0) {
        out.error = "pipe: " + std::string(std::strerror(errno));
        return out;
    }
    ::fcntl(pfd[1], F_SETFD, FD_CLOEXEC);

    pid_t pid = ::fork();
    if (pid < 0) {
        out.error = "fork: " + std::string(std::strerror(errno));
        ::close(pfd[0]);
        ::close(pfd[1]);
        return out;
    }
    if (pid == 0) {
        ::close(pfd[0]);
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
            if (devnull > 2) ::close(devnull);
        }
        ::execv(exe.c_str(), cargv.data());
        int e = errno;
        ssize_t w = ::write(pfd[1], &e, sizeof(e));
        (void)w;
        ::_exit(127);
    }

    ::close(pfd[1]);
    int child_errno = 0;
    ssize_t got = ::read(pfd[0], &child_errno, sizeof(child_errno));
    ::close(pfd[0]);
    if (got > 0) {
        out.error = "exec: " + std::string(std::strerror(child_errno));
        return out;
    }
    out.started = true;
    out.pid = (long long)pid;
    return out;
}

}  // namespace snake::sys

#else  // _WIN32

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <mutex>

namespace snake::sys {

namespace {

std::mutex& init_mutex() {
    static std::mutex m;
    return m;
}

int& ref_count() {
    static int n = 0;
    return n;
}

}  // namespace

bool net_init() {
    std::lock_guard<std::mutex> lock(init_mutex());
    if (ref_count() > 0) return true;
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) return false;
    ref_count() = 1;
    return true;
}

void net_shutdown() {
    std::lock_guard<std::mutex> lock(init_mutex());
    if (ref_count() == 0) return;
    ref_count() = 0;
    WSACleanup();
}

void close_socket(rr_socket_t s) {
    if (s != kInvalidSocket) closesocket((SOCKET)s);
}

bool set_socket_timeout(rr_socket_t s, int seconds) {
    if (seconds <= 0) return true;
    DWORD ms = (DWORD)seconds * 1000u;
    bool ok = setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ms, sizeof(ms)) == 0;
    ok = setsockopt((SOCKET)s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&ms, sizeof(ms)) == 0 && ok;
    return ok;
}

int wait_readable(rr_socket_t s, int timeout_ms) {
    WSAPOLLFD pfd;
    pfd.fd = (SOCKET)s;
    pfd.events = POLLRDNORM;
    pfd.revents = 0;
    return WSAPoll(&pfd, 1, timeout_ms);
}

const char* wsa_text(int err) {
    switch (err) {
        case WSAEACCES: return "permission denied";
        case WSAEADDRINUSE: return "address already in use";
        case WSAEADDRNOTAVAIL: return "address not available";
        case WSAECONNABORTED: return "software caused connection abort";
        case WSAECONNREFUSED: return "connection refused";
        case WSAECONNRESET: return "connection reset by peer";
        case WSAEHOSTUNREACH: return "no route to host";
        case WSAEINVAL: return "invalid argument";
        case WSAENETUNREACH: return "network is unreachable";
        case WSAETIMEDOUT: return "connection timed out";
        case WSANOTINITIALISED: return "winsock not initialised";
        case WSAEWOULDBLOCK: return "resource temporarily unavailable";
        default: return "unknown error";
    }
}

std::string socket_error_text(int err) {
    if (err == 0) return "socket(0)";
    return "socket(" + std::to_string(err) + "): " + wsa_text(err);
}

int socket_last_error() { return (int)WSAGetLastError(); }

void sleep_ms(long long ms) {
    if (ms <= 0) return;
    Sleep((DWORD)ms);
}

namespace {

std::string escape_arg(const std::string& s) {
    if (s.empty()) return "\"\"";
    bool special = false;
    for (char c : s) {
        if (c == '"' || c == '\\' || c == ' ' || c == '\t') special = true;
    }
    if (!special) return s;
    std::string b = "\"";
    size_t slashes = 0;
    for (char c : s) {
        if (c == '\\') {
            slashes++;
        } else if (c == '"') {
            b.append(slashes, '\\');
            slashes = 0;
            b.push_back('\\');
        } else {
            slashes = 0;
        }
        b.push_back(c);
    }
    b.append(slashes, '\\');
    b.push_back('"');
    return b;
}

std::string command_line_impl(const std::string& exe, const std::vector<std::string>& args) {
    std::string line = escape_arg(exe);
    for (const auto& a : args) {
        line.push_back(' ');
        line += escape_arg(a);
    }
    return line;
}

std::string last_error_text(DWORD err) {
    char* buf = nullptr;
    DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, err, 0, (LPSTR)&buf, 0, nullptr);
    std::string text;
    if (n != 0 && buf != nullptr) {
        text.assign(buf, n);
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
            text.pop_back();
        }
        LocalFree(buf);
    } else {
        text = "error " + std::to_string((unsigned long)err);
    }
    return text;
}

}  // namespace

std::string command_line(const std::string& exe, const std::vector<std::string>& args) {
    return command_line_impl(exe, args);
}

std::string make_temp_dir(const std::string& prefix) {
    char tmp[MAX_PATH + 1];
    DWORD n = GetTempPathA(sizeof(tmp), tmp);
    if (n == 0 || n >= sizeof(tmp)) return "";
    static unsigned long counter = 0;
    for (int attempt = 0; attempt < 100; ++attempt) {
        char name[64];
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        unsigned long long salt = (unsigned long long)now.QuadPart ^
                                  ((unsigned long long)GetCurrentProcessId() << 32) ^
                                  (++counter * 2654435761ull);
        std::snprintf(name, sizeof(name), "%s%08llx%08llx", prefix.c_str(),
                      (salt >> 32) & 0xffffffffull, salt & 0xffffffffull);
        std::string dir = std::string(tmp) + name;
        if (CreateDirectoryA(dir.c_str(), nullptr)) return dir;
        if (GetLastError() != ERROR_ALREADY_EXISTS) return "";
    }
    return "";
}

bool write_file_exec(const std::string& path, const std::string& data) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    size_t off = 0;
    while (off < data.size()) {
        DWORD chunk = (DWORD)((data.size() - off) > 0x40000000u ? 0x40000000u : data.size() - off);
        DWORD written = 0;
        if (!WriteFile(h, data.data() + off, chunk, &written, nullptr) || written == 0) break;
        off += written;
    }
    CloseHandle(h);
    return off == data.size();
}

bool remove_file(const std::string& path) { return DeleteFileA(path.c_str()) != 0; }

bool remove_dir(const std::string& path) { return RemoveDirectoryA(path.c_str()) != 0; }

bool remove_tree(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return GetLastError() == ERROR_FILE_NOT_FOUND ||
                                                      GetLastError() == ERROR_PATH_NOT_FOUND;
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        if (attrs & FILE_ATTRIBUTE_READONLY)
            SetFileAttributesA(path.c_str(), attrs & ~(DWORD)FILE_ATTRIBUTE_READONLY);
        return DeleteFileA(path.c_str()) != 0;
    }
    std::string pattern = path + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        bool ok = true;
        do {
            std::string name = fd.cFileName;
            if (name == "." || name == "..") continue;
            if (!remove_tree(path + "\\" + name)) ok = false;
        } while (FindNextFileA(h, &fd));
        FindClose(h);
        if (!ok) return false;
    }
    return RemoveDirectoryA(path.c_str()) != 0;
}

std::string exe_path() {
    char buf[MAX_PATH * 4];
    DWORD n = GetModuleFileNameA(nullptr, buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return "";
    return std::string(buf, n);
}

Spawned spawn_detached(const std::string& exe, const std::vector<std::string>& args) {
    Spawned out;
    std::string cmdline = command_line(exe, args);
    std::vector<char> mutable_cmd(cmdline.begin(), cmdline.end());
    mutable_cmd.push_back('\0');

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;
    HANDLE nul = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    STARTUPINFOA si;
    std::memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    if (si.hStdInput == nullptr || si.hStdInput == INVALID_HANDLE_VALUE) si.hStdInput = nul;
    si.hStdOutput = nul;
    si.hStdError = nul;

    PROCESS_INFORMATION pi;
    std::memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                             nullptr, nullptr, &si, &pi);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) {
        out.error = last_error_text(GetLastError());
        return out;
    }
    out.started = true;
    out.pid = (long long)pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return out;
}

}  // namespace snake::sys

#endif  // _WIN32
