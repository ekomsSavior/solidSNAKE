#ifdef _WIN32

#include <windows.h>

#include "snake/payloads.hpp"

namespace snake::payloads {

std::string file_owner(const std::string&) { return "unknown"; }

bool disk_space(const std::string&, uint64_t&, uint64_t&) { return false; }

bool kill_process(int pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (h == nullptr) return false;
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok != 0;
}

}  // namespace snake::payloads

#endif  // _WIN32
