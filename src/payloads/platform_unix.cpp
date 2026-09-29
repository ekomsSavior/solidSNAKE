#ifndef _WIN32

#include <signal.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include <cstdio>

#include "snake/payloads.hpp"

namespace snake::payloads {

std::string file_owner(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return "unknown";
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u", (unsigned)st.st_uid);
    return buf;
}

bool disk_space(const std::string& path, uint64_t& total, uint64_t& free) {
    struct statvfs vfs;
    if (statvfs(path.c_str(), &vfs) != 0) return false;
    uint64_t bs = vfs.f_bsize;
    total = (uint64_t)vfs.f_blocks * bs;
    free = (uint64_t)vfs.f_bfree * bs;
    return true;
}

bool kill_process(int pid) { return kill((pid_t)pid, SIGKILL) == 0; }

}  // namespace snake::payloads

#endif  // !_WIN32
