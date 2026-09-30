#pragma GCC system_header
#ifndef SNAKE_WIN32_UNISTD_H
#define SNAKE_WIN32_UNISTD_H

#include_next <unistd.h>

#include <windows.h>

inline unsigned int getuid(void) { return (unsigned int)-1; }
inline unsigned int geteuid(void) { return (unsigned int)-1; }
inline unsigned int getgid(void) { return (unsigned int)-1; }
inline unsigned int getegid(void) { return (unsigned int)-1; }

#ifndef _SC_NPROCESSORS_ONLN
#define _SC_NPROCESSORS_ONLN 84
#endif

inline long sysconf(int name) {
    if (name == _SC_NPROCESSORS_ONLN) {
        return (long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    }
    return -1;
}

#endif  // SNAKE_WIN32_UNISTD_H
