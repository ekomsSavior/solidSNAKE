#ifndef SNAKE_WIN32_SYS_PTRACE_H
#define SNAKE_WIN32_SYS_PTRACE_H

#include <errno.h>
#include <sys/types.h>

#define PTRACE_TRACEME 0
#define PTRACE_PEEKTEXT 1
#define PTRACE_PEEKDATA 2
#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5
#define PTRACE_GETREGS 12
#define PTRACE_SETREGS 13
#define PTRACE_ATTACH 16
#define PTRACE_DETACH 17

inline long ptrace(int, pid_t, void*, void*) {
    errno = ENOSYS;
    return -1;
}

#endif  // SNAKE_WIN32_SYS_PTRACE_H
