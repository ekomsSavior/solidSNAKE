#pragma GCC system_header
#ifndef SNAKE_WIN32_SYS_STAT_H
#define SNAKE_WIN32_SYS_STAT_H

#include_next <sys/stat.h>

#include <direct.h>

#ifndef S_IFSOCK
#define S_IFSOCK 0xC000
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif
#ifndef S_ISUID
#define S_ISUID 0x0800
#endif
#ifndef S_ISGID
#define S_ISGID 0x0400
#endif
#ifndef S_ISVTX
#define S_ISVTX 0x0200
#endif

inline int lstat(const char* path, struct stat* st) { return stat(path, st); }

inline int mkdir(const char* path, int /*mode*/) { return _mkdir(path); }

#endif  // SNAKE_WIN32_SYS_STAT_H
