#ifndef SNAKE_WIN32_PWD_H
#define SNAKE_WIN32_PWD_H

#include <windows.h>

#include <cstring>
#include <sys/types.h>

struct passwd {
    char* pw_name;
    char* pw_passwd;
    unsigned int pw_uid;
    unsigned int pw_gid;
    char* pw_gecos;
    char* pw_dir;
    char* pw_shell;
};

inline char* rr_win_home_dir(void) {
    static char home[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("USERPROFILE", home, (DWORD)sizeof(home));
    if (n == 0 || n >= sizeof(home)) {
        char drive[MAX_PATH] = {0};
        char path[MAX_PATH] = {0};
        GetEnvironmentVariableA("HOMEDRIVE", drive, (DWORD)sizeof(drive));
        GetEnvironmentVariableA("HOMEPATH", path, (DWORD)sizeof(path));
        home[0] = '\0';
        if (drive[0] != '\0' || path[0] != '\0') {
            size_t d = strlen(drive);
            size_t p = strlen(path);
            if (d + p + 1 < sizeof(home)) {
                memcpy(home, drive, d);
                memcpy(home + d, path, p);
                home[d + p] = '\0';
            }
        }
    }
    return home;
}

inline struct passwd* rr_win_passwd(void) {
    static struct passwd pw;
    static char name[MAX_PATH];
    DWORD cap = (DWORD)sizeof(name);
    if (GetUserNameA(name, &cap) == 0) name[0] = '\0';
    pw.pw_name = name;
    pw.pw_passwd = const_cast<char*>("x");
    pw.pw_uid = (unsigned int)-1;
    pw.pw_gid = (unsigned int)-1;
    pw.pw_gecos = name;
    pw.pw_dir = rr_win_home_dir();
    pw.pw_shell = const_cast<char*>("cmd.exe");
    return &pw;
}

inline struct passwd* getpwuid(unsigned int) { return rr_win_passwd(); }
inline struct passwd* getpwnam(const char*) { return rr_win_passwd(); }

#endif  // SNAKE_WIN32_PWD_H
