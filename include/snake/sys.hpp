#pragma once

#include <cstdint>
#include <string>
#include <vector>

#if defined(_WIN32)
using rr_socket_t = uintptr_t;
#else
using rr_socket_t = int;
#endif

namespace snake::sys {

#if defined(_WIN32)
inline constexpr rr_socket_t kInvalidSocket = (rr_socket_t)~(rr_socket_t)0;
#else
inline constexpr rr_socket_t kInvalidSocket = -1;
#endif

bool net_init();

void net_shutdown();

void close_socket(rr_socket_t s);

bool set_socket_timeout(rr_socket_t s, int seconds);

int wait_readable(rr_socket_t s, int timeout_ms);

std::string socket_error_text(int err);

int socket_last_error();

void sleep_ms(long long ms);

std::string make_temp_dir(const std::string& prefix);

bool write_file_exec(const std::string& path, const std::string& data);

bool remove_file(const std::string& path);
bool remove_dir(const std::string& path);
bool remove_tree(const std::string& path);

std::string exe_path();

struct Spawned {
    bool started = false;
    long long pid = 0;
    std::string error;
};

Spawned spawn_detached(const std::string& exe, const std::vector<std::string>& args);

#if defined(_WIN32)
std::string command_line(const std::string& exe, const std::vector<std::string>& args);
#endif

}  // namespace snake::sys
