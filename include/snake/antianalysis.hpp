#pragma once

#include <string>
#include <vector>

namespace snake {

struct AnalysisReadings {
    long long uptime_secs = 0;
    double disk_total_gb = 0.0;
    long long ram_total_mb = 0;
    int cpu_count = 0;
    std::vector<std::string> mac_addresses;
    std::vector<std::string> process_names;
};

namespace analysis_weights {
inline constexpr int kUptimeUnder300 = 2;
inline constexpr int kUptimeUnder600 = 1;
inline constexpr int kDiskUnder10Gb = 2;
inline constexpr int kDiskUnder20Gb = 1;
inline constexpr int kRamUnder2048Mb = 2;
inline constexpr int kRamUnder4096Mb = 1;
inline constexpr int kCpuUnder2 = 2;
inline constexpr int kHypervisorOui = 3;
inline constexpr int kAnalysisTool = 4;
}  // namespace analysis_weights

inline constexpr int kConservativeThreshold = 6;
inline constexpr int kParanoidThreshold = 3;

struct AnalysisPolicy {
    bool enabled = false;
    int threshold = kConservativeThreshold;
    bool check_vm_oui = true;
    bool check_tool_names = true;
};

bool analysis_policy_parse(const std::string& threshold_text, bool paranoid,
                           AnalysisPolicy& out, std::string& err);

bool analysis_readings_from_spec(const std::string& spec, AnalysisReadings& out);

bool analysis_is_hypervisor_oui(const std::string& mac);

bool analysis_is_tool_name(const std::string& name);

struct AnalysisVerdict {
    int score = 0;
    bool hostile = false;
    std::vector<std::string> reasons;
};

AnalysisVerdict analysis_verdict(const AnalysisReadings& r, const AnalysisPolicy& p);

}  // namespace snake
