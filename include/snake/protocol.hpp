#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace snake::protocol {

namespace implant_type {
inline constexpr const char* kWindows = "windows";
inline constexpr const char* kLinux = "linux";
inline constexpr const char* kMacOS = "darwin";
inline constexpr const char* kAndroid = "android";
inline constexpr const char* kIOS = "ios";
}  // namespace implant_type

struct BeaconPayload {
    std::string id;
    std::string type;
    std::string target;
    int64_t ts = 0;
    double jitter = 0.0;
    std::optional<std::string> hostname;
    std::optional<std::string> arch;
    std::optional<std::string> peer_addr;
};

struct Task {
    std::string id;
    std::string type;
    std::map<std::string, std::string> payload;
    int64_t ts = 0;
    std::optional<int> ttl;
};

struct TaskResult {
    std::string task_id;
    bool success = false;
    std::optional<std::string> output;
    std::optional<std::string> error;
    int64_t ts = 0;
};

struct Bundle {
    std::optional<BeaconPayload> beacon;
    std::optional<Task> task;
    std::optional<TaskResult> task_result;
};

std::string to_json(const BeaconPayload&);
std::string to_json(const Task&);
std::string to_json(const TaskResult&);
std::string bundle_to_json(const Bundle&);

std::optional<BeaconPayload> beacon_from_json(const std::string&);
std::optional<Task> task_from_json(const std::string&);
std::optional<TaskResult> task_result_from_json(const std::string&);
std::optional<Bundle> bundle_from_json(const std::string&);
std::vector<Task> tasks_from_json(const std::string&);

}  // namespace snake::protocol
