#include "snake/protocol.hpp"

#include <nlohmann/json.hpp>

namespace snake::protocol {

using nlohmann::ordered_json;

namespace {
bool nonempty(const std::optional<std::string>& s) { return s && !s->empty(); }
}  // namespace

std::string to_json(const BeaconPayload& b) {
    ordered_json j;
    j["id"] = b.id;
    j["type"] = b.type;
    j["target"] = b.target;
    j["ts"] = b.ts;
    j["jitter"] = b.jitter;
    if (nonempty(b.hostname)) j["hostname"] = *b.hostname;
    if (nonempty(b.arch)) j["arch"] = *b.arch;
    if (nonempty(b.peer_addr)) j["peer_addr"] = *b.peer_addr;
    return j.dump();
}

std::string to_json(const Task& t) {
    ordered_json j;
    j["id"] = t.id;
    j["type"] = t.type;
    ordered_json payload = ordered_json::object();
    for (const auto& [k, v] : t.payload) payload[k] = v;
    j["payload"] = std::move(payload);
    j["ts"] = t.ts;
    if (t.ttl) j["ttl"] = *t.ttl;
    return j.dump();
}

std::string to_json(const TaskResult& r) {
    ordered_json j;
    j["task_id"] = r.task_id;
    j["success"] = r.success;
    if (nonempty(r.output)) j["output"] = *r.output;
    if (nonempty(r.error)) j["error"] = *r.error;
    j["ts"] = r.ts;
    return j.dump();
}

std::string bundle_to_json(const Bundle& b) {
    ordered_json j = ordered_json::object();
    if (b.beacon) j["beacon"] = ordered_json::parse(to_json(*b.beacon));
    if (b.task) j["task"] = ordered_json::parse(to_json(*b.task));
    if (b.task_result) j["task_result"] = ordered_json::parse(to_json(*b.task_result));
    return j.dump();
}

std::optional<BeaconPayload> beacon_from_json(const std::string& s) {
    try {
        auto j = ordered_json::parse(s);
        BeaconPayload b;
        b.id = j.value("id", "");
        b.type = j.value("type", "");
        b.target = j.value("target", "");
        b.ts = j.value("ts", int64_t(0));
        b.jitter = j.value("jitter", 0.0);
        if (j.contains("hostname")) b.hostname = j["hostname"].get<std::string>();
        if (j.contains("arch")) b.arch = j["arch"].get<std::string>();
        if (j.contains("peer_addr")) b.peer_addr = j["peer_addr"].get<std::string>();
        return b;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<Task> task_from_json(const std::string& s) {
    try {
        auto j = ordered_json::parse(s);
        Task t;
        t.id = j.value("id", "");
        t.type = j.value("type", "");
        t.ts = j.value("ts", int64_t(0));
        if (j.contains("ttl")) t.ttl = j["ttl"].get<int>();
        if (j.contains("payload") && j["payload"].is_object()) {
            for (auto& [k, v] : j["payload"].items()) {
                if (v.is_string()) {
                    t.payload[k] = v.get<std::string>();
                } else {
                    t.payload[k] = v.dump();
                }
            }
        }
        return t;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<TaskResult> task_result_from_json(const std::string& s) {
    try {
        auto j = ordered_json::parse(s);
        TaskResult r;
        r.task_id = j.value("task_id", "");
        r.success = j.value("success", false);
        r.ts = j.value("ts", int64_t(0));
        if (j.contains("output")) r.output = j["output"].get<std::string>();
        if (j.contains("error")) r.error = j["error"].get<std::string>();
        return r;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<Bundle> bundle_from_json(const std::string& s) {
    try {
        auto j = ordered_json::parse(s);
        Bundle b;
        if (j.contains("beacon")) b.beacon = beacon_from_json(j["beacon"].dump());
        if (j.contains("task")) b.task = task_from_json(j["task"].dump());
        if (j.contains("task_result")) b.task_result = task_result_from_json(j["task_result"].dump());
        return b;
    } catch (...) {
        return std::nullopt;
    }
}

std::vector<Task> tasks_from_json(const std::string& s) {
    std::vector<Task> out;
    try {
        auto j = ordered_json::parse(s);
        if (j.is_array()) {
            for (const auto& el : j) {
                auto t = task_from_json(el.dump());
                if (t) out.push_back(*t);
            }
        }
    } catch (...) {
    }
    return out;
}

}  // namespace snake::protocol
