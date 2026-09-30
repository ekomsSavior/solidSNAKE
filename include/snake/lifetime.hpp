#pragma once

#include <cstdint>
#include <string>

#include "snake/crypto.hpp"

namespace snake {

bool parse_duration_secs(const std::string& text, long long& out_secs);

bool parse_kill_date_utc(const std::string& text, long long& out_epoch);

struct LifetimePolicy {
    bool has_kill_date = false;
    long long kill_date_epoch = 0;
    bool has_max_runtime = false;
    long long max_runtime_secs = 0;
};

bool lifetime_policy_parse(const std::string& kill_date, const std::string& max_runtime,
                           LifetimePolicy& out, std::string& err);

std::string lifetime_expiry_reason(const LifetimePolicy& p, long long now, long long start);

void zeroize(Bytes& b);

}  // namespace snake
