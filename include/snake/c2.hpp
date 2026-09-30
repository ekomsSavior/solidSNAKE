#pragma once

#include <string>
#include <vector>

#include "snake/crypto.hpp"

namespace snake::c2 {

struct Config {
    std::string listen = ":4443";
    std::string mesh;
    std::string bootstrap;
    std::string db_path = "data/c2.db";
    std::string password;
    std::string key_hex;
    std::string tls_cert;
    std::string tls_key;
    bool gen_certs = false;
    bool gen_certs_only = false;
    bool force_certs = false;
    std::string cert_sans;
    std::string node_id;
};

std::string usage();

std::string random_node_id();

void log_line(const std::string& msg);

std::string truncate(const std::string& s, size_t n);

std::string banner(const Config& cfg, const std::string& node_id, const Bytes& session_key,
                   bool tls_enabled);

bool decode_session_key(const std::string& hex, Bytes* key, std::string* err);

bool parse_args(const std::vector<std::string>& argv, Config& cfg, bool& help, std::string& err);

int c2_main(int argc, char** argv);

}  // namespace snake::c2
