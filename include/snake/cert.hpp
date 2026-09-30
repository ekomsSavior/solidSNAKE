#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "snake/crypto.hpp"

namespace snake::cert {

struct CertSpec {
    std::string common_name;
    std::string organization;
    std::vector<std::string> dns_names;
    std::vector<std::string> ip_addresses;
    bool digital_signature = true;
    bool key_encipherment = false;
    bool server_auth = false;
    bool client_auth = false;
    bool basic_constraints_valid = true;
    int64_t not_before_offset_secs = -3600;
    int64_t not_after_offset_secs = 365LL * 24 * 3600;
    int64_t serial = 0;
};

struct KeyMaterial {
    Bytes cert_der;
    Bytes key_pkcs8_der;
    Bytes key_seed;
};

bool create_self_signed(const CertSpec& spec, KeyMaterial* out, std::string* err);

std::vector<std::string> local_dns_names();
std::vector<std::string> local_ip_addresses();

void apply_extra_sans(const std::string& extra_sans, std::vector<std::string>* dns_names,
                      std::vector<std::string>* ip_addresses);

bool parse_ip(const std::string& s, std::string* canonical);

struct SelfSignedFiles {
    std::string cert_file;
    std::string key_file;
    bool generated = false;
};

bool ensure_self_signed(const std::string& node_id, const std::string& extra_sans, bool force,
                        const std::string& cert_dir, SelfSignedFiles* out, std::string* err);

bool write_self_signed(const std::string& node_id, const std::string& extra_sans,
                       const std::string& cert_dir, std::string* cert_file, std::string* key_file,
                       std::string* err);

}  // namespace snake::cert
