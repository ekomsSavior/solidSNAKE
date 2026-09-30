#include "snake/cert.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace snake::cert {

namespace {

std::string openssl_err() {
    unsigned long e = ERR_get_error();
    if (e == 0) return "openssl error";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

std::string canonical_ip(const void* addr, int family) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (!inet_ntop(family, addr, buf, sizeof(buf))) return "";
    if (family == AF_INET6) {
        const unsigned char* b = static_cast<const unsigned char*>(addr);
        static const unsigned char v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if (std::memcmp(b, v4mapped, 12) == 0) {
            char v4[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, b + 12, v4, sizeof(v4));
            return std::string(v4);
        }
    }
    return std::string(buf);
}

bool ip_bytes(const std::string& s, std::vector<unsigned char>* out) {
    unsigned char b[16];
    if (inet_pton(AF_INET, s.c_str(), b) == 1) {
        out->assign(b, b + 4);
        return true;
    }
    if (inet_pton(AF_INET6, s.c_str(), b) == 1) {
        static const unsigned char v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if (std::memcmp(b, v4mapped, 12) == 0) {
            out->assign(b + 12, b + 16);
        } else {
            out->assign(b, b + 16);
        }
        return true;
    }
    return false;
}

bool add_dns_san(GENERAL_NAMES* gens, const std::string& name) {
    GENERAL_NAME* gen = GENERAL_NAME_new();
    if (!gen) return false;
    gen->type = GEN_DNS;
    ASN1_IA5STRING* s = ASN1_IA5STRING_new();
    if (!s || !ASN1_STRING_set(s, name.data(), static_cast<int>(name.size()))) {
        ASN1_IA5STRING_free(s);
        GENERAL_NAME_free(gen);
        return false;
    }
    gen->d.dNSName = s;
    if (!sk_GENERAL_NAME_push(gens, gen)) {
        GENERAL_NAME_free(gen);
        return false;
    }
    return true;
}

bool add_ip_san(GENERAL_NAMES* gens, const std::string& text) {
    std::vector<unsigned char> bytes;
    if (!ip_bytes(text, &bytes)) return false;
    GENERAL_NAME* gen = GENERAL_NAME_new();
    if (!gen) return false;
    gen->type = GEN_IPADD;
    ASN1_OCTET_STRING* s = ASN1_OCTET_STRING_new();
    if (!s || !ASN1_OCTET_STRING_set(s, bytes.data(), static_cast<int>(bytes.size()))) {
        ASN1_OCTET_STRING_free(s);
        GENERAL_NAME_free(gen);
        return false;
    }
    gen->d.iPAddress = s;
    if (!sk_GENERAL_NAME_push(gens, gen)) {
        GENERAL_NAME_free(gen);
        return false;
    }
    return true;
}

bool add_v3_ext(X509* x, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (!ext) return false;
    int ok = X509_add_ext(x, ext, -1);
    X509_EXTENSION_free(ext);
    return ok == 1;
}

bool write_pem_file(const std::string& path, bool private_key, const KeyMaterial& km,
                    std::string* err) {
    BIO* bio = BIO_new_file(path.c_str(), "w");
    if (!bio) {
        *err = "open " + path + ": " + std::strerror(errno);
        return false;
    }
    int ok = 0;
    if (private_key) {
        const unsigned char* p = km.key_pkcs8_der.data();
        PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p,
                                                          static_cast<long>(km.key_pkcs8_der.size()));
        if (p8) {
            EVP_PKEY* key = EVP_PKCS82PKEY(p8);
            if (key) {
                ok = PEM_write_bio_PKCS8PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
                EVP_PKEY_free(key);
            }
            PKCS8_PRIV_KEY_INFO_free(p8);
        }
    } else {
        const unsigned char* p = km.cert_der.data();
        X509* x = d2i_X509(nullptr, &p, static_cast<long>(km.cert_der.size()));
        if (x) {
            ok = PEM_write_bio_X509(bio, x);
            X509_free(x);
        }
    }
    BIO_free(bio);
    if (ok != 1) {
        *err = "write " + path + ": " + openssl_err();
        return false;
    }
    return true;
}

}  // namespace

bool create_self_signed(const CertSpec& spec, KeyMaterial* out, std::string* err) {
    bool ok = false;
    EVP_PKEY_CTX* pctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    X509* x = nullptr;
    GENERAL_NAMES* gens = nullptr;

    ERR_clear_error();
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        *err = "ed25519 keygen: " + openssl_err();
        goto done;
    }
    x = X509_new();
    if (!x) {
        *err = "X509_new: " + openssl_err();
        goto done;
    }
    if (X509_set_version(x, 2) != 1) {
        *err = "set version: " + openssl_err();
        goto done;
    }
    {
        int64_t serial = spec.serial;
        if (serial <= 0) {
            serial = static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
        }
        if (ASN1_INTEGER_set_int64(X509_get_serialNumber(x), serial) != 1) {
            *err = "set serial: " + openssl_err();
            goto done;
        }
    }
    {
        X509_NAME* name = X509_get_subject_name(x);
        if (!name ||
            (!spec.organization.empty() &&
             X509_NAME_add_entry_by_txt(
                 name, "O", MBSTRING_UTF8,
                 reinterpret_cast<const unsigned char*>(spec.organization.c_str()), -1, -1, 0) != 1)) {
            *err = "set subject O: " + openssl_err();
            goto done;
        }
        if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                       reinterpret_cast<const unsigned char*>(spec.common_name.c_str()),
                                       -1, -1, 0) != 1) {
            *err = "set subject CN: " + openssl_err();
            goto done;
        }
        if (X509_set_issuer_name(x, name) != 1) {
            *err = "set issuer: " + openssl_err();
            goto done;
        }
    }
    if (X509_gmtime_adj(X509_getm_notBefore(x), static_cast<long>(spec.not_before_offset_secs)) ==
            nullptr ||
        X509_gmtime_adj(X509_getm_notAfter(x), static_cast<long>(spec.not_after_offset_secs)) ==
            nullptr) {
        *err = "set validity: " + openssl_err();
        goto done;
    }
    if (X509_set_pubkey(x, pkey) != 1) {
        *err = "set public key: " + openssl_err();
        goto done;
    }

    if (spec.basic_constraints_valid) {
        if (!add_v3_ext(x, NID_basic_constraints, "critical,CA:FALSE")) {
            *err = "basic constraints: " + openssl_err();
            goto done;
        }
    }
    {
        std::string ku = "critical,digitalSignature";
        if (spec.key_encipherment) ku += ",keyEncipherment";
        if (!add_v3_ext(x, NID_key_usage, ku.c_str())) {
            *err = "key usage: " + openssl_err();
            goto done;
        }
    }
    {
        std::string eku;
        if (spec.client_auth) eku = "clientAuth";
        if (spec.server_auth) eku += (eku.empty() ? "" : ",") + std::string("serverAuth");
        if (!eku.empty() && !add_v3_ext(x, NID_ext_key_usage, eku.c_str())) {
            *err = "ext key usage: " + openssl_err();
            goto done;
        }
    }
    if (!spec.dns_names.empty() || !spec.ip_addresses.empty()) {
        gens = sk_GENERAL_NAME_new_null();
        if (!gens) {
            *err = "san alloc: " + openssl_err();
            goto done;
        }
        for (const std::string& d : spec.dns_names) {
            if (!add_dns_san(gens, d)) {
                *err = "san dns " + d;
                goto done;
            }
        }
        for (const std::string& ip : spec.ip_addresses) {
            if (!add_ip_san(gens, ip)) {
                *err = "san ip " + ip;
                goto done;
            }
        }
        X509_EXTENSION* ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
        if (!ext || X509_add_ext(x, ext, -1) != 1) {
            X509_EXTENSION_free(ext);
            *err = "san extension: " + openssl_err();
            goto done;
        }
        X509_EXTENSION_free(ext);
    }

    if (X509_sign(x, pkey, nullptr) <= 0) {
        *err = "sign: " + openssl_err();
        goto done;
    }

    {
        int n = i2d_X509(x, nullptr);
        if (n <= 0) {
            *err = "encode cert: " + openssl_err();
            goto done;
        }
        out->cert_der.resize(static_cast<size_t>(n));
        unsigned char* p = out->cert_der.data();
        i2d_X509(x, &p);
    }
    {
        PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(pkey);
        if (!p8) {
            *err = "encode key: " + openssl_err();
            goto done;
        }
        int n = i2d_PKCS8_PRIV_KEY_INFO(p8, nullptr);
        if (n <= 0) {
            *err = "encode key: " + openssl_err();
            PKCS8_PRIV_KEY_INFO_free(p8);
            goto done;
        }
        out->key_pkcs8_der.resize(static_cast<size_t>(n));
        unsigned char* p = out->key_pkcs8_der.data();
        i2d_PKCS8_PRIV_KEY_INFO(p8, &p);
        PKCS8_PRIV_KEY_INFO_free(p8);
    }
    {
        if (EVP_PKEY_id(pkey) == EVP_PKEY_ED25519) {
            unsigned char raw[32];
            size_t len = sizeof(raw);
            if (EVP_PKEY_get_raw_private_key(pkey, raw, &len) == 1) {
                out->key_seed.assign(raw, raw + len);
            }
        }
    }
    ok = true;

done:
    if (gens) sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    if (x) X509_free(x);
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return ok;
}

std::vector<std::string> local_dns_names() {
    std::vector<std::string> out{"localhost"};
    char hbuf[256] = {0};
    if (gethostname(hbuf, sizeof(hbuf) - 1) == 0 && hbuf[0] != '\0') out.emplace_back(hbuf);
    return out;
}

std::vector<std::string> local_ip_addresses() {
    std::vector<std::string> out{"127.0.0.1", "::1"};
    struct ifaddrs* ifs = nullptr;
    if (getifaddrs(&ifs) != 0) return out;
    for (struct ifaddrs* it = ifs; it; it = it->ifa_next) {
        if (!it->ifa_addr) continue;
        int family = it->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;
        const void* addr = family == AF_INET
                               ? static_cast<const void*>(&reinterpret_cast<sockaddr_in*>(it->ifa_addr)->sin_addr)
                               : static_cast<const void*>(&reinterpret_cast<sockaddr_in6*>(it->ifa_addr)->sin6_addr);
        std::string s = canonical_ip(addr, family);
        if (s.empty()) continue;
        bool dup = false;
        for (const std::string& seen : out) {
            if (seen == s) {
                dup = true;
                break;
            }
        }
        if (!dup) out.push_back(s);
    }
    freeifaddrs(ifs);
    return out;
}

bool parse_ip(const std::string& s, std::string* canonical) {
    std::vector<unsigned char> bytes;
    if (!ip_bytes(s, &bytes)) return false;
    if (canonical) {
        if (bytes.size() == 4) {
            char b[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, bytes.data(), b, sizeof(b));
            *canonical = b;
        } else {
            char b[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, bytes.data(), b, sizeof(b));
            *canonical = b;
        }
    }
    return true;
}

void apply_extra_sans(const std::string& extra_sans, std::vector<std::string>* dns_names,
                      std::vector<std::string>* ip_addresses) {
    size_t pos = 0;
    while (pos <= extra_sans.size()) {
        size_t comma = extra_sans.find(',', pos);
        std::string item = extra_sans.substr(pos, comma == std::string::npos ? std::string::npos
                                                                             : comma - pos);
        pos = comma == std::string::npos ? extra_sans.size() + 1 : comma + 1;
        size_t b = item.find_first_not_of(" \t\r\n\v\f");
        size_t e = item.find_last_not_of(" \t\r\n\v\f");
        if (b == std::string::npos) continue;
        item = item.substr(b, e - b + 1);
        if (item.empty()) continue;
        std::string canon;
        if (parse_ip(item, &canon)) {
            bool dup = false;
            for (const std::string& seen : *ip_addresses) {
                if (seen == canon) {
                    dup = true;
                    break;
                }
            }
            if (!dup) ip_addresses->push_back(canon);
            continue;
        }
        dns_names->push_back(item);
    }
}

bool write_self_signed(const std::string& node_id, const std::string& extra_sans,
                       const std::string& cert_dir, std::string* cert_file, std::string* key_file,
                       std::string* err) {
    CertSpec spec;
    spec.common_name = node_id;
    spec.organization = "Ranger C3";
    spec.dns_names = local_dns_names();
    spec.ip_addresses = local_ip_addresses();
    apply_extra_sans(extra_sans, &spec.dns_names, &spec.ip_addresses);
    spec.digital_signature = true;
    spec.key_encipherment = true;
    spec.server_auth = true;
    spec.basic_constraints_valid = true;

    KeyMaterial km;
    if (!create_self_signed(spec, &km, err)) return false;

    if (::mkdir(cert_dir.c_str(), 0700) != 0 && errno != EEXIST) {
        *err = "mkdir " + cert_dir + ": " + std::strerror(errno);
        return false;
    }
    *cert_file = cert_dir + "/c2-cert.pem";
    *key_file = cert_dir + "/c2-key.pem";
    if (!write_pem_file(*cert_file, false, km, err)) return false;
    if (!write_pem_file(*key_file, true, km, err)) return false;
    return true;
}

bool ensure_self_signed(const std::string& node_id, const std::string& extra_sans, bool force,
                        const std::string& cert_dir, SelfSignedFiles* out, std::string* err) {
    out->cert_file = cert_dir + "/c2-cert.pem";
    out->key_file = cert_dir + "/c2-key.pem";
    out->generated = false;
    if (!force) {
        struct stat st;
        if (::stat(out->cert_file.c_str(), &st) == 0 &&
            ::stat(out->key_file.c_str(), &st) == 0) {
            return true;
        }
    }
    std::string cf, kf;
    if (!write_self_signed(node_id, extra_sans, cert_dir, &cf, &kf, err)) return false;
    out->cert_file = cf;
    out->key_file = kf;
    out->generated = true;
    return true;
}

}  // namespace snake::cert
