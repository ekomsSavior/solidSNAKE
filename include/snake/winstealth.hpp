#ifndef SNAKE_WINSTEALTH_HPP
#define SNAKE_WINSTEALTH_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include "snake/stealth.hpp"

namespace snake {
namespace winstealth {

std::uint32_t fnv1a_ascii(const char* name);
std::uint32_t fnv1a_ascii(const std::string& name);
std::uint32_t fnv1a_wide(const wchar_t* name, std::size_t len);
std::uint32_t fnv1a_wide(const wchar_t* name);

struct ImageView {
    const std::uint8_t* base = nullptr;
    std::size_t size = 0;
    bool ok() const { return base != nullptr && size != 0; }
};

std::uint32_t pe_export_rva(ImageView image, std::uint32_t name_hash);

bool pe_section_span(ImageView image, std::uint32_t rva, std::size_t& off, std::size_t& len);

std::uint32_t stub_ssn(const std::uint8_t* code, std::size_t len, bool& ok);

std::int64_t find_syscall_gadget(const std::uint8_t* code, std::size_t len);

enum class Module : std::uint32_t { ntdll = 0, kernel32 = 1, amsi = 2 };

enum class Api : std::uint32_t {
    NtAllocateVirtualMemory = 0,
    NtProtectVirtualMemory,
    NtCreateThreadEx,
    NtQueryVirtualMemory,
    NtFreeVirtualMemory,
    NtWriteVirtualMemory,
    VirtualLock,
    VirtualUnlock,
    VirtualProtect,
    GetSystemInfo,
    Count
};

struct ApiSpec {
    Module module;
    bool syscall;
};

ApiSpec api_spec(Api api);
const std::string& api_name(Api api);
const std::string& module_name(Module module);

using RawSyscall = long long (*)(std::uint32_t, void*, unsigned long long, unsigned long long,
                                 unsigned long long, unsigned long long, unsigned long long,
                                 unsigned long long, unsigned long long, unsigned long long,
                                 unsigned long long, unsigned long long, unsigned long long);

inline constexpr std::size_t kMaxSyscallArgs = 11;

class Table {
  public:
    bool load(ImageView image, Module module);

    void set_raw_syscall(RawSyscall fn);
    bool has_raw_syscall() const { return raw_ != nullptr; }

    bool resolved(Api api) const;
    bool is_syscall(Api api) const;
    std::uint32_t ssn(Api api) const;
    std::uint32_t code_rva(Api api) const;
    std::uintptr_t code_ptr(Api api) const;

    const std::uint8_t* base() const { return base_; }
    std::size_t resolved_count() const { return resolved_; }
    std::size_t unresolved_count() const { return unresolved_; }

    std::uint32_t gadget_offset() const { return gadget_off_; }
    const void* gadget_ptr() const;

    long long syscall(Api api, const std::uint64_t* args, std::size_t nargs) const;

    static constexpr long long kNoSyscall = -1;

  private:
    struct Entry {
        bool resolved = false;
        bool syscall = false;
        std::uint32_t rva = 0;
        std::uint32_t ssn = 0;
    };
    Entry entries_[static_cast<std::size_t>(Api::Count)];
    const std::uint8_t* base_ = nullptr;
    std::size_t size_ = 0;
    std::uint32_t gadget_off_ = 0;
    std::size_t resolved_ = 0;
    std::size_t unresolved_ = 0;
    RawSyscall raw_ = nullptr;
};

#ifdef _WIN32
ImageView loaded_module(Module module);

bool init();
bool initialized();
Table& module_table(Module module);

void* export_fn(Api api);

bool virtual_lock(void* addr, std::size_t len);
bool virtual_unlock(void* addr, std::size_t len);
bool virtual_protect(void* addr, std::size_t len, unsigned long new_protect,
                     unsigned long& old_protect);

unsigned long system_page_size();

long long nt_allocate_virtual_memory(std::uintptr_t* base, std::uintptr_t zero_bits,
                                     std::uintptr_t* size, unsigned long alloc_type,
                                     unsigned long protect);
long long nt_protect_virtual_memory(std::uintptr_t* base, std::uintptr_t* size,
                                    unsigned long new_protect, unsigned long* old_protect);
long long nt_create_thread_ex(std::uintptr_t* thread, unsigned long access,
                              std::uintptr_t obj_attrs, std::uintptr_t process,
                              std::uintptr_t start, std::uintptr_t argument,
                              unsigned long flags, std::uintptr_t zero_bits,
                              std::uintptr_t stack_size, std::uintptr_t max_stack_size,
                              std::uintptr_t attr_list);
long long nt_query_virtual_memory(std::uintptr_t base, std::uintptr_t what, void* info,
                                  std::size_t info_len, std::uintptr_t* returned);
long long nt_free_virtual_memory(std::uintptr_t* base, std::uintptr_t* size,
                                 unsigned long free_type);
long long nt_write_virtual_memory(std::uintptr_t process, std::uintptr_t base, void* buffer,
                                  std::size_t len, std::uintptr_t* written);
#endif  // _WIN32

}  // namespace winstealth
}  // namespace snake

#endif  // SNAKE_WINSTEALTH_HPP
