#include "snake/winstealth.hpp"

#ifdef _WIN32

#include <cstring>

namespace snake {
namespace winstealth {

extern "C" long long snake_indirect_syscall(std::uint32_t ssn, void* gadget,
                                            unsigned long long a1, unsigned long long a2,
                                            unsigned long long a3, unsigned long long a4,
                                            unsigned long long a5, unsigned long long a6,
                                            unsigned long long a7, unsigned long long a8,
                                            unsigned long long a9, unsigned long long a10,
                                            unsigned long long a11);

__asm__(
    ".globl snake_indirect_syscall\n"
    "snake_indirect_syscall:\n"
    "movq %r8, %r10\n"
    "movl %ecx, %eax\n"
    "movq %rdx, %rcx\n"
    "movq %r9, %rdx\n"
    "movq 0x28(%rsp), %r8\n"
    "movq 0x30(%rsp), %r9\n"
    "movq 0x38(%rsp), %r11\n"
    "movq %r11, 0x28(%rsp)\n"
    "movq 0x40(%rsp), %r11\n"
    "movq %r11, 0x30(%rsp)\n"
    "movq 0x48(%rsp), %r11\n"
    "movq %r11, 0x38(%rsp)\n"
    "movq 0x50(%rsp), %r11\n"
    "movq %r11, 0x40(%rsp)\n"
    "movq 0x58(%rsp), %r11\n"
    "movq %r11, 0x48(%rsp)\n"
    "movq 0x60(%rsp), %r11\n"
    "movq %r11, 0x50(%rsp)\n"
    "movq 0x68(%rsp), %r11\n"
    "movq %r11, 0x58(%rsp)\n"
    "jmpq *%rcx\n");

namespace {

constexpr std::size_t kPebLdr = 0x18;
constexpr std::size_t kLdrInMemoryOrderList = 0x20;
constexpr std::size_t kEntryInMemoryOrderLinks = 0x10;
constexpr std::size_t kEntryDllBase = 0x30;
constexpr std::size_t kEntrySizeOfImage = 0x40;
constexpr std::size_t kEntryBaseDllName = 0x58;
constexpr std::size_t kUnicodeBuffer = 0x08;

constexpr std::uint64_t kCurrentProcess = static_cast<std::uint64_t>(-1);

template <typename T>
T load_at(const std::uint8_t* p) {
    T v;
    std::memcpy(&v, p, sizeof(T));
    return v;
}

std::uint8_t* peb_address() {
#if defined(__x86_64__) || defined(_M_X64)
    void* peb = nullptr;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
    return static_cast<std::uint8_t*>(peb);
#else
    return nullptr;
#endif
}

Table g_ntdll;
Table g_kernel32;
bool g_init = false;

}  // namespace

ImageView loaded_module(Module module) {
    ImageView view;
    const std::uint32_t want = fnv1a_ascii(module_name(module));
    std::uint8_t* peb = peb_address();
    if (!peb) return view;
    const std::uint8_t* ldr = load_at<std::uint8_t*>(peb + kPebLdr);
    if (!ldr) return view;
    const std::uint8_t* head = ldr + kLdrInMemoryOrderList;
    const std::uint8_t* link = load_at<std::uint8_t*>(head);
    while (link && link != head) {
        const std::uint8_t* entry = link - kEntryInMemoryOrderLinks;
        const wchar_t* name = load_at<const wchar_t*>(entry + kEntryBaseDllName + kUnicodeBuffer);
        std::size_t chars = load_at<std::uint16_t>(entry + kEntryBaseDllName) / sizeof(wchar_t);
        if (chars && name && name[chars - 1] == 0) --chars;
        if (name && chars && fnv1a_wide(name, chars) == want) {
            view.base = load_at<const std::uint8_t*>(entry + kEntryDllBase);
            view.size = load_at<std::uint32_t>(entry + kEntrySizeOfImage);
            return view;
        }
        link = load_at<const std::uint8_t*>(link);
    }
    return view;
}

Table& module_table(Module module) {
    return module == Module::kernel32 ? g_kernel32 : g_ntdll;
}

bool init() {
    if (g_init) return true;
    const ImageView ntdll = loaded_module(Module::ntdll);
    const ImageView kernel32 = loaded_module(Module::kernel32);
    if (!ntdll.ok() || !kernel32.ok()) return false;
    g_ntdll.load(ntdll, Module::ntdll);
    g_kernel32.load(kernel32, Module::kernel32);
    g_ntdll.set_raw_syscall(&snake_indirect_syscall);
    g_init = true;
    return true;
}

bool initialized() { return g_init; }

void* export_fn(Api api) {
    if (!init()) return nullptr;
    return reinterpret_cast<void*>(g_kernel32.code_ptr(api));
}

bool virtual_lock(void* addr, std::size_t len) {
    using Fn = int (*)(void*, std::size_t);
    auto* fn = reinterpret_cast<Fn>(export_fn(Api::VirtualLock));
    if (!fn) return false;
    return fn(addr, len) != 0;
}

bool virtual_unlock(void* addr, std::size_t len) {
    using Fn = int (*)(void*, std::size_t);
    auto* fn = reinterpret_cast<Fn>(export_fn(Api::VirtualUnlock));
    if (!fn) return false;
    return fn(addr, len) != 0;
}

bool virtual_protect(void* addr, std::size_t len, unsigned long new_protect,
                     unsigned long& old_protect) {
    using Fn = int (*)(void*, std::size_t, unsigned long, unsigned long*);
    auto* fn = reinterpret_cast<Fn>(export_fn(Api::VirtualProtect));
    if (!fn) return false;
    unsigned long old = 0;
    const int ok = fn(addr, len, new_protect, &old);
    if (ok) old_protect = old;
    return ok != 0;
}

namespace {

struct SystemInfo {
    std::uint32_t oem_id;
    std::uint32_t page_size;
    void* min_addr;
    void* max_addr;
    std::uintptr_t active_mask;
    std::uint32_t processors;
    std::uint32_t processor_type;
    std::uint32_t allocation_granularity;
    std::uint16_t processor_level;
    std::uint16_t processor_revision;
};

static_assert(sizeof(SystemInfo) == 48, "SYSTEM_INFO is 48 bytes on x64");

}  // namespace

unsigned long system_page_size() {
    using Fn = int (*)(void*);
    auto* fn = reinterpret_cast<Fn>(export_fn(Api::GetSystemInfo));
    if (!fn) return 4096;
    SystemInfo si{};
    fn(&si);
    return si.page_size ? si.page_size : 4096;
}

long long nt_allocate_virtual_memory(std::uintptr_t* base, std::uintptr_t zero_bits,
                                     std::uintptr_t* size, unsigned long alloc_type,
                                     unsigned long protect) {
    const std::uint64_t args[6] = {kCurrentProcess, base ? reinterpret_cast<std::uint64_t>(base) : 0,
                                   static_cast<std::uint64_t>(zero_bits),
                                   size ? reinterpret_cast<std::uint64_t>(size) : 0,
                                   alloc_type, protect};
    return g_ntdll.syscall(Api::NtAllocateVirtualMemory, args, 6);
}

long long nt_protect_virtual_memory(std::uintptr_t* base, std::uintptr_t* size,
                                    unsigned long new_protect, unsigned long* old_protect) {
    const std::uint64_t args[5] = {kCurrentProcess,
                                   base ? reinterpret_cast<std::uint64_t>(base) : 0,
                                   size ? reinterpret_cast<std::uint64_t>(size) : 0, new_protect,
                                   old_protect ? reinterpret_cast<std::uint64_t>(old_protect) : 0};
    return g_ntdll.syscall(Api::NtProtectVirtualMemory, args, 5);
}

long long nt_create_thread_ex(std::uintptr_t* thread, unsigned long access,
                              std::uintptr_t obj_attrs, std::uintptr_t process,
                              std::uintptr_t start, std::uintptr_t argument, unsigned long flags,
                              std::uintptr_t zero_bits, std::uintptr_t stack_size,
                              std::uintptr_t max_stack_size, std::uintptr_t attr_list) {
    const std::uint64_t args[11] = {thread ? reinterpret_cast<std::uint64_t>(thread) : 0,
                                    access,
                                    static_cast<std::uint64_t>(obj_attrs),
                                    process,
                                    start,
                                    argument,
                                    flags,
                                    static_cast<std::uint64_t>(zero_bits),
                                    static_cast<std::uint64_t>(stack_size),
                                    static_cast<std::uint64_t>(max_stack_size),
                                    static_cast<std::uint64_t>(attr_list)};
    return g_ntdll.syscall(Api::NtCreateThreadEx, args, 11);
}

long long nt_query_virtual_memory(std::uintptr_t base, std::uintptr_t what, void* info,
                                  std::size_t info_len, std::uintptr_t* returned) {
    const std::uint64_t args[6] = {kCurrentProcess,
                                   static_cast<std::uint64_t>(base),
                                   static_cast<std::uint64_t>(what),
                                   reinterpret_cast<std::uint64_t>(info),
                                   info_len,
                                   returned ? reinterpret_cast<std::uint64_t>(returned) : 0};
    return g_ntdll.syscall(Api::NtQueryVirtualMemory, args, 6);
}

long long nt_free_virtual_memory(std::uintptr_t* base, std::uintptr_t* size,
                                 unsigned long free_type) {
    const std::uint64_t args[4] = {kCurrentProcess,
                                   base ? reinterpret_cast<std::uint64_t>(base) : 0,
                                   size ? reinterpret_cast<std::uint64_t>(size) : 0, free_type};
    return g_ntdll.syscall(Api::NtFreeVirtualMemory, args, 4);
}

long long nt_write_virtual_memory(std::uintptr_t process, std::uintptr_t base, void* buffer,
                                  std::size_t len, std::uintptr_t* written) {
    const std::uint64_t args[5] = {process,
                                   static_cast<std::uint64_t>(base),
                                   reinterpret_cast<std::uint64_t>(buffer),
                                   len,
                                   written ? reinterpret_cast<std::uint64_t>(written) : 0};
    return g_ntdll.syscall(Api::NtWriteVirtualMemory, args, 5);
}

}  // namespace winstealth
}  // namespace snake

#else  // !_WIN32

#endif  // _WIN32
