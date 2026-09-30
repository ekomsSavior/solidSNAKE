#include "snake/sleepmask.hpp"

#include <cstdlib>
#include <cstring>

#include <sodium.h>

#ifdef _WIN32
#include "snake/winstealth.hpp"
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace snake {

namespace {

struct PageRange {
    void* addr = nullptr;
    std::size_t len = 0;
};

PageRange containing_pages(void* addr, std::size_t len) {
    const std::size_t ps = SleepMask::page_size();
    const auto mask = (std::uintptr_t)(ps - 1);
    const auto start = (std::uintptr_t)addr & ~mask;
    const auto end = ((std::uintptr_t)addr + len + mask) & ~mask;
    return PageRange{(void*)start, (std::size_t)(end - start)};
}

#ifdef _WIN32
PageRange covered_pages(void* addr, std::size_t len) {
    const std::size_t ps = SleepMask::page_size();
    const auto mask = (std::uintptr_t)(ps - 1);
    const auto start = ((std::uintptr_t)addr + mask) & ~mask;
    const auto end = ((std::uintptr_t)addr + len) & ~mask;
    if (end <= start) return PageRange{};
    return PageRange{(void*)start, (std::size_t)(end - start)};
}
#endif

bool lock_pages(void* addr, std::size_t len) {
    if (!addr || len == 0) return false;
#ifdef _WIN32
    return winstealth::virtual_lock(addr, len);
#else
    if (mlock(addr, len) != 0) return false;
#ifdef MADV_DONTDUMP
    (void)madvise(addr, len, MADV_DONTDUMP);
#endif
    return true;
#endif
}

void unlock_pages(void* addr, std::size_t len) {
    if (!addr || len == 0) return;
#ifdef _WIN32
    (void)winstealth::virtual_unlock(addr, len);
#else
    (void)munlock(addr, len);
#endif
}

#ifdef _WIN32
constexpr unsigned long kPageNoAccess = 0x01;

bool protect_none(void* addr, std::size_t len, void*& saved) {
    unsigned long old = 0;
    if (!winstealth::virtual_protect(addr, len, kPageNoAccess, old)) return false;
    saved = (void*)(std::uintptr_t)old;
    return true;
}

void restore_protect(void* addr, std::size_t len, void* saved) {
    unsigned long old = 0;
    (void)winstealth::virtual_protect(addr, len, (unsigned long)(std::uintptr_t)saved, old);
}
#endif

void stream_xor(void* addr, std::size_t len, const Bytes& nonce, const Bytes& key) {
    (void)crypto_stream_xchacha20_xor((unsigned char*)addr, (const unsigned char*)addr,
                                      (unsigned long long)len, nonce.data(), key.data());
}

}  // namespace

std::size_t SleepMask::page_size() {
#ifdef _WIN32
    static const std::size_t ps = (std::size_t)winstealth::system_page_size();
    return ps;
#else
    static const std::size_t ps = [] {
        long v = sysconf(_SC_PAGESIZE);
        return (std::size_t)(v > 0 ? v : 4096);
    }();
    return ps;
#endif
}

SleepMask::SleepMask() {
    const char* opt_out = std::getenv("SNAKE_NO_SLEEP_MASK");
    if (opt_out && opt_out[0] != '\0') enabled_ = false;
}

SleepMask::~SleepMask() {
    if (active_) (void)unmask();
    sodium_memzero(key_.data(), key_.size());
    sodium_memzero(auth_key_.data(), auth_key_.size());
}

MaskReport SleepMask::mask(const std::vector<MaskRegion>& regions) {
    MaskReport rep;
    if (!enabled_) {
        rep.ok = true;
        return rep;
    }
    if (active_) {
        rep.error = "already masked";
        return rep;
    }

    key_ = random_bytes(32);
    static const char kDerivation[] = "solidSNAKE sleep mask v1 integrity";
    Bytes material = key_;
    material.insert(material.end(), kDerivation, kDerivation + sizeof(kDerivation) - 1);
    auth_key_ = sha256(material);
    sodium_memzero(material.data(), material.size());

    PageRange kp = containing_pages(key_.data(), key_.size());
    if (lock_pages(kp.addr, kp.len)) key_locks_.emplace_back(kp.addr, kp.len);
    PageRange ap = containing_pages(auth_key_.data(), auth_key_.size());
    if (lock_pages(ap.addr, ap.len)) key_locks_.emplace_back(ap.addr, ap.len);

    entries_.clear();
    rep.ok = true;
    for (const MaskRegion& r : regions) {
        if (!r.addr || r.len == 0) continue;
        Entry e;
        e.addr = r.addr;
        e.len = r.len;
        e.nonce = random_bytes(24);
        e.tag.resize(crypto_onetimeauth_poly1305_BYTES);
        (void)crypto_onetimeauth_poly1305(e.tag.data(), (const unsigned char*)r.addr,
                                          (unsigned long long)r.len, auth_key_.data());

        PageRange lp = containing_pages(r.addr, r.len);
        e.lock_addr = lp.addr;
        e.lock_len = lp.len;
        e.locked = lock_pages(lp.addr, lp.len);

        stream_xor(r.addr, r.len, e.nonce, key_);

#ifdef _WIN32
        PageRange cp = covered_pages(r.addr, r.len);
        if (cp.addr && cp.len) {
            void* saved = nullptr;
            if (protect_none(cp.addr, cp.len, saved)) {
                e.prot = true;
                e.prot_addr = cp.addr;
                e.prot_len = cp.len;
                e.prot_saved = saved;
            }
        }
#endif

        entries_.push_back(std::move(e));
        rep.regions++;
        rep.bytes += r.len;
        if (entries_.back().locked) rep.locked++;
    }
    if (entries_.empty()) {
        for (auto& l : key_locks_) unlock_pages(l.first, l.second);
        key_locks_.clear();
        sodium_memzero(key_.data(), key_.size());
        sodium_memzero(auth_key_.data(), auth_key_.size());
        key_.clear();
        auth_key_.clear();
        return rep;
    }
    active_ = true;
    return rep;
}

MaskReport SleepMask::unmask() {
    MaskReport rep;
    if (!enabled_ || !active_) {
        rep.ok = true;
        return rep;
    }
    rep.ok = true;
    for (Entry& e : entries_) {
#ifdef _WIN32
        if (e.prot) restore_protect(e.prot_addr, e.prot_len, e.prot_saved);
#endif
        stream_xor(e.addr, e.len, e.nonce, key_);
        if (crypto_onetimeauth_poly1305_verify((const unsigned char*)e.tag.data(),
                                               (const unsigned char*)e.addr,
                                               (unsigned long long)e.len,
                                               auth_key_.data()) != 0) {
            if (rep.ok) rep.error = "integrity check failed on restore";
            rep.ok = false;
        }
        rep.regions++;
        rep.bytes += e.len;
        if (e.locked) rep.locked++;
    }
    for (auto& l : key_locks_) unlock_pages(l.first, l.second);
    key_locks_.clear();
    for (Entry& e : entries_) {
        if (e.locked) unlock_pages(e.lock_addr, e.lock_len);
    }
    sodium_memzero(key_.data(), key_.size());
    sodium_memzero(auth_key_.data(), auth_key_.size());
    key_.clear();
    auth_key_.clear();
    entries_.clear();
    active_ = false;
    return rep;
}

}  // namespace snake
