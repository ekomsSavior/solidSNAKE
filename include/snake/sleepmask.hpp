#ifndef SNAKE_SLEEPMASK_HPP
#define SNAKE_SLEEPMASK_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "snake/crypto.hpp"

namespace snake {

struct MaskRegion {
    void* addr = nullptr;
    std::size_t len = 0;
};

struct MaskReport {
    bool ok = false;
    std::size_t regions = 0;
    std::size_t bytes = 0;
    std::size_t locked = 0;
    std::string error;
};

class SleepMask {
  public:
    SleepMask();
    ~SleepMask();

    bool enabled() const { return enabled_; }
    void disable() { enabled_ = false; }
    bool active() const { return active_; }

    MaskReport mask(const std::vector<MaskRegion>& regions);

    MaskReport unmask();

    static std::size_t page_size();

  private:
    struct Entry {
        void* addr = nullptr;
        std::size_t len = 0;
        Bytes nonce;
        Bytes tag;
        void* lock_addr = nullptr;
        std::size_t lock_len = 0;
        bool locked = false;
#ifdef _WIN32
        void* prot_addr = nullptr;
        std::size_t prot_len = 0;
        void* prot_saved = nullptr;
        bool prot = false;
#endif
    };

    bool enabled_ = true;
    bool active_ = false;
    Bytes key_;
    Bytes auth_key_;
    std::vector<Entry> entries_;
    std::vector<std::pair<void*, std::size_t>> key_locks_;

    SleepMask(const SleepMask&) = delete;
    SleepMask& operator=(const SleepMask&) = delete;
};

}  // namespace snake

#endif  // SNAKE_SLEEPMASK_HPP
