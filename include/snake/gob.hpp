#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "snake/crypto.hpp"

namespace snake::gob {

struct Heartbeat {
    std::string node_id;
    std::string addr;
    std::vector<std::string> implants;
    int64_t timestamp = 0;
    Bytes signature;
};

void encode_uint(std::string* out, uint64_t x);
void encode_int(std::string* out, int64_t i);
bool decode_uint(const uint8_t* buf, size_t len, size_t* pos, uint64_t* out);
bool decode_int(const uint8_t* buf, size_t len, size_t* pos, int64_t* out);

void encode_string(std::string* out, const std::string& s);
void encode_byte_slice(std::string* out, const Bytes& b);
void encode_string_slice(std::string* out, const std::vector<std::string>& v);

extern const uint8_t kTypeDescriptors[112];

class Encoder {
  public:
    std::string encode(const Heartbeat& hb);
    void reset() { sent_types_ = false; }

  private:
    bool sent_types_ = false;
};

class Decoder {
  public:
    bool feed(const uint8_t* data, size_t len, std::vector<Heartbeat>* out, std::string* err);
    const std::string& error() const { return err_; }
    bool failed() const { return failed_; }

  private:
    std::string buf_;
    std::string err_;
    bool failed_ = false;
};

}  // namespace snake::gob
