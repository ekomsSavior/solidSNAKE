#include "snake/gob.hpp"

#include <cstring>

namespace snake::gob {

namespace {

constexpr int64_t kTypeId = 64;

}  // namespace

const uint8_t kTypeDescriptors[112] = {
    0x58, 0x7f, 0x03, 0x01, 0x01, 0x0d, 0x4d, 0x65, 0x73, 0x68, 0x48, 0x65, 0x61, 0x72, 0x74, 0x62,
    0x65, 0x61, 0x74, 0x01, 0xff, 0x80, 0x00, 0x01, 0x05, 0x01, 0x06, 0x4e, 0x6f, 0x64, 0x65, 0x49,
    0x44, 0x01, 0x0c, 0x00, 0x01, 0x04, 0x41, 0x64, 0x64, 0x72, 0x01, 0x0c, 0x00, 0x01, 0x08, 0x49,
    0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x73, 0x01, 0xff, 0x82, 0x00, 0x01, 0x09, 0x54, 0x69, 0x6d,
    0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x01, 0x04, 0x00, 0x01, 0x09, 0x53, 0x69, 0x67, 0x6e, 0x61,
    0x74, 0x75, 0x72, 0x65, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x16, 0xff, 0x81, 0x02, 0x01, 0x01, 0x08,
    0x5b, 0x5d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x01, 0xff, 0x82, 0x00, 0x01, 0x0c, 0x00, 0x00,
};

void encode_uint(std::string* out, uint64_t x) {
    if (x <= 0x7F) {
        out->push_back(static_cast<char>(x));
        return;
    }
    uint8_t be[8];
    for (int i = 0; i < 8; ++i) be[i] = static_cast<uint8_t>((x >> (8 * (7 - i))) & 0xFF);
    int nz = 0;
    while (nz < 8 && be[nz] == 0) ++nz;
    int nbytes = 8 - nz;
    out->push_back(static_cast<char>(static_cast<uint8_t>(256 - nbytes)));
    out->append(reinterpret_cast<const char*>(be + nz), static_cast<size_t>(nbytes));
}

void encode_int(std::string* out, int64_t i) {
    uint64_t x;
    if (i < 0) {
        x = (static_cast<uint64_t>(~i) << 1) | 1;
    } else {
        x = static_cast<uint64_t>(i) << 1;
    }
    encode_uint(out, x);
}

bool decode_uint(const uint8_t* buf, size_t len, size_t* pos, uint64_t* out) {
    if (*pos >= len) return false;
    uint8_t b = buf[(*pos)++];
    if (b <= 0x7F) {
        *out = b;
        return true;
    }
    size_t n = static_cast<size_t>(256 - b);
    if (n > 8 || *pos + n > len) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | buf[(*pos)++];
    *out = v;
    return true;
}

bool decode_int(const uint8_t* buf, size_t len, size_t* pos, int64_t* out) {
    uint64_t u = 0;
    if (!decode_uint(buf, len, pos, &u)) return false;
    if (u & 1) {
        *out = static_cast<int64_t>(~(u >> 1));
    } else {
        *out = static_cast<int64_t>(u >> 1);
    }
    return true;
}

void encode_string(std::string* out, const std::string& s) {
    encode_uint(out, s.size());
    out->append(s);
}

void encode_byte_slice(std::string* out, const Bytes& b) {
    encode_uint(out, b.size());
    out->append(reinterpret_cast<const char*>(b.data()), b.size());
}

void encode_string_slice(std::string* out, const std::vector<std::string>& v) {
    encode_uint(out, v.size());
    for (const std::string& s : v) encode_string(out, s);
}

std::string Encoder::encode(const Heartbeat& hb) {
    std::string body;
    encode_int(&body, kTypeId);
    int64_t last_field = 0;
    auto field = [&](int64_t id, const std::string& value) {
        encode_uint(&body, static_cast<uint64_t>(id - last_field));
        last_field = id;
        body += value;
    };
    if (!hb.node_id.empty()) {
        std::string v;
        encode_string(&v, hb.node_id);
        field(1, v);
    }
    if (!hb.addr.empty()) {
        std::string v;
        encode_string(&v, hb.addr);
        field(2, v);
    }
    if (!hb.implants.empty()) {
        std::string v;
        encode_string_slice(&v, hb.implants);
        field(3, v);
    }
    if (hb.timestamp != 0) {
        std::string v;
        encode_int(&v, hb.timestamp);
        field(4, v);
    }
    if (!hb.signature.empty()) {
        std::string v;
        encode_byte_slice(&v, hb.signature);
        field(5, v);
    }
    body.push_back('\0');

    std::string out;
    if (!sent_types_) {
        out.append(reinterpret_cast<const char*>(kTypeDescriptors), sizeof(kTypeDescriptors));
        sent_types_ = true;
    }
    encode_uint(&out, body.size());
    out += body;
    return out;
}

namespace {

bool parse_message(const uint8_t* b, size_t len, Heartbeat* hb, bool* has_value, std::string* err) {
    size_t pos = 0;
    int64_t id = 0;
    if (!decode_int(b, len, &pos, &id)) {
        *err = "truncated gob type id";
        return false;
    }
    *has_value = false;
    if (id < 0) return true;
    int64_t fieldnum = 0;
    for (;;) {
        uint64_t delta = 0;
        if (!decode_uint(b, len, &pos, &delta)) {
            *err = "truncated gob field delta";
            return false;
        }
        if (delta == 0) break;
        fieldnum += static_cast<int64_t>(delta);
        switch (fieldnum) {
            case 1:
            case 2: {
                uint64_t n = 0;
                if (!decode_uint(b, len, &pos, &n) || pos + n > len) {
                    *err = "truncated gob string";
                    return false;
                }
                std::string s(reinterpret_cast<const char*>(b + pos), static_cast<size_t>(n));
                pos += n;
                if (fieldnum == 1) hb->node_id = s;
                else hb->addr = s;
                break;
            }
            case 3: {
                uint64_t n = 0;
                if (!decode_uint(b, len, &pos, &n)) {
                    *err = "truncated gob slice length";
                    return false;
                }
                hb->implants.clear();
                for (uint64_t i = 0; i < n; ++i) {
                    uint64_t sl = 0;
                    if (!decode_uint(b, len, &pos, &sl) || pos + sl > len) {
                        *err = "truncated gob slice element";
                        return false;
                    }
                    hb->implants.emplace_back(reinterpret_cast<const char*>(b + pos),
                                              static_cast<size_t>(sl));
                    pos += sl;
                }
                break;
            }
            case 4: {
                int64_t ts = 0;
                if (!decode_int(b, len, &pos, &ts)) {
                    *err = "truncated gob timestamp";
                    return false;
                }
                hb->timestamp = ts;
                break;
            }
            case 5: {
                uint64_t n = 0;
                if (!decode_uint(b, len, &pos, &n) || pos + n > len) {
                    *err = "truncated gob byte slice";
                    return false;
                }
                hb->signature.assign(b + pos, b + pos + n);
                pos += n;
                break;
            }
            default:
                *err = "unknown gob field " + std::to_string(fieldnum);
                return false;
        }
    }
    *has_value = true;
    return true;
}

}  // namespace

bool Decoder::feed(const uint8_t* data, size_t len, std::vector<Heartbeat>* out, std::string* err) {
    if (failed_) {
        if (err) *err = err_;
        return false;
    }
    buf_.append(reinterpret_cast<const char*>(data), len);
    size_t pos = 0;
    for (;;) {
        size_t p = pos;
        uint64_t mlen = 0;
        if (!decode_uint(reinterpret_cast<const uint8_t*>(buf_.data()), buf_.size(), &p, &mlen)) {
            break;
        }
        if (p + mlen > buf_.size()) break;
        Heartbeat hb;
        bool has_value = false;
        std::string perr;
        if (!parse_message(reinterpret_cast<const uint8_t*>(buf_.data()) + p,
                           static_cast<size_t>(mlen), &hb, &has_value, &perr)) {
            failed_ = true;
            err_ = perr;
            if (err) *err = err_;
            return false;
        }
        if (has_value) out->push_back(hb);
        pos = p + static_cast<size_t>(mlen);
    }
    buf_.erase(0, pos);
    return true;
}

}  // namespace snake::gob
