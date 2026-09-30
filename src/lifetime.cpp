#include "snake/lifetime.hpp"

#include <cctype>
#include <cstdlib>
#include <limits>

#include <sodium.h>

namespace snake {

namespace {

constexpr long long kMaxNanos = 9223372036854775807LL;
constexpr long long kSecNanos = 1000000000LL;

long long unit_nanos(const std::string& u) {
    if (u == "ns") return 1LL;
    if (u == "us") return 1000LL;
    if (u == "ms") return 1000000LL;
    if (u == "s") return kSecNanos;
    if (u == "m") return 60LL * kSecNanos;
    if (u == "h") return 3600LL * kSecNanos;
    return 0;
}

bool is_digit(char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; }

long long days_from_civil(long long y, unsigned m, unsigned d) {
    y -= (m <= 2);
    const long long era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u;
    const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097LL + static_cast<long long>(doe) - 719468LL;
}

bool is_leap(long long y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

unsigned days_in_month(long long y, unsigned m) {
    static const unsigned lens[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (m == 2 && is_leap(y)) return 29;
    return lens[m - 1];
}

bool read_digits(const std::string& s, size_t& i, size_t n, long long& out) {
    if (i + n > s.size()) return false;
    long long v = 0;
    for (size_t k = 0; k < n; k++) {
        char c = s[i + k];
        if (!is_digit(c)) return false;
        v = v * 10 + static_cast<long long>(c - '0');
    }
    i += n;
    out = v;
    return true;
}

long double frac_value(const std::string& frac) {
    long double v = 0.0L;
    long double scale = 0.1L;
    for (char c : frac) {
        v += static_cast<long double>(c - '0') * scale;
        scale *= 0.1L;
    }
    return v;
}

}  // namespace

bool parse_duration_secs(const std::string& text, long long& out_secs) {
    if (text.empty()) return false;
    size_t i = 0;
    bool neg = false;
    if (text[i] == '+' || text[i] == '-') {
        neg = (text[i] == '-');
        i++;
    }
    if (i >= text.size()) return false;

    long long acc = 0;
    bool any = false;
    while (i < text.size()) {
        size_t digits_start = i;
        while (i < text.size() && is_digit(text[i])) i++;
        if (i == digits_start) return false;
        unsigned long long intpart = 0;
        for (size_t k = digits_start; k < i; k++) {
            unsigned long long digit = static_cast<unsigned long long>(text[k] - '0');
            if (intpart > (std::numeric_limits<unsigned long long>::max() - digit) / 10u)
                return false;
            intpart = intpart * 10u + digit;
        }
        std::string frac;
        if (i < text.size() && text[i] == '.') {
            i++;
            size_t fs = i;
            while (i < text.size() && is_digit(text[i])) i++;
            if (i == fs) return false;
            frac = text.substr(fs, i - fs);
        }
        size_t unit_start = i;
        while (i < text.size() && std::isalpha(static_cast<unsigned char>(text[i]))) i++;
        long long mult = unit_nanos(text.substr(unit_start, i - unit_start));
        if (mult == 0) return false;

        if (intpart > static_cast<unsigned long long>(kMaxNanos / mult)) return false;
        long long whole = static_cast<long long>(intpart) * mult;
        if (acc > kMaxNanos - whole) return false;

        long long extra = 0;
        if (!frac.empty()) {
            long double sub = frac_value(frac) * static_cast<long double>(mult);
            if (sub >= static_cast<long double>(kMaxNanos)) return false;
            extra = static_cast<long long>(sub);
        }
        if (acc + whole > kMaxNanos - extra) return false;
        acc += whole + extra;
        any = true;
    }
    if (!any) return false;

    out_secs = neg ? -(acc / kSecNanos) : (acc / kSecNanos);
    return true;
}

bool parse_kill_date_utc(const std::string& text, long long& out_epoch) {
    size_t i = 0;
    long long year = 0, month = 0, day = 0, hour = 0, minute = 0;
    if (!read_digits(text, i, 4, year)) return false;
    if (i >= text.size() || text[i] != '-') return false;
    i++;
    if (!read_digits(text, i, 2, month)) return false;
    if (i >= text.size() || text[i] != '-') return false;
    i++;
    if (!read_digits(text, i, 2, day)) return false;
    if (i < text.size()) {
        if (text[i] != 'T') return false;
        i++;
        if (!read_digits(text, i, 2, hour)) return false;
        if (i >= text.size() || text[i] != ':') return false;
        i++;
        if (!read_digits(text, i, 2, minute)) return false;
    }
    if (i != text.size()) return false;
    if (year < 1970 || month < 1 || month > 12) return false;
    if (day < 1 || day > static_cast<long long>(days_in_month(year, static_cast<unsigned>(month))))
        return false;
    if (hour > 23 || minute > 59) return false;

    long long days = days_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
    out_epoch = days * 86400LL + hour * 3600LL + minute * 60LL;
    return true;
}

bool lifetime_policy_parse(const std::string& kill_date, const std::string& max_runtime,
                           LifetimePolicy& out, std::string& err) {
    out = LifetimePolicy{};
    err.clear();
    if (!kill_date.empty()) {
        long long epoch = 0;
        if (!parse_kill_date_utc(kill_date, epoch)) {
            err = "bad --kill-date: want YYYY-MM-DD or YYYY-MM-DDTHH:MM (UTC)";
            return false;
        }
        out.has_kill_date = true;
        out.kill_date_epoch = epoch;
    }
    if (!max_runtime.empty()) {
        long long secs = 0;
        if (!parse_duration_secs(max_runtime, secs)) {
            err = "bad --max-runtime: want a duration such as 90s, 30m or 1h30m";
            return false;
        }
        out.has_max_runtime = true;
        out.max_runtime_secs = secs;
    }
    return true;
}

std::string lifetime_expiry_reason(const LifetimePolicy& p, long long now, long long start) {
    if (p.has_kill_date && now >= p.kill_date_epoch) return "kill date reached";
    if (p.has_max_runtime && now - start >= p.max_runtime_secs) return "max runtime exceeded";
    return "";
}

void zeroize(Bytes& b) {
    if (b.empty()) return;
    sodium_memzero(b.data(), b.size());
    b.clear();
}

}  // namespace snake
