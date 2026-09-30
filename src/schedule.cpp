#include "snake/schedule.hpp"

#include <cctype>
#include <ctime>

namespace snake {

namespace {

constexpr int kMinutesPerDay = 1440;
constexpr int kDaysPerWeek = 7;
constexpr long long kMaxScanMinutes = static_cast<long long>(kDaysPerWeek) * kMinutesPerDay;

bool is_digit(char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; }

std::string lower_ascii(const std::string& s) {
    std::string out = s;
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool read_hhmm(const std::string& s, size_t& i, int& out_min) {
    if (i + 5 > s.size()) return false;
    if (!is_digit(s[i]) || !is_digit(s[i + 1])) return false;
    if (s[i + 2] != ':') return false;
    if (!is_digit(s[i + 3]) || !is_digit(s[i + 4])) return false;
    int hh = (s[i] - '0') * 10 + (s[i + 1] - '0');
    int mm = (s[i + 3] - '0') * 10 + (s[i + 4] - '0');
    if (hh > 23 || mm > 59) return false;
    i += 5;
    out_min = hh * 60 + mm;
    return true;
}

bool day_token(const std::string& raw, int& out_day) {
    std::string tok = lower_ascii(raw);
    if (tok.empty()) return false;
    bool all_digits = true;
    for (char c : tok) {
        if (!is_digit(c)) {
            all_digits = false;
            break;
        }
    }
    if (all_digits) {
        if (tok.size() > 1) return false;
        int d = tok[0] - '0';
        if (d < 0 || d >= kDaysPerWeek) return false;
        out_day = d;
        return true;
    }
    static const char* kNames[kDaysPerWeek] = {"sunday",  "monday", "tuesday",
                                               "wednesday", "thursday", "friday", "saturday"};
    for (int d = 0; d < kDaysPerWeek; d++) {
        const std::string full = kNames[d];
        if (tok.size() == 3 ? full.compare(0, 3, tok) == 0 : full == tok) {
            out_day = d;
            return true;
        }
    }
    return false;
}

}  // namespace

bool parse_work_hours(const std::string& text, WorkHours& out) {
    size_t i = 0;
    int start = 0, end = 0;
    if (!read_hhmm(text, i, start)) return false;
    if (i >= text.size() || text[i] != '-') return false;
    i++;
    if (!read_hhmm(text, i, end)) return false;
    if (i != text.size()) return false;
    if (start == end) return false;
    out.start_min = start;
    out.end_min = end;
    return true;
}

bool parse_work_days(const std::string& text, unsigned& out_mask) {
    unsigned mask = 0;
    size_t i = 0;
    while (i < text.size()) {
        size_t comma = text.find(',', i);
        size_t end = (comma == std::string::npos) ? text.size() : comma;
        std::string tok = text.substr(i, end - i);
        if (tok.empty()) return false;
        size_t dash = tok.find('-');
        if (dash == std::string::npos) {
            int d = 0;
            if (!day_token(tok, d)) return false;
            mask |= 1u << d;
        } else {
            std::string a = tok.substr(0, dash);
            std::string b = tok.substr(dash + 1);
            int da = 0, db = 0;
            if (a.empty() || b.empty() || !day_token(a, da) || !day_token(b, db)) return false;
            if (da > db) return false;
            for (int d = da; d <= db; d++) mask |= 1u << d;
        }
        if (comma == std::string::npos) break;
        i = comma + 1;
        if (i >= text.size()) return false;
    }
    if (mask == 0) return false;
    out_mask = mask;
    return true;
}

bool schedule_policy_parse(const std::string& work_hours, const std::string& work_days,
                          SchedulePolicy& out, std::string& err) {
    out = SchedulePolicy{};
    err.clear();
    if (!work_hours.empty()) {
        WorkHours h;
        if (!parse_work_hours(work_hours, h)) {
            err = "bad --work-hours: want HH:MM-HH:MM (local time, e.g. 09:00-17:00)";
            return false;
        }
        out.has_work_hours = true;
        out.hours = h;
    }
    if (!work_days.empty()) {
        unsigned mask = 0;
        if (!parse_work_days(work_days, mask)) {
            err = "bad --work-days: want day names or 0-6 (0=Sun), e.g. mon-fri or sat,sun";
            return false;
        }
        out.has_work_days = true;
        out.days_mask = mask;
    }
    return true;
}

bool schedule_active(const SchedulePolicy& p, int weekday, int hour, int minute) {
    const int mod = hour * 60 + minute;
    bool in_hours = true;
    bool wrapping_tail = false;
    if (p.has_work_hours) {
        if (p.hours.start_min < p.hours.end_min) {
            in_hours = mod >= p.hours.start_min && mod < p.hours.end_min;
        } else {
            in_hours = mod >= p.hours.start_min || mod < p.hours.end_min;
            wrapping_tail = mod < p.hours.end_min;
        }
    }
    bool day_ok = true;
    if (p.has_work_days) {
        int owner = weekday;
        if (wrapping_tail) owner = (weekday + kDaysPerWeek - 1) % kDaysPerWeek;
        day_ok = ((p.days_mask >> owner) & 1u) != 0;
    }
    return in_hours && day_ok;
}

long long schedule_seconds_until_active(const SchedulePolicy& p, int weekday, int hour, int minute) {
    if (schedule_active(p, weekday, hour, minute)) return 0;
    const int mod = hour * 60 + minute;
    for (long long k = 1; k <= kMaxScanMinutes; k++) {
        const int abs_min = mod + static_cast<int>(k);
        const int m = abs_min % kMinutesPerDay;
        const int w = (weekday + abs_min / kMinutesPerDay) % kDaysPerWeek;
        if (schedule_active(p, w, m / 60, m % 60)) return k * 60;
    }
    return kMaxScanMinutes * 60;
}

void schedule_local_now(int& weekday, int& hour, int& minute) {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    std::tm* tp = std::localtime(&t);
    if (tp != nullptr) tmv = *tp;
    weekday = tmv.tm_wday;
    hour = tmv.tm_hour;
    minute = tmv.tm_min;
}

}  // namespace snake
