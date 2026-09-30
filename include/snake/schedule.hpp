#pragma once

#include <cstdint>
#include <string>

namespace snake {

struct WorkHours {
    int start_min = 0;
    int end_min = 0;
};

bool parse_work_hours(const std::string& text, WorkHours& out);

bool parse_work_days(const std::string& text, unsigned& out_mask);

struct SchedulePolicy {
    bool has_work_hours = false;
    WorkHours hours;
    bool has_work_days = false;
    unsigned days_mask = 0;
};

bool schedule_policy_parse(const std::string& work_hours, const std::string& work_days,
                           SchedulePolicy& out, std::string& err);

bool schedule_active(const SchedulePolicy& p, int weekday, int hour, int minute);

long long schedule_seconds_until_active(const SchedulePolicy& p, int weekday, int hour, int minute);

void schedule_local_now(int& weekday, int& hour, int& minute);

}  // namespace snake
