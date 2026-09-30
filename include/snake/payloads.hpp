#pragma once

#include <cstdint>
#include <ctime>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "snake/crypto.hpp"

namespace snake::payloads {

using Args = std::map<std::string, std::string>;
using Output = Bytes;

class PayloadError : public std::runtime_error {
  public:
    explicit PayloadError(const std::string& what) : std::runtime_error(what) {}
};

class Payload {
  public:
    virtual ~Payload() = default;
    virtual const char* name() const = 0;
    virtual const char* category() const = 0;
    virtual const char* description() const = 0;
    virtual Output execute(const Args& args) const = 0;
};

void Register(Payload* p);
Payload* Get(const std::string& name);
std::vector<Payload*> List();

struct Info {
    std::string name;
    std::string category;
    std::string description;
};
std::vector<Info> InfoList();

std::string ExecuteByName(const std::string& name, const Args& args);

Args ExecuteTaskArgs(const nlohmann::json& payload);
Args ExecuteTaskArgs(const std::map<std::string, std::string>& payload);

std::string MarshalJSON(const nlohmann::json& v);

struct HttpResponse {
    int status = 0;
    std::string body;
    bool ok = false;
};
using Headers = std::vector<std::pair<std::string, std::string>>;
HttpResponse http_request(const std::string& method, const std::string& url, const Headers& headers);
HttpResponse http_get(const std::string& url, const Headers& headers);

std::string file_owner(const std::string& path);
bool disk_space(const std::string& path, uint64_t& total, uint64_t& free);
bool kill_process(int pid);

struct CmdResult {
    std::string out;
    int exit_code = -1;
    bool ok = false;
    std::string err;
};
CmdResult run_cmd(const std::string& cmd);
CmdResult run_cmd_out(const std::vector<std::string>& argv);
std::string which_exe(const std::string& name);
CmdResult run_cmd_ctx(const std::vector<std::string>& argv, int timeout_seconds);
CmdResult run_argv_stdin(const std::vector<std::string>& argv, const std::string& input);
CmdResult run_argv_combined(const std::vector<std::string>& argv);

bool safe_mode();

bool path_exists(const std::string& path, bool& is_dir);
bool mut_mkdir_p(const std::string& path, unsigned mode);
bool mut_write(const std::string& path, const std::string& data, unsigned mode);
bool mut_append(const std::string& path, const std::string& data, unsigned mode);
bool mut_chmod(const std::string& path, unsigned mode);
bool mut_chtimes(const std::string& path, std::time_t t);
bool mut_truncate(const std::string& path);
CmdResult mut_run_argv(const std::vector<std::string>& argv);
CmdResult mut_run_shell(const std::string& cmd);
CmdResult mut_run_argv_combined(const std::vector<std::string>& argv);
bool mut_remove_all(const std::string& path);
bool mut_remove(const std::string& path);
bool mut_kill_process(int pid);
CmdResult mut_run_argv_stdin(const std::vector<std::string>& argv, const std::string& input);
bool mut_ptrace_attach(int pid, int& err);

std::string now_rfc3339();
std::string local_rfc3339();
std::string prog_argv0();
std::string errno_text(int err);
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char sep);
bool read_file(const std::string& path, std::string& out);
std::string hostname_now();

}  // namespace snake::payloads
