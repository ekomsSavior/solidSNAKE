#include "snake/runner.hpp"

#include <cstdio>
#include <string>
#include <vector>

#include "snake/payloads.hpp"

namespace snake::runner {

namespace {

std::string pad(const std::string& s, size_t width) {
    std::string out = s;
    while (out.size() < width) out.push_back(' ');
    return out;
}

}  // namespace

std::string banner() { return "solidSNAKE - C++17 Payloads"; }

std::string help_text() {
    std::string out = banner() + "\n\n";
    out += "Usage: payloads <payload_name> [--arg key=value ...]\n";
    out += "       payloads --list\n";
    out += "       payloads --help\n\n";
    out += "Available payloads:\n";
    for (const auto& p : payloads::InfoList()) {
        out += "  " + pad(p.name, 20) + " [" + pad(p.category, 12) + "] " + p.description + "\n";
    }
    return out;
}

Parsed parse_args(const std::vector<std::string>& argv) {
    Parsed out;
    if (argv.empty()) {
        out.mode = Mode::kHelp;
        return out;
    }
    const std::string& first = argv[0];
    if (first == "--help" || first == "-h") {
        out.mode = Mode::kHelp;
        return out;
    }
    if (first == "--list" || first == "--info") {
        out.mode = Mode::kList;
        return out;
    }
    out.mode = Mode::kExec;
    out.name = first;
    for (size_t i = 1; i < argv.size(); ++i) {
        const std::string& a = argv[i];
        std::string kv;
        if (a.rfind("--arg=", 0) == 0) {
            kv = a.substr(6);
        } else if (a.rfind("--", 0) == 0) {
            kv = a.substr(2);
        } else if (a.find('=') != std::string::npos) {
            kv = a;
        } else {
            continue;
        }
        size_t eq = kv.find('=');
        if (eq == std::string::npos) continue;
        out.args[kv.substr(0, eq)] = kv.substr(eq + 1);
    }
    return out;
}

int runner_main(int argc, char** argv) {
    Parsed p = parse_args(std::vector<std::string>(argv + 1, argv + argc));
    if (p.mode == Mode::kHelp) {
        std::fputs(help_text().c_str(), stdout);
        return 0;
    }
    if (p.mode == Mode::kList) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& info : payloads::InfoList()) {
            nlohmann::json o;
            o["name"] = info.name;
            o["category"] = info.category;
            o["description"] = info.description;
            arr.push_back(o);
        }
        std::fputs((payloads::MarshalJSON(arr) + "\n").c_str(), stdout);
        return 0;
    }
    try {
        std::fputs((payloads::ExecuteByName(p.name, p.args) + "\n").c_str(), stdout);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
    return 0;
}

}  // namespace snake::runner
