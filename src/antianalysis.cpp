#include "snake/antianalysis.hpp"

#include <cctype>
#include <cstdlib>

namespace snake {

namespace {

std::string lower_ascii(const std::string& s) {
    std::string out = s;
    for (char& c : out) c = (char)std::tolower((unsigned char)c);
    return out;
}

bool is_hex_digit(char c) { return std::isxdigit((unsigned char)c) != 0; }

std::string oui_of(const std::string& mac) {
    std::string hex;
    hex.reserve(mac.size());
    for (char c : mac) {
        if (is_hex_digit(c)) hex.push_back((char)std::tolower((unsigned char)c));
    }
    if (hex.size() < 6) return "";
    return hex.substr(0, 6);
}

const char* const kHypervisorOuis[] = {
    "000569",
    "000c29",
    "001c14",
    "005056",
    "005069",
    "080027",
    "0a0027",
    "00155d",
    "0003ff",
    "00163e",
    "001c42",
    "0021f6",
    "000f4b",
    "525400",
};

const char* const kToolNames[] = {
    "gdb", "lldb", "strace", "ltrace", "radare2", "rizin", "r2", "ida", "ida64", "ida32",
    "ghidra", "jd-gui", "x64dbg", "x32dbg", "ollydbg", "windbg", "dnspy", "pestudio",
    "scylla", "cheatengine", "frida", "frida-server", "apimonitor", "apispy",
    "wireshark", "tshark", "tcpdump", "rawcap", "fiddler", "mitmproxy", "burpsuite",
    "procmon", "procmon64", "procexp", "procexp64", "processhacker", "processhacker2",
    "tcpview", "autoruns", "autoruns64", "regmon", "filemon", "systeminformer",
    "cuckoo", "sandboxie", "sandboxiedcomlaunch", "sandboxierpcss", "joesandbox",
    "volatility", "dumpit", "bsa", "noriben", "fakenet", "inetsim", "capturebat",
    "vmwareuser", "vmtoolsd", "vboxservice", "vboxcontrol", "vboxtray", "vboxguest",
    "vmsrvc", "vmusrvc", "xenservice", "qemu-ga", "qemuwmi", "vgauthservice",
};

}  // namespace

bool analysis_policy_parse(const std::string& threshold_text, bool paranoid,
                           AnalysisPolicy& out, std::string& err) {
    out = AnalysisPolicy{};
    if (paranoid && !threshold_text.empty()) {
        err = "bad --analysis-threshold: cannot be combined with --analysis-paranoid";
        return false;
    }
    if (paranoid) {
        out.enabled = true;
        out.threshold = kParanoidThreshold;
        return true;
    }
    if (threshold_text.empty()) return true;

    for (char c : threshold_text) {
        if (std::isdigit((unsigned char)c) == 0) {
            err = "bad --analysis-threshold: must be a positive integer (1-1000)";
            return false;
        }
    }
    long v = std::strtol(threshold_text.c_str(), nullptr, 10);
    if (v < 1 || v > 1000) {
        err = "bad --analysis-threshold: must be a positive integer (1-1000)";
        return false;
    }
    out.enabled = true;
    out.threshold = (int)v;
    return true;
}

bool analysis_readings_from_spec(const std::string& spec, AnalysisReadings& out) {
    out = AnalysisReadings{};
    if (spec.empty()) return false;

    auto trim = [](const std::string& s) {
        size_t b = 0, e = s.size();
        while (b < e && std::isspace((unsigned char)s[b])) b++;
        while (e > b && std::isspace((unsigned char)s[e - 1])) e--;
        return s.substr(b, e - b);
    };

    size_t pos = 0;
    bool any = false;
    while (pos <= spec.size()) {
        size_t comma = spec.find(',', pos);
        std::string token = trim(spec.substr(pos, comma == std::string::npos ? std::string::npos
                                                                             : comma - pos));
        pos = (comma == std::string::npos) ? spec.size() + 1 : comma + 1;
        if (token.empty()) continue;

        size_t eq = token.find('=');
        if (eq == std::string::npos) return false;
        std::string key = trim(token.substr(0, eq));
        std::string val = trim(token.substr(eq + 1));
        if (key.empty() || val.empty()) return false;

        if (key == "uptime") {
            char* end = nullptr;
            long long v = std::strtoll(val.c_str(), &end, 10);
            if (end == nullptr || *end != '\0' || v < 0) return false;
            out.uptime_secs = v;
        } else if (key == "disk") {
            char* end = nullptr;
            double v = std::strtod(val.c_str(), &end);
            if (end == nullptr || *end != '\0' || !(v >= 0.0)) return false;
            out.disk_total_gb = v;
        } else if (key == "ram") {
            char* end = nullptr;
            long long v = std::strtoll(val.c_str(), &end, 10);
            if (end == nullptr || *end != '\0' || v < 0) return false;
            out.ram_total_mb = v;
        } else if (key == "cpu") {
            char* end = nullptr;
            long long v = std::strtoll(val.c_str(), &end, 10);
            if (end == nullptr || *end != '\0' || v < 0) return false;
            out.cpu_count = (int)v;
        } else if (key == "mac") {
            out.mac_addresses.push_back(val);
        } else if (key == "tool") {
            out.process_names.push_back(val);
        } else {
            return false;
        }
        any = true;
    }
    return any;
}

bool analysis_is_hypervisor_oui(const std::string& mac) {
    std::string oui = oui_of(mac);
    if (oui.empty()) return false;
    for (const char* known : kHypervisorOuis) {
        if (oui == known) return true;
    }
    return false;
}

bool analysis_is_tool_name(const std::string& name) {
    std::string base = lower_ascii(name);
    if (base.size() > 4 && base.compare(base.size() - 4, 4, ".exe") == 0) {
        base.resize(base.size() - 4);
    }
    if (base.empty()) return false;
    for (const char* known : kToolNames) {
        if (base == known) return true;
    }
    return false;
}

AnalysisVerdict analysis_verdict(const AnalysisReadings& r, const AnalysisPolicy& p) {
    AnalysisVerdict v;
    if (!p.enabled) return v;

    if (r.uptime_secs < 300) {
        v.score += analysis_weights::kUptimeUnder300;
        v.reasons.push_back("uptime " + std::to_string(r.uptime_secs) + "s (<300s) +" +
                            std::to_string(analysis_weights::kUptimeUnder300));
    } else if (r.uptime_secs < 600) {
        v.score += analysis_weights::kUptimeUnder600;
        v.reasons.push_back("uptime " + std::to_string(r.uptime_secs) + "s (<600s) +" +
                            std::to_string(analysis_weights::kUptimeUnder600));
    }

    if (r.disk_total_gb > 0.0 && r.disk_total_gb < 10.0) {
        v.score += analysis_weights::kDiskUnder10Gb;
        v.reasons.push_back("disk " + std::to_string(r.disk_total_gb) + "GB (<10GB) +" +
                            std::to_string(analysis_weights::kDiskUnder10Gb));
    } else if (r.disk_total_gb >= 10.0 && r.disk_total_gb < 20.0) {
        v.score += analysis_weights::kDiskUnder20Gb;
        v.reasons.push_back("disk " + std::to_string(r.disk_total_gb) + "GB (<20GB) +" +
                            std::to_string(analysis_weights::kDiskUnder20Gb));
    }

    if (r.ram_total_mb > 0 && r.ram_total_mb < 2048) {
        v.score += analysis_weights::kRamUnder2048Mb;
        v.reasons.push_back("ram " + std::to_string(r.ram_total_mb) + "MB (<2048MB) +" +
                            std::to_string(analysis_weights::kRamUnder2048Mb));
    } else if (r.ram_total_mb >= 2048 && r.ram_total_mb < 4096) {
        v.score += analysis_weights::kRamUnder4096Mb;
        v.reasons.push_back("ram " + std::to_string(r.ram_total_mb) + "MB (<4096MB) +" +
                            std::to_string(analysis_weights::kRamUnder4096Mb));
    }

    if (r.cpu_count < 2) {
        v.score += analysis_weights::kCpuUnder2;
        v.reasons.push_back("cpu " + std::to_string(r.cpu_count) + " (<2) +" +
                            std::to_string(analysis_weights::kCpuUnder2));
    }

    if (p.check_vm_oui) {
        bool matched = false;
        for (const std::string& mac : r.mac_addresses) {
            std::string oui = oui_of(mac);
            if (oui.empty() || !analysis_is_hypervisor_oui(mac)) continue;
            matched = true;
            v.reasons.push_back("hypervisor oui " + oui + " (" + mac + ") +" +
                                std::to_string(analysis_weights::kHypervisorOui));
        }
        if (matched) v.score += analysis_weights::kHypervisorOui;
    }

    if (p.check_tool_names) {
        bool matched = false;
        for (const std::string& name : r.process_names) {
            if (!analysis_is_tool_name(name)) continue;
            matched = true;
            v.reasons.push_back("analysis tool running: " + name + " +" +
                                std::to_string(analysis_weights::kAnalysisTool));
        }
        if (matched) v.score += analysis_weights::kAnalysisTool;
    }

    v.hostile = v.score >= p.threshold;
    return v;
}

}  // namespace snake
