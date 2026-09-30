#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "snake/cert.hpp"
#include "snake/crypto.hpp"
#include "snake/gob.hpp"

namespace snake::mesh {

struct PeerInfo {
    std::string id;
    std::string addr;
    int implants = 0;
    std::string version;
};

bool generate_mesh_cert(const std::string& node_id, cert::KeyMaterial* out, std::string* err);

std::string heartbeat_payload(const gob::Heartbeat& hb);

Bytes sign_heartbeat(const Bytes& seed, const gob::Heartbeat& hb);
bool verify_heartbeat(const Bytes& pub, const gob::Heartbeat& hb);

struct Config {
    std::string node_id;
    std::string listen_addr;
    std::vector<std::string> bootstrap;
    cert::KeyMaterial tls;
    bool signing = false;
    Bytes signing_seed;
    std::function<void(const gob::Heartbeat&)> on_heartbeat;
    std::function<void(const PeerInfo&)> on_peer_join;
    std::function<void(const std::string&)> on_peer_leave;
    int heartbeat_interval_ms = 30000;
};

class Node {
  public:
    explicit Node(Config cfg);
    ~Node();
    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    bool start(std::string* err);
    void stop();
    std::vector<std::string> peers();
    size_t peer_count();
    uint16_t port() const { return port_; }

    size_t broadcast_heartbeat();

  private:
    struct Peer;
    struct Conn;

    void accept_loop();
    void heartbeat_loop();
    void handle_peer(std::shared_ptr<Conn> conn);
    void dial_peer(const std::string& addr);

    Config cfg_;
    void* ssl_ctx_ = nullptr;
    int listen_fd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::mutex mu_;
    std::map<std::string, std::shared_ptr<Peer>> peers_;
    std::vector<std::thread> workers_;
    std::thread accept_thread_;
    std::thread heartbeat_thread_;
    std::vector<std::thread> dial_threads_;
};

}  // namespace snake::mesh
