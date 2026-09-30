#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace snake::http {

struct Request {
    std::string method;
    std::string path;
    std::string raw_path;
    std::string query;
    std::string version;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;

    std::string header(const std::string& name) const;
};

struct Response {
    int status = 200;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool hijacked = false;

    void set_header(const std::string& name, const std::string& value);
};

class Conn {
  public:
    virtual ~Conn() = default;
    virtual bool write_all(const uint8_t* data, size_t len) = 0;
    virtual long read_some(uint8_t* buf, size_t len) = 0;

    bool write_all(const std::string& s);
    bool write_all(const std::vector<uint8_t>& b) {
        return b.empty() ? true : write_all(b.data(), b.size());
    }
    bool read_exact(uint8_t* buf, size_t len);
    bool read_line(std::string* out, size_t max_len);
    const std::string& error() const { return err_; }

  protected:
    void set_error(const std::string& e) { if (err_.empty()) err_ = e; }
    std::vector<uint8_t> pending_;
    std::string err_;
};

using Handler = std::function<void(const Request&, Response&, Conn&)>;

class Server {
  public:
    Server() = default;
    ~Server();
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    void set_handler(Handler h) { handler_ = std::move(h); }

    bool listen(const std::string& addr, const std::string& cert_file,
                const std::string& key_file, std::string* err);
    void serve_forever();
    void stop();
    uint16_t port() const { return port_; }

    Response dispatch(const Request& req, Conn* conn);

  private:
    void handle_conn(int fd);

    Handler handler_;
    int listen_fd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::thread accept_thread_;
    std::vector<std::thread> workers_;
    std::mutex workers_mu_;
    void* ssl_ctx_ = nullptr;
};

const char* status_text(int code);

std::string html_escape(const std::string& s);

}  // namespace snake::http
