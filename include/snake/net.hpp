#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "snake/crypto.hpp"

namespace snake::net {

struct TlsOptions {
    bool skip_verify = false;
    std::string ca_file;
    std::string fingerprint_hex;
    int timeout_seconds = 0;
};

class TlsClient {
  public:
    TlsClient();
    ~TlsClient();
    TlsClient(const TlsClient&) = delete;
    TlsClient& operator=(const TlsClient&) = delete;

    bool connect(const std::string& host, uint16_t port, const TlsOptions& opts);
    bool write_all(const uint8_t* data, size_t len);
    bool write_all(const Bytes& b);
    long read_some(uint8_t* buf, size_t len);
    void close();
    const std::string& error() const { return err_; }

  private:
    struct Impl;
    Impl* impl_ = nullptr;
    std::string err_;
};

struct HttpResponse {
    int status = 0;
    std::string body;
    std::map<std::string, std::string> headers;
};

using HeaderList = std::vector<std::pair<std::string, std::string>>;

std::string build_request_head(const std::string& method, const std::string& host, uint16_t port,
                               const std::string& path, const HeaderList& headers,
                               const std::string& body);

std::optional<HttpResponse> http_request(TlsClient& c, const std::string& method,
                                         const std::string& host, uint16_t port,
                                         const std::string& path, const HeaderList& headers,
                                         const std::string& body);

std::optional<HttpResponse> http_get_plain(const std::string& host, uint16_t port,
                                           const std::string& path, const HeaderList& headers,
                                           int timeout_seconds);

class WsClient {
  public:
    bool handshake(TlsClient& c, const std::string& host, uint16_t port, const std::string& path,
                   const HeaderList& extra_headers);
    bool send_binary(const Bytes& payload);
    std::optional<Bytes> recv_message();
    const std::string& error() const { return err_; }

  private:
    bool fill(size_t need);
    bool send_frame(uint8_t opcode, const Bytes& payload, bool masked);

    TlsClient* c_ = nullptr;
    Bytes pending_;
    std::string err_;
};

}  // namespace snake::net
