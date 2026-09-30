#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CXX="${MINGW_CXX:-x86_64-w64-mingw32-g++}"
OUT="${TMPDIR:-/tmp}/snake-winstealth"
CFLAGS="-std=c++17 -O2 -Wall -Wextra -Wpedantic -I$ROOT/include -D_WIN32_WINNT=0x0601"

say()  { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

FAIL=0
ok()  { say "PASS  $*"; }
bad() { say "FAIL  $*"; FAIL=1; }

if ! have "$CXX"; then
	say "SKIP  windows/amd64 stealth check: $CXX not installed (apt install g++-mingw-w64-x86-64)"
	exit 0
fi

SENSITIVE=(
	NtAllocateVirtualMemory NtProtectVirtualMemory NtCreateThreadEx NtQueryVirtualMemory
	NtFreeVirtualMemory NtWriteVirtualMemory VirtualLock VirtualUnlock VirtualProtect
	GetSystemInfo
)

EVADE_NAMES=(AmsiScanBuffer EtwEventWrite LoadLibraryA)

mkdir -p "$OUT"
TUS=(src/winstealth.cpp src/winstealth_windows.cpp src/evade.cpp src/evade_windows.cpp \
     tests/winstealth_scratch.cpp)

say "== compile check (mingw, -Wall -Wextra -Wpedantic) =="
for tu in "${TUS[@]}"; do
	obj="$OUT/$(basename "$tu" .cpp).o"
	if "$CXX" $CFLAGS -c "$ROOT/$tu" -o "$obj" 2>"$OUT/cc.log"; then
		ok "compiled $tu"
	else
		bad "compiling $tu"; cat "$OUT/cc.log"
	fi
done

say "== sleepmask Win32 arm (the item-6 consumer) =="
if [ -f /usr/include/sodium.h ]; then
	SHIM="${TMPDIR:-/tmp}/snake-sodium-headers"
	rm -rf "$SHIM"
	mkdir -p "$SHIM"
	cp /usr/include/sodium.h "$SHIM/" && cp -r /usr/include/sodium "$SHIM/"
	if "$CXX" $CFLAGS -isystem "$SHIM" -c "$ROOT/src/sleepmask.cpp" -o "$OUT/sleepmask.o" \
		2>"$OUT/cc.log"; then
		ok "compiled src/sleepmask.cpp (Win32 arm) under mingw"
	else
		bad "compiling src/sleepmask.cpp under mingw"; cat "$OUT/cc.log"
	fi
else
	say "SKIP  src/sleepmask.cpp Win32 arm: no host libsodium headers to borrow"
fi

say "== our objects: no import thunk, no plaintext name =="
for tu in "${TUS[@]}"; do
	obj="$OUT/$(basename "$tu" .cpp).o"
	[ -f "$obj" ] || continue
	for name in "${SENSITIVE[@]}" "${EVADE_NAMES[@]}"; do
		if objdump -t "$obj" 2>/dev/null | grep -qE "[[:space:]]_+imp_${name}$"; then
			bad "$tu references the import thunk for $name"
		fi
		if strings -n 6 "$obj" 2>/dev/null | grep -qF "$name"; then
			bad "$tu carries the plaintext name $name"
		fi
	done
done
ok "winstealth/evade objects carry no static import and no plaintext name"

say "== scratch PE =="
if ! "$CXX" $CFLAGS "$ROOT/src/winstealth.cpp" "$ROOT/src/winstealth_windows.cpp" \
	"$ROOT/src/evade.cpp" "$ROOT/src/evade_windows.cpp" \
	"$ROOT/tests/winstealth_scratch.cpp" -o "$OUT/winstealth-scratch.exe" 2>"$OUT/link.log"; then
	bad "linking the scratch PE"; cat "$OUT/link.log"
	say "== cannot continue without the scratch PE =="
	exit 1
fi
ok "linked the scratch PE"
printf 'int main() { return 0; }\n' > "$OUT/baseline.cpp"
if ! "$CXX" $CFLAGS "$OUT/baseline.cpp" -o "$OUT/baseline.exe" 2>"$OUT/link.log"; then
	bad "linking the baseline PE"; cat "$OUT/link.log"
else
	ok "linked the baseline PE (mingw CRT reference)"
fi
file "$OUT/winstealth-scratch.exe" | sed 's/^/      /'

SCRATCH_STRINGS="$OUT/scratch.strings"
BASE_STRINGS="$OUT/baseline.strings"
strings -n 6 "$OUT/winstealth-scratch.exe" > "$SCRATCH_STRINGS" 2>/dev/null
strings -n 6 "$OUT/baseline.exe" > "$BASE_STRINGS" 2>/dev/null

RESIDUAL=0
for name in "${SENSITIVE[@]}" "${EVADE_NAMES[@]}"; do
	if grep -qF "$name" "$SCRATCH_STRINGS"; then
		if grep -qF "$name" "$BASE_STRINGS"; then
			say "      note: $name is carried by the mingw CRT itself (present in the baseline)"
		else
			bad "$name was introduced by the scratch PE - not dynamically resolved"
			RESIDUAL=1
		fi
	else
		ok "$name is absent from the scratch PE"
	fi
done
[ "$RESIDUAL" -eq 0 ] && ok "the scratch PE adds no sensitive name over the CRT baseline"

say "== source literals (every occurrence must sit inside SNAKE_OBF) =="
for src in src/winstealth.cpp src/winstealth_windows.cpp src/evade.cpp src/evade_windows.cpp \
	src/sleepmask.cpp include/snake/winstealth.hpp include/snake/evade.hpp; do
	for name in "${SENSITIVE[@]}" "${EVADE_NAMES[@]}"; do
		while IFS= read -r line; do
			[ -z "$line" ] && continue
			case "$line" in
				*"SNAKE_OBF(\"$name\")"*) : ;;
				*) bad "$src has an unmasked \"$name\" literal: $line" ;;
			esac
		done < <(grep -n "\"$name\"" "$ROOT/$src" | cut -d: -f2-)
	done
done
ok "source scan finished"

say "== summary =="
if [ "$FAIL" -eq 0 ]; then
	say "PASS  windows/amd64 stealth v1 + AMSI/ETW: clean compile, no sensitive import, no plaintext name"
	exit 0
fi
say "FAIL  windows/amd64 stealth v1 + AMSI/ETW (see above)"
exit 1
