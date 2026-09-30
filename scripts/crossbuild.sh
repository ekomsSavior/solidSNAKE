#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CROSS_ROOT="${CROSS_ROOT:-/tmp/snake-cross}"
SRC_DL="$CROSS_ROOT/dl"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

say()  { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

record() {
	RESULTS+=("$(printf '%-7s %-16s %s' "$1" "$2" "$3")")
	case "$1" in
		PASS) PASS=$((PASS + 1)) ;;
		FAIL) FAIL=$((FAIL + 1)) ;;
		SKIP) SKIP=$((SKIP + 1)) ;;
	esac
}

deps_ready() {
	local p="$1"
	[ -f "$p/include/sodium.h" ] && [ -f "$p/include/openssl/ssl.h" ] || return 1
	{ [ -f "$p/lib/libssl.a" ] || [ -f "$p/lib64/libssl.a" ]; } || return 1
	{ [ -f "$p/lib/libsodium.a" ] || [ -f "$p/lib64/libsodium.a" ]; } || return 1
	return 0
}

ensure_arm64_deps() {
	have aarch64-linux-gnu-g++ || return 1
	ensure_deps arm64 aarch64-linux-gnu aarch64-linux-gnu aarch64-linux-gnu-
}

ensure_win64_deps() {
	have x86_64-w64-mingw32-g++ || return 1
	ensure_deps win64 x86_64-w64-mingw32 mingw64 x86_64-w64-mingw32-
}

ensure_deps() {
	local tag="$1" host="$2" ossltarget="$3" xprefix="$4"
	local p="$CROSS_ROOT/$tag" s="$CROSS_ROOT/src-$tag"
	deps_ready "$p" && return 0
	mkdir -p "$SRC_DL" "$s"
	[ -f "$SRC_DL/libsodium-1.0.20.tar.gz" ] \
		|| curl -sSL --retry 3 -o "$SRC_DL/libsodium-1.0.20.tar.gz" \
			https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz || return 1
	[ -f "$SRC_DL/openssl-3.5.7.tar.gz" ] \
		|| curl -sSL --retry 3 -o "$SRC_DL/openssl-3.5.7.tar.gz" \
			https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz || return 1
	[ -d "$s/libsodium-1.0.20" ] || tar xf "$SRC_DL/libsodium-1.0.20.tar.gz" -C "$s" || return 1
	[ -d "$s/openssl-3.5.7" ] || tar xf "$SRC_DL/openssl-3.5.7.tar.gz" -C "$s" || return 1
	(cd "$s/libsodium-1.0.20" \
		&& ./configure --host="$host" --prefix="$p" --disable-shared --enable-static \
			>/dev/null 2>&1 && make -j"$(nproc)" >/dev/null 2>&1 && make install >/dev/null 2>&1) || return 1
	(cd "$s/openssl-3.5.7" \
		&& ./Configure "$ossltarget" --cross-compile-prefix="$xprefix" --prefix="$p" \
			--openssldir="$p/ssl" no-shared no-tests >/dev/null 2>&1 \
		&& make -j"$(nproc)" >/dev/null 2>&1 && make install_sw >/dev/null 2>&1) || return 1
	deps_ready "$p"
}

cross_make() {
	local triple="$1" cc="$2" cxx="$3" prefix="$4" exe="$5"
	local build="$ROOT/build/cross/${triple//\//-}"
	make -C "$ROOT" -s \
		BUILD="$build" EXE="$exe" CC="$cc" CXX="$cxx" \
		CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -Wpedantic -Iinclude -Ithird_party -Ithird_party/sqlite -I$prefix/include" \
		LDLIBS="-L$prefix/lib -lsodium" \
		NETLIBS="-L$prefix/lib -lssl -lcrypto -ldl" \
		"$build/solidsnake$exe" "$build/solidsnake-stager$exe" "$build/solidsnake-payloads$exe"
}

artifact_ok() {
	[ -f "$1" ] || return 1
	file -b "$1" | grep -Eq "$2"
}

size_of() { stat -c %s "$1" 2>/dev/null || echo 0; }

target_linux_amd64() {
	say "[*] linux/amd64 (native g++)"
	if ! make -C "$ROOT" -s build/solidsnake build/solidsnake-stager build/solidsnake-payloads; then
		record FAIL linux/amd64 "native build failed"
		return
	fi
	local ok=1 f
	for f in solidsnake solidsnake-stager solidsnake-payloads; do
		artifact_ok "$ROOT/build/$f" 'ELF 64-bit LSB.*x86-64' || ok=0
	done
	[ "$ok" = 1 ] && record PASS linux/amd64 "ELF x86-64 ($(size_of "$ROOT/build/solidsnake") B implant)" \
		|| record FAIL linux/amd64 "artifact check failed"
}

target_linux_arm64() {
	say "[*] linux/arm64 (aarch64-linux-gnu-g++, static cross deps)"
	if ! have aarch64-linux-gnu-g++; then
		record SKIP linux/arm64 "no aarch64-linux-gnu-g++ (apt install g++-aarch64-linux-gnu)"
		return
	fi
	if ! ensure_arm64_deps; then
		record SKIP linux/arm64 "arm64 libsodium/OpenSSL missing (could not cross-build)"
		return
	fi
	local build="$ROOT/build/cross/linux-arm64"
	if ! make -C "$ROOT" -s cross-linux-arm64 CROSS_ROOT="$CROSS_ROOT" >/tmp/snake-crossbuild-arm64.log 2>&1; then
		say "    build log tail:"; tail -5 /tmp/snake-crossbuild-arm64.log | sed 's/^/      /'
		record FAIL linux/arm64 "compile/link failed"
		return
	fi
	local ok=1 f
	for f in solidsnake solidsnake-stager solidsnake-payloads; do
		artifact_ok "$build/$f" 'ELF 64-bit LSB.*ARM aarch64' || ok=0
	done
	if [ "$ok" = 1 ] && have qemu-aarch64; then
		qemu-aarch64 -L /usr/aarch64-linux-gnu "$build/solidsnake-payloads" --list >/tmp/snake-crossbuild-arm64-smoke.txt 2>&1 \
			|| { say "    qemu smoke failed:"; tail -3 /tmp/snake-crossbuild-arm64-smoke.txt | sed 's/^/      /'; ok=0; }
		grep -q sysrecon /tmp/snake-crossbuild-arm64-smoke.txt || ok=0
	fi
	[ "$ok" = 1 ] && record PASS linux/arm64 "ELF aarch64, qemu --list ok ($(size_of "$build/solidsnake") B implant)" \
		|| record FAIL linux/arm64 "artifact/smoke check failed"
}

target_windows_amd64() {
	say "[*] windows/amd64 (mingw)"
	if ! have x86_64-w64-mingw32-g++; then
		record SKIP windows/amd64 "no x86_64-w64-mingw32-g++ (apt install g++-mingw-w64-x86-64)"
		return
	fi
	if ! ensure_win64_deps; then
		record SKIP windows/amd64 "win64 libsodium/OpenSSL missing (could not cross-build)"
		return
	fi
	local build="$ROOT/build/cross/windows-amd64" first_err=""
	local built=0 missing="" b leg
	for b in solidsnake solidsnake-stager solidsnake-payloads; do
		case "$b" in
			solidsnake)     leg=cross-windows-amd64-implant ;;
			solidsnake-stager) leg=cross-windows-amd64-stager ;;
			*)             leg=cross-windows-amd64-runner ;;
		esac
		if make -C "$ROOT" -s CROSS_ROOT="$CROSS_ROOT" "$leg" \
			>/tmp/snake-crossbuild-win-$b.log 2>&1; then
			built=$((built + 1))
		else
			missing="${missing:+$missing, }$b"
			[ -n "$first_err" ] || first_err="$(grep -m1 -E 'error:|Error [0-9]' /tmp/snake-crossbuild-win-$b.log | cut -c1-90)"
		fi
	done
	if [ "$built" = 3 ]; then
		local ok=1 f
		for f in solidsnake solidsnake-stager solidsnake-payloads; do
			artifact_ok "$build/$f.exe" 'PE32\+ executable.*x86-64' || ok=0
		done
		[ "$ok" = 1 ] && record PASS windows/amd64 "PE32+ x86-64 (all three fleet binaries)" \
			|| record FAIL windows/amd64 "artifact check failed"
		return
	fi
	record SKIP windows/amd64 "$built/3 build (pending: $missing; ${first_err:-see /tmp/snake-crossbuild-win-*.log})"
}

target_darwin_amd64() {
	say "[*] darwin/amd64 (clang)"
	if ! have clang++; then
		record SKIP darwin/amd64 "no clang++"
		return
	fi
	if [ ! -d "${MACOS_SDK:-/opt/MacOSX.sdk}" ] && [ ! -d /usr/local/osxcross ]; then
		record SKIP darwin/amd64 "no macOS SDK (cross-linking Mach-O needs one; see README)"
		return
	fi
	record SKIP darwin/amd64 "SDK present but Mach-O cross deps not wired"
}

say "solidSNAKE cross-build matrix ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
mkdir -p "$ROOT/build/cross"
want() {
	[ -z "${CROSS_TARGETS:-}" ] && return 0
	case " ${CROSS_TARGETS} " in *" $1 "*) return 0 ;; esac
	return 1
}
want linux/amd64   && target_linux_amd64
want linux/arm64   && target_linux_arm64
want windows/amd64 && target_windows_amd64
want darwin/amd64  && target_darwin_amd64

say ""
say "STATUS   TARGET           DETAIL"
printf '%s\n' "${RESULTS[@]}"
say ""
say "linux server: build/solidsnake-c2 (native, $(size_of "$ROOT/build/solidsnake-c2") B) - C2 stays linux-only"
say "totals: $PASS pass, $FAIL fail, $SKIP skip"

[ "$FAIL" -eq 0 ] || exit 1
exit 0
