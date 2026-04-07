# Quick Start

## Prerequisites

- **Rust 1.93+** with cargo
- **CMake**, **Clang**, **GMP**, **NASM**, **zstd** (for Longfellow C++ build)
- **Node.js 22+** (for the frontend)

On Ubuntu/Debian:
```bash
sudo apt-get install build-essential cmake clang libgmp-dev nasm libzstd-dev
```

## Clone and Build

```bash
git clone https://github.com/alik-eth/zk-eidas.git
cd zk-eidas
git submodule update --init    # pulls vendor/longfellow-zk

cargo build --workspace        # builds all crates + Longfellow C++ via cmake
```

## Run the Demo

```bash
# Terminal 1: API server
cargo run -p zk-eidas-demo-api

# Terminal 2: Frontend
cd demo/web && npm install && npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The first proof request will take ~4 minutes (circuit generation). Subsequent proofs are sub-second.

## Pre-Generate Circuits (Optional)

To skip the first-proof delay:

```bash
cargo build --release -p longfellow-sys --bin generate-circuits
./target/release/generate-circuits ./circuit-cache
CIRCUIT_CACHE_PATH=./circuit-cache cargo run -p zk-eidas-demo-api
```

## Your First Proof

1. Go to the **Sandbox** page
2. Select a credential type (PID is default)
3. Click **Issue** — the server creates a signed mdoc credential
4. Select predicates (e.g., "Age >= 18")
5. Click **Prove** — the server generates a Longfellow proof
6. The proof is verified automatically and results are displayed
7. Click **Print** to generate QR codes for paper verification

## Running Tests

```bash
# Rust tests (90 tests)
cargo test --workspace

# Frontend tests (28 tests)
cd demo/web && npx vitest run
```
