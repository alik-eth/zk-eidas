# Docker Build

## Multi-Stage Architecture

The Dockerfile has 4 stages, optimized for layer caching:

```
circuit-builder → rust-builder → web-builder → runtime
```

### Stage 1: circuit-builder

Builds Longfellow C++ (via cmake) and pre-generates all 4 circuit sizes (1-4 attributes). This is the most expensive stage (~4 minutes) but **only invalidates when `vendor/longfellow-zk/` or `crates/` change** — not on application code changes.

```dockerfile
FROM ubuntu:24.04 AS circuit-builder
# Install: cmake, clang, libgtest-dev, libbenchmark-dev, libzstd-dev, rust
COPY vendor/longfellow-zk/ vendor/longfellow-zk/
COPY Cargo.toml Cargo.lock crates/ demo/api/Cargo.toml
RUN cargo build --release -p longfellow-sys --bin generate-circuits
RUN ./target/release/generate-circuits /app/circuit-cache
```

A stub `demo/api/Cargo.toml` + `main.rs` is created so cargo can resolve the workspace without copying the full API source.

### Stage 2: rust-builder

Extends circuit-builder with the full demo API source. Rebuilds only the API binary — Longfellow C++ and circuit cache are already built.

```dockerfile
FROM circuit-builder AS rust-builder
COPY demo/api/ demo/api/
RUN cargo build --release -p zk-eidas-demo-api --bin zk-eidas-demo-api --bin pre-warm
```

### Stage 3: web-builder

Builds the React frontend (TanStack Router + Tailwind CSS):

```dockerfile
FROM node:22-slim AS web-builder
COPY demo/web/package.json demo/web/package-lock.json ./
RUN npm install
COPY demo/web/ ./
RUN npm run build
```

### Stage 4: runtime

Ubuntu 24.04 with nginx, supervisord, Node.js. Copies artifacts from all previous stages:

- API binary + pre-warm binary from rust-builder
- Pre-generated circuit cache from circuit-builder
- Built frontend from web-builder
- nginx config, supervisord config, loading page

## Build Dependencies

The Longfellow C++ build requires these system packages:

| Package | Why |
|---------|-----|
| `cmake` | Build system for Longfellow C++ |
| `libbenchmark-dev` | Required by Longfellow's CMakeLists.txt |
| `libgtest-dev` | Required by Longfellow's CMakeLists.txt |
| `libzstd-dev` | Circuit compression (zstd) |
| `clang` | C++ compiler |
| `nasm` | Assembly for crypto primitives |
| `libgmp-dev` | Arbitrary precision arithmetic |

## Cache Optimization

The key insight: circuit generation depends only on `vendor/` and `crates/` — not on `demo/api/src/`. By splitting the Dockerfile so circuit generation happens before API source is copied, Docker's layer cache avoids the 4-minute circuit rebuild on every code change.

Typical rebuild after API-only changes: ~30 seconds (just recompile Rust + copy frontend).
