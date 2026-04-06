# Stage 1: Build Rust API (Longfellow — no WASM, no Circom, no rapidsnark)
FROM ubuntu:24.04 AS rust-builder
RUN apt-get update && apt-get install -y curl build-essential pkg-config libssl-dev clang git libgmp-dev nasm unzip cmake && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.93.0
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app

# Copy Longfellow C++ library (needed by longfellow-sys build.rs)
COPY vendor/longfellow-zk/ vendor/longfellow-zk/

# Layer 1: cache dependencies (only rebuilds when Cargo.toml/Cargo.lock change)
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY demo/api/Cargo.toml demo/api/Cargo.toml
RUN mkdir -p demo/api/src && echo 'fn main() {}' > demo/api/src/main.rs && \
    cargo build --release -p zk-eidas-demo-api 2>/dev/null || true && \
    rm -rf demo/api/src

# Layer 2: build actual source
COPY demo/api/ demo/api/
RUN touch demo/api/src/main.rs && \
    rm -rf target/release/.fingerprint/zk-eidas-demo-api-* \
           target/release/zk-eidas-demo-api \
           target/release/pre-warm \
           target/release/deps/zk_eidas_demo_api-* && \
    cargo build --release -p zk-eidas-demo-api --bin zk-eidas-demo-api --bin pre-warm

# Stage 2: Build frontend (no WASM, no verifier-sdk)
FROM node:22-slim AS web-builder
WORKDIR /app/demo/web
COPY demo/web/package.json demo/web/package-lock.json* ./
RUN npm install
COPY demo/web/ ./
RUN npm run build

# Stage 3: Runtime
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y nginx supervisor curl libstdc++6 libgmp10 ca-certificates gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Rust binaries
COPY --from=rust-builder /app/target/release/zk-eidas-demo-api /app/api-server
COPY --from=rust-builder /app/target/release/pre-warm /app/pre-warm

# Copy pre-built proof cache
COPY demo/api/proof-cache/ /app/proof-cache/

# Copy frontend build
COPY --from=web-builder /app/demo/web/ /app/web/

# Deploy configs
COPY deploy/loading.html /app/loading.html
COPY deploy/nginx.conf /etc/nginx/sites-available/default
COPY deploy/supervisord.conf /etc/supervisor/conf.d/demo.conf

EXPOSE 8080

CMD ["supervisord", "-n"]
