# Stage 1a: Build dependencies + generate circuit cache
# Circuit cache only depends on vendor/longfellow-zk/ and crates/ — cached across code changes.
FROM ubuntu:24.04 AS circuit-builder
RUN apt-get update && apt-get install -y curl build-essential pkg-config libssl-dev clang git libgmp-dev nasm unzip cmake libbenchmark-dev libgtest-dev libzstd-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.93.0
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app

COPY vendor/longfellow-zk/ vendor/longfellow-zk/
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY demo/api/Cargo.toml demo/api/Cargo.toml
RUN mkdir -p demo/api/src && echo 'fn main(){}' > demo/api/src/main.rs

# Build the circuit generator binary and pre-generate all 4 circuit sizes
RUN cargo build --release -p longfellow-sys --bin generate-circuits && \
    mkdir -p /app/circuit-cache && \
    ./target/release/generate-circuits /app/circuit-cache

# Stage 1b: Build actual API binary (rebuilds on source changes, circuits cached above)
FROM circuit-builder AS rust-builder
COPY demo/api/ demo/api/
RUN cargo build --release -p zk-eidas-demo-api --bin zk-eidas-demo-api --bin pre-warm

# Stage 1c: Build WASM verifier (parallel with rust-builder)
FROM circuit-builder AS wasm-builder
RUN rustup target add wasm32-unknown-unknown && \
    cargo install wasm-pack --version 0.13.1
COPY crates/zk-eidas-wasm/ crates/zk-eidas-wasm/
RUN wasm-pack build --target web --release crates/zk-eidas-wasm

# Stage 2: Build frontend
FROM node:22-slim AS web-builder
WORKDIR /app/demo/web
COPY demo/web/package.json demo/web/package-lock.json* ./
RUN npm install
COPY demo/web/ ./
COPY --from=wasm-builder /app/crates/zk-eidas-wasm/pkg/ /app/crates/zk-eidas-wasm/pkg/
RUN npm run build

# Stage 3: Runtime
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y nginx supervisor curl libstdc++6 libgmp10 libzstd1 ca-certificates gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=rust-builder /app/target/release/zk-eidas-demo-api /app/api-server
COPY --from=rust-builder /app/target/release/pre-warm /app/pre-warm
COPY --from=circuit-builder /app/circuit-cache/ /app/circuit-cache/
COPY demo/api/proof-cache/ /app/proof-cache/
COPY --from=web-builder /app/demo/web/ /app/web/
COPY deploy/loading.html /app/loading.html
COPY deploy/nginx.conf /etc/nginx/sites-available/default
COPY deploy/supervisord.conf /etc/supervisor/conf.d/demo.conf

EXPOSE 8080
CMD ["supervisord", "-n"]
