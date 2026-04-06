# Stage 1a: Build dependencies + generate circuit cache
# Circuit generation only depends on vendor/longfellow-zk/ and crates/.
# This layer is cached as long as those don't change.
FROM ubuntu:24.04 AS circuit-builder
RUN apt-get update && apt-get install -y curl build-essential pkg-config libssl-dev clang git libgmp-dev nasm unzip cmake libbenchmark-dev libgtest-dev libzstd-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.93.0
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app

COPY vendor/longfellow-zk/ vendor/longfellow-zk/
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY demo/api/Cargo.toml demo/api/Cargo.toml

# Build a minimal binary that can generate circuits
RUN mkdir -p demo/api/src && echo 'fn main() {}' > demo/api/src/main.rs && \
    cargo build --release -p zk-eidas-demo-api 2>/dev/null || true && \
    rm -rf demo/api/src
# Stub source with just --generate-circuits support
RUN mkdir -p demo/api/src && printf '\
fn main() {\n\
    let args: Vec<String> = std::env::args().collect();\n\
    if args.len() >= 3 && args[1] == "--generate-circuits" {\n\
        let dir = std::path::PathBuf::from(&args[2]);\n\
        std::fs::create_dir_all(&dir).unwrap();\n\
        for n in 1..=4usize {\n\
            let path = dir.join(format!("mdoc-{}attr.bin", n));\n\
            eprint!("[generate] Circuit {}-attr... ", n);\n\
            let t0 = std::time::Instant::now();\n\
            let circuit = longfellow_sys::mdoc::MdocCircuit::generate(n)\n\
                .unwrap_or_else(|e| panic!("circuit {} failed: {}", n, e));\n\
            circuit.save(&path).unwrap();\n\
            eprintln!("done in {:.1}s", t0.elapsed().as_secs_f64());\n\
        }\n\
        return;\n\
    }\n\
}\n' > demo/api/src/main.rs && \
    rm -rf target/release/.fingerprint/zk-eidas-demo-api-* target/release/zk-eidas-demo-api target/release/deps/zk_eidas_demo_api-* && \
    cargo build --release -p zk-eidas-demo-api --bin zk-eidas-demo-api && \
    mkdir -p /app/circuit-cache && \
    ./target/release/zk-eidas-demo-api --generate-circuits /app/circuit-cache && \
    rm -rf demo/api/src

# Stage 1b: Build actual API binary (rebuilds on source changes, but circuits are cached above)
FROM circuit-builder AS rust-builder
COPY demo/api/ demo/api/
RUN touch demo/api/src/main.rs && \
    rm -rf target/release/.fingerprint/zk-eidas-demo-api-* \
           target/release/zk-eidas-demo-api \
           target/release/pre-warm \
           target/release/deps/zk_eidas_demo_api-* && \
    cargo build --release -p zk-eidas-demo-api --bin zk-eidas-demo-api --bin pre-warm

# Stage 2: Build frontend
FROM node:22-slim AS web-builder
WORKDIR /app/demo/web
COPY demo/web/package.json demo/web/package-lock.json* ./
RUN npm install
COPY demo/web/ ./
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

# Copy Rust binaries
COPY --from=rust-builder /app/target/release/zk-eidas-demo-api /app/api-server
COPY --from=rust-builder /app/target/release/pre-warm /app/pre-warm

# Copy pre-generated circuit cache (from circuit-builder, cached separately from source changes)
COPY --from=circuit-builder /app/circuit-cache/ /app/circuit-cache/

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
