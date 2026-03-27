# Stage 1: Build Rust API + WASM module
FROM ubuntu:24.04 AS rust-builder
RUN apt-get update && apt-get install -y curl build-essential pkg-config libssl-dev clang git libgmp-dev nasm unzip && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.93.0
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add wasm32-unknown-unknown && cargo install wasm-pack
WORKDIR /app

# Layer 1: cache dependencies (only rebuilds when Cargo.toml/Cargo.lock change)
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY demo/api/Cargo.toml demo/api/Cargo.toml
COPY tools/ tools/
RUN mkdir -p demo/api/src && echo 'fn main() {}' > demo/api/src/main.rs && \
    cargo build --release -p zk-eidas-demo-api 2>/dev/null || true && \
    rm -rf demo/api/src

# Layer 2: build actual source (fast when only code changes)
# Touch source + nuke fingerprints to force cargo to rebuild the binary
COPY demo/api/ demo/api/
RUN touch demo/api/src/main.rs && \
    rm -rf target/release/.fingerprint/zk-eidas-demo-api-* \
           target/release/zk-eidas-demo-api \
           target/release/pre-warm \
           target/release/deps/zk_eidas_demo_api-* && \
    cargo build --release -p zk-eidas-demo-api --bin zk-eidas-demo-api --bin pre-warm

# Layer 3: build WASM module for on-device browser proving
RUN wasm-pack build crates/zk-eidas-wasm --target web --out-dir ../../demo/web/pkg

# Stage 2: Build frontend
FROM node:22-slim AS web-builder
WORKDIR /app/demo/web
COPY demo/web/package.json demo/web/package-lock.json* ./
# Copy and build local SDK package (referenced by file: dependency)
COPY packages/verifier-sdk/ /app/packages/verifier-sdk/
RUN cd /app/packages/verifier-sdk && npm install && npm run build
RUN npm install
COPY demo/web/ ./
# Copy real WASM module and replace stub with re-export for on-device browser proving
COPY --from=rust-builder /app/demo/web/pkg/ ./pkg/
RUN echo 'export { default } from "./zk_eidas_wasm.js"; export * from "./zk_eidas_wasm.js";' > ./pkg/zk-eidas-wasm.js
RUN npm run build

# Stage 3: Compile C++ witness generator for ECDSA circuit (native speed)
FROM ubuntu:24.04 AS cpp-builder
RUN apt-get update && apt-get install -y build-essential nasm libgmp-dev nlohmann-json3-dev && rm -rf /var/lib/apt/lists/*
COPY circuits/build/ecdsa_verify/ecdsa_verify_cpp/ /build/
WORKDIR /build
RUN make -j$(nproc)

# Stage 4: Runtime
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

# Copy rapidsnark shared library (needed at runtime)
COPY --from=rust-builder /app/target/release/build/rust-rapidsnark-*/out/rapidsnark/x86_64/librapidsnark.so /usr/local/lib/
RUN ldconfig

# Copy compiled circuits (zkey excluded from context via .dockerignore, downloaded below)
COPY circuits/build/ /app/circuits/build/

# Download the 1.2GB ECDSA zkey from UploadThing (not in Docker context to speed up builds)
RUN curl -L -o /app/circuits/build/ecdsa_verify/ecdsa_verify.zkey \
    "https://ruvpd2ka1g.ufs.sh/f/vsKUhXCDRm2gNVLwvum9EROnsC6LBwY0z83lumTkxKGvgDpb"

# Copy C++ witness generator binary + data file
COPY --from=cpp-builder /build/ecdsa_verify /app/circuits/build/ecdsa_verify/ecdsa_verify_cpp/ecdsa_verify
COPY --from=cpp-builder /build/ecdsa_verify.dat /app/circuits/build/ecdsa_verify/ecdsa_verify_cpp/ecdsa_verify.dat

# Copy pre-built proof cache (generated locally via pre-warm binary)
COPY demo/api/proof-cache/ /app/proof-cache/

# Copy frontend build + node_modules
COPY --from=web-builder /app/demo/web/ /app/web/

# Deploy configs (extracted so Dockerfile changes don't bust cache)
COPY deploy/loading.html /app/loading.html
COPY deploy/nginx.conf /etc/nginx/sites-available/default
COPY deploy/supervisord.conf /etc/supervisor/conf.d/demo.conf

EXPOSE 8080

CMD ["supervisord", "-n"]
