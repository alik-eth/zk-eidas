# Circuit Cache & Startup

## The Problem

Longfellow circuit generation takes ~4 minutes and ~1.6 GB RAM per circuit. With 4 circuit sizes (1-4 attributes), generating all circuits at startup would take 16+ minutes and require a large VM.

## The Solution: Pre-Generation

Circuits are generated once during the Docker build and serialized to disk. At runtime, they're loaded from files — 0ms startup.

### generate-circuits Binary

The `longfellow-sys` crate includes a dedicated binary:

```bash
cargo build --release -p longfellow-sys --bin generate-circuits
./target/release/generate-circuits /path/to/cache/
```

This generates 4 files:
- `circuit_1attr.bin` (~320 KB, zstd-compressed)
- `circuit_2attr.bin` (~340 KB)
- `circuit_3attr.bin` (~350 KB)
- `circuit_4attr.bin` (~360 KB)

### MdocCircuit Serialization

The `MdocCircuit` type wraps the raw circuit bytes returned by the Longfellow C++ library:

```rust
impl MdocCircuit {
    pub fn save(&self, path: &Path) -> io::Result<()> {
        fs::write(path, &self.bytes)
    }

    pub fn load(path: &Path, num_attributes: usize) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        Ok(Self { bytes, spec_index: num_attributes - 1, num_attributes })
    }
}
```

The serialized form is the raw `CircuitRep::to_bytes()` output from Longfellow's C++ — a portable binary blob containing the full circuit specification.

### Runtime Loading

The demo API checks for `CIRCUIT_CACHE_PATH` at startup:

1. If set: loads all 4 circuit files into `longfellow_circuits` array — instant
2. If not set: circuits are generated lazily on first prove request for each attribute count — slow but works without pre-generation

```bash
# With cache (0ms startup):
CIRCUIT_CACHE_PATH=/app/circuit-cache cargo run -p zk-eidas-demo-api

# Without cache (generates on demand):
cargo run -p zk-eidas-demo-api
```

## Docker Integration

In the Dockerfile, the circuit-builder stage runs `generate-circuits` and stores results in `/app/circuit-cache/`. The runtime stage copies this directory and sets the environment variable:

```dockerfile
COPY --from=circuit-builder /app/circuit-cache/ /app/circuit-cache/
ENV CIRCUIT_CACHE_PATH=/app/circuit-cache
```

This layer is cached by Docker — if `vendor/longfellow-zk/` and `crates/` haven't changed, the circuit generation is skipped entirely on subsequent builds.

## Performance Impact

| Scenario | Startup Time | First Proof |
|----------|-------------|-------------|
| No cache | 0ms | ~4 min (generates circuit) |
| With cache | 0ms (loads ~1.4 MB from disk) | <100ms |
| Docker build | N/A (built offline) | <100ms |
