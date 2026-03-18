# zk-eidas Demo

Interactive demo of zero-knowledge selective disclosure for eIDAS 2.0 credentials.

## Prerequisites

- Rust (cargo)
- Node.js (npm)
- Compiled Circom circuits (run `make` in `circuits/`)

## Quick Start

```bash
chmod +x demo/start.sh
./demo/start.sh
```

Then open http://localhost:3000

## Manual Start

Terminal 1 (API):
```bash
cd demo/api
CIRCUITS_PATH="../../circuits/predicates" cargo run --release
```

Terminal 2 (Frontend):
```bash
cd demo/web
npm run dev
```
