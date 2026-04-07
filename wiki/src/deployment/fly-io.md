# Fly.io Deployment

## Configuration

The project deploys to [Fly.io](https://fly.io) as a single machine in Amsterdam:

```toml
# fly.toml
app = 'zk-eidas'
primary_region = 'ams'

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = 'stop'
  auto_start_machines = true
  min_machines_running = 1

[[vm]]
  memory = '2gb'
  cpu_kind = 'shared'
  cpus = 1
```

## VM Sizing

- **2 GB RAM / 1 shared CPU** is sufficient because circuits are pre-generated during Docker build
- During the build stage, circuit generation needs ~1.6 GB RAM — but that happens in the Docker builder, not at runtime
- Runtime proving uses ~200-400 MB per proof (one at a time, gated by a semaphore)

## Runtime Architecture

The container runs two processes via supervisord:

1. **nginx** — serves the static React frontend, proxies `/issuer/`, `/holder/`, `/verifier/`, `/escrow/`, `/tsp/`, `/proofs/` to the API
2. **zk-eidas-demo-api** — Axum server on port 3001, loads pre-generated circuits from `/app/circuit-cache/` at startup

nginx config highlights:
- `client_max_body_size 20m` (Longfellow proofs are ~350 KB)
- Health check at `/` returns the static frontend
- API routes proxied to `http://127.0.0.1:3001`

## Deploying

```bash
fly deploy              # Build + deploy
fly logs                # Watch runtime logs
fly ssh console         # SSH into the machine
```

The first deploy after a Longfellow C++ change takes ~5 minutes (circuit generation). Subsequent deploys with only Rust/frontend changes take ~2 minutes.

## Health Check

Fly.io checks `GET /` every 10 seconds with a 30-second grace period. During startup, the API loads circuit cache files (0ms with pre-generated cache). A "starting up" JSON response is returned until circuits are loaded.

## Multiple Deployments

The project has two Fly apps:
- **zk-eidas** — production (`fly.toml`, `zk-eidas.com`)
- **eidas-longfellow** — legacy test deployment (`fly.longfellow.toml`)
