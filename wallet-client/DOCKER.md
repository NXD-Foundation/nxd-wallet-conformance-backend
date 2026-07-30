# Wallet Client Docker Setup

This document describes how to run the wallet-client service using Docker and Docker Compose.

## Monorepo build context (required)

The `Dockerfile` copies paths relative to the **repository root** (`wallet-client/...` and sibling `utils/`). Shared root `utils/` is re-exported by `wallet-client/utils`, so that directory must be in the build context.

**Do not** run `docker build .` from inside `wallet-client/` — Docker will look for `wallet-client/package.json` under the wrong context and fail with `"/wallet-client/...": not found`.

### Build the image alone

From the **repository root** (`rfc-issuer-v1/`):

```bash
docker build -f wallet-client/Dockerfile -t endimion13/aptitude-wallet-client:0.0.1f .
```

From **`wallet-client/`** (context is still the parent):

```bash
docker build -f Dockerfile -t endimion13/aptitude-wallet-client:0.0.1f ..
```

Both are equivalent: `-f` points at the Dockerfile; the final `.` / `..` is the **build context** (must be the monorepo root).

### Compose

`docker-compose.yml` already sets `context: ..` and `dockerfile: wallet-client/Dockerfile`, so compose works from `wallet-client/`:

```bash
cd wallet-client
docker-compose up -d --build
```

## Quick Start

```bash
# From wallet-client/ (compose build context is the monorepo root)
docker-compose up -d --build

# Check service status
docker-compose ps

# View logs
docker-compose logs -f wallet-client
```

## Services

### wallet-client
The main wallet service that handles credential issuance and presentation flows.

**Port:** 4000
**Health Check:** `GET /health`

### redis
Redis database for storing credentials and session data.

**Port:** 6379
**Password:** `wallet_redis_password`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 4000 | Server port |
| `NODE_ENV` | production | Node environment |
| `WALLET_REDIS` | redis:6379 | Redis connection string |
| `REDIS_PASSWORD` | wallet_redis_password | Redis password |
| `WALLET_CREDENTIAL_TTL` | 86400 | Credential storage TTL (seconds) |
| `WALLET_TEST_SESSION_TTL` | 86400 | Test session TTL (seconds) |
| `WALLET_DEBUG_CREDENTIAL` | false | Enable full credential logging |
| `WALLET_MDL_STRICT` | false | Enable strict MDL verification |
| `WALLET_POLL_TIMEOUT_MS` | 30000 | Deferred credential polling timeout |
| `WALLET_POLL_INTERVAL_MS` | 2000 | Deferred credential polling interval (fallback when issuer omits `interval`) |

## APTITUDE RFC001/002 profile notes

This wallet targets APTITUDE RFC001 issuance (WIA/WUA, DPoP, `eu-eaa-offer://`) and RFC002
presentation (DCQL, `openid4vp://present`). It does **not** use WE BUILD CS-01/02 profile
environment variables (`WALLET_PROFILE=webuild-cs01`, `TRUST_PROFILE_PATH`, etc.).

Use `curl http://localhost:4000/health` to inspect runtime configuration.

## Usage Examples

### Start services
```bash
docker-compose up -d
```

### Stop services
```bash
docker-compose down
```

### Rebuild and restart
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### View logs
```bash
# All services
docker-compose logs -f

# Wallet client only
docker-compose logs -f wallet-client

# Redis only
docker-compose logs -f redis
```

### Access the service
```bash
# Health check
curl http://localhost:4000/health

# Issue credentials
curl -X POST http://localhost:4000/issue \
  -H "Content-Type: application/json" \
  -d '{"issuer": "http://your-issuer.com", "offer": "openid-credential-offer://..."}'
```

## Volumes

- `redis-data`: Persistent Redis data storage
- `./keys:/workspace/wallet-client/keys:ro`: Read-only mount for key files (optional)

## Networks

- `wallet-network`: Internal network for service communication

## Security Notes

- The wallet-client runs as a non-root user
- Redis is configured with password authentication
- Health checks are enabled for both services
- Services restart automatically unless explicitly stopped

## Troubleshooting

### Build fails with `"/wallet-client/...": not found`

You built with context = `wallet-client/` (e.g. `docker build .` inside that folder). Rebuild with monorepo root as context — see [Monorepo build context](#monorepo-build-context-required).

### Service won't start
```bash
# Check logs
docker-compose logs wallet-client

# Check if Redis is healthy
docker-compose exec redis redis-cli ping
```

### Redis connection issues
```bash
# Test Redis connection
docker-compose exec wallet-client node -e "
const redis = require('redis');
const client = redis.createClient({url: 'redis://redis:6379', password: 'wallet_redis_password'});
client.connect().then(() => console.log('Redis connected')).catch(console.error);
"
```

### Port conflicts
If port 4000 or 6379 are already in use, modify the `docker-compose.yml` file to use different ports:

```yaml
ports:
  - "4001:4000"  # Map host port 4001 to container port 4000
```
