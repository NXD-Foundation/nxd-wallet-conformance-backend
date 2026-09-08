# Wallet Client Docker Setup

This document describes how to run the wallet-client service using Docker and Docker Compose.

## Quick Start

```bash
# From wallet-client/ (compose context is the monorepo root)
docker-compose up -d --build

# Or build the image alone from the monorepo root:
#   docker build -f wallet-client/Dockerfile -t endimion13/wallet-client:TAG .
#
# Do not `docker build .` inside wallet-client/ — shared utils/ and trust/
# live one level up and must be in the build context.

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
| `WALLET_PROFILE` | `compatibility` | Issuance profile: `compatibility` (permissive) or `webuild-cs01` (CS-01 conformance) |
| `CS01_DISABLE_PRE_AUTHORIZED` | unset | **CS-01 only.** Set `true` to block `pre-authorized_code`; `authorization_code` still works |
| `WALLET_CLIENT_ID` | `wallet-client` | OAuth `client_id`; must match Wallet Unit Attestation subject in CS-01 mode |
| `WALLET_ATTESTATION_SOURCE` | `local-key` | Attestation key source (`local-key` only; `trust-framework` not yet implemented) |
| `WALLET_PROVIDER_URL` | unset | Public Wallet Provider base URL behind the reverse proxy (HTTPS required for `webuild-cs01`). Example: `https://host.example/wallet-client`. WIA/KA `status_list.uri` values are `{WALLET_PROVIDER_URL}/status-lists/{wia\|ka}/1`. |
| `WALLET_STATUS_ADMIN_TOKEN` | unset | Bearer token for `POST /status-lists/:kind/:listId/entries/:idx/revoke`. Required in `webuild-cs01` mode. |
| `WALLET_STATUS_LIST_TTL` | `3600` | Status List Token `ttl`/`exp` interval and HTTP `Cache-Control` max-age, in seconds. |
| `WALLET_CREDENTIAL_TTL` | 86400 | Credential storage TTL (seconds) |
| `WALLET_TEST_SESSION_TTL` | 86400 | Test session TTL (seconds) |
| `WALLET_DEBUG_CREDENTIAL` | false | Enable full credential logging |
| `WALLET_MDL_STRICT` | false | Enable strict MDL verification |
| `WALLET_POLL_TIMEOUT_MS` | 30000 | Deferred credential polling timeout |
| `WALLET_POLL_INTERVAL_MS` | 2000 | Deferred credential polling interval (fallback when issuer omits `interval`) |

### WE BUILD CS-01 profile (`WALLET_PROFILE=webuild-cs01`)

Use this profile for ITB+ and remote interop against CS-01 issuers (including Spherity-style pre-auth offers):

- **Both grant types** are supported by default: `authorization_code` and `pre-authorized_code`
- **Auth-code path:** PAR mandatory, PKCE S256, WUA headers, DPoP-bound tokens, scope from offer/metadata
- **Pre-auth path:** WUA headers (no body `client_assertion`), DPoP mandatory, credential selection via `credential_configuration_ids`
- **Deferred issuance:** polls `/credential_deferred` with `Authorization: DPoP` + `DPoP` proof header; honors issuer `interval` from 202 responses
- **Opt-out:** `CS01_DISABLE_PRE_AUTHORIZED=true` disables pre-auth only (legacy strict CS-01 testers)
- **WIA/KA status lists:** the wallet-client is the Wallet Provider publisher. CS-01 startup requires `WALLET_PROVIDER_URL` (HTTPS) and `WALLET_STATUS_ADMIN_TOKEN`. The reverse proxy must forward the advertised `/status-lists/...` path unchanged to this service; the Status List JWT `sub` and the WIA/KA `status_list.uri` are that public URL.

Example `docker-compose.yml` override:

```yaml
environment:
  - WALLET_PROFILE=webuild-cs01
  - WALLET_CLIENT_ID=wallet-client
  - WALLET_ATTESTATION_SOURCE=local-key
  - WALLET_PROVIDER_URL=https://host.example/wallet-client
  - WALLET_STATUS_ADMIN_TOKEN=change-me
```

Check runtime policy: `curl http://localhost:4000/health` — `grantPolicy.preAuthorizedEnabled` should be `true` unless opted out. `statusLists.wia` and `statusLists.ka` should match the reverse-proxied URLs.

Status list fetch (issuers/relying parties):

```bash
curl -H "Accept: application/statuslist+jwt" \
  https://host.example/wallet-client/status-lists/wia/1
curl -H "Accept: application/statuslist+jwt" \
  https://host.example/wallet-client/status-lists/ka/1
```

Revoke a published entry:

```bash
curl -X POST \
  -H "Authorization: Bearer change-me" \
  https://host.example/wallet-client/status-lists/wia/1/entries/0/revoke
```

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
- `./keys:/app/keys:ro`: Read-only mount for key files (optional)

## Networks

- `wallet-network`: Internal network for service communication

## Security Notes

- The wallet-client runs as a non-root user
- Redis is configured with password authentication
- Health checks are enabled for both services
- Services restart automatically unless explicitly stopped

## Troubleshooting

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
