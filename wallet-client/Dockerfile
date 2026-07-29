# Build with the repository root as the context because the wallet imports
# shared utils/, trust/, and data/trust/ modules. Either invocation is valid:
#   # from the repository root
#   docker build -f wallet-client/Dockerfile -t endimion13/wallet-client:TAG .
#   # from wallet-client/
#   docker build -f Dockerfile -t endimion13/wallet-client:TAG ..
#
# Layout mirrors the repo so relative imports work:
#   /workspace/wallet-client/src/...
#   /workspace/utils/...
#   /workspace/trust/...
#   /workspace/node_modules/...  (deps resolve for wallet + trust/)

FROM node:20-slim

RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Install wallet-client deps at the monorepo root so /workspace/trust can resolve them
COPY wallet-client/package.json wallet-client/package-lock.json* ./
RUN npm install --omit=dev && npm cache clean --force

# Shared monorepo modules (../../utils and ../../../utils|trust from wallet-client)
COPY utils ./utils
COPY trust ./trust
COPY data/trust ./data/trust

# Wallet-client application
COPY wallet-client/src ./wallet-client/src
COPY wallet-client/utils ./wallet-client/utils
COPY wallet-client/data ./wallet-client/data
COPY wallet-client/didjwks ./wallet-client/didjwks
COPY wallet-client/x509EC ./wallet-client/x509EC
COPY wallet-client/x509 ./wallet-client/x509
COPY wallet-client/x509CS03 ./wallet-client/x509CS03
COPY wallet-client/X25519 ./wallet-client/X25519

WORKDIR /workspace/wallet-client

ENV TRUST_PROFILE_PATH=/workspace/data/trust/webuild-wp4-pilot.json

RUN groupadd -r wallet && useradd -r -g wallet wallet \
 && chown -R wallet:wallet /workspace
USER wallet

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

EXPOSE 4000

CMD ["node", "src/server.js"]
