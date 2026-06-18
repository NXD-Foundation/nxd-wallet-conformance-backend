/**
 * Wallet Unit Attestation (WUA) material for OAuth client authentication and credential binding.
 *
 * CS-01 uses local Wallet Provider fixture-signed WIA/KA material. The trust framework
 * and trusted-list validation are intentionally not implemented yet; local fixture
 * signatures and token shape are enough for conformance development.
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { decodeJwt } from "jose";
import {
  ensureOrCreateEcKeyPair,
  generateDidJwkFromPrivateJwk,
  createWIA,
  createWUA,
  createOAuthClientAttestationJwt,
  createOAuthClientAttestationPopJwt,
} from "./crypto.js";
import { assertOutboundClientIdAligned } from "./walletClientId.js";
import { isWebuildCs01Profile } from "./profile.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WALLET_PROVIDER_KEY_PATH = path.resolve(__dirname, "../../x509EC/ec_private_pkcs8.key");
const WALLET_PROVIDER_CERT_PATH = path.resolve(__dirname, "../../x509EC/client_certificate.crt");
const STATUS_MAINTENANCE_SECONDS = 31 * 24 * 60 * 60;
const CS01_WIA_TTL_SECONDS = 23 * 60 * 60;
const CS01_KA_TTL_HOURS = 23;
const issuedAttestationIds = new Set();

export const ATTESTATION_SOURCES = Object.freeze({
  LOCAL_KEY: "local-key",
  /** Reserved for future trust-framework-backed Wallet Unit Attestation. */
  TRUST_FRAMEWORK: "trust-framework",
});

export const LOCAL_KEY_ATTESTATION_NOTE =
  "Wallet Unit Attestation is generated from local Wallet Provider fixture keys. Trust-framework-backed attestation is not yet implemented.";

export class AttestationSourceError extends Error {
  constructor(message) {
    super(message);
    this.name = "AttestationSourceError";
    this.errorCode = "invalid_attestation_source";
  }
}

export function normalizeAttestationSource(value) {
  if (value == null || value === "" || value === ATTESTATION_SOURCES.LOCAL_KEY) {
    return ATTESTATION_SOURCES.LOCAL_KEY;
  }
  if (value === ATTESTATION_SOURCES.TRUST_FRAMEWORK) {
    return ATTESTATION_SOURCES.TRUST_FRAMEWORK;
  }
  throw new AttestationSourceError(
    `Unknown WALLET_ATTESTATION_SOURCE '${value}'. Supported values: ${ATTESTATION_SOURCES.LOCAL_KEY}`,
  );
}

export function resolveAttestationSource(profile, env = process.env) {
  const requested = normalizeAttestationSource(env.WALLET_ATTESTATION_SOURCE);
  if (requested === ATTESTATION_SOURCES.TRUST_FRAMEWORK) {
    throw new AttestationSourceError(
      "Trust-framework-backed Wallet Unit Attestation is not yet implemented; only local-key attestation is available",
    );
  }
  if (isWebuildCs01Profile(profile) && requested !== ATTESTATION_SOURCES.LOCAL_KEY) {
    throw new AttestationSourceError(
      "WE BUILD CS-01 profile currently supports only local Wallet Provider fixture attestation",
    );
  }
  return ATTESTATION_SOURCES.LOCAL_KEY;
}

export function describeAttestationConfiguration(profile, env = process.env) {
  const source = resolveAttestationSource(profile, env);
  return {
    source,
    trustFrameworkIntegrated: false,
    localKeyAttestationOnly: true,
    implementationNote: LOCAL_KEY_ATTESTATION_NOTE,
    cs01UsesHeadersOnly: isWebuildCs01Profile(profile),
  };
}

/** CS-01 uses Wallet Unit Attestation headers only; no parallel OAuth body client_assertion. */
export function allowsLegacyBodyClientAssertion(profile) {
  return !isWebuildCs01Profile(profile);
}

/**
 * Compatibility-only body client_assertion JWT (legacy mixed client authentication).
 * CS-01 must not use this; client authentication is Wallet Unit Attestation headers only.
 */
export async function createLegacyBodyClientAssertionJwt({
  keyPath,
  audience,
  alg = "ES256",
  ttlHours = 1,
}) {
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath, alg);
  const issuer = generateDidJwkFromPrivateJwk(publicJwk);
  return createWIA({
    privateJwk,
    publicJwk,
    issuer,
    audience,
    alg,
    ttlHours,
  });
}

function pemCertificateToX5c(certPem) {
  return certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
}

function loadWalletProviderFixtureMaterial() {
  const privateKeyPem = fs.readFileSync(WALLET_PROVIDER_KEY_PATH, "utf8");
  const certPem = fs.readFileSync(WALLET_PROVIDER_CERT_PATH, "utf8");
  return {
    privateKeyPem,
    x5c: [pemCertificateToX5c(certPem)],
  };
}

function statusListReference(kind) {
  return {
    status_list: {
      idx: Math.floor(Math.random() * 1000000),
      uri: `https://wallet-provider.example/status/${kind}`,
    },
  };
}

function statusMaintenanceObject(kind, now) {
  return {
    status: statusListReference(kind),
    exp: now + STATUS_MAINTENANCE_SECONDS,
  };
}

function markAttestationJwtUsedOnce(jwt, label) {
  const payload = decodeJwt(jwt);
  const jti = payload?.jti;
  if (!jti) {
    throw new AttestationSourceError(`${label} is missing jti for single-use lifecycle tracking`);
  }
  if (issuedAttestationIds.has(jti)) {
    throw new AttestationSourceError(`${label} jti '${jti}' was already used in this wallet-client process`);
  }
  issuedAttestationIds.add(jti);
  return jti;
}

export function resetWalletUnitAttestationLifecycleForTests() {
  issuedAttestationIds.clear();
}

export function getWalletUnitAttestationLifecycleStateForTests() {
  return { usedJwtIds: Array.from(issuedAttestationIds) };
}

async function createLocalKeyWalletUnitAttestationClientAuth({
  keyPath,
  clientId,
  endpointAudience,
  authorizationServerIssuer,
  alg = "ES256",
  challenge = null,
  cnfKeyPair = null,
  cs01 = false,
}) {
  const cnfKeys = cnfKeyPair || (await ensureOrCreateEcKeyPair(keyPath, alg));
  const { privateJwk, publicJwk } = cnfKeys;
  const now = Math.floor(Date.now() / 1000);
  const walletProvider = cs01 ? loadWalletProviderFixtureMaterial() : null;
  const attestationJwt = await createOAuthClientAttestationJwt({
    privateJwk,
    privateKeyPem: walletProvider?.privateKeyPem || null,
    publicJwk,
    issuer: cs01 ? null : clientId,
    subject: clientId,
    audience: endpointAudience,
    cnfJwk: publicJwk,
    alg,
    ttlSeconds: cs01 ? CS01_WIA_TTL_SECONDS : 300,
    includeJwkHeader: !cs01,
    headerParams: cs01 ? { x5c: walletProvider.x5c } : null,
    extraClaims: cs01
      ? {
          wallet_name: "Test Wallet Client",
          wallet_version: "1.0.0",
          wallet_link: "https://wallet-provider.example/wallet-client",
          wallet_solution_certification_information: {
            scheme: "local-dev-fixture",
            assurance: "not-trust-framework-validated",
          },
          client_status: statusMaintenanceObject("wia", now),
        }
      : null,
  });
  const popJwt = await createOAuthClientAttestationPopJwt({
    privateJwk,
    publicJwk,
    issuer: clientId,
    audience: authorizationServerIssuer,
    alg,
    challenge,
  });
  assertOutboundClientIdAligned({ clientId, attestationJwt, popJwt });
  const attestationJti = markAttestationJwtUsedOnce(attestationJwt, "WIA");
  return {
    source: ATTESTATION_SOURCES.LOCAL_KEY,
    trustFrameworkIntegrated: false,
    cnfKeyPair: cnfKeys,
    attestationJti,
    headers: {
      "OAuth-Client-Attestation": attestationJwt,
      "OAuth-Client-Attestation-PoP": popJwt,
    },
  };
}

/**
 * Wallet Unit Attestation for PAR and Token client authentication (OAuth-Client-Attestation headers).
 */
export async function createWalletUnitAttestationClientAuth({
  profile,
  keyPath,
  clientId,
  endpointAudience,
  authorizationServerIssuer,
  alg = "ES256",
  stage = "client authentication",
  challenge = null,
  cnfKeyPair = null,
}) {
  const source = resolveAttestationSource(profile);
  switch (source) {
    case ATTESTATION_SOURCES.LOCAL_KEY:
      return {
        ...(await createLocalKeyWalletUnitAttestationClientAuth({
          keyPath,
          clientId,
          endpointAudience,
          authorizationServerIssuer,
          alg,
          challenge,
          cnfKeyPair,
          cs01: isWebuildCs01Profile(profile),
        })),
        stage,
        implementationNote: LOCAL_KEY_ATTESTATION_NOTE,
      };
    default:
      throw new AttestationSourceError(
        `Unsupported Wallet Unit Attestation source '${source}' for ${stage}`,
      );
  }
}

/**
 * Wallet Unit Key Attestation JWT used as proof key_attestation at the Credential Endpoint.
 */
export async function createWalletUnitCredentialKeyAttestation({
  profile,
  keyPath,
  proofPublicJwk,
  credentialEndpoint,
  subjectPrivateJwk = null,
  subjectPublicJwk = null,
  alg = "ES256",
  ttlHours = 24,
}) {
  const source = resolveAttestationSource(profile);
  const cs01 = isWebuildCs01Profile(profile);
  const signingKeys =
    subjectPrivateJwk && subjectPublicJwk
      ? { privateJwk: subjectPrivateJwk, publicJwk: subjectPublicJwk }
      : await ensureOrCreateEcKeyPair(keyPath, alg);
  const { privateJwk, publicJwk } = signingKeys;
  const now = Math.floor(Date.now() / 1000);
  const walletProvider = cs01 ? loadWalletProviderFixtureMaterial() : null;
  const issuer = cs01 ? null : generateDidJwkFromPrivateJwk(publicJwk);
  const attestationJwt = await createWUA({
    privateJwk,
    privateKeyPem: walletProvider?.privateKeyPem || null,
    publicJwk,
    issuer,
    audience: cs01 ? null : credentialEndpoint,
    attestedKeys: [proofPublicJwk],
    eudiWalletInfo: cs01
      ? null
      : {
          general_info: {
            name: "Test Wallet Client",
            version: "1.0.0",
          },
          key_storage_info: {
            storage_type: "software",
            protection_level: "software",
          },
        },
    headerParams: cs01 ? { x5c: walletProvider.x5c } : null,
    includeJwkHeader: !cs01,
    extraClaims: cs01
      ? {
          key_storage: ["iso_18045_high"],
          user_authentication: ["iso_18045_high"],
          certification: {
            scheme: "local-dev-fixture",
            assurance: "software-test-key",
          },
          key_storage_status: statusMaintenanceObject("ka", now),
        }
      : null,
    alg,
    ttlHours: cs01 ? CS01_KA_TTL_HOURS : ttlHours,
  });
  const attestationJti = markAttestationJwtUsedOnce(attestationJwt, "KA");
  return {
    source,
    trustFrameworkIntegrated: false,
    attestationJwt,
    attestationJti,
    implementationNote: LOCAL_KEY_ATTESTATION_NOTE,
  };
}

/** @deprecated Use createWalletUnitAttestationClientAuth().headers instead. */
export async function buildOAuthClientAttestationHeaders(options) {
  const result = await createWalletUnitAttestationClientAuth({
    profile: options.profile,
    keyPath: options.keyPath,
    clientId: options.clientId,
    endpointAudience: options.endpointAudience,
    authorizationServerIssuer: options.authorizationServerIssuer,
    alg: options.alg,
    stage: "legacy wrapper",
  });
  return result.headers;
}
