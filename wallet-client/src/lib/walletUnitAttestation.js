/**
 * Wallet Unit Attestation (WUA) material for OAuth client authentication and credential binding.
 *
 * Current implementation status:
 * - CS-01 and compatibility mode both use locally generated keys as the attestation source.
 * - Trust-framework-backed attestation (external attester, provisioned material) is NOT implemented.
 * - The request shape follows WE BUILD CS-01 (OAuth-Client-Attestation headers at PAR/Token).
 *
 * Future trust-framework integration should implement a new attestation source behind
 * `createWalletUnitAttestationClientAuth()` without changing call sites in the issuance flow.
 */

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

export const ATTESTATION_SOURCES = Object.freeze({
  LOCAL_KEY: "local-key",
  /** Reserved for future trust-framework-backed Wallet Unit Attestation. */
  TRUST_FRAMEWORK: "trust-framework",
});

export const LOCAL_KEY_ATTESTATION_NOTE =
  "Wallet Unit Attestation is generated from locally generated keys. Trust-framework-backed attestation is not yet implemented.";

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
      "WE BUILD CS-01 profile currently supports only local-key Wallet Unit Attestation",
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

async function createLocalKeyWalletUnitAttestationClientAuth({
  keyPath,
  clientId,
  endpointAudience,
  authorizationServerIssuer,
  alg = "ES256",
}) {
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath, alg);
  const attestationJwt = await createOAuthClientAttestationJwt({
    privateJwk,
    publicJwk,
    issuer: clientId,
    subject: clientId,
    audience: endpointAudience,
    cnfJwk: publicJwk,
    alg,
  });
  const popJwt = await createOAuthClientAttestationPopJwt({
    privateJwk,
    publicJwk,
    issuer: clientId,
    audience: authorizationServerIssuer,
    alg,
  });
  assertOutboundClientIdAligned({ clientId, attestationJwt, popJwt });
  return {
    source: ATTESTATION_SOURCES.LOCAL_KEY,
    trustFrameworkIntegrated: false,
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
 * Wallet Unit Attestation JWT used as proof key_attestation at the Credential Endpoint.
 * Generated from local keys until trust-framework integration exists.
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
  const signingKeys =
    subjectPrivateJwk && subjectPublicJwk
      ? { privateJwk: subjectPrivateJwk, publicJwk: subjectPublicJwk }
      : await ensureOrCreateEcKeyPair(keyPath, alg);
  const { privateJwk, publicJwk } = signingKeys;
  const issuer = generateDidJwkFromPrivateJwk(publicJwk);
  const attestationJwt = await createWUA({
    privateJwk,
    publicJwk,
    issuer,
    audience: credentialEndpoint,
    attestedKeys: [proofPublicJwk],
    eudiWalletInfo: {
      general_info: {
        name: "Test Wallet Client",
        version: "1.0.0",
      },
      key_storage_info: {
        storage_type: "software",
        protection_level: "software",
      },
    },
    alg,
    ttlHours,
  });
  return {
    source,
    trustFrameworkIntegrated: false,
    attestationJwt,
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
