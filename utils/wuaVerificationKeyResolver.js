/**
 * Shared Wallet Provider attestation (WUA / key-attestation JWT) validation.
 * Both credential-proof transports use this module so their key resolution,
 * signature verification, WUA claims, and Wallet Provider policy stay aligned.
 */
import { X509Certificate } from "crypto";
import jwt from "jsonwebtoken";
import * as jose from "jose";

const WUA_SPEC_REF = "TS3 Wallet Unit Attestation";
const OID4VCI_KEY_ATTESTATION_SPEC_REF = "OpenID4VCI 1.0 Appendix D.1";

export function parseBooleanEnvFlag(value, defaultValue = false) {
  if (value === undefined || value === null) return defaultValue;
  const normalized = String(value).trim().toLowerCase();
  if (normalized === "") return defaultValue;
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return defaultValue;
}

/** Strict configured-key enforcement is opt-in while this remains an interoperability issuer. */
export function isWuaTrustFrameworkEnforced() {
  return parseBooleanEnvFlag(process.env.ENFORCE_WUA_TRUST_FRAMEWORK, false);
}

function withSpecRef(message, ...refs) {
  const present = refs.filter(Boolean);
  return present.length ? `${message}${message.endsWith(".") ? "" : "."} See ${present.join(" and ")}.` : message;
}

/** `wallet_unit_attestation_jwks` is authoritative; the older field is a fallback alias. */
export function getWalletProviderAttestationJwks(issuerMetadata = {}) {
  const primary = issuerMetadata?.wallet_unit_attestation_jwks?.keys;
  if (Array.isArray(primary) && primary.length) return { keys: primary, source: "wallet_unit_attestation_jwks" };
  const alias = issuerMetadata?.key_attestation_jwks?.keys;
  if (Array.isArray(alias) && alias.length) return { keys: alias, source: "key_attestation_jwks" };
  return { keys: [], source: null };
}

/** Backward-compatible export for callers that only need the configured key list. */
export function collectWalletProviderAttestationJwks(issuerMetadata) {
  return getWalletProviderAttestationJwks(issuerMetadata).keys;
}

export function jwkFromAttestationHeaderX5c(decodedHeader) {
  if (!Array.isArray(decodedHeader?.x5c) || decodedHeader.x5c.length === 0) {
    throw new Error("x5c must be a non-empty array in the attestation JWT protected header");
  }
  try {
    return new X509Certificate(Buffer.from(decodedHeader.x5c[0], "base64")).publicKey.export({ format: "jwk" });
  } catch (error) {
    throw new Error(`WUA x5c certificate parsing failed: ${error?.message || error}`);
  }
}

/**
 * Resolve a WUA verification key and report its source without exposing key material.
 * Strict mode accepts only configured Wallet Provider keys.
 */
export function resolveWalletProviderAttestationVerificationKey(decodedHeader, issuerMetadata = {}, options = {}) {
  const specRefs = options.specRefs ?? [WUA_SPEC_REF, OID4VCI_KEY_ATTESTATION_SPEC_REF];
  const { keys, source } = getWalletProviderAttestationJwks(issuerMetadata);
  if (keys.length) {
    const kid = decodedHeader?.kid;
    if (!kid && keys.length > 1) {
      throw new Error(withSpecRef("Cannot verify WUA signature: protected-header kid is required when multiple configured Wallet Provider keys exist", ...specRefs));
    }
    const jwk = kid ? keys.find((key) => key.kid === kid) : keys[0];
    if (!jwk) {
      throw new Error(withSpecRef(`Cannot verify WUA signature: no configured Wallet Provider key matches kid '${kid}'`, ...specRefs));
    }
    return {
      jwk,
      source: source === "wallet_unit_attestation_jwks" ? "configured_primary" : "configured_alias",
      trustFrameworkEnforced: isWuaTrustFrameworkEnforced(),
    };
  }

  if (isWuaTrustFrameworkEnforced()) {
    throw new Error(withSpecRef("Cannot verify WUA signature: ENFORCE_WUA_TRUST_FRAMEWORK=true requires configured wallet_unit_attestation_jwks (or key_attestation_jwks)", ...specRefs));
  }
  if (decodedHeader?.jwk) return { jwk: decodedHeader.jwk, source: "header_jwk", trustFrameworkEnforced: false };
  if (Array.isArray(decodedHeader?.x5c) && decodedHeader.x5c.length) {
    return { jwk: jwkFromAttestationHeaderX5c(decodedHeader), source: "header_x5c", trustFrameworkEnforced: false };
  }
  throw new Error(withSpecRef("Cannot verify WUA signature: configure wallet_unit_attestation_jwks (or key_attestation_jwks), or send WUA with jwk or x5c in the protected header", ...specRefs));
}

/** Backward-compatible resolver return shape. */
export function resolveWalletProviderAttestationVerificationJwk(decodedHeader, issuerMetadata = {}, options = {}) {
  return resolveWalletProviderAttestationVerificationKey(decodedHeader, issuerMetadata, options).jwk;
}

/** Shared required WUA payload checks for every transport. */
export function validateWalletUnitAttestationClaims(payload, options = {}) {
  const specRefs = options.specRefs ?? [WUA_SPEC_REF, OID4VCI_KEY_ATTESTATION_SPEC_REF];
  if (!payload || typeof payload !== "object") throw new Error(withSpecRef("WUA JWT payload is missing or invalid", ...specRefs));
  if (!payload.iss) throw new Error(withSpecRef("WUA JWT missing iss claim", ...specRefs));
  const walletInfo = payload.eudi_wallet_info;
  if (!walletInfo?.general_info || !walletInfo?.key_storage_info) {
    throw new Error(withSpecRef("WUA JWT missing eudi_wallet_info.general_info or eudi_wallet_info.key_storage_info", ...specRefs));
  }
  if (!Array.isArray(payload.attested_keys) || payload.attested_keys.length === 0) {
    throw new Error(withSpecRef("WUA JWT attested_keys must be a non-empty array", ...specRefs));
  }
  for (const key of payload.attested_keys) {
    if (!key || typeof key !== "object" || !key.kty) throw new Error(withSpecRef("WUA JWT attested_keys must contain JWK objects", ...specRefs));
  }
  return { hasStatus: Boolean(payload.status?.status_list) };
}

/** Current shared policy hook; replace with trusted-list/certificate/revocation checks later. */
export function isWalletProviderAttestationTrustedByPolicy(_payload, _header, _issuerMetadata) {
  return true;
}

/** Shared parse, signature, claim, and policy pipeline for both WUA transports. */
export async function verifyWalletProviderAttestation(wuaJwt, issuerMetadata = {}, options = {}) {
  const specRefs = options.specRefs ?? [WUA_SPEC_REF, OID4VCI_KEY_ATTESTATION_SPEC_REF];
  const decoded = jwt.decode(wuaJwt, { complete: true });
  if (!decoded?.header || !decoded?.payload) throw new Error(withSpecRef("WUA JWT is malformed", ...specRefs));
  const alg = decoded.header.alg;
  if (!alg || typeof alg !== "string") throw new Error(withSpecRef("WUA JWT header missing alg", ...specRefs));
  const key = resolveWalletProviderAttestationVerificationKey(decoded.header, issuerMetadata, { specRefs });
  let payload;
  try {
    const verificationKey = await jose.importJWK(key.jwk, alg);
    ({ payload } = await jose.jwtVerify(wuaJwt, verificationKey, { algorithms: [alg] }));
  } catch (error) {
    throw new Error(withSpecRef(`WUA signature verification failed: ${error?.message || error}`, ...specRefs));
  }
  const claimSummary = validateWalletUnitAttestationClaims(payload, { specRefs });
  if (!isWalletProviderAttestationTrustedByPolicy(payload, decoded.header, issuerMetadata)) {
    throw new Error(withSpecRef("WUA rejected: Wallet Provider (iss) not trusted by issuer policy", ...specRefs));
  }
  return { header: decoded.header, payload, verificationKeySource: key.source, trustFrameworkEnforced: key.trustFrameworkEnforced, ...claimSummary };
}
