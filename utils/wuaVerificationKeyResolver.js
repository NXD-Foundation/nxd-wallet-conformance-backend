/** Shared WUA / key-attestation validation for every credential-proof transport. */
import { X509Certificate } from "crypto";
import jwt from "jsonwebtoken";
import * as jose from "jose";
import { parseReferencedTokenStatus, publicJwkOnly } from "./wuaStatusListVerifier.js";

export const KEY_ATTESTATION_JWT_TYP = "key-attestation+jwt";
const DEFAULT_REFS = ["TS3 Wallet Unit Attestation", "OpenID4VCI 1.0 Appendix D.1"];
const KA_TYP_REFS = ["OpenID4VCI 1.0 Appendix D.1", "CS-04 Annex A.2"];

function withSpecRef(message, ...refs) {
  const present = refs.filter(Boolean);
  return present.length ? `${message}${message.endsWith(".") ? "" : "."} See ${present.join(" and ")}.` : message;
}

export function isWuaTrustFrameworkEnforced() {
  return ["1", "true", "yes", "on"].includes(String(process.env.ENFORCE_WUA_TRUST_FRAMEWORK || "").trim().toLowerCase());
}

/** Primary configured keys take precedence; the older property is a fallback alias. */
export function getWalletProviderAttestationJwks(metadata = {}) {
  const primary = metadata?.wallet_unit_attestation_jwks?.keys;
  if (Array.isArray(primary) && primary.length) return { keys: primary, source: "wallet_unit_attestation_jwks" };
  const alias = metadata?.key_attestation_jwks?.keys;
  if (Array.isArray(alias) && alias.length) return { keys: alias, source: "key_attestation_jwks" };
  return { keys: [], source: null };
}

export function jwkFromAttestationHeaderX5c(header) {
  if (!Array.isArray(header?.x5c) || !header.x5c.length) throw new Error("WUA x5c must be a non-empty protected-header array");
  try {
    return new X509Certificate(Buffer.from(header.x5c[0], "base64")).publicKey.export({ format: "jwk" });
  } catch (error) {
    throw new Error(`WUA x5c certificate parsing failed: ${error?.message || error}`);
  }
}

export function resolveWalletProviderAttestationVerificationKey(header, metadata = {}, options = {}) {
  const refs = options.specRefs ?? DEFAULT_REFS;
  const { keys, source } = getWalletProviderAttestationJwks(metadata);
  if (keys.length) {
    const kid = header?.kid;
    if (!kid && keys.length > 1) throw new Error(withSpecRef("Cannot verify WUA signature: protected-header kid is required for multiple configured Wallet Provider keys", ...refs));
    const jwk = kid ? keys.find((key) => key.kid === kid) : keys[0];
    if (!jwk) throw new Error(withSpecRef(`Cannot verify WUA signature: no configured Wallet Provider key matches kid '${kid}'`, ...refs));
    return { jwk, verificationKeySource: source === "wallet_unit_attestation_jwks" ? "configured_primary" : "configured_alias", trustFrameworkEnforced: isWuaTrustFrameworkEnforced() };
  }
  if (isWuaTrustFrameworkEnforced()) {
    throw new Error(withSpecRef("Cannot verify WUA signature: ENFORCE_WUA_TRUST_FRAMEWORK=true requires configured wallet_unit_attestation_jwks (or key_attestation_jwks)", ...refs));
  }
  if (header?.jwk) return { jwk: header.jwk, verificationKeySource: "header_jwk", trustFrameworkEnforced: false };
  if (Array.isArray(header?.x5c) && header.x5c.length) return { jwk: jwkFromAttestationHeaderX5c(header), verificationKeySource: "header_x5c", trustFrameworkEnforced: false };
  throw new Error(withSpecRef("Cannot verify WUA signature: configure wallet_unit_attestation_jwks (or key_attestation_jwks), or send WUA with jwk or x5c in the protected header", ...refs));
}

export function validateWalletUnitAttestationClaims(payload, options = {}) {
  const refs = options.specRefs ?? DEFAULT_REFS;
  if (!payload || typeof payload !== "object") throw new Error(withSpecRef("WUA JWT payload is missing or invalid", ...refs));
  const legacy = payload.eudi_wallet_info;
  const isLegacy = Boolean(legacy);
  const isCs04 = Array.isArray(payload.key_storage) && payload.key_storage.length > 0 && Array.isArray(payload.user_authentication) && payload.user_authentication.length > 0 && Boolean(payload.certification);
  if (isLegacy) {
    if (!legacy.general_info || !legacy.key_storage_info) throw new Error(withSpecRef("WUA JWT missing eudi_wallet_info.general_info or eudi_wallet_info.key_storage_info", ...refs));
  } else if (!isCs04) {
    throw new Error(withSpecRef("Key Attestation missing TS03 claims key_storage, user_authentication, or certification", ...refs));
  }
  if (!Array.isArray(payload.attested_keys) || payload.attested_keys.length === 0 || payload.attested_keys.some((key) => !key || typeof key !== "object" || !key.kty)) {
    throw new Error(withSpecRef("WUA JWT attested_keys must be a non-empty array of JWK objects", ...refs));
  }
  const warnings = [];
  if (isLegacy) {
    const hasStatus = Boolean(payload.status?.status_list || payload.key_storage_status?.status);
    if (!hasStatus) throw new Error(withSpecRef("Key Attestation missing required key_storage_status", ...refs));
    const kss = payload.key_storage_status;
    if (kss) {
      const parsed = parseReferencedTokenStatus(kss, { required: false, kind: "ka" });
      if (parsed?.incomplete) warnings.push("KA key_storage_status.status_list incomplete (warning only)");
      if (typeof kss.exp !== "number") warnings.push("KA key_storage_status.exp missing (warning only)");
      else if (kss.exp < Math.floor(Date.now() / 1000)) throw new Error(withSpecRef("Key Attestation key_storage_status.exp is expired", ...refs));
    }
    return { isLegacy, isCs04, hasStatus: true, warnings };
  }
  const kss = payload.key_storage_status;
  if (!kss || typeof kss !== "object") {
    throw new Error(withSpecRef("Key Attestation missing required key_storage_status", ...refs));
  }
  parseReferencedTokenStatus(kss, { required: true, kind: "ka" });
  if (typeof kss.exp !== "number") {
    warnings.push("KA key_storage_status.exp missing (warning only)");
  } else if (kss.exp < Math.floor(Date.now() / 1000)) {
    throw new Error(withSpecRef("Key Attestation key_storage_status.exp is expired", ...refs));
  }
  return { isLegacy, isCs04, hasStatus: true, warnings };
}

/** Shared trust hook; trust-framework sessions retain their existing route-level decision. */
export function isWalletProviderAttestationTrustedByPolicy(_payload, _header, _metadata) {
  return true;
}

export async function verifyWalletProviderAttestation(wuaJwt, metadata = {}, options = {}) {
  const refs = options.specRefs ?? DEFAULT_REFS;
  const decoded = jwt.decode(wuaJwt, { complete: true });
  if (!decoded?.header || !decoded?.payload) throw new Error(withSpecRef("WUA JWT is malformed", ...refs));
  if (decoded.header.typ !== KEY_ATTESTATION_JWT_TYP) {
    throw new Error(
      withSpecRef(
        `Proof JWT is malformed or missing algorithm. Key attestation: invalid typ. Received: '${decoded.header.typ ?? "missing"}', expected: '${KEY_ATTESTATION_JWT_TYP}'`,
        ...KA_TYP_REFS,
        ...refs.filter((ref) => !KA_TYP_REFS.includes(ref))
      )
    );
  }
  if (!decoded.header.alg || typeof decoded.header.alg !== "string") throw new Error(withSpecRef("WUA JWT header missing alg", ...refs));
  const resolved = resolveWalletProviderAttestationVerificationKey(decoded.header, metadata, { specRefs: refs });
  let payload;
  try {
    const key = await jose.importJWK(resolved.jwk, decoded.header.alg);
    ({ payload } = await jose.jwtVerify(wuaJwt, key, { algorithms: [decoded.header.alg] }));
  } catch (error) {
    throw new Error(withSpecRef(`WUA signature verification failed: ${error?.message || error}`, ...refs));
  }
  const claims = validateWalletUnitAttestationClaims(payload, { specRefs: refs });
  if (!isWalletProviderAttestationTrustedByPolicy(payload, decoded.header, metadata)) throw new Error(withSpecRef("WUA rejected: Wallet Provider is not trusted by issuer policy", ...refs));
  return { header: decoded.header, payload, ...claims, ...resolved, jwk: publicJwkOnly(resolved.jwk) };
}
