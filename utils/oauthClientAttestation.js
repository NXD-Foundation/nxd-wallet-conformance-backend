/**
 * OAuth 2.0 Attestation-Based Client Authentication (wallet attestation headers)
 * as used at PAR and token endpoints (OID4VCI 1.0, HAIP 1.0).
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth
 */

import fs from "fs";
import path from "path";
import * as jose from "jose";
import {
  buildWiaStatusListEvidence,
  evaluateWuaStatusList,
  parseReferencedTokenStatus,
  publicJwkOnly,
} from "./wuaStatusListVerifier.js";

export const CLIENT_ATTESTATION_JWT_TYP = "oauth-client-attestation+jwt";
export const CLIENT_ATTESTATION_POP_TYP = "oauth-client-attestation-pop+jwt";
const SPEC_REFS = {
  HAIP_WALLET_ATTESTATION: "HAIP 1.0 §4.3-4.4.1",
  OAUTH_CLIENT_ATTESTATION: "draft-ietf-oauth-attestation-based-client-auth-08 §4.1.1",
  OAUTH_CLIENT_ATTESTATION_POP: "draft-ietf-oauth-attestation-based-client-auth-08 §4.1.2",
  JWK_PUBLIC_ONLY: "RFC 7517",
};

function withSpecRef(message, ...refs) {
  const present = refs.filter(Boolean);
  if (present.length === 0) return message;
  return `${message} See ${present.join(" and ")}.`;
}

const ASYMMETRIC_ALGS = new Set(["ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"]);

let _trustedJwksCache = null;

export function resetClientAttestationTrustedJwksCache() {
  _trustedJwksCache = null;
}

/**
 * JWKS object trusted to sign client attestation JWTs (wallet attester keys).
 * Configured in data/oauth-config.json as `client_attestation_trusted_jwks`.
 */
export function getTrustedClientAttesterJwks() {
  if (_trustedJwksCache) return _trustedJwksCache;
  try {
    const oauthPath = path.join(process.cwd(), "data/oauth-config.json");
    const cfg = JSON.parse(fs.readFileSync(oauthPath, "utf8"));
    const jwks = cfg.client_attestation_trusted_jwks;
    _trustedJwksCache =
      jwks && Array.isArray(jwks.keys) ? jwks : { keys: [] };
    return _trustedJwksCache;
  } catch {
    _trustedJwksCache = { keys: [] };
    return _trustedJwksCache;
  }
}

export function getOAuthClientAttestationHeaders(headers) {
  const h = headers || {};
  const att = firstHeaderValue(h, "oauth-client-attestation");
  const pop = firstHeaderValue(h, "oauth-client-attestation-pop");
  return { attestationJwt: att, popJwt: pop };
}

function firstHeaderValue(headers, lowerName) {
  const keys = Object.keys(headers);
  for (const k of keys) {
    if (k.toLowerCase() === lowerName) {
      const v = headers[k];
      if (Array.isArray(v)) {
        if (v.length === 1) return String(v[0]).trim();
        return null;
      }
      if (typeof v === "string") return v.trim();
    }
  }
  return undefined;
}

/**
 * Reject JWKs that include private key material (RFC 7517 — must not ship private keys in cnf).
 */
export function assertCnfJwkIsPublicOnly(jwk) {
  if (!jwk || typeof jwk !== "object") {
    throw new Error(withSpecRef("cnf.jwk missing or not an object", SPEC_REFS.OAUTH_CLIENT_ATTESTATION, SPEC_REFS.JWK_PUBLIC_ONLY));
  }
  const forbidden = ["d", "p", "q", "dp", "dq", "qi", "oth"];
  for (const f of forbidden) {
    if (jwk[f] !== undefined) {
      throw new Error(withSpecRef("cnf.jwk must not contain private key material", SPEC_REFS.OAUTH_CLIENT_ATTESTATION, SPEC_REFS.JWK_PUBLIC_ONLY));
    }
  }
  if (!jwk.kty) {
    throw new Error(withSpecRef("cnf.jwk missing kty", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
  }
}

export function assertAsymmetricJwtAlg(alg) {
  if (!alg || alg === "none" || alg.startsWith("HS")) {
    throw new Error(withSpecRef("JWT must use an asymmetric signature algorithm", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
  }
  if (!ASYMMETRIC_ALGS.has(alg)) {
    throw new Error(withSpecRef(`Unsupported or non-asymmetric alg: ${alg}`, SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
  }
}

/**
 * Verifies client attestation JWT signature against trusted attester JWKS.
 * @returns {Promise<{ payload: object, protectedHeader: object }>}
 * @throws If trustedJwks has no keys (use {@link decodeClientAttestationJwtPayloadUnverified} for dev-only bypass at call site).
 */
export async function verifyClientAttestationJwt(attestationJwt, trustedJwks, options = {}) {
  const { clockTolerance = 120 } = options;
  if (!trustedJwks?.keys?.length) {
    throw new Error("No trusted client attester keys configured");
  }
  try {
    const JWKS = jose.createLocalJWKSet(trustedJwks);
    const { payload, protectedHeader } = await jose.jwtVerify(attestationJwt, JWKS, {
      clockTolerance,
      typ: CLIENT_ATTESTATION_JWT_TYP,
    });
    assertAsymmetricJwtAlg(protectedHeader.alg);
    return { payload, protectedHeader };
  } catch (error) {
    if (error?.code === "ERR_JWT_CLAIM_VALIDATION_FAILED" && String(error?.message || "").includes('"typ"')) {
      throw new Error(
        withSpecRef(
          `Attestation JWT must have typ ${CLIENT_ATTESTATION_JWT_TYP}`,
          SPEC_REFS.HAIP_WALLET_ATTESTATION,
          SPEC_REFS.OAUTH_CLIENT_ATTESTATION
        )
      );
    }
    throw error;
  }
}

/**
 * Decodes attestation JWT payload without verifying the attester signature (dev / no trust anchor).
 * Still enforces asymmetric alg and expected `typ` in the protected header.
 */
export function decodeClientAttestationJwtPayloadUnverified(attestationJwt) {
  const protectedHeader = jose.decodeProtectedHeader(attestationJwt);
  assertAsymmetricJwtAlg(protectedHeader.alg);
  if (protectedHeader.typ !== CLIENT_ATTESTATION_JWT_TYP) {
    throw new Error(
      withSpecRef(
        `Attestation JWT must have typ ${CLIENT_ATTESTATION_JWT_TYP}`,
        SPEC_REFS.HAIP_WALLET_ATTESTATION,
        SPEC_REFS.OAUTH_CLIENT_ATTESTATION
      )
    );
  }
  const payload = jose.decodeJwt(attestationJwt);
  return { payload, protectedHeader };
}

/**
 * Verifies PoP JWT: signature must match cnf.jwk from the attestation, typ, aud, freshness.
 */
export async function verifyClientAttestationPopJwt(
  popJwt,
  cnfJwk,
  {
    authorizationServerIssuer,
    clockTolerance = 120,
    maxIatAgeSeconds = 600,
  }
) {
  assertCnfJwkIsPublicOnly(cnfJwk);
  const decoded = jose.decodeProtectedHeader(popJwt);
  assertAsymmetricJwtAlg(decoded.alg);
  const publicKey = await jose.importJWK(cnfJwk, decoded.alg);
  let payload;
  let protectedHeader;
  try {
    ({ payload, protectedHeader } = await jose.jwtVerify(popJwt, publicKey, {
      audience: authorizationServerIssuer,
      clockTolerance,
      typ: CLIENT_ATTESTATION_POP_TYP,
    }));
  } catch (error) {
    const message = String(error?.message || "");
    if (error?.code === "ERR_JWT_CLAIM_VALIDATION_FAILED" && message.includes('"typ"')) {
      throw new Error(
        withSpecRef(
          `PoP JWT must have typ ${CLIENT_ATTESTATION_POP_TYP}`,
          SPEC_REFS.OAUTH_CLIENT_ATTESTATION_POP
        )
      );
    }
    if (error?.code === "ERR_JWT_CLAIM_VALIDATION_FAILED" && message.includes('"aud"')) {
      throw new Error(
        withSpecRef(
          `PoP JWT aud must match authorization server issuer '${authorizationServerIssuer}'`,
          SPEC_REFS.OAUTH_CLIENT_ATTESTATION_POP
        )
      );
    }
    throw error;
  }
  assertAsymmetricJwtAlg(protectedHeader.alg);

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== "number") {
    throw new Error(withSpecRef("PoP JWT missing iat", SPEC_REFS.OAUTH_CLIENT_ATTESTATION_POP));
  }
  if (Math.abs(now - payload.iat) > maxIatAgeSeconds + clockTolerance) {
    throw new Error(withSpecRef("PoP JWT iat is outside allowed freshness window", SPEC_REFS.OAUTH_CLIENT_ATTESTATION_POP));
  }
  if (!payload.jti) {
    throw new Error(withSpecRef("PoP JWT missing jti", SPEC_REFS.OAUTH_CLIENT_ATTESTATION_POP));
  }
  return { payload, protectedHeader };
}

export function assertClientIdMatchesAttestationSub(clientId, attestationSub) {
  if (clientId == null || clientId === "") return;
  if (attestationSub !== clientId) {
    throw new Error(withSpecRef("client_id does not match attestation sub", SPEC_REFS.HAIP_WALLET_ATTESTATION));
  }
}

export function assertPopIssMatchesAttestationSub(popIss, attestationSub) {
  if (popIss !== attestationSub) {
    throw new Error(withSpecRef("PoP iss does not match attestation sub", SPEC_REFS.OAUTH_CLIENT_ATTESTATION_POP));
  }
}

function base64DerToPem(b64) {
  const lines = String(b64).match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

async function matchingTrustedAttesterJwk(attestationJwt, trustedJwks, alg) {
  const header = jose.decodeProtectedHeader(attestationJwt);
  const keys = trustedJwks?.keys || [];
  if (header?.kid) {
    const matched = keys.find((key) => key.kid === header.kid);
    if (!matched) {
      throw new Error(
        withSpecRef(
          `Cannot verify WIA signature: no trusted attester key matches kid '${header.kid}'`,
          SPEC_REFS.OAUTH_CLIENT_ATTESTATION
        )
      );
    }
    return publicJwkOnly(matched);
  }
  for (const candidate of keys) {
    try {
      const key = await jose.importJWK(candidate, alg);
      await jose.jwtVerify(attestationJwt, key, { algorithms: [alg], typ: CLIENT_ATTESTATION_JWT_TYP });
      return publicJwkOnly(candidate);
    } catch {
      continue;
    }
  }
  throw new Error(
    withSpecRef(
      "Cannot verify WIA signature: no configured attester key verified the attestation",
      SPEC_REFS.OAUTH_CLIENT_ATTESTATION
    )
  );
}

/**
 * Resolve verification key for WIA JWS: trusted JWKS, x5c chain, or header.jwk (dev).
 */
export async function resolveWiaVerificationKey(attestationJwt, trustedJwks, protectedHeader) {
  const header = protectedHeader ?? jose.decodeProtectedHeader(attestationJwt);
  const alg = header?.alg || "ES256";

  if (trustedJwks?.keys?.length) {
    const JWKS = jose.createLocalJWKSet(trustedJwks);
    const { protectedHeader: verifiedHeader } = await jose.jwtVerify(attestationJwt, JWKS, {
      typ: CLIENT_ATTESTATION_JWT_TYP,
      algorithms: [alg],
    });
    const verificationJwk = await matchingTrustedAttesterJwk(attestationJwt, trustedJwks, alg);
    return { verified: true, protectedHeader: verifiedHeader, alg, verificationJwk };
  }

  if (Array.isArray(header?.x5c) && header.x5c.length > 0) {
    const key = await jose.importX509(base64DerToPem(header.x5c[0]), alg);
    await jose.jwtVerify(attestationJwt, key, { algorithms: [alg], typ: CLIENT_ATTESTATION_JWT_TYP });
    const verificationJwk = publicJwkOnly(await jose.exportJWK(key));
    return { verified: true, protectedHeader: header, alg, verificationJwk };
  }

  if (header?.jwk) {
    const key = await jose.importJWK(header.jwk, alg);
    await jose.jwtVerify(attestationJwt, key, { algorithms: [alg], typ: CLIENT_ATTESTATION_JWT_TYP });
    return { verified: true, protectedHeader: header, alg, verificationJwk: publicJwkOnly(header.jwk) };
  }

  throw new Error(
    withSpecRef(
      "Cannot verify WIA signature: configure client_attestation_trusted_jwks or provide x5c/jwk in WIA header",
      SPEC_REFS.OAUTH_CLIENT_ATTESTATION
    )
  );
}

/**
 * Structural validation for CS-04 WIA claims (without Trusted List check).
 * @returns {{ warnings: string[] }}
 */
export function validateWiaStructureClaims(payload, { requireClientStatus = false } = {}) {
  const warnings = [];
  if (!payload || typeof payload !== "object") {
    throw new Error(withSpecRef("WIA payload missing or invalid", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
  }
  if (!payload.sub || typeof payload.sub !== "string") {
    throw new Error(withSpecRef("WIA missing sub claim", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
  }
  if (typeof payload.exp !== "number" || typeof payload.iat !== "number") {
    throw new Error(withSpecRef("WIA missing exp or iat claim", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
  }
  const ttlHours = (payload.exp - payload.iat) / 3600;
  if (ttlHours < 0) {
    throw new Error(withSpecRef("WIA has invalid expiration (exp < iat)", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
  }
  if (ttlHours >= 24) {
    throw new Error(
      withSpecRef(
        `WIA TTL (${ttlHours.toFixed(2)} hours) exceeds maximum allowed (24 hours)`,
        SPEC_REFS.OAUTH_CLIENT_ATTESTATION
      )
    );
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) {
    throw new Error(withSpecRef("WIA JWT has expired", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
  }
  if (!payload.cnf?.jwk) {
    throw new Error(withSpecRef("WIA missing cnf.jwk", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
  }
  assertCnfJwkIsPublicOnly(payload.cnf.jwk);

  if (!payload.client_status) {
    if (requireClientStatus) {
      throw new Error(withSpecRef("WIA missing required client_status claim", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
    }
    warnings.push("WIA missing client_status; revocation maintenance not asserted (warning only)");
  } else {
    const cs = payload.client_status;
    const parsed = parseReferencedTokenStatus(cs, { required: requireClientStatus, kind: "wia" });
    if (!requireClientStatus && parsed?.incomplete) {
      warnings.push("WIA client_status.status_list incomplete (warning only)");
    }
    if (typeof cs.exp !== "number") {
      if (requireClientStatus) {
        throw new Error(withSpecRef("WIA client_status.exp is missing", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
      }
      warnings.push("WIA client_status.exp missing (warning only)");
    } else if (cs.exp < now) {
      throw new Error(withSpecRef("WIA client_status.exp is expired", SPEC_REFS.OAUTH_CLIENT_ATTESTATION));
    }
  }

  return { warnings };
}

/**
 * Stub: Wallet Provider trusted via Trusted List — always true until TL is wired.
 */
export function isWalletProviderTrustedByPolicy(_payload, _header) {
  return true;
}

/**
 * @returns {Promise<string>} JWK thumbprint (sha256) of WIA cnf.jwk
 */
export async function computeWiaCnfJkt(cnfJwk) {
  assertCnfJwkIsPublicOnly(cnfJwk);
  return jose.calculateJwkThumbprint(cnfJwk, "sha256");
}

/**
 * Full validation for PAR / token when OAuth-Client-Attestation headers are used.
 *
 * - If neither header is sent → { skip: true } unless requireAttestation is true.
 * - If exactly one header is sent → invalid_client (malformed client auth).
 * - If both are sent → verify PoP against `cnf.jwk` from the attestation JWT.
 * - When strictWiaSignature is true, verify WIA JWS via JWKS, x5c, or header.jwk.
 */
export async function validateOAuthClientAttestationFromRequest({
  headers,
  clientId,
  authorizationServerIssuer,
  trustedJwks,
  clockTolerance = 120,
  maxPopIatAgeSeconds = 600,
  requireAttestation = false,
  strictWiaSignature = false,
  statusList = {},
}) {
  const { attestationJwt, popJwt } = getOAuthClientAttestationHeaders(headers);

  const hasAtt = Boolean(attestationJwt);
  const hasPop = Boolean(popJwt);

  if (!hasAtt && !hasPop) {
    if (requireAttestation) {
      return {
        skip: false,
        ok: false,
        statusCode: 401,
        oauthError: "invalid_client",
        errorDescription: withSpecRef(
          "Wallet Instance Attestation headers are required for this credential",
          SPEC_REFS.HAIP_WALLET_ATTESTATION,
          SPEC_REFS.OAUTH_CLIENT_ATTESTATION
        ),
      };
    }
    return { skip: true };
  }

  if (hasAtt !== hasPop) {
    return {
      skip: false,
      ok: false,
      statusCode: 401,
      oauthError: "invalid_client",
      errorDescription: withSpecRef(
        "Both OAuth-Client-Attestation and OAuth-Client-Attestation-PoP are required",
        SPEC_REFS.HAIP_WALLET_ATTESTATION,
        SPEC_REFS.OAUTH_CLIENT_ATTESTATION,
        SPEC_REFS.OAUTH_CLIENT_ATTESTATION_POP
      ),
    };
  }

  const jwks = trustedJwks ?? getTrustedClientAttesterJwks();

  try {
    let attestationPayload;
    let protectedHeader;
    let verificationJwk = null;
    const useStrictSig = strictWiaSignature || requireAttestation;

    if (useStrictSig) {
      const sig = await resolveWiaVerificationKey(attestationJwt, jwks?.keys?.length ? jwks : null, null);
      protectedHeader = sig.protectedHeader;
      attestationPayload = jose.decodeJwt(attestationJwt);
      verificationJwk = sig.verificationJwk || null;
      assertAsymmetricJwtAlg(protectedHeader.alg);
    } else if (jwks?.keys?.length) {
      const verified = await verifyClientAttestationJwt(attestationJwt, jwks, { clockTolerance });
      attestationPayload = verified.payload;
      protectedHeader = verified.protectedHeader;
      verificationJwk = await matchingTrustedAttesterJwk(attestationJwt, jwks, protectedHeader.alg);
    } else {
      const decoded = decodeClientAttestationJwtPayloadUnverified(attestationJwt);
      attestationPayload = decoded.payload;
      protectedHeader = decoded.protectedHeader;
      if (protectedHeader.jwk) {
        verificationJwk = publicJwkOnly(protectedHeader.jwk);
      } else if (Array.isArray(protectedHeader.x5c) && protectedHeader.x5c.length) {
        const key = await jose.importX509(base64DerToPem(protectedHeader.x5c[0]), protectedHeader.alg || "ES256");
        verificationJwk = publicJwkOnly(await jose.exportJWK(key));
      }
    }

    const { warnings: wiaWarnings } = validateWiaStructureClaims(attestationPayload, {
      requireClientStatus: requireAttestation,
    });

    if (!isWalletProviderTrustedByPolicy(attestationPayload, protectedHeader)) {
      throw new Error(
        withSpecRef("WIA rejected: Wallet Provider not trusted by issuer policy", SPEC_REFS.OAUTH_CLIENT_ATTESTATION)
      );
    }

    const cnfJwk = attestationPayload.cnf?.jwk;
    assertCnfJwkIsPublicOnly(cnfJwk);

    const { payload: popPayload } = await verifyClientAttestationPopJwt(popJwt, cnfJwk, {
      authorizationServerIssuer,
      clockTolerance,
      maxIatAgeSeconds: maxPopIatAgeSeconds,
    });

    assertClientIdMatchesAttestationSub(clientId, attestationPayload.sub);
    assertPopIssMatchesAttestationSub(popPayload.iss, attestationPayload.sub);

    const wiaCnfJkt = await computeWiaCnfJkt(cnfJwk);
    let wiaStatusList = null;
    if (requireAttestation) {
      const parsed = parseReferencedTokenStatus(attestationPayload.client_status, {
        required: true,
        kind: "wia",
      });
      const statusVerificationJwk = publicJwkOnly(verificationJwk);
      if (!statusVerificationJwk) {
        throw new Error(
          withSpecRef(
            "WIA Status List Token cannot be verified without the Wallet Provider public key",
            SPEC_REFS.OAUTH_CLIENT_ATTESTATION
          )
        );
      }
      await evaluateWuaStatusList({
        uri: parsed.uri,
        idx: parsed.idx,
        verificationJwk: statusVerificationJwk,
        kind: "wia",
        ...statusList,
      });
      wiaStatusList = buildWiaStatusListEvidence({
        uri: parsed.uri,
        idx: parsed.idx,
        exp: parsed.exp,
        verificationJwk: statusVerificationJwk,
      });
    }

    return {
      skip: false,
      ok: true,
      attestationPayload,
      protectedHeader,
      popPayload,
      wiaCnfJkt,
      wiaWarnings,
      clientStatusPresent: Boolean(attestationPayload.client_status),
      verificationJwk: publicJwkOnly(verificationJwk),
      wiaStatusList,
    };
  } catch (err) {
    return {
      skip: false,
      ok: false,
      statusCode: 401,
      oauthError: "invalid_client",
      errorDescription: err.message || "Client attestation verification failed",
    };
  }
}
