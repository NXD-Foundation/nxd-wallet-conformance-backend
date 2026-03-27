/**
 * OAuth 2.0 Attestation-Based Client Authentication (wallet attestation headers)
 * as used at PAR and token endpoints (OID4VCI 1.0, HAIP 1.0).
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth
 */

import fs from "fs";
import path from "path";
import * as jose from "jose";

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

/**
 * Full validation for PAR / token when OAuth-Client-Attestation headers are used.
 *
 * - If neither header is sent → { skip: true } (e.g. public client without attestation).
 * - If exactly one header is sent → invalid_client (malformed client auth).
 * - If both are sent → verify PoP against `cnf.jwk` from the attestation JWT. When
 *   `client_attestation_trusted_jwks` is non-empty, the attestation JWT signature is verified
 *   against those keys; when empty, the attester signature is not verified (PoP still is).
 */
export async function validateOAuthClientAttestationFromRequest({
  headers,
  clientId,
  authorizationServerIssuer,
  trustedJwks,
  clockTolerance = 120,
  maxPopIatAgeSeconds = 600,
}) {
  const { attestationJwt, popJwt } = getOAuthClientAttestationHeaders(headers);

  const hasAtt = Boolean(attestationJwt);
  const hasPop = Boolean(popJwt);

  if (!hasAtt && !hasPop) {
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
    if (jwks?.keys?.length) {
      const { payload } = await verifyClientAttestationJwt(attestationJwt, jwks, { clockTolerance });
      attestationPayload = payload;
    } else {
      const decoded = decodeClientAttestationJwtPayloadUnverified(attestationJwt);
      attestationPayload = decoded.payload;
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

    return {
      skip: false,
      ok: true,
      attestationPayload,
      popPayload,
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
