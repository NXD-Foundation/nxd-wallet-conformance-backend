import {
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  calculateJwkThumbprint,
} from "jose";

export const WIA_JWT_TYP = "oauth-client-attestation+jwt";
export const WIA_POP_JWT_TYP = "oauth-client-attestation-pop+jwt";

function normalizeAudienceUrl(url) {
  if (url == null || url === "") return url;
  try {
    const u = new URL(String(url));
    u.hash = "";
    if (u.pathname !== "/" && u.pathname.endsWith("/")) {
      u.pathname = u.pathname.slice(0, -1);
    }
    return u.toString();
  } catch {
    return String(url);
  }
}

function audienceIncludes(audClaim, expectedAudience) {
  const expected = normalizeAudienceUrl(expectedAudience);
  if (!expected) return false;
  if (Array.isArray(audClaim)) {
    return audClaim.some((a) => normalizeAudienceUrl(a) === expected);
  }
  return normalizeAudienceUrl(audClaim) === expected;
}

function assertCnfJwkIsPublicOnly(jwk) {
  if (!jwk || typeof jwk !== "object") {
    throw new Error("wia_cnf_missing: WIA cnf.jwk is required for PoP");
  }
  for (const k of ["d", "p", "q", "dp", "dq", "qi", "oth"]) {
    if (jwk[k] !== undefined) {
      throw new Error("wia_cnf_invalid: cnf.jwk must not contain private key material");
    }
  }
  if (!jwk.kty) {
    throw new Error("wia_cnf_invalid: cnf.jwk missing kty");
  }
}

/**
 * Local RFC001 §7.3 / §7.4 checks before sending PAR or Token requests.
 * Verifies WIA/PoP shape, audiences, PoP signature under WIA `cnf.jwk`, and optional `client_id` = WIA `sub`.
 */
export async function validateWiaMaterialForParOrToken({
  wiaJwt,
  wiaPopJwt,
  endpointAudience,
  authorizationServerIssuer,
  clientId,
  clockTolerance = 120,
  maxPopIatAgeSeconds = 600,
}) {
  if (!wiaJwt || !wiaPopJwt) {
    throw new Error("wia_required: WIA and WIA PoP JWTs are required for PAR/Token");
  }

  const wiaHeader = decodeProtectedHeader(wiaJwt);
  if (wiaHeader.typ !== WIA_JWT_TYP) {
    throw new Error(`wia_invalid_typ: expected ${WIA_JWT_TYP}`);
  }

  let wiaPayload;
  if (wiaHeader.jwk) {
    const wiaKey = await importJWK(wiaHeader.jwk, wiaHeader.alg || "ES256");
    ({ payload: wiaPayload } = await jwtVerify(wiaJwt, wiaKey, {
      clockTolerance,
      typ: WIA_JWT_TYP,
    }));
    if (!audienceIncludes(wiaPayload.aud, endpointAudience)) {
      throw new Error(
        `wia_aud_mismatch: WIA aud must include endpoint audience ${endpointAudience}`,
      );
    }
  } else {
    wiaPayload = decodeJwt(wiaJwt);
    if (!audienceIncludes(wiaPayload.aud, endpointAudience)) {
      throw new Error(
        `wia_aud_mismatch: WIA aud must include endpoint audience ${endpointAudience}`,
      );
    }
    const now = Math.floor(Date.now() / 1000);
    if (typeof wiaPayload.exp === "number" && wiaPayload.exp < now - clockTolerance) {
      throw new Error("wia_expired: WIA JWT has expired");
    }
    if (typeof wiaPayload.nbf === "number" && wiaPayload.nbf > now + clockTolerance) {
      throw new Error("wia_not_yet_valid: WIA JWT is not yet valid");
    }
  }

  if (clientId != null && clientId !== "" && wiaPayload.sub !== clientId) {
    throw new Error("wia_client_id_mismatch: client_id must equal WIA sub");
  }

  const cnfJwk = wiaPayload.cnf?.jwk;
  assertCnfJwkIsPublicOnly(cnfJwk);

  const popHeader = decodeProtectedHeader(wiaPopJwt);
  if (popHeader.typ !== WIA_POP_JWT_TYP) {
    throw new Error(`wia_pop_invalid_typ: expected ${WIA_POP_JWT_TYP}`);
  }

  const asIssuer = normalizeAudienceUrl(authorizationServerIssuer);
  if (!asIssuer) {
    throw new Error("wia_pop_aud_missing: authorization server issuer is required for PoP aud");
  }

  const popKey = await importJWK(cnfJwk, popHeader.alg || "ES256");
  const { payload: popPayload } = await jwtVerify(wiaPopJwt, popKey, {
    clockTolerance,
    typ: WIA_POP_JWT_TYP,
  });
  if (!audienceIncludes(popPayload.aud, asIssuer)) {
    throw new Error(
      `wia_pop_aud_mismatch: PoP aud must match authorization server issuer ${authorizationServerIssuer}`,
    );
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof popPayload.iat !== "number") {
    throw new Error("wia_pop_invalid: PoP JWT missing iat");
  }
  if (Math.abs(now - popPayload.iat) > maxPopIatAgeSeconds + clockTolerance) {
    throw new Error("wia_pop_invalid: PoP JWT iat is outside allowed freshness window");
  }
  if (!popPayload.jti) {
    throw new Error("wia_pop_invalid: PoP JWT missing jti");
  }
  if (popPayload.iss !== wiaPayload.sub) {
    throw new Error("wia_pop_iss_mismatch: PoP iss must equal WIA sub (wallet instance id)");
  }

  if (wiaHeader.jwk && cnfJwk) {
    const tHeader = await calculateJwkThumbprint(wiaHeader.jwk, "sha256");
    const tCnf = await calculateJwkThumbprint(cnfJwk, "sha256");
    if (tHeader !== tCnf) {
      throw new Error("wia_cnf_mismatch: WIA cnf.jwk must match the attestation signing key");
    }
  }

  return {
    wiaPayload,
    popPayload,
    walletInstanceId: wiaPayload.sub,
    walletProviderId: wiaPayload.iss,
  };
}
