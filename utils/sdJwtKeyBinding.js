import {
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
} from "jose";

function decodeJwtPayload(jwt) {
  if (typeof jwt !== "string") return null;
  const parts = jwt.split(".");
  if (parts.length < 2) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function publicJwk(jwk) {
  if (!jwk || typeof jwk !== "object") return null;
  const result = { ...jwk };
  delete result.d;
  delete result.dp;
  delete result.dq;
  delete result.p;
  delete result.q;
  delete result.qi;
  return result;
}

export function jwkPublicEquals(a, b) {
  const left = publicJwk(a);
  const right = publicJwk(b);
  if (!left || !right) return false;

  const keyFields = ["kty", "crv", "x", "y", "e", "n"];
  return keyFields.every(
    (field) => (left[field] || undefined) === (right[field] || undefined),
  );
}

export function extractKeyBindingJwtFromSdJwt(sdJwt) {
  if (typeof sdJwt !== "string") return null;
  const parts = sdJwt.split("~").filter((part) => part.length > 0);
  const last = parts[parts.length - 1];
  return last && last.split(".").length === 3 ? last : null;
}

export function extractCredentialCnfJwkFromSdJwt(sdJwt) {
  if (typeof sdJwt !== "string") return null;
  const issuerJwt = sdJwt.split("~")[0];
  const payload = decodeJwtPayload(issuerJwt);
  return payload?.cnf?.jwk || null;
}

export async function validateSdJwtKeyBindingMatchesCredential({
  sdJwt,
  keyBindingJwt,
  clockTolerance = 300,
} = {}) {
  const kbJwt = keyBindingJwt || extractKeyBindingJwtFromSdJwt(sdJwt);
  if (!kbJwt) {
    throw new Error("missing_key_binding_jwt");
  }

  const cnfJwk = extractCredentialCnfJwkFromSdJwt(sdJwt);
  if (!cnfJwk) {
    throw new Error("credential_cnf_jwk_missing");
  }

  let header;
  try {
    header = decodeProtectedHeader(kbJwt);
  } catch {
    throw new Error("invalid_key_binding_jwt_header");
  }

  try {
    const verificationKey = await importJWK(cnfJwk, header.alg || cnfJwk.alg);
    await jwtVerify(kbJwt, verificationKey, { clockTolerance });
  } catch {
    throw new Error("key_binding_signature_invalid");
  }

  return {
    ok: true,
    cnfJwk: publicJwk(cnfJwk),
    keyBindingJwk: publicJwk(cnfJwk),
  };
}
