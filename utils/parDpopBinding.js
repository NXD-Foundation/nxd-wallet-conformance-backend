import * as jose from "jose";

const MAX_PAST_IAT_SECONDS = 300;
const MAX_FUTURE_IAT_SECONDS = 60;
const ALLOWED_ALGS = ["ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"];

function bindingError(message) {
  const error = new Error(message);
  error.errorCode = "invalid_dpop_proof";
  return error;
}

/**
 * RFC 9449 §10: a PAR request binds the authorization code to a DPoP key with
 * either a `dpop_jkt` parameter or a DPoP proof header. When both are sent the
 * thumbprints must match. Returns the bound thumbprint, or null when neither is sent.
 */
export async function resolveParDpopJkt({ dpopHeader, dpopJkt, expectedHtu, now = Math.floor(Date.now() / 1000) }) {
  let headerJkt = null;
  if (typeof dpopHeader === "string" && dpopHeader) {
    let protectedHeader;
    try {
      protectedHeader = jose.decodeProtectedHeader(dpopHeader);
    } catch {
      throw bindingError("DPoP proof header is not a valid JWS");
    }
    if (protectedHeader.typ !== "dpop+jwt") throw bindingError("DPoP proof typ must be dpop+jwt");
    if (!ALLOWED_ALGS.includes(protectedHeader.alg)) throw bindingError("DPoP proof uses an unsupported algorithm");
    if (!protectedHeader.jwk || protectedHeader.jwk.d) throw bindingError("DPoP proof must carry a public jwk");
    let payload;
    try {
      const key = await jose.importJWK(protectedHeader.jwk, protectedHeader.alg);
      ({ payload } = await jose.jwtVerify(dpopHeader, key, { algorithms: [protectedHeader.alg] }));
    } catch (error) {
      throw bindingError(`DPoP proof signature is invalid (${error.message})`);
    }
    if (payload.htm !== "POST") throw bindingError("DPoP proof htm must be POST");
    if (payload.htu !== expectedHtu) throw bindingError(`DPoP proof htu must be ${expectedHtu}`);
    if (typeof payload.jti !== "string" || !payload.jti) throw bindingError("DPoP proof jti is required");
    if (!Number.isFinite(payload.iat) || payload.iat < now - MAX_PAST_IAT_SECONDS || payload.iat > now + MAX_FUTURE_IAT_SECONDS) {
      throw bindingError("DPoP proof iat is outside the accepted time window");
    }
    headerJkt = await jose.calculateJwkThumbprint(protectedHeader.jwk, "sha256");
  }
  const paramJkt = typeof dpopJkt === "string" && dpopJkt ? dpopJkt : null;
  if (headerJkt && paramJkt && headerJkt !== paramJkt) {
    throw bindingError("dpop_jkt does not match the DPoP proof key");
  }
  return headerJkt || paramJkt;
}
