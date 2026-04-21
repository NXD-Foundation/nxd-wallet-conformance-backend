import { jwtVerify, decodeProtectedHeader, importX509 } from "jose";

function pemFromDerBase64(b64) {
  const body = String(b64).replace(/\s+/g, "");
  const lines = body.match(/.{1,64}/g) || [body];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * @param {string} body
 * @returns {string | null} compact serialization or null
 */
export function trimCompactJws(body) {
  if (typeof body !== "string") return null;
  const t = body.trim();
  if (!t) return null;
  const parts = t.split(".");
  if (parts.length !== 3) return null;
  return t;
}

/**
 * Verify OpenID Credential Issuer metadata delivered as a JWS (RFC001 §7.7 / ETSI), using `x5c` from the protected header.
 *
 * @param {string} compactJwt
 * @returns {Promise<{ payload: import('jose').JWTPayload, header: import('jose').ProtectedHeaderParameters }>}
 */
export async function verifyIssuerMetadataJws(compactJwt) {
  const header = decodeProtectedHeader(compactJwt);
  const x5c = header.x5c;
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new Error("Signed issuer metadata JWS missing x5c in the protected header");
  }
  const alg = header.alg;
  if (!alg || !["ES256", "ES384", "RS256", "PS256"].includes(alg)) {
    throw new Error(`Signed issuer metadata JWS uses unsupported alg: ${alg ?? "(none)"}`);
  }
  const derB64 = typeof x5c[0] === "string" ? x5c[0] : Buffer.from(x5c[0]).toString("base64");
  const leafPem = pemFromDerBase64(derB64);
  const key = await importX509(leafPem, alg);
  const { payload } = await jwtVerify(compactJwt, key, { algorithms: [alg] });
  return { payload, header };
}

/**
 * Parse a successful HTTP response from `/.well-known/openid-credential-issuer`.
 * Supports `application/json` and signed `application/jwt` / `typ: jwt` metadata.
 *
 * @param {Response} res — `ok` is assumed true by caller
 * @returns {Promise<{ meta: object, debug: object | null }>}
 */
export async function parseIssuerMetadataHttpResponse(res) {
  const ct = (res.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  const text = await res.text();
  const compact = trimCompactJws(text);

  if (!compact) {
    let meta;
    try {
      meta = JSON.parse(text);
    } catch (e) {
      throw new Error(`Issuer metadata response is not JSON: ${e.message}`);
    }
    return { meta, debug: null };
  }

  let header;
  try {
    header = decodeProtectedHeader(compact);
  } catch {
    throw new Error("Issuer metadata looks like a compact JWS but the protected header is invalid");
  }

  const typ = header.typ != null ? String(header.typ).toLowerCase() : "";
  const declaredAsJwt = ct === "application/jwt" || typ === "jwt";

  if (!declaredAsJwt) {
    throw new Error(
      "Issuer metadata response is a compact JWS; use Content-Type: application/jwt or set JWS header typ to jwt",
    );
  }

  if (!header.x5c || !Array.isArray(header.x5c) || header.x5c.length === 0) {
    throw new Error("Signed issuer metadata (JWT) is missing x5c");
  }

  const { payload } = await verifyIssuerMetadataJws(compact);
  const meta = { ...payload };
  const issuerInfo = meta.issuer_info;
  const regCert =
    issuerInfo && typeof issuerInfo === "object" && "registration_certificate" in issuerInfo
      ? issuerInfo.registration_certificate
      : null;

  const debug = {
    signed_metadata_jws: true,
    issuer_info_registration_certificate: regCert,
  };

  return { meta, debug };
}
