import { compactDecrypt, exportJWK, generateKeyPair } from "jose";

/**
 * OID4VCI credential_response_encryption object for the credential request body.
 * @param {object} ephemeralPublicJwk — public JWK (kty EC P-256, alg ECDH-ES)
 * @param {string} enc — content encryption alg from issuer metadata (e.g. A128GCM)
 */
export function buildCredentialResponseEncryption(ephemeralPublicJwk, enc) {
  return {
    jwk: ephemeralPublicJwk,
    enc,
  };
}

/**
 * When issuer metadata advertises ECDH-ES + enc, prepare an ephemeral P-256 key pair
 * and the request fragment to send.
 * @param {object} issuerMeta — credential issuer metadata
 * @returns {Promise<{ credential_response_encryption: object, privateKey: import("jose").KeyLike } | null>}
 */
export async function prepareCredentialResponseEncryption(issuerMeta) {
  const block = issuerMeta?.credential_response_encryption;
  if (!block || typeof block !== "object") return null;

  const algs = block.alg_values_supported;
  const encs = block.enc_values_supported;
  if (!Array.isArray(algs) || !algs.includes("ECDH-ES")) return null;
  if (!Array.isArray(encs) || encs.length === 0) return null;

  const enc = encs[0];
  const { publicKey, privateKey } = await generateKeyPair("ECDH-ES", { crv: "P-256" });
  const jwk = await exportJWK(publicKey);
  jwk.alg = "ECDH-ES";

  return {
    credential_response_encryption: buildCredentialResponseEncryption(jwk, enc),
    privateKey,
  };
}

/**
 * Parse credential (or deferred) success response: JSON, or compact JWE when encrypted.
 * @param {string} responseText
 * @param {string | null | undefined} contentType
 * @param {import("jose").KeyLike | null | undefined} decryptionPrivateKey — ephemeral private key when encryption was requested
 */
export async function parseCredentialResponsePayload(responseText, contentType, decryptionPrivateKey) {
  const trimmed = (responseText ?? "").trim();
  if (!trimmed) return null;

  if (!decryptionPrivateKey) {
    return JSON.parse(trimmed);
  }

  const ct = (contentType || "").toLowerCase();
  const looksLikeJwe = trimmed.split(".").length === 5;

  if (ct.includes("application/jwt") || looksLikeJwe) {
    const { plaintext } = await compactDecrypt(trimmed, decryptionPrivateKey);
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  return JSON.parse(trimmed);
}
