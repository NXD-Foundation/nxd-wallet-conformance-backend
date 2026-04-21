import crypto from "node:crypto";

/**
 * Map verifier-advertised names (OIDC4VP / RFC002) to Node digest names and KB-JWT claim value.
 * Unsupported algorithms are ignored so callers can fall back to SHA-256.
 */
function mapHashAlgToNode(raw) {
  if (raw == null || typeof raw !== "string") return null;
  const n = raw.trim().toLowerCase().replace(/_/g, "-");
  if (n === "sha-256" || n === "sha256") return { node: "sha256", claim: "sha-256" };
  return null;
}

/**
 * @param {object | null | undefined} authorizationRequestPayload - verified OpenID4VP authorization request JWT payload
 * @returns {{ node: string, claim: string }}
 */
export function pickTransactionDataDigestAlgorithm(authorizationRequestPayload) {
  const list = authorizationRequestPayload?.transaction_data_hashes_alg_values;
  if (Array.isArray(list)) {
    for (const raw of list) {
      const m = mapHashAlgToNode(String(raw));
      if (m) return m;
    }
  }
  return { node: "sha256", claim: "sha-256" };
}

/**
 * RFC002 §8 / VP-CHECK: hash each `transaction_data[]` string as UTF-8 bytes (the literal base64url
 * payload element), digest with the selected algorithm, encode digest as base64url.
 *
 * @param {unknown[]} transactionDataEntries
 * @param {string} nodeDigestName - e.g. `sha256`
 * @returns {string[] | null}
 */
export function computeTransactionDataHashesEntries(transactionDataEntries, nodeDigestName) {
  if (!Array.isArray(transactionDataEntries) || transactionDataEntries.length === 0) {
    return null;
  }
  return transactionDataEntries.map((entry) => {
    if (typeof entry !== "string") {
      throw new Error("transaction_data[] entries must be strings for key-binding hashes");
    }
    return crypto
      .createHash(nodeDigestName)
      .update(entry, "utf8")
      .digest("base64url");
  });
}

/**
 * @param {object | null | undefined} authorizationRequestPayload
 * @returns {{ transaction_data_hashes: string[]; transaction_data_hashes_alg: string } | null}
 */
export function transactionDataBindingForSdJwtKb(authorizationRequestPayload) {
  const tx = authorizationRequestPayload?.transaction_data;
  if (!Array.isArray(tx) || tx.length === 0) return null;
  const { node, claim } = pickTransactionDataDigestAlgorithm(authorizationRequestPayload);
  const hashes = computeTransactionDataHashesEntries(tx, node);
  if (!hashes?.length) return null;
  return {
    transaction_data_hashes: hashes,
    transaction_data_hashes_alg: claim,
  };
}
