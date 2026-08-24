import { createHash } from "crypto";

/**
 * Compute the OpenID4VP transaction-data hash.
 *
 * OpenID4VP binds the exact string received in transaction_data. In
 * particular, callers must not base64url-decode the value before hashing.
 *
 * @param {string} transactionData
 * @returns {string} base64url SHA-256 digest
 */
export function computeTransactionDataHash(transactionData) {
  if (typeof transactionData !== "string" || transactionData.length === 0) {
    throw new TypeError("transaction_data entry must be a non-empty string");
  }
  return createHash("sha256")
    .update(transactionData, "utf8")
    .digest("base64url");
}
