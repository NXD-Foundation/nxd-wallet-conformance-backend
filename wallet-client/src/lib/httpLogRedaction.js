const sensitiveFields = new Set([
  "access_token", "refresh_token", "id_token", "authorization", "dpop", "dpop-nonce",
  "c_nonce", "nonce", "client_assertion", "proof", "proofs", "privatejwk", "privatekey",
  "oauth-client-attestation", "oauth-client-attestation-pop", "oauth-client-attestation-challenge",
]);

/** Redact HTTP diagnostics without modifying the response used by protocol code. */
export function redactHttpLog(value) {
  if (Array.isArray(value)) return value.map(redactHttpLog);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key, sensitiveFields.has(key.toLowerCase()) ? "<redacted>" : redactHttpLog(item),
  ]));
}
