/** Strict WE BUILD CS-02 encoding helpers shared by wallet and verifier. */
export const CS02_BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export function isStrictCs02EcP256Jwk(jwk) {
  return !!jwk && typeof jwk === "object" && jwk.kty === "EC" && jwk.crv === "P-256";
}

export function isStrictCs02Base64Url(value, { allowEmpty = false } = {}) {
  return typeof value === "string" &&
    (allowEmpty || value.length > 0) &&
    (allowEmpty && value.length === 0 || CS02_BASE64URL_PATTERN.test(value));
}

export function decodeStrictCs02Base64Url(value) {
  if (!isStrictCs02Base64Url(value)) {
    throw new TypeError("value must be a non-empty unpadded base64url string");
  }
  return Buffer.from(value, "base64url");
}

/** Deterministic JSON form for protocol values that are hashed or encrypted. */
export function canonicalizeCs02Json(value) {
  if (value === undefined || typeof value === "function" || typeof value === "symbol") {
    throw new TypeError("canonical CS-02 JSON cannot contain non-JSON values");
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeCs02Json).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeCs02Json(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
