/** WE BUILD CS-07 verifier-side Digital Credentials API primitives. */

export const CS07_DC_API_PROTOCOL = "openid4vp-v1-signed";
export const CS07_DC_API_RESPONSE_MODE = "dc_api.jwt";

function truthy(value) {
  if (value == null || value === "") return false;
  return ["1", "true", "yes"].includes(String(value).trim().toLowerCase());
}

/** Resolve the configured browser origin; never derive it from request headers. */
export function resolveCs07VerifierOrigin({
  serverURL = process.env.SERVER_URL,
  env = process.env,
} = {}) {
  const configured = env.DC_API_VERIFIER_ORIGIN || serverURL;
  if (typeof configured !== "string" || configured.trim() === "") {
    throw new Error("DC API verifier origin is not configured");
  }
  let parsed;
  try {
    parsed = new URL(configured);
  } catch {
    throw new Error("DC API verifier origin must be an absolute URL");
  }
  if (!parsed.protocol || !parsed.hostname || parsed.username || parsed.password) {
    throw new Error("DC API verifier origin must be a valid non-credential URL");
  }
  if (parsed.search || parsed.hash || parsed.pathname !== "/") {
    throw new Error("DC API verifier origin must not contain a path, query, or fragment");
  }
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && truthy(env.DC_API_ALLOW_HTTP))) {
    throw new Error("DC API verifier origin must use HTTPS");
  }
  return parsed.origin;
}

export function cs07ExpectedAudience(origin) {
  if (typeof origin !== "string" || origin.length === 0) {
    throw new Error("DC API verifier origin is required for response audience binding");
  }
  return `origin:${origin}`;
}

export function buildCs07DigitalCredentialRequest(signedRequest) {
  if (typeof signedRequest !== "string" || signedRequest.split(".").length !== 3) {
    throw new Error("CS-07 DC API request must contain a compact signed JAR");
  }
  return {
    protocol: CS07_DC_API_PROTOCOL,
    data: { request: signedRequest },
  };
}

export class Cs07DcApiResponseError extends Error {
  constructor(message, errorCode = "invalid_request") {
    super(message);
    this.name = "Cs07DcApiResponseError";
    this.errorCode = errorCode;
  }
}

function isPlainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.prototype.toString.call(value) === "[object Object]";
}

function assertJsonComplexity(value, depth = 0, state = { keys: 0 }) {
  if (depth > 8) throw new Cs07DcApiResponseError("DigitalCredential data is too deeply nested");
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      state.keys += 1;
      if (state.keys > 1000) throw new Cs07DcApiResponseError("DigitalCredential data contains too many members");
      if (typeof key !== "string" || key.length > 256) {
        throw new Cs07DcApiResponseError("DigitalCredential data contains an invalid member name");
      }
      assertJsonComplexity(child, depth + 1, state);
    }
  }
}

/** Normalize the serialized DigitalCredential returned by browser code. */
export function normalizeCs07DigitalCredentialResponse(envelope) {
  if (!isPlainObject(envelope)) {
    throw new Cs07DcApiResponseError("DigitalCredential response must be a JSON object");
  }
  assertJsonComplexity(envelope);
  if (Object.keys(envelope).some((key) => key !== "protocol" && key !== "data")) {
    throw new Cs07DcApiResponseError("DigitalCredential envelope contains unexpected fields");
  }
  if (envelope.protocol !== CS07_DC_API_PROTOCOL) {
    throw new Cs07DcApiResponseError(
      `Unsupported DigitalCredential protocol "${String(envelope.protocol || "")}"`,
    );
  }
  if (!isPlainObject(envelope.data)) {
    throw new Cs07DcApiResponseError("DigitalCredential data must be a JSON object");
  }
  const keys = Object.keys(envelope.data);
  if (typeof envelope.data.error === "string") {
    if (keys.some((key) => key !== "error")) {
      throw new Cs07DcApiResponseError("Wallet protocol error response must contain only error");
    }
    if (envelope.data.error.length === 0) {
      throw new Cs07DcApiResponseError("Wallet protocol error must be non-empty");
    }
    return { protocol: envelope.protocol, walletError: { error: envelope.data.error } };
  }
  if (typeof envelope.data.response !== "string" || envelope.data.response.length === 0) {
    throw new Cs07DcApiResponseError("DigitalCredential data.response must be a non-empty compact JWE");
  }
  if (keys.some((key) => key !== "response")) {
    throw new Cs07DcApiResponseError("Successful DigitalCredential response contains unexpected fields");
  }
  if (envelope.data.response.split(".").length !== 5) {
    throw new Cs07DcApiResponseError("DigitalCredential data.response must be a compact JWE");
  }
  return { protocol: envelope.protocol, encryptedResponse: envelope.data.response };
}

export function parseCs07AuthorizationResponse(value, dcqlQuery) {
  let response = value;
  if (typeof response === "string") {
    try {
      response = JSON.parse(response);
    } catch {
      throw new Cs07DcApiResponseError("Decrypted DC API response must be a JSON object");
    }
  }
  if (!isPlainObject(response)) {
    throw new Cs07DcApiResponseError("Decrypted DC API response must be a JSON object");
  }
  assertJsonComplexity(response);
  if (response.error != null) {
    throw new Cs07DcApiResponseError("Wallet protocol error was returned inside the encrypted response");
  }
  if (!isPlainObject(response.vp_token)) {
    throw new Cs07DcApiResponseError("Decrypted DC API response must contain a vp_token object");
  }

  const queries = Array.isArray(dcqlQuery?.credentials) ? dcqlQuery.credentials : [];
  const knownIds = new Map(queries.map((query) => [query.id, query]));
  const receivedIds = Object.keys(response.vp_token);
  if (receivedIds.length === 0 || receivedIds.some((id) => !knownIds.has(id))) {
    throw new Cs07DcApiResponseError("vp_token contains an unknown or empty DCQL credential id");
  }
  for (const query of queries) {
    const valueForId = response.vp_token[query.id];
    if (valueForId == null) {
      if (query.required !== false) {
        throw new Cs07DcApiResponseError(`vp_token is missing required DCQL credential id "${query.id}"`);
      }
      continue;
    }
    if (!query.multiple && Array.isArray(valueForId) && valueForId.length > 1) {
      throw new Cs07DcApiResponseError(`vp_token contains multiple presentations for "${query.id}"`);
    }
  }
  return { response, vpToken: response.vp_token };
}
