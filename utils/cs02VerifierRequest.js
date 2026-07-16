/**
 * WE BUILD CS-02 verifier-side authorization request (JAR) generation validation.
 */

import * as jose from "jose";
import { validateCs02DcqlQuery } from "../wallet-client/src/lib/cs02DcqlValidation.js";
import { isStrictCs02Base64Url, decodeStrictCs02Base64Url } from "./cs02Encoding.js";
import {
  buildStrictCs02ClientMetadata,
  validateX509SanDnsTrustAnchor as validateX509SanDnsTrustForRequestGeneration,
  validateVerifierAttestationTrust as validateVerifierAttestationForRequestGeneration,
} from "./cs02TrustPolicy.js";

export const CS02_JAR_TYP = "oauth-authz-req+jwt";
export const CS02_JAR_ALG = "ES256";
export const CS02_DEFAULT_AUDIENCE = "https://self-issued.me/v2";
export const CS02_MAX_REQUEST_LIFETIME_SEC = 300;
export const CS02_ALLOWED_RESPONSE_MODES = new Set([
  "direct_post",
  "direct_post.jwt",
  "dc_api",
  "dc_api.jwt",
]);
export const CS02_DEFAULT_RESPONSE_MODE = "direct_post";
export const CS02_ALLOWED_CLIENT_ID_SCHEMES = new Set([
  "x509_san_dns",
  "verifier_attestation",
  "decentralized_identifier",
]);
export const CS02_SUPPORTED_TRANSACTION_DATA_TYPES = new Set([
  "qes_authorization",
  "payment_data",
  "https://cloudsignatureconsortium.org/2025/qes",
]);
export const TS12_SUPPORTED_TRANSACTION_DATA_TYPES = new Set([
  "urn:eudi:sca:payment:1",
]);
export const CS02_ADVERTISED_VP_FORMATS = new Set(["dc+sd-jwt", "vc+sd-jwt", "mso_mdoc"]);
export const CS02_NONCE_PATTERN = /^[A-Za-z0-9_-]+$/;

export class Cs02VerifierRequestError extends Error {
  constructor(message, errorCode = "invalid_request") {
    super(message);
    this.name = "Cs02VerifierRequestError";
    this.errorCode = errorCode;
  }
}

export function validateCs02Nonce(nonce) {
  if (!isStrictCs02Base64Url(nonce)) {
    throw new Cs02VerifierRequestError(
      "CS-02 authorization request nonce must be a non-empty base64url string",
      "invalid_request",
    );
  }
  return nonce;
}

function truthyEnv(value) {
  if (value == null || value === "") return false;
  const normalized = String(value).trim().toLowerCase();
  return normalized === "true" || normalized === "1" || normalized === "yes";
}

export function resolveVerifierCs02Options(env = process.env) {
  const compatibility = truthyEnv(env.VERIFIER_CS02_COMPATIBILITY ?? env.CS02_COMPATIBILITY);
  const ts12Compatibility = truthyEnv(env.VERIFIER_TS12_COMPATIBILITY);
  return {
    strict: !compatibility,
    allowRs256Jar: compatibility,
    allowUnsignedRedirectUriJar: compatibility,
    allowLegacyOpenId4VpInvocation: compatibility,
    allowTs12TransactionData: compatibility || ts12Compatibility,
  };
}

export function isVerifierCs02StrictMode(env = process.env) {
  return resolveVerifierCs02Options(env).strict;
}

export function parseVerifierClientIdScheme(clientId) {
  if (!clientId || typeof clientId !== "string") {
    return { scheme: "unknown", value: clientId };
  }
  if (clientId.startsWith("x509_san_dns:")) return { scheme: "x509_san_dns", value: clientId };
  if (clientId.startsWith("verifier_attestation:")) {
    return { scheme: "verifier_attestation", value: clientId };
  }
  if (clientId.startsWith("decentralized_identifier:")) {
    return { scheme: "decentralized_identifier", value: clientId };
  }
  if (clientId.startsWith("did:web:") || clientId.startsWith("did:jwk:")) {
    return { scheme: "legacy_did", value: clientId };
  }
  if (clientId.startsWith("redirect_uri:")) return { scheme: "redirect_uri", value: clientId };
  if (clientId.startsWith("x509_hash:")) return { scheme: "x509_hash", value: clientId };
  return { scheme: "unknown", value: clientId };
}

export function resolveEffectiveClientId(clientId) {
  if (clientId.startsWith("decentralized_identifier:")) {
    return clientId.substring("decentralized_identifier:".length);
  }
  if (clientId.startsWith("redirect_uri:")) {
    return clientId.substring("redirect_uri:".length);
  }
  return clientId;
}

export function resolveVerifierDidMethod(clientId) {
  const effectiveClientId = resolveEffectiveClientId(clientId);
  if (typeof effectiveClientId !== "string" || !effectiveClientId.startsWith("did:")) {
    return "unknown";
  }
  if (effectiveClientId.startsWith("did:web:")) return "did:web";
  if (effectiveClientId.startsWith("did:jwk:")) return "did:jwk";
  return "unsupported";
}

export function validateCs02ResponseMode(responseMode, options = { strict: true }) {
  if (!CS02_ALLOWED_RESPONSE_MODES.has(responseMode)) {
    throw new Cs02VerifierRequestError(
      `Unsupported response_mode "${responseMode}"`,
      "invalid_request",
    );
  }
  if (options.strict && responseMode === "direct_post.jwt") {
    // Allowed, but callers should ensure response JWT/JWE validation is configured.
    return;
  }
}

export function validateCs02TransactionDataEntries(transactionData, dcqlQuery, options = { strict: true }) {
  if (!transactionData) return;
  if (!Array.isArray(transactionData)) {
    throw new Cs02VerifierRequestError("transaction_data must be an array", "invalid_request");
  }

  const dcqlCredentialIds = Array.isArray(dcqlQuery?.credentials)
    ? dcqlQuery.credentials.map((cred) => cred.id).filter(Boolean)
    : [];

  for (let index = 0; index < transactionData.length; index += 1) {
    const entry = transactionData[index];
    if (typeof entry !== "string") {
      throw new Cs02VerifierRequestError(
        `transaction_data[${index}] must be a base64url-encoded JSON string`,
        "invalid_request",
      );
    }

    let decoded;
    try {
      decoded = JSON.parse(decodeStrictCs02Base64Url(entry).toString("utf8"));
    } catch {
      if (options.strict) {
        throw new Cs02VerifierRequestError(
          `transaction_data[${index}] is not valid base64url-encoded JSON`,
          "invalid_request",
        );
      }
      continue;
    }

    if (typeof decoded?.type !== "string" || decoded.type.length === 0) {
      throw new Cs02VerifierRequestError(
        `transaction_data[${index}] must include a non-empty type`,
        "invalid_request",
      );
    }

    const supportedTypes = new Set(CS02_SUPPORTED_TRANSACTION_DATA_TYPES);
    if (options.allowTs12TransactionData) {
      for (const type of TS12_SUPPORTED_TRANSACTION_DATA_TYPES) {
        supportedTypes.add(type);
      }
    }

    if (
      options.strict &&
      !supportedTypes.has(decoded.type)
    ) {
      throw new Cs02VerifierRequestError(
        `Unsupported transaction_data type "${decoded.type}"`,
        "invalid_request",
      );
    }

    if (decoded.credential_ids != null) {
      if (
        !Array.isArray(decoded.credential_ids) ||
        decoded.credential_ids.length === 0 ||
        !decoded.credential_ids.every((id) => typeof id === "string" && id.length > 0)
      ) {
        throw new Cs02VerifierRequestError(
          "transaction_data credential_ids must be a non-empty string array when present",
          "invalid_request",
        );
      }
      const invalidIds = decoded.credential_ids.filter((id) => !dcqlCredentialIds.includes(id));
      if (invalidIds.length > 0) {
        throw new Cs02VerifierRequestError(
          `transaction_data credential_ids reference unknown DCQL ids: ${invalidIds.join(", ")}`,
          "invalid_request",
        );
      }
    }
  }
}

export function validateCs02JarGenerationInput({
  client_id,
  response_uri = null,
  presentation_definition,
  dcql_query,
  response_mode,
  response_type = "vp_token",
  nonce = null,
  transaction_data = null,
  options = { strict: true },
}) {
  const { scheme } = parseVerifierClientIdScheme(client_id);
  const didMethod = resolveVerifierDidMethod(client_id);

  if (scheme === "legacy_did") {
    throw new Cs02VerifierRequestError(
      'CS-02 DID client_id values must use the "decentralized_identifier:" prefix',
      "invalid_client",
    );
  }

  if (scheme === "decentralized_identifier" && !["did:web", "did:jwk"].includes(didMethod)) {
    throw new Cs02VerifierRequestError(
      `Unsupported CS-02 DID method "${didMethod}" inside decentralized_identifier client_id`,
      "invalid_client",
    );
  }

  if (!options.strict) return;

  if (presentation_definition) {
    throw new Cs02VerifierRequestError(
      "presentation_definition is not supported in CS-02 mode; use dcql_query",
      "invalid_request",
    );
  }

  if (!dcql_query) {
    throw new Cs02VerifierRequestError("CS-02 authorization request requires dcql_query", "invalid_request");
  }

  validateCs02DcqlQuery(dcql_query, options);
  validateCs02ResponseMode(response_mode, options);
  if (response_uri != null) {
    let parsed;
    try { parsed = new URL(response_uri); } catch {
      throw new Cs02VerifierRequestError("CS-02 response_uri must be an absolute URI", "invalid_request");
    }
    if (parsed.protocol !== "https:") {
      throw new Cs02VerifierRequestError("CS-02 response_uri must use HTTPS", "invalid_request");
    }
  }
  if (nonce != null) validateCs02Nonce(nonce);

  if (response_type !== "vp_token") {
    throw new Cs02VerifierRequestError('CS-02 response_type must be "vp_token"', "invalid_request");
  }

  if (scheme === "redirect_uri") {
    throw new Cs02VerifierRequestError(
      "redirect_uri client identifier scheme is not supported in CS-02 mode",
      "invalid_client",
    );
  }
  if (scheme === "x509_hash" || scheme === "unknown") {
    throw new Cs02VerifierRequestError(
      `Unsupported CS-02 client identifier scheme "${scheme}"`,
      "invalid_client",
    );
  }
  if (!CS02_ALLOWED_CLIENT_ID_SCHEMES.has(scheme)) {
    throw new Cs02VerifierRequestError(
      `Unsupported CS-02 client identifier scheme "${scheme}"`,
      "invalid_client",
    );
  }

  validateCs02TransactionDataEntries(transaction_data, dcql_query, options);
}

export function applyCs02JarTimestamps(jwtPayload, responseMode) {
  const now = Math.floor(Date.now() / 1000);
  jwtPayload.iat = now;
  if (responseMode === "dc_api" || responseMode === "dc_api.jwt") {
    jwtPayload.exp = now + 60 * 60;
  } else {
    jwtPayload.exp = now + CS02_MAX_REQUEST_LIFETIME_SEC;
  }
  return jwtPayload;
}

export function validateCs02SignedJar(requestJwt, options = { strict: true }) {
  if (!options.strict) return;
  const parts = String(requestJwt || "").split(".");
  if (parts.length < 3 || !parts[2]) {
    throw new Cs02VerifierRequestError("CS-02 authorization request must be a signed JAR", "invalid_request");
  }

  const header = jose.decodeProtectedHeader(requestJwt);
  const payload = jose.decodeJwt(requestJwt);

  if (header.alg !== CS02_JAR_ALG) {
    throw new Cs02VerifierRequestError(
      `CS-02 JAR must be signed with ${CS02_JAR_ALG} (got "${header.alg}")`,
      "invalid_request",
    );
  }
  if (header.typ !== CS02_JAR_TYP) {
    throw new Cs02VerifierRequestError(
      `CS-02 JAR typ must be ${CS02_JAR_TYP}`,
      "invalid_request",
    );
  }

  for (const field of [
    "client_id",
    "nonce",
    "state",
    "response_uri",
    "response_type",
    "response_mode",
    "iat",
    "exp",
    "dcql_query",
  ]) {
    if (payload[field] == null || payload[field] === "") {
      throw new Cs02VerifierRequestError(
        `Generated CS-02 JAR missing required field "${field}"`,
        "invalid_request",
      );
    }
  }

  if (payload.presentation_definition) {
    throw new Cs02VerifierRequestError(
      "Generated CS-02 JAR must not include presentation_definition",
      "invalid_request",
    );
  }

  if (payload.response_type !== "vp_token") {
    throw new Cs02VerifierRequestError(
      'Generated CS-02 JAR response_type must be "vp_token"',
      "invalid_request",
    );
  }

  validateCs02ResponseMode(payload.response_mode, options);
  validateCs02Nonce(payload.nonce);

  if (payload.exp - payload.iat > CS02_MAX_REQUEST_LIFETIME_SEC + 5) {
    if (payload.response_mode !== "dc_api" && payload.response_mode !== "dc_api.jwt") {
      throw new Cs02VerifierRequestError(
        "Generated CS-02 JAR lifetime exceeds five minutes",
        "invalid_request",
      );
    }
  }

  validateCs02DcqlQuery(payload.dcql_query, options);
  validateCs02TransactionDataEntries(payload.transaction_data, payload.dcql_query, options);
}

export function filterClientMetadataForCs02(clientMetadata, responseMode) {
  return buildStrictCs02ClientMetadata(clientMetadata, responseMode);
}

export {
  validateX509SanDnsTrustForRequestGeneration,
  validateVerifierAttestationForRequestGeneration,
};

export function resolveCs02JarSigningPolicy({
  client_id,
  jar_alg,
  response_mode,
  options = resolveVerifierCs02Options(),
}) {
  const effectiveClientId = resolveEffectiveClientId(client_id);
  const { scheme } = parseVerifierClientIdScheme(client_id);

  if (options.strict) {
    if (scheme === "redirect_uri") {
      throw new Cs02VerifierRequestError(
        "CS-02 mode forbids unsigned redirect_uri authorization requests",
        "invalid_client",
      );
    }
    return {
      alg: CS02_JAR_ALG,
      forceEs256: true,
      scheme,
      effectiveClientId,
      useVerifierP12: true,
    };
  }

  const useEs256 =
    typeof jar_alg === "string" && jar_alg.toUpperCase() === "ES256";
  return {
    alg: useEs256 ? CS02_JAR_ALG : jar_alg || "RS256",
    forceEs256: useEs256,
    scheme,
    effectiveClientId,
    useVerifierP12: useEs256,
  };
}

export function createCs02OpenId4VpRequestUrl(requestUri, clientId, usePostMethod = false) {
  const base = `openid4vp://present?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
  return usePostMethod ? `${base}&request_uri_method=post` : base;
}

export function createOpenId4VpRequestUrl(requestUri, clientId, usePostMethod = false, env = process.env) {
  const options = resolveVerifierCs02Options(env);
  if (options.strict && !options.allowLegacyOpenId4VpInvocation) {
    return createCs02OpenId4VpRequestUrl(requestUri, clientId, usePostMethod);
  }
  const base = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
  return usePostMethod ? `${base}&request_uri_method=post` : base;
}
