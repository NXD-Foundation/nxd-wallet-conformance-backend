/**
 * WE BUILD CS-02 wallet-side authorization request (JAR) validation.
 * Runs after deep-link parsing and request-uri fetch, before credential selection.
 */

import fetch from "node-fetch";
import {
  jwtVerify,
  importJWK,
  importX509,
  decodeProtectedHeader,
} from "jose";
import { X509Certificate } from "@peculiar/x509";
import {
  OPENID4VP_PRESENT_HOST,
  isOpenId4VpPresentInvocation,
} from "./openid4vpUri.js";
import { isWebuildCs02Profile, resolveWalletProfile } from "./profile.js";
import {
  validateX509SanDnsTrustAnchor,
  validateVerifierAttestationTrust,
  validateCs02ClientMetadata,
  validateCs02RequestUriQueryPrecedence,
  validateDidJwkTrustRules,
  validateDidWebKidResolution,
  resolveCs02EffectiveClientMetadata,
  Cs02TrustPolicyError,
} from "../../utils/cs02TrustPolicy.js";
import { isStrictCs02Base64Url, decodeStrictCs02Base64Url, isStrictCs02EcP256Jwk } from "../../../utils/cs02Encoding.js";

export {
  validateX509SanDnsTrustAnchor,
  validateVerifierAttestationTrust,
} from "../../utils/cs02TrustPolicy.js";

export const CS02_JAR_TYP = "oauth-authz-req+jwt";
export const CS02_ALLOWED_ALGS = new Set(["ES256"]);
export const CS02_FORBIDDEN_ALGS = new Set(["none", "RS256", "ES256K", "EdDSA"]);
export const CS02_ALLOWED_CLIENT_ID_SCHEMES = new Set([
  "x509_san_dns",
  "verifier_attestation",
  "decentralized_identifier",
]);
export const CS02_DEFAULT_AUDIENCES = ["https://self-issued.me/v2"];
export const CS02_REQUEST_URI_CONTENT_TYPE = "application/oauth-authz-req+jwt";
export const CS02_ALLOWED_REQUEST_URI_METHODS = new Set(["get", "post"]);
export const CS02_DEFAULT_REQUEST_MAX_LIFETIME_SEC = 300;
export const CS02_DEFAULT_CLOCK_SKEW_SEC = 300;
export const CS02_NONCE_PATTERN = /^[A-Za-z0-9_-]+$/;
export const CS02_SUPPORTED_TRANSACTION_DATA_TYPES = new Set([
  "qes_authorization",
  "payment_data",
  "https://cloudsignatureconsortium.org/2025/qes",
]);

export class Cs02ValidationError extends Error {
  constructor(message, errorCode = "invalid_request") {
    super(message);
    this.name = "Cs02ValidationError";
    this.errorCode = errorCode;
  }
}

function truthyEnv(value) {
  if (value == null || value === "") return false;
  const normalized = String(value).trim().toLowerCase();
  return normalized === "true" || normalized === "1" || normalized === "yes";
}

function parseWalletAudiences(raw) {
  if (raw == null || raw === "") {
    return [...CS02_DEFAULT_AUDIENCES];
  }
  return String(raw)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function resolveCs02ValidationOptions(env = process.env) {
  const profile = resolveWalletProfile(env);
  const compatibility = truthyEnv(env.CS02_COMPATIBILITY);
  return {
    strict: isWebuildCs02Profile(profile) || !compatibility,
    allowHttp: truthyEnv(env.CS02_ALLOW_HTTP),
    allowLegacyInvocation: truthyEnv(env.CS02_ALLOW_LEGACY_INVOCATION),
    walletAudiences: parseWalletAudiences(env.CS02_WALLET_AUDIENCES),
    requestMaxLifetimeSec:
      Number(env.CS02_REQUEST_MAX_LIFETIME_SEC) || CS02_DEFAULT_REQUEST_MAX_LIFETIME_SEC,
    clockSkewSec: Number(env.CS02_CLOCK_SKEW_SEC) || CS02_DEFAULT_CLOCK_SKEW_SEC,
  };
}

export function isCs02StrictPresentationMode(env = process.env) {
  return resolveCs02ValidationOptions(env).strict;
}

export function decodeJarParts(requestJwt) {
  const parts = String(requestJwt || "").split(".");
  if (parts.length < 2) {
    throw new Cs02ValidationError("Authorization request must be a signed JWT/JAR", "invalid_request");
  }
  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw new Cs02ValidationError("Authorization request JWT is malformed", "invalid_request");
  }
  return { header, payload };
}

export function parseCs02ClientIdScheme(clientId) {
  if (!clientId || typeof clientId !== "string") {
    return { scheme: "unknown", value: clientId };
  }
  if (clientId.startsWith("x509_san_dns:")) {
    return { scheme: "x509_san_dns", value: clientId };
  }
  if (clientId.startsWith("verifier_attestation:")) {
    return { scheme: "verifier_attestation", value: clientId };
  }
  if (clientId.startsWith("decentralized_identifier:")) {
    return { scheme: "decentralized_identifier", value: clientId };
  }
  if (clientId.startsWith("did:web:") || clientId.startsWith("did:jwk:")) {
    return { scheme: "legacy_did", value: clientId };
  }
  return { scheme: "unknown", value: clientId };
}

export function resolveCs02EffectiveClientId(clientId) {
  if (typeof clientId !== "string") return clientId;
  if (clientId.startsWith("decentralized_identifier:")) {
    return clientId.substring("decentralized_identifier:".length);
  }
  return clientId;
}

export function resolveCs02DidMethod(clientId) {
  const effectiveClientId = resolveCs02EffectiveClientId(clientId);
  if (typeof effectiveClientId !== "string" || !effectiveClientId.startsWith("did:")) {
    return "unknown";
  }
  if (effectiveClientId.startsWith("did:web:")) return "did:web";
  if (effectiveClientId.startsWith("did:jwk:")) return "did:jwk";
  return "unsupported";
}

export function isP256Jwk(jwk) {
  return isStrictCs02EcP256Jwk(jwk) && jwk?.x && jwk?.y;
}

function assertEs256P256Jwk(jwk, context) {
  if (!isP256Jwk(jwk)) {
    throw new Cs02ValidationError(
      `CS-02 requires ES256 with P-256 signing key (${context})`,
      "invalid_client",
    );
  }
}

function assertEs256P256Certificate(pem, context) {
  try {
    const cert = new X509Certificate(pem);
    const spki = cert.publicKey;
    const algorithmName =
      typeof spki?.algorithm === "string" ? spki.algorithm : spki?.algorithm?.name;
    const namedCurve =
      spki?.namedCurve ||
      spki?.algorithm?.namedCurve ||
      spki?.ecPublicKey?.namedCurve;
    if (algorithmName && !["EC", "ECDSA", "id-ecPublicKey"].includes(algorithmName)) {
      throw new Cs02ValidationError(
        `CS-02 requires ES256 with P-256 signing key (${context})`,
        "invalid_client",
      );
    }
    if (namedCurve && namedCurve !== "P-256" && namedCurve !== "prime256v1") {
      throw new Cs02ValidationError(
        `CS-02 requires ES256 with P-256 signing key (${context})`,
        "invalid_client",
      );
    }
  } catch (error) {
    if (error instanceof Cs02ValidationError) throw error;
    throw new Cs02ValidationError(
      `Unable to validate signing certificate curve (${context})`,
      "invalid_client",
    );
  }
}

function logValidationFailure(log, check, details = {}) {
  try {
    log?.("[CS02] request validation failed", { check, ...details });
  } catch {}
}

export function validateCs02DeepLink(deepLink, options, log = () => {}) {
  let url;
  try {
    url = new URL(deepLink);
  } catch {
    logValidationFailure(log, "deep_link_parse");
    throw new Cs02ValidationError("Invalid openid4vp deep link", "invalid_request");
  }

  if (url.protocol !== "openid4vp:") {
    logValidationFailure(log, "deep_link_scheme", { protocol: url.protocol });
    throw new Cs02ValidationError("Unsupported request scheme", "invalid_request");
  }

  if (!isOpenId4VpPresentInvocation(url)) {
    if (!options.allowLegacyInvocation) {
      logValidationFailure(log, "deep_link_authority", { authority: url.hostname || "(empty)" });
      throw new Cs02ValidationError(
        `Unsupported openid4vp authority "${url.hostname || ""}"; CS-02 requires "${OPENID4VP_PRESENT_HOST}"`,
        "invalid_request",
      );
    }
  }

  const requestUri = url.searchParams.get("request_uri");
  const clientId = url.searchParams.get("client_id");
  const method = url.searchParams.get("request_uri_method") || "get";

  validateCs02RequestUri(requestUri, options, log);
  validateCs02RequestUriMethod(method, log);

  return { requestUri, clientId, method, url };
}

export function validateCs02RequestUri(requestUri, options, log = () => {}) {
  if (!requestUri || typeof requestUri !== "string") {
    logValidationFailure(log, "missing_request_uri");
    throw new Cs02ValidationError("Missing request_uri in deep link", "invalid_request_uri");
  }

  let parsed;
  try {
    parsed = new URL(requestUri);
  } catch {
    logValidationFailure(log, "request_uri_not_absolute", { requestUri });
    throw new Cs02ValidationError("request_uri must be absolute", "invalid_request_uri");
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    logValidationFailure(log, "request_uri_scheme", { protocol: parsed.protocol });
    throw new Cs02ValidationError("request_uri must use HTTPS or HTTP", "invalid_request_uri");
  }

  if (parsed.protocol === "http:" && !options.allowHttp) {
    logValidationFailure(log, "request_uri_http_forbidden", { host: parsed.host });
    throw new Cs02ValidationError(
      "CS-02 requires HTTPS request_uri (set CS02_ALLOW_HTTP=true for local development)",
      "invalid_request_uri",
    );
  }
}

export function validateCs02RequestUriMethod(method, log = () => {}) {
  const normalized = String(method || "get").trim().toLowerCase();
  if (!CS02_ALLOWED_REQUEST_URI_METHODS.has(normalized)) {
    logValidationFailure(log, "request_uri_method", { method });
    throw new Cs02ValidationError(
      `Unsupported request_uri_method "${method}"`,
      "invalid_request_uri_method",
    );
  }
  return normalized;
}

export function validateCs02RequestUriResponseContentType(contentType, log = () => {}) {
  if (!contentType) {
    logValidationFailure(log, "missing_request_uri_content_type");
    throw new Cs02ValidationError(
      "Request URI response must include Content-Type",
      "invalid_request",
    );
  }
  const normalized = String(contentType).split(";")[0].trim().toLowerCase();
  if (normalized !== CS02_REQUEST_URI_CONTENT_TYPE) {
    logValidationFailure(log, "request_uri_content_type", { contentType: normalized });
    throw new Cs02ValidationError(
      `Request URI response Content-Type must be ${CS02_REQUEST_URI_CONTENT_TYPE}`,
      "invalid_request",
    );
  }
}

export function validateCs02JarHeader(header, log = () => {}) {
  if (!header?.alg) {
    logValidationFailure(log, "missing_jar_alg");
    throw new Cs02ValidationError("Authorization request JWT must specify alg", "invalid_request");
  }
  if (header.alg === "none" || CS02_FORBIDDEN_ALGS.has(header.alg)) {
    logValidationFailure(log, "forbidden_jar_alg", { alg: header.alg });
    throw new Cs02ValidationError(
      `Unsupported authorization request signing algorithm "${header.alg}"`,
      "invalid_request",
    );
  }
  if (!CS02_ALLOWED_ALGS.has(header.alg)) {
    logValidationFailure(log, "unsupported_jar_alg", { alg: header.alg });
    throw new Cs02ValidationError(
      `CS-02 requires ES256 authorization request signatures (got "${header.alg}")`,
      "invalid_request",
    );
  }
  if (header.typ !== CS02_JAR_TYP) {
    logValidationFailure(log, "jar_typ", { typ: header.typ });
    throw new Cs02ValidationError(
      `Authorization request JWT typ must be ${CS02_JAR_TYP}`,
      "invalid_request",
    );
  }
}

function audienceMatchesPolicy(aud, allowedAudiences) {
  const values = Array.isArray(aud) ? aud : aud != null ? [aud] : [];
  return values.some((entry) => allowedAudiences.includes(entry));
}

export function validateCs02JarPayload(payload, options, log = () => {}) {
  const requiredFields = [
    "client_id",
    "nonce",
    "response_uri",
    "state",
    "response_type",
    "response_mode",
    "iat",
    "exp",
    "dcql_query",
  ];
  for (const field of requiredFields) {
    if (payload?.[field] == null || payload[field] === "") {
      logValidationFailure(log, "missing_jar_field", { field });
      throw new Cs02ValidationError(
        `Authorization request JWT missing required field "${field}"`,
        "invalid_request",
      );
    }
  }

  if (payload.response_type !== "vp_token") {
    logValidationFailure(log, "response_type", { response_type: payload.response_type });
    throw new Cs02ValidationError('Authorization request response_type must be "vp_token"', "invalid_request");
  }

  const now = Math.floor(Date.now() / 1000);
  const iat = Number(payload.iat);
  const exp = Number(payload.exp);
  if (!Number.isFinite(iat) || !Number.isFinite(exp)) {
    logValidationFailure(log, "invalid_jar_timestamps");
    throw new Cs02ValidationError("Authorization request iat/exp must be numeric", "invalid_request");
  }

  if (exp <= now) {
    logValidationFailure(log, "jar_expired", { exp, now });
    throw new Cs02ValidationError("Authorization request JWT is expired", "invalid_request");
  }

  if (iat - now > options.clockSkewSec) {
    logValidationFailure(log, "jar_iat_future", { iat, now });
    throw new Cs02ValidationError("Authorization request iat is outside accepted clock skew", "invalid_request");
  }

  if (now - iat > options.clockSkewSec) {
    logValidationFailure(log, "jar_iat_stale", { iat, now });
    throw new Cs02ValidationError("Authorization request iat is outside accepted clock skew", "invalid_request");
  }

  if (exp - iat > options.requestMaxLifetimeSec) {
    logValidationFailure(log, "jar_lifetime", { iat, exp, max: options.requestMaxLifetimeSec });
    throw new Cs02ValidationError("Authorization request lifetime exceeds accepted maximum", "invalid_request");
  }

  if (!audienceMatchesPolicy(payload.aud, options.walletAudiences)) {
    logValidationFailure(log, "jar_audience", {
      aud: payload.aud,
      allowed: options.walletAudiences,
    });
    throw new Cs02ValidationError("Authorization request audience is not accepted by wallet policy", "invalid_request");
  }

  validateCs02ClientId(payload.client_id, log);
  validateCs02Nonce(payload.nonce, log);
  validateCs02ResponseUri(payload.response_uri, options, log);
  validateCs02TransactionData(payload.transaction_data, log, payload.dcql_query);

  if (payload.client_metadata != null && options.strict) {
    try {
      validateCs02ClientMetadata(payload.client_metadata, {
        responseMode: payload.response_mode,
        strict: true,
      });
    } catch (error) {
      if (error instanceof Cs02TrustPolicyError) {
        logValidationFailure(log, "client_metadata", { message: error.message });
        throw new Cs02ValidationError(error.message, error.errorCode);
      }
      throw error;
    }
  }
}

export function validateCs02ResponseUri(responseUri, options = {}, log = () => {}) {
  if (typeof responseUri !== "string" || responseUri.length === 0) {
    logValidationFailure(log, "response_uri_missing");
    throw new Cs02ValidationError("Authorization response_uri must be a non-empty URI", "invalid_request");
  }
  let parsed;
  try {
    parsed = new URL(responseUri);
  } catch {
    logValidationFailure(log, "response_uri_invalid");
    throw new Cs02ValidationError("Authorization response_uri must be an absolute URI", "invalid_request");
  }
  if (parsed.protocol !== "https:" && !(options.allowHttp === true && parsed.protocol === "http:")) {
    logValidationFailure(log, "response_uri_https", { protocol: parsed.protocol });
    throw new Cs02ValidationError(
      "CS-02 authorization response_uri must use HTTPS",
      "invalid_request",
    );
  }
  return responseUri;
}

export function validateCs02TransactionData(transactionData, log = () => {}, dcqlQuery = null) {
  if (transactionData == null) return;
  if (!Array.isArray(transactionData)) {
    logValidationFailure(log, "transaction_data_array");
    throw new Cs02ValidationError("transaction_data must be an array", "invalid_request");
  }
  for (let index = 0; index < transactionData.length; index += 1) {
    const entry = transactionData[index];
    if (!isStrictCs02Base64Url(entry)) {
      logValidationFailure(log, "transaction_data_encoding", { index });
      throw new Cs02ValidationError(
        `transaction_data[${index}] must be a non-empty base64url string`,
        "invalid_request",
      );
    }
    let decoded;
    try {
      decoded = JSON.parse(decodeStrictCs02Base64Url(entry).toString("utf8"));
    } catch {
      logValidationFailure(log, "transaction_data_json", { index });
      throw new Cs02ValidationError(
        `transaction_data[${index}] must contain a valid JSON object with type`,
        "invalid_request",
      );
    }
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
      throw new Cs02ValidationError(`transaction_data[${index}] must contain a JSON object`, "invalid_request");
    }
    if (typeof decoded.type !== "string" || decoded.type.length === 0) {
      throw new Cs02ValidationError(`transaction_data[${index}] must include a non-empty type`, "invalid_request");
    }
    if (!CS02_SUPPORTED_TRANSACTION_DATA_TYPES.has(decoded.type)) {
      throw new Cs02ValidationError(
        `Unsupported transaction_data type "${decoded.type}"`,
        "invalid_request",
      );
    }
    if (decoded.credential_ids != null && (
      !Array.isArray(decoded.credential_ids) ||
      decoded.credential_ids.length === 0 ||
      !decoded.credential_ids.every((id) => typeof id === "string" && id.length > 0)
    )) {
      throw new Cs02ValidationError(
        `transaction_data[${index}].credential_ids must be a non-empty string array`,
        "invalid_request",
      );
    }
    if (decoded.credential_ids != null && Array.isArray(dcqlQuery?.credentials)) {
      const knownIds = new Set(dcqlQuery.credentials.map((credential) => credential?.id));
      if (decoded.credential_ids.some((id) => !knownIds.has(id))) {
        throw new Cs02ValidationError(
          `transaction_data[${index}].credential_ids reference an unknown DCQL id`,
          "invalid_request",
        );
      }
    }
  }
}

export function validateCs02Nonce(nonce, log = () => {}) {
  if (!isStrictCs02Base64Url(nonce)) {
    logValidationFailure(log, "nonce_syntax", { nonceType: typeof nonce });
    throw new Cs02ValidationError(
      "Authorization request nonce must be a non-empty base64url string",
      "invalid_request",
    );
  }
  return nonce;
}

export function validateCs02ClientId(clientId, log = () => {}) {
  const { scheme } = parseCs02ClientIdScheme(clientId);
  if (!CS02_ALLOWED_CLIENT_ID_SCHEMES.has(scheme)) {
    logValidationFailure(log, "client_id_scheme", { scheme, clientId });
    if (scheme === "legacy_did") {
      throw new Cs02ValidationError(
        'CS-02 DID client_id values must use the "decentralized_identifier:" prefix',
        "invalid_client",
      );
    }
    throw new Cs02ValidationError(
      `Unsupported CS-02 client identifier scheme "${scheme}"`,
      "invalid_client",
    );
  }

  const didMethod = resolveCs02DidMethod(clientId);
  if (scheme === "decentralized_identifier" && !["did:web", "did:jwk"].includes(didMethod)) {
    logValidationFailure(log, "client_id_did_method", { didMethod, clientId });
    throw new Cs02ValidationError(
      `Unsupported CS-02 DID method "${didMethod}" inside decentralized_identifier client_id`,
      "invalid_client",
    );
  }
}

export function validateCs02DeepLinkClientIdConsistency(deepLinkClientId, jarClientId, log = () => {}) {
  if (!deepLinkClientId) return;
  if (deepLinkClientId !== jarClientId) {
    logValidationFailure(log, "client_id_mismatch", {
      deepLinkClientId,
      jarClientId,
    });
    throw new Cs02ValidationError(
      "Deep link client_id does not match authorization request client_id",
      "invalid_client",
    );
  }
}

function fromCs02TrustPolicyError(error) {
  if (error instanceof Cs02TrustPolicyError) {
    throw new Cs02ValidationError(error.message, error.errorCode);
  }
  throw error;
}

async function resolveDidWebDocument(did, options = {}) {
  const fetchImpl = options.fetchImpl || fetch;
  if (!did.startsWith("did:web:")) {
    throw new Cs02ValidationError(`Expected did:web identifier, received: ${did}`, "invalid_client");
  }
  const withoutPrefix = did.replace(/^did:web:/, "");
  const parts = withoutPrefix.split(":");
  const host = parts.shift();
  const path = parts.length ? `/${parts.join("/")}` : "";
  const urls = [`https://${host}/.well-known/did.json`, `https://${host}${path}/did.json`];
  for (const url of urls) {
    try {
      const res = await fetchImpl(url);
      if (res.ok) {
        return { document: await res.json(), resolutionUrl: url };
      }
    } catch {}
  }
  throw new Cs02ValidationError("did:web resolution failed", "invalid_client");
}

function x5cLeafPem(header) {
  if (!Array.isArray(header?.x5c) || header.x5c.length === 0) {
    throw new Cs02ValidationError("x509_san_dns authorization request must include x5c", "invalid_client");
  }
  if (header.x5c.some((entry) => {
    if (typeof entry !== "string" || entry.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(entry)) return true;
    try { return Buffer.from(entry, "base64").length === 0; } catch { return true; }
  })) {
    throw new Cs02ValidationError("x509_san_dns authorization request contains malformed x5c", "invalid_client");
  }
  const der = header.x5c[0];
  return `-----BEGIN CERTIFICATE-----\n${der.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
}

async function verifyJarWithX5cLeaf(requestJwt, header, clientId, context) {
  const pem = x5cLeafPem(header);
  assertEs256P256Certificate(pem, context);
  const key = await importX509(pem, "ES256");
  const verified = await jwtVerify(requestJwt, key, { clockTolerance: 0 });
  await validateX509SanDnsTrustAnchor(clientId, header, pem);
  return verified;
}

async function verifyJarWithDidWeb(requestJwt, header, clientId, options) {
  const kid = header?.kid;
  const did = resolveCs02EffectiveClientId(String(clientId)).split("#")[0];

  try {
    const { document, resolutionUrl } = await resolveDidWebDocument(did, options);
    const { verificationMethod } = validateDidWebKidResolution(document, kid, did, {
      resolutionUrl,
    });
    const key = await importJWK(verificationMethod.publicKeyJwk, "ES256");
    return await jwtVerify(requestJwt, key, { clockTolerance: options.clockSkewSec });
  } catch (error) {
    if (error instanceof Cs02ValidationError) throw error;
    fromCs02TrustPolicyError(error);
  }
}

async function verifyJarWithDidJwk(requestJwt, header, clientId, options) {
  const effectiveClientId = resolveCs02EffectiveClientId(clientId);
  let jwk;
  try {
    jwk = JSON.parse(
      Buffer.from(String(effectiveClientId).substring("did:jwk:".length), "base64url").toString("utf8"),
    );
  } catch {
    throw new Cs02ValidationError("did:jwk client_id is malformed", "invalid_client");
  }
  try {
    validateDidJwkTrustRules(jwk, "did:jwk client_id");
  } catch (error) {
    fromCs02TrustPolicyError(error);
  }
  const key = await importJWK(jwk, header?.alg || "ES256");
  return jwtVerify(requestJwt, key, { clockTolerance: options.clockSkewSec });
}

async function verifyJarWithVerifierAttestation(requestJwt, header, clientId, options) {
  if (!header?.jwt || typeof header.jwt !== "string") {
    throw new Cs02ValidationError(
      "verifier_attestation authorization request must include JOSE header jwt",
      "invalid_client",
    );
  }
  const attestation = await validateVerifierAttestationTrust(header, clientId);
  if (!attestation.structureValid || !attestation.clientBindingValid) {
    throw new Cs02ValidationError(
      "verifier_attestation JWT is malformed or not bound to the client",
      "invalid_client",
    );
  }
  return verifyJarWithX5cLeaf(requestJwt, header, clientId, "verifier_attestation x5c");
}

export async function verifyCs02JarSignature(requestJwt, header, payload, options, log = () => {}) {
  const clientId = payload?.client_id;
  validateCs02ClientId(clientId, log);
  const { scheme } = parseCs02ClientIdScheme(clientId);
  const didMethod = resolveCs02DidMethod(clientId);

  try {
    switch (scheme) {
      case "x509_san_dns":
        return await verifyJarWithX5cLeaf(requestJwt, header, clientId, "x509_san_dns x5c");
      case "decentralized_identifier":
        if (didMethod === "did:web") {
          return await verifyJarWithDidWeb(requestJwt, header, clientId, options);
        }
        if (didMethod === "did:jwk") {
          return await verifyJarWithDidJwk(requestJwt, header, clientId, options);
        }
        throw new Cs02ValidationError(
          `Unsupported CS-02 DID method "${didMethod}" inside decentralized_identifier client_id`,
          "invalid_client",
        );
      case "verifier_attestation":
        return await verifyJarWithVerifierAttestation(requestJwt, header, clientId, options);
      default:
        throw new Cs02ValidationError(
          `Unsupported CS-02 client identifier scheme "${scheme}"`,
          "invalid_client",
        );
    }
  } catch (error) {
    if (error instanceof Cs02ValidationError) throw error;
    if (error instanceof Cs02TrustPolicyError) {
      throw new Cs02ValidationError(error.message, error.errorCode);
    }
    logValidationFailure(log, "jar_signature_verification", {
      scheme,
      message: error?.message || String(error),
    });
    throw new Cs02ValidationError(
      "Authorization request JWT signature verification failed",
      "invalid_client",
    );
  }
}

export async function validateAndVerifyCs02AuthorizationRequest(
  requestJwt,
  { deepLinkClientId, deepLinkUrl, expectedWalletNonce, options, log = () => {} } = {},
) {
  if (!requestJwt || typeof requestJwt !== "string") {
    logValidationFailure(log, "unsigned_or_malformed_jar");
    throw new Cs02ValidationError("Authorization request must be a signed JWT/JAR", "invalid_request");
  }
  const parts = requestJwt.split(".");
  if (parts.length < 3 || !parts[2]) {
    logValidationFailure(log, "unsigned_or_malformed_jar");
    throw new Cs02ValidationError("Authorization request must be a signed JWT/JAR", "invalid_request");
  }

  const { header, payload } = decodeJarParts(requestJwt);
  validateCs02JarHeader(header, log);
  validateCs02JarPayload(payload, options, log);
  if (options.strict && payload.response_mode === "direct_post.jwt" &&
      payload.client_metadata == null && payload.client_metadata_uri == null) {
    throw new Cs02ValidationError(
      "direct_post.jwt authorization requests require client metadata for encrypted response negotiation",
      "invalid_request",
    );
  }
  if (expectedWalletNonce != null) {
    if (typeof payload.wallet_nonce !== "string" || payload.wallet_nonce !== expectedWalletNonce) {
      logValidationFailure(log, "wallet_nonce_mismatch");
      throw new Cs02ValidationError(
        "Authorization request wallet_nonce does not match the POST request",
        "invalid_request",
      );
    }
  }
  validateCs02DeepLinkClientIdConsistency(deepLinkClientId, payload.client_id, log);
  if (deepLinkUrl && options.strict) {
    try {
      validateCs02RequestUriQueryPrecedence(deepLinkUrl, payload, log);
    } catch (error) {
      if (error instanceof Cs02TrustPolicyError) {
        throw new Cs02ValidationError(error.message, error.errorCode);
      }
      throw error;
    }
  }

  const verified = await verifyCs02JarSignature(requestJwt, header, payload, options, log);

  let effectiveClientMetadata = null;
  if (
    options.strict &&
    (payload.client_metadata != null || payload.client_metadata_uri != null)
  ) {
    try {
      const resolved = await resolveCs02EffectiveClientMetadata(payload, {
        fetchImpl: options.fetchImpl,
        strict: true,
        log,
      });
      effectiveClientMetadata = resolved.effectiveMetadata;
      if (Array.isArray(effectiveClientMetadata?.redirect_uris) &&
          !effectiveClientMetadata.redirect_uris.includes(payload.response_uri)) {
        throw new Cs02ValidationError(
          "response_uri is not listed in client_metadata.redirect_uris",
          "invalid_client",
        );
      }
    } catch (error) {
      if (error instanceof Cs02TrustPolicyError) {
        logValidationFailure(log, "client_metadata_uri", { message: error.message });
        throw new Cs02ValidationError(error.message, error.errorCode);
      }
      throw error;
    }
  } else if (payload.client_metadata != null || payload.client_metadata_uri != null) {
    try {
      const resolved = await resolveCs02EffectiveClientMetadata(payload, {
        fetchImpl: options.fetchImpl,
        strict: false,
        log,
      });
      effectiveClientMetadata = resolved.effectiveMetadata;
    } catch (error) {
      try {
        log?.("[CS02] client metadata resolution skipped in compatibility mode", {
          message: error?.message || String(error),
        });
      } catch {}
    }
  }

  return {
    header: verified.protectedHeader || header,
    payload: verified.payload || payload,
    effectiveClientMetadata,
  };
}

export async function fetchCs02AuthorizationRequestJwt(requestUri, method, options, log = () => {}) {
  const normalizedMethod = validateCs02RequestUriMethod(method, log);
  validateCs02RequestUri(requestUri, options, log);
  const fetchImpl = options?.fetchImpl || fetch;

  const headers = {
    Accept: CS02_REQUEST_URI_CONTENT_TYPE,
  };

  let response;
  if (normalizedMethod === "post") {
    const form = new URLSearchParams();
    if (options?.walletNonce != null) form.set("wallet_nonce", options.walletNonce);
    response = await fetchImpl(requestUri, {
      method: "POST",
      headers: {
        ...headers,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: form.toString(),
    });
  } else {
    response = await fetchImpl(requestUri, { method: "GET", headers });
  }

  const contentType = response.headers.get("content-type") || "";
  const body = await response.text().catch(() => "");

  if (!response.ok) {
    logValidationFailure(log, "request_uri_fetch_status", {
      status: response.status,
      method: normalizedMethod,
    });
    throw new Cs02ValidationError(
      `Auth request ${normalizedMethod.toUpperCase()} error ${response.status}`,
      "invalid_request_uri",
    );
  }

  validateCs02RequestUriResponseContentType(contentType, log);

  if (!body || body.split(".").length < 3) {
    logValidationFailure(log, "request_uri_body_not_jar", { bodyLength: body?.length || 0 });
    throw new Cs02ValidationError(
      "Request URI response must contain a signed authorization request JWT",
      "invalid_request",
    );
  }

  return { requestJwt: body, contentType, walletNonce: options?.walletNonce ?? null };
}

export function summarizeJarForLog(requestJwt) {
  try {
    const header = decodeProtectedHeader(requestJwt);
    const { payload } = decodeJarParts(requestJwt);
    return {
      alg: header?.alg,
      typ: header?.typ,
      client_id: payload?.client_id,
      response_type: payload?.response_type,
      has_dcql_query: !!payload?.dcql_query,
      aud: payload?.aud,
    };
  } catch {
    return { malformed: true };
  }
}
