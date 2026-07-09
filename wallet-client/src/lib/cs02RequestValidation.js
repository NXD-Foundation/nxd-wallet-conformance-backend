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

export const CS02_JAR_TYP = "oauth-authz-req+jwt";
export const CS02_ALLOWED_ALGS = new Set(["ES256"]);
export const CS02_FORBIDDEN_ALGS = new Set(["none", "RS256", "ES256K", "EdDSA"]);
export const CS02_ALLOWED_CLIENT_ID_SCHEMES = new Set([
  "x509_san_dns",
  "verifier_attestation",
  "did:web",
  "did:jwk",
]);
export const CS02_DEFAULT_AUDIENCES = ["https://self-issued.me/v2"];
export const CS02_REQUEST_URI_CONTENT_TYPE = "application/oauth-authz-req+jwt";
export const CS02_ALLOWED_REQUEST_URI_METHODS = new Set(["get", "post"]);
export const CS02_DEFAULT_REQUEST_MAX_LIFETIME_SEC = 300;
export const CS02_DEFAULT_CLOCK_SKEW_SEC = 300;

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
  if (clientId.startsWith("did:web:")) {
    return { scheme: "did:web", value: clientId };
  }
  if (clientId.startsWith("did:jwk:")) {
    return { scheme: "did:jwk", value: clientId };
  }
  return { scheme: "unknown", value: clientId };
}

export function isP256Jwk(jwk) {
  return jwk?.kty === "EC" && jwk?.crv === "P-256" && jwk?.x && jwk?.y;
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
}

export function validateCs02ClientId(clientId, log = () => {}) {
  const { scheme } = parseCs02ClientIdScheme(clientId);
  if (!CS02_ALLOWED_CLIENT_ID_SCHEMES.has(scheme)) {
    logValidationFailure(log, "client_id_scheme", { scheme, clientId });
    throw new Cs02ValidationError(
      `Unsupported CS-02 client identifier scheme "${scheme}"`,
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

export async function validateX509SanDnsTrustAnchor(_clientId, _header, _leafCertPem) {
  // TODO(CS-02 trust framework): validate x5c chain against configured trust anchors.
  // TODO(CS-02 trust framework): enforce SAN DNS match to client_id host.
  return { trusted: true, placeholder: true };
}

export async function validateVerifierAttestationTrust(_header, _clientId) {
  // TODO(CS-02 trust framework): validate VA-JWT issuer against trusted verifier-attestation issuers.
  // TODO(CS-02 trust framework): enforce sub match, exp/iat, and JAR signing-key binding.
  return { trusted: true, placeholder: true };
}

async function resolveDidDocument(did) {
  if (did.startsWith("did:web:")) {
    const withoutPrefix = did.replace(/^did:web:/, "");
    const parts = withoutPrefix.split(":");
    const host = parts.shift();
    const path = parts.length ? `/${parts.join("/")}` : "";
    const urls = [`https://${host}/.well-known/did.json`, `https://${host}${path}/did.json`];
    for (const url of urls) {
      try {
        const res = await fetch(url);
        if (res.ok) return res.json();
      } catch {}
    }
    throw new Cs02ValidationError("did:web resolution failed", "invalid_client");
  }

  if (did.startsWith("did:jwk:")) {
    try {
      const json = JSON.parse(
        Buffer.from(did.substring("did:jwk:".length), "base64url").toString("utf8"),
      );
      return {
        verificationMethod: [{ id: `${did}#0`, type: "JsonWebKey2020", publicKeyJwk: json }],
      };
    } catch {
      throw new Cs02ValidationError("did:jwk decode failed", "invalid_client");
    }
  }

  throw new Cs02ValidationError(`Unsupported DID method in client_id: ${did}`, "invalid_client");
}

function x5cLeafPem(header) {
  if (!Array.isArray(header?.x5c) || header.x5c.length === 0) {
    throw new Cs02ValidationError("x509_san_dns authorization request must include x5c", "invalid_client");
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
  const did =
    (header?.kid && String(header.kid).startsWith("did:") && String(header.kid).split("#")[0]) ||
    String(clientId).split("#")[0];
  const doc = await resolveDidDocument(did);
  const vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
  if (vms.length === 0) {
    throw new Cs02ValidationError("did:web document has no verification methods", "invalid_client");
  }

  const kid = header?.kid;
  const candidates = kid
    ? vms.filter(
        (vm) =>
          vm?.id === kid ||
          vm?.id === `${did}#${kid}` ||
          (typeof kid === "string" && vm?.id?.endsWith(`#${kid.split("#").pop()}`)),
      )
    : vms;

  const selected = candidates.length > 0 ? candidates : vms;
  let lastError = null;
  for (const vm of selected) {
    if (!vm?.publicKeyJwk) continue;
    try {
      assertEs256P256Jwk(vm.publicKeyJwk, "did:web verification method");
      const key = await importJWK(vm.publicKeyJwk, "ES256");
      return await jwtVerify(requestJwt, key, { clockTolerance: options.clockSkewSec });
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Cs02ValidationError("did:web JAR signature verification failed", "invalid_client");
}

async function verifyJarWithDidJwk(requestJwt, header, clientId, options) {
  let jwk;
  try {
    jwk = JSON.parse(
      Buffer.from(String(clientId).substring("did:jwk:".length), "base64url").toString("utf8"),
    );
  } catch {
    throw new Cs02ValidationError("did:jwk client_id is malformed", "invalid_client");
  }
  assertEs256P256Jwk(jwk, "did:jwk client_id");
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
  await validateVerifierAttestationTrust(header, clientId);
  return verifyJarWithX5cLeaf(requestJwt, header, clientId, "verifier_attestation x5c");
}

export async function verifyCs02JarSignature(requestJwt, header, payload, options, log = () => {}) {
  const clientId = payload?.client_id;
  validateCs02ClientId(clientId, log);
  const { scheme } = parseCs02ClientIdScheme(clientId);

  try {
    switch (scheme) {
      case "x509_san_dns":
        return verifyJarWithX5cLeaf(requestJwt, header, clientId, "x509_san_dns x5c");
      case "did:web":
        return verifyJarWithDidWeb(requestJwt, header, clientId, options);
      case "did:jwk":
        return verifyJarWithDidJwk(requestJwt, header, clientId, options);
      case "verifier_attestation":
        return verifyJarWithVerifierAttestation(requestJwt, header, clientId, options);
      default:
        throw new Cs02ValidationError(
          `Unsupported CS-02 client identifier scheme "${scheme}"`,
          "invalid_client",
        );
    }
  } catch (error) {
    if (error instanceof Cs02ValidationError) throw error;
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
  { deepLinkClientId, options, log = () => {} } = {},
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
  validateCs02DeepLinkClientIdConsistency(deepLinkClientId, payload.client_id, log);

  const verified = await verifyCs02JarSignature(requestJwt, header, payload, options, log);
  return {
    header: verified.protectedHeader || header,
    payload: verified.payload || payload,
  };
}

export async function fetchCs02AuthorizationRequestJwt(requestUri, method, options, log = () => {}) {
  const normalizedMethod = validateCs02RequestUriMethod(method, log);
  validateCs02RequestUri(requestUri, options, log);

  const headers = {
    Accept: CS02_REQUEST_URI_CONTENT_TYPE,
  };

  let response;
  if (normalizedMethod === "post") {
    const form = new URLSearchParams();
    response = await fetch(requestUri, {
      method: "POST",
      headers: {
        ...headers,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: form.toString(),
    });
  } else {
    response = await fetch(requestUri, { method: "GET", headers });
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

  return { requestJwt: body, contentType };
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
