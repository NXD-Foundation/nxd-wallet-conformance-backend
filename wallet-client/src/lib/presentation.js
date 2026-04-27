import fetch from "node-fetch";
import crypto from "node:crypto";
import { jwtVerify, createLocalJWKSet, importJWK, importX509 } from "jose";
import {
  createProofJwt,
  generateDidJwkFromPrivateJwk,
  ensureOrCreateEcKeyPair,
} from "./crypto.js";
import { resolveDeviceKeyPath } from "./deviceKeyPaths.js";
import {
  getWalletCredentialByType,
  listWalletCredentialTypes,
  appendWalletLog,
  storeWalletPresentationSession,
  getWalletPresentationSession,
} from "./cache.js";
import {
  buildMdocPresentation,
  isMdocCredential,
} from "../../utils/mdlVerification.js";
import { didKeyToJwks } from "../../utils/cryptoUtils.js";
import { normalizeVerifierInfo } from "./verifierInfoNormalize.js";
import {
  extractCs03Request,
  loadLocalCs03Signer,
  selectMatchingCs03Signer,
  fetchCs03Documents,
  buildCs03SignatureObject,
  buildInlineCs03VpToken,
  buildOobCs03VpToken,
  sendCs03OobResponse,
} from "./cs03.js";
import { transactionDataBindingForSdJwtKb } from "./transactionDataKb.js";
import { normalizeDcqlClaimsToSegmentLists } from "./dcqlClaimsPaths.js";
export { normalizeDcqlClaimsToSegmentLists } from "./dcqlClaimsPaths.js";
import {
  storedCredentialMatchesDcqlQuery,
  presentationFormatFromDcqlQuery,
} from "./dcqlCredentialSelection.js";

function makeSessionLogger(sessionId) {
  return function sessionLog(...args) {
    try {
      console.log(...args);
    } catch {}
    if (!sessionId) return;
    try {
      // Separate string messages from structured data
      const messages = [];
      let data = null;

      // If last arg is a plain object (not null, not array, not Date, etc.), treat it as structured data
      if (args.length > 0) {
        const lastArg = args[args.length - 1];
        if (
          lastArg &&
          typeof lastArg === "object" &&
          !Array.isArray(lastArg) &&
          !(lastArg instanceof Date) &&
          !(lastArg instanceof Error) &&
          Object.prototype.toString.call(lastArg) === "[object Object]"
        ) {
          // Last argument is structured data
          data = lastArg;
          // Process remaining args as messages
          for (let i = 0; i < args.length - 1; i++) {
            const arg = args[i];
            if (typeof arg === "string") {
              messages.push(arg);
            } else {
              try {
                messages.push(JSON.stringify(arg));
              } catch {
                messages.push(String(arg));
              }
            }
          }
        } else {
          // No structured data, convert all args to messages
          for (const arg of args) {
            if (typeof arg === "string") {
              messages.push(arg);
            } else {
              try {
                messages.push(JSON.stringify(arg));
              } catch {
                messages.push(String(arg));
              }
            }
          }
        }
      }

      const message = messages.join(" ");
      const logEntry = { level: "info", message };
      if (data) {
        logEntry.data = data;
      }
      appendWalletLog(sessionId, logEntry).catch(() => {});
    } catch {}
  };
}

function parseOpenId4VpDeepLink(deepLink) {
  console.log("[present] Parsing deep link:", deepLink);
  const url = new URL(deepLink);
  const supported = new Set(["openid4vp:", "mdoc-openid4vp:", "eu-eaap:"]);
  if (!supported.has(url.protocol)) {
    throw new Error(`Unsupported request scheme: ${url.protocol}`);
  }
  const requestUri = url.searchParams.get("request_uri");
  const clientId = url.searchParams.get("client_id");
  const method = url.searchParams.get("request_uri_method") || "get";
  console.log("[present] Parsed deep link →", { requestUri, clientId, method });
  return { requestUri, clientId, method };
}

/**
 * RFC002 §8.2 — optional `wallet_metadata` on request_uri POST.
 * Advertises supported VP formats/response modes, mdoc handover nonce, and an encryption JWK for JAR/JWE.
 */
export function buildWalletMetadataForVpRequest({ publicJwk, mdocGeneratedNonce }) {
  if (!publicJwk || typeof publicJwk !== "object") {
    throw new Error("buildWalletMetadataForVpRequest: publicJwk is required");
  }
  const encKey = { ...publicJwk };
  delete encKey.d;
  encKey.use = "enc";
  delete encKey.alg;
  const meta = {
    vp_formats_supported: ["jwt_vp", "dc+sd-jwt", "vc+sd-jwt", "mso_mdoc"],
    vp_formats: ["jwt_vp", "dc+sd-jwt", "vc+sd-jwt", "mso_mdoc"],
    response_modes_supported: ["direct_post", "direct_post.jwt"],
    response_modes: ["direct_post", "direct_post.jwt"],
    jwks: { keys: [encKey] },
    authorization_encryption_alg_values_supported: ["ECDH-ES+A256KW"],
    authorization_encryption_enc_values_supported: ["A256GCM"],
  };
  if (typeof mdocGeneratedNonce === "string" && mdocGeneratedNonce.length > 0) {
    meta.mdoc_generated_nonce = mdocGeneratedNonce;
  }
  return meta;
}

async function fetchAuthorizationRequestJwt(requestUri, method, { walletMetadata } = {}) {
  if (!requestUri) throw new Error("Missing request_uri in deep link");
  if (method && method.toLowerCase() === "post") {
    const form = new URLSearchParams();
    if (walletMetadata && typeof walletMetadata === "object") {
      form.append("wallet_metadata", JSON.stringify(walletMetadata));
    }
    console.log("[present] Fetching request JWT via POST:", requestUri);
    const res = await fetch(requestUri, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    const text = await res.text().catch(() => "");
    console.log(
      "[present] POST request_uri status:",
      res.status,
      "body.len=",
      text?.length,
    );
    if (!res.ok)
      throw new Error(
        `Auth request POST error ${res.status}${text ? ": " + text : ""}`,
      );
    return text;
  }
  console.log("[present] Fetching request JWT via GET:", requestUri);
  const res = await fetch(requestUri);
  const text = await res.text().catch(() => "");
  console.log(
    "[present] GET request_uri status:",
    res.status,
    "body.len=",
    text?.length,
  );
  if (!res.ok) throw new Error(`Auth request GET error ${res.status}`);
  return text;
}

function decodeJwt(token) {
  const parts = token.split(".");
  if (parts.length < 2) throw new Error("Invalid JWT");
  const payload = JSON.parse(
    Buffer.from(parts[1], "base64url").toString("utf8"),
  );
  const header = JSON.parse(
    Buffer.from(parts[0], "base64url").toString("utf8"),
  );
  console.log(
    "[present] Decoded request JWT header.alg=",
    header.alg,
    "payload.keys=",
    Object.keys(payload),
  );
  return { header, payload };
}

async function fetchJson(url, description) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`${description} fetch error ${res.status}`);
  }
  return res.json();
}

async function resolveDidDocument(did) {
  if (did.startsWith("did:web:")) {
    const withoutPrefix = did.replace(/^did:web:/, "");
    const parts = withoutPrefix.split(":");
    const host = parts.shift();
    const path = parts.length ? "/" + parts.join("/") : "";
    const urls = [
      `https://${host}/.well-known/did.json`,
      `https://${host}${path}/did.json`,
    ];
    for (const url of urls) {
      try {
        const res = await fetch(url);
        if (res.ok) return res.json();
      } catch {}
    }
    throw new Error("did:web resolution failed");
  }
  if (did.startsWith("did:jwk:")) {
    try {
      const json = JSON.parse(Buffer.from(did.substring("did:jwk:".length), "base64url").toString("utf8"));
      return { verificationMethod: [{ id: did + "#0", type: "JsonWebKey2020", publicKeyJwk: json }] };
    } catch {
      throw new Error("did:jwk decode failed");
    }
  }
  if (did.startsWith("did:key:")) {
    const jwks = await didKeyToJwks(did);
    const first = Array.isArray(jwks?.keys) && jwks.keys.length ? jwks.keys[0] : null;
    if (!first) throw new Error("did:key resolution returned no keys");
    return { verificationMethod: [{ id: did + "#0", type: "JsonWebKey2020", publicKeyJwk: first }] };
  }
  throw new Error("Unsupported DID method");
}

async function verifyJwtWithDid(jwt, header, didOrIss) {
  const did = (header?.kid && header.kid.startsWith("did:")) ? header.kid.split("#")[0] : didOrIss;
  if (!did || !String(did).startsWith("did:")) {
    throw new Error("No DID available for verification");
  }
  const doc = await resolveDidDocument(String(did));
  const vms = doc.verificationMethod || [];
  let lastErr = null;
  for (const vm of vms) {
    if (!vm?.publicKeyJwk) continue;
    try {
      const key = await importJWK(vm.publicKeyJwk, header?.alg || "ES256");
      return await jwtVerify(jwt, key, { clockTolerance: 300 });
    } catch (error) {
      lastErr = error;
    }
  }
  throw lastErr || new Error("DID verification failed");
}

function throwInvalidPresentationRequest(desc) {
  throw new Error(`invalid_request: ${desc}`);
}

/**
 * Extract RFC002 `verifier_info` from an OpenID4VP authorization request JWT payload.
 * Normalises the same fields as the issuer/verifier ({@link normalizeVerifierInfo}).
 *
 * @param {Record<string, unknown>} payload - Decoded request JWT payload
 * @returns {Record<string, unknown> | null}
 */
export function parseVerifierInfo(payload) {
  if (!payload || typeof payload !== "object") return null;
  const raw = payload.verifier_info;
  if (raw == null || raw === "") return null;
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    try {
      const parsed = JSON.parse(trimmed);
      return normalizeVerifierInfo(parsed);
    } catch {
      console.warn("[present] verifier_info claim is not valid JSON; ignoring");
      return null;
    }
  }
  if (typeof raw === "object" && !Array.isArray(raw)) {
    return normalizeVerifierInfo(raw);
  }
  return null;
}

function attachVerifierInfoToResult(result, verifierInfo) {
  const base =
    result && typeof result === "object" && !Array.isArray(result)
      ? result
      : { outcome: result };
  return {
    ...base,
    verifier_info: verifierInfo ?? null,
  };
}

/** RFC002 §8.3.4 — wallet reports these to verifier `response_uri` on local presentation failure */
export const WalletRfc002PresentationErrors = Object.freeze({
  INVALID_PRESENTATION: "invalid_presentation",
  MALFORMED_RESPONSE: "malformed_response",
  USER_CANCELLATION: "user_cancellation",
  EXPIRED_REQUEST: "expired_request",
  UNSUPPORTED_CREDENTIAL_FORMAT: "unsupported_credential_format",
  MISSING_REQUIRED_PROOF: "missing_required_proof",
  FAILED_CORRELATION: "failed_correlation",
  FAILED_VALIDATION: "failed_validation",
});

function decodeRequestJwtPayloadQuiet(token) {
  if (typeof token !== "string" || !token.length) throw new Error("Invalid JWT");
  const parts = token.split(".");
  if (parts.length < 2) throw new Error("Invalid JWT");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

function extractVerifierDeliveryContext(requestPayload) {
  if (!requestPayload || typeof requestPayload !== "object") {
    return { responseUri: null, state: null, responseMode: null };
  }
  const responseUri = requestPayload.response_uri;
  const state = requestPayload.state ?? null;
  let responseMode = requestPayload.response_mode || "direct_post";
  if (responseUri && /direct_post\.jwt/i.test(String(responseUri))) {
    responseMode = "direct_post.jwt";
  }
  return {
    responseUri:
      typeof responseUri === "string" && responseUri.length ? responseUri : null,
    state,
    responseMode,
  };
}

/**
 * Map a thrown presentation error to RFC002 §8.3.4 `error` codes for the verifier.
 * @param {unknown} err
 * @returns {{ code: string, description: string }}
 */
export function mapWalletPresentationErrorToRfc002(err) {
  const msg = err?.message || String(err);
  const joseCode = err && typeof err === "object" ? err.code : null;
  if (
    joseCode === "ERR_JWT_EXPIRED" ||
    /jwt expired|token expired|timestamp check failed/i.test(msg)
  ) {
    return {
      code: WalletRfc002PresentationErrors.EXPIRED_REQUEST,
      description: msg,
    };
  }
  if (msg.startsWith("invalid_request:")) {
    return {
      code: WalletRfc002PresentationErrors.MALFORMED_RESPONSE,
      description: msg.replace(/^invalid_request:\s*/i, "").trim() || msg,
    };
  }
  if (msg.includes("client_id does not match deep link")) {
    return {
      code: WalletRfc002PresentationErrors.FAILED_CORRELATION,
      description: msg,
    };
  }
  if (
    msg.includes("unsupported client_id_scheme") ||
    msg.includes("Unsupported request scheme")
  ) {
    return {
      code: WalletRfc002PresentationErrors.UNSUPPORTED_CREDENTIAL_FORMAT,
      description: msg,
    };
  }
  if (msg.includes("matched no disclosures") || msg.includes("claims mismatch")) {
    return {
      code: WalletRfc002PresentationErrors.FAILED_VALIDATION,
      description: msg,
    };
  }
  if (
    msg.includes("Credential not found") ||
    msg.includes("No credentials available") ||
    msg.includes("could not be satisfied") ||
    msg.includes("Unable to extract presentable credential") ||
    msg.includes("Unable to determine audience")
  ) {
    return {
      code: WalletRfc002PresentationErrors.INVALID_PRESENTATION,
      description: msg,
    };
  }
  if (
    msg.includes("Missing response_uri") ||
    msg.includes("Missing nonce") ||
    msg.includes("Authorization request JWT verification failed") ||
    (/signature verification failed/i.test(msg) && /jwt|jws/i.test(msg)) ||
    msg.includes("Authorization request JWT must be signed") ||
    msg.includes("no verifier trust material") ||
    msg.includes("credential_ids") ||
    msg.includes("transaction_data") ||
    msg.includes("dcql_query.credentials[]") ||
    msg.includes("Auth request GET error") ||
    msg.includes("Auth request POST error") ||
    msg.includes("Missing request_uri")
  ) {
    return {
      code: WalletRfc002PresentationErrors.MALFORMED_RESPONSE,
      description: msg,
    };
  }
  if (
    msg.includes("DID verification failed") ||
    msg.includes("did:jwk decode failed") ||
    msg.includes("Unsupported DID method")
  ) {
    return {
      code: WalletRfc002PresentationErrors.MALFORMED_RESPONSE,
      description: msg,
    };
  }
  if (msg.includes("Fetch VP request error") || msg.includes("Unexpected response from verifier")) {
    return {
      code: WalletRfc002PresentationErrors.FAILED_CORRELATION,
      description: msg,
    };
  }
  if (
    msg.includes("missing_required_proof") ||
    msg.includes("Missing required proof")
  ) {
    return {
      code: WalletRfc002PresentationErrors.MISSING_REQUIRED_PROOF,
      description: msg,
    };
  }
  if (msg.includes("CS-03")) {
    return {
      code: WalletRfc002PresentationErrors.MALFORMED_RESPONSE,
      description: msg,
    };
  }
  return {
    code: WalletRfc002PresentationErrors.INVALID_PRESENTATION,
    description: msg,
  };
}

function isVerifierHttpRejectionError(err) {
  const msg = err?.message || "";
  return /^Verifier (direct_post|response) error /i.test(msg);
}

async function postWalletErrorToResponseUri({
  responseUri,
  state,
  error,
  error_description,
  slog,
}) {
  const form = new URLSearchParams();
  form.set("error", error);
  form.set("error_description", error_description);
  if (state != null && state !== "") form.set("state", String(state));
  const body = form.toString();
  try {
    slog("[PRESENTATION] [REQUEST] POST error to verifier response_uri", {
      url: responseUri,
      error,
    });
  } catch {}
  const res = await fetch(responseUri, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const resText = await res.text().catch(() => "");
  try {
    slog("[PRESENTATION] [RESPONSE] Verifier error-POST response", {
      url: responseUri,
      status: res.status,
      body: resText?.slice(0, 500),
    });
  } catch {}
  return res.status;
}

async function finalizeWalletPresentationFailure(
  err,
  payload,
  parsedVerifierInfo,
  slog,
  logSessionId,
) {
  const { code, description } = mapWalletPresentationErrorToRfc002(err);
  let persisted = null;
  if (logSessionId) {
    try {
      persisted = await getWalletPresentationSession(logSessionId);
    } catch {
      /* ignore */
    }
  }
  let ctx = extractVerifierDeliveryContext(payload);
  if (!ctx.responseUri && persisted?.response_uri) {
    ctx = {
      responseUri: persisted.response_uri,
      state: persisted.state,
      responseMode: persisted.response_mode,
    };
  }
  try {
    slog("[PRESENTATION] [ERROR] presentation_session (Redis)", {
      client_id: persisted?.client_id ?? null,
      response_uri: persisted?.response_uri ?? null,
      response_mode: persisted?.response_mode ?? null,
    });
  } catch {}
  let verifier_error_delivered = false;
  let verifier_error_post_http_status = null;
  if (ctx.responseUri) {
    try {
      verifier_error_post_http_status = await postWalletErrorToResponseUri({
        responseUri: ctx.responseUri,
        state: ctx.state,
        error: code,
        error_description: description,
        slog,
      });
      verifier_error_delivered = verifier_error_post_http_status != null;
    } catch (e) {
      try {
        slog("[PRESENTATION] [ERROR] Failed to POST error to response_uri", {
          error: e?.message || String(e),
        });
      } catch {}
    }
  }
  return attachVerifierInfoToResult(
    {
      status: "error",
      error: code,
      error_description: description,
      verifier_error_delivered,
      ...(verifier_error_post_http_status != null
        ? { verifier_error_post_http_status }
        : {}),
      ...(persisted ? { presentation_session: persisted } : {}),
    },
    parsedVerifierInfo,
  );
}

/**
 * RFC002 / OpenID4VP: `client_id` for x509_hash MUST be `x509_hash:` + base64url(SHA-256(DER(leaf))).
 * `x5c[0]` is standard base64-encoded DER (RFC 7515).
 */
export function computeX509HashClientIdFromLeafX5c(x5c0) {
  if (typeof x5c0 !== "string" || !x5c0.length) {
    throw new Error("missing leaf x5c");
  }
  const der = Buffer.from(x5c0, "base64");
  if (!der.length) {
    throw new Error("empty certificate DER from x5c[0]");
  }
  const digest = crypto.createHash("sha256").update(der).digest();
  return `x509_hash:${digest.toString("base64url")}`;
}

function x509LeafPemFromX5cFirst(x5c0) {
  const lines = x5c0.match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

/**
 * Prefer `client_id` prefix over `client_id_scheme` so the binding implied by the identifier wins.
 */
function inferPresentationClientIdScheme(payload) {
  const cid = payload?.client_id;
  if (typeof cid === "string") {
    if (cid.startsWith("x509_hash:")) return "x509_hash";
    if (cid.startsWith("x509_san_dns:")) return "x509_san_dns";
    if (cid.startsWith("x509_san_uri:")) return "x509_san_uri";
  }
  const raw = payload?.client_id_scheme;
  if (typeof raw === "string" && raw.trim()) {
    return raw.trim().toLowerCase();
  }
  return null;
}

const WALLET_KNOWN_CLIENT_ID_SCHEMES = new Set([
  "x509_hash",
  "x509_san_dns",
  "x509_san_uri",
  "redirect_uri",
]);

function assertClientIdSchemeAllowedForWallet(payload) {
  const raw = payload?.client_id_scheme;
  if (raw == null || raw === "") return;
  const s = String(raw).trim().toLowerCase();
  if (WALLET_KNOWN_CLIENT_ID_SCHEMES.has(s)) return;
  const cid = payload?.client_id;
  if (typeof cid === "string" && cid.startsWith("did:")) return;
  throwInvalidPresentationRequest(`unsupported client_id_scheme '${raw}'`);
}

function assertClientIdSchemeConsistentWithX509Hash(payload) {
  const cid = payload?.client_id;
  const raw = payload?.client_id_scheme;
  const schemeNorm = typeof raw === "string" && raw.trim() ? String(raw).trim().toLowerCase() : "";

  if (schemeNorm === "x509_hash") {
    if (typeof cid !== "string" || !cid.startsWith("x509_hash:")) {
      throwInvalidPresentationRequest(
        "client_id_scheme is x509_hash but client_id is not an x509_hash identifier",
      );
    }
  }

  if (typeof cid === "string" && cid.startsWith("x509_hash:")) {
    if (schemeNorm && schemeNorm !== "x509_hash") {
      throwInvalidPresentationRequest(
        `client_id uses x509_hash prefix but client_id_scheme is '${raw}' (expected x509_hash)`,
      );
    }
  }
}

export async function verifyAuthorizationRequestJwt(requestJwt, { expectedClientId }) {
  const { header, payload } = decodeJwt(requestJwt);
  if (!header?.alg || header.alg === "none") {
    throw new Error("Authorization request JWT must be signed");
  }
  if (expectedClientId && payload?.client_id && payload.client_id !== expectedClientId) {
    throw new Error("Authorization request client_id does not match deep link client_id");
  }

  assertClientIdSchemeConsistentWithX509Hash(payload);

  const inferredScheme = inferPresentationClientIdScheme(payload);
  const isX509Hash =
    inferredScheme === "x509_hash" ||
    (typeof payload?.client_id === "string" && payload.client_id.startsWith("x509_hash:"));

  if (isX509Hash) {
    if (!Array.isArray(header?.x5c) || typeof header.x5c[0] !== "string" || !header.x5c[0].length) {
      throwInvalidPresentationRequest(
        "x509_hash authorization request requires a non-empty JOSE x5c header (leaf certificate)",
      );
    }
    let expectedFromCert;
    try {
      expectedFromCert = computeX509HashClientIdFromLeafX5c(header.x5c[0]);
    } catch (e) {
      throwInvalidPresentationRequest(e?.message || "invalid x5c leaf certificate encoding");
    }
    if (typeof payload.client_id !== "string" || payload.client_id !== expectedFromCert) {
      throwInvalidPresentationRequest(
        `x509_hash client_id does not match SHA-256 hash of leaf certificate (expected ${expectedFromCert}, received ${payload.client_id})`,
      );
    }
    const pem = x509LeafPemFromX5cFirst(header.x5c[0]);
    const certKey = await importX509(pem, header.alg);
    const verified = await jwtVerify(requestJwt, certKey, { clockTolerance: 300 });
    return {
      header: verified.protectedHeader || header,
      payload: verified.payload,
    };
  }

  assertClientIdSchemeAllowedForWallet(payload);

  const looseX509 =
    inferredScheme === "x509_san_dns" ||
    inferredScheme === "x509_san_uri" ||
    (typeof payload?.client_id === "string" &&
      (payload.client_id.startsWith("x509_san_dns:") ||
        payload.client_id.startsWith("x509_san_uri:")));
  if (looseX509) {
    console.warn(
      "[present] RFC002: x509_san_dns / x509_san_uri client_id uses legacy wallet validation path; ETSI profile recommends x509_hash",
    );
  }

  const metadataCandidates = [];
  const inlineClientMetadata = payload.client_metadata || payload.clientMetadata;
  if (inlineClientMetadata && typeof inlineClientMetadata === "object") {
    metadataCandidates.push(inlineClientMetadata);
  }
  if (payload.client_metadata_uri) {
    const remoteMetadata = await fetchJson(payload.client_metadata_uri, "client_metadata_uri");
    if (remoteMetadata && typeof remoteMetadata === "object") {
      metadataCandidates.push(remoteMetadata);
    }
  }

  const verificationAttempts = [];

  if (Array.isArray(header?.x5c) && header.x5c.length > 0) {
    verificationAttempts.push(async () => {
      const pem = x509LeafPemFromX5cFirst(header.x5c[0]);
      const certKey = await importX509(pem, header.alg || "ES256");
      return jwtVerify(requestJwt, certKey, { clockTolerance: 300 });
    });
  }

  for (const metadata of metadataCandidates) {
    if (metadata?.jwks?.keys?.length) {
      verificationAttempts.push(async () => jwtVerify(requestJwt, createLocalJWKSet(metadata.jwks), { clockTolerance: 300 }));
    }
    if (metadata?.jwks_uri) {
      verificationAttempts.push(async () => {
        const jwks = await fetchJson(metadata.jwks_uri, "jwks_uri");
        return jwtVerify(requestJwt, createLocalJWKSet(jwks), { clockTolerance: 300 });
      });
    }
    if (Array.isArray(metadata?.x5c) && metadata.x5c.length > 0) {
      verificationAttempts.push(async () => {
        const pem = x509LeafPemFromX5cFirst(metadata.x5c[0]);
        const certKey = await importX509(pem, header.alg || "ES256");
        return jwtVerify(requestJwt, certKey, { clockTolerance: 300 });
      });
    }
  }

  const didCandidate =
    (header?.kid && String(header.kid).startsWith("did:") && String(header.kid).split("#")[0]) ||
    (payload?.client_id && String(payload.client_id).startsWith("did:") && String(payload.client_id)) ||
    (expectedClientId && String(expectedClientId).startsWith("did:") && String(expectedClientId));
  if (didCandidate) {
    verificationAttempts.push(async () => verifyJwtWithDid(requestJwt, header, didCandidate));
  }

  if (verificationAttempts.length === 0) {
    throw new Error("Authorization request JWT verification failed: no verifier trust material available");
  }

  let lastError = null;
  for (const attempt of verificationAttempts) {
    try {
      const verified = await attempt();
      return {
        header: verified.protectedHeader || header,
        payload: verified.payload,
      };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error("Authorization request JWT verification failed");
}

function buildPresentationSubmission(presentationDefinition, credentialFormat) {
  if (!presentationDefinition) return undefined;
  console.log(
    "[present] Building presentation_submission from definition:",
    presentationDefinition.id,
  );
  console.log(
    "[present] Input descriptors:",
    presentationDefinition.input_descriptors?.length || 0,
  );

  const inputDescriptors = presentationDefinition.input_descriptors || [];
  const format = credentialFormat || inferRootFormat(presentationDefinition);
  const descriptorMap = inputDescriptors.map((d) => ({
    id: d.id,
    format,
    path: "$.vp_token",
  }));

  console.log(
    "[present] Descriptor map:",
    JSON.stringify(descriptorMap, null, 2),
  );

  // The verifier expects JSON string in some handlers; keep as string to be safe
  const submission = {
    definition_id: presentationDefinition.id || "pd",
    descriptor_map: descriptorMap,
  };
  console.log(
    "[present] Built presentation_submission:",
    JSON.stringify(submission, null, 2),
  );
  return JSON.stringify(submission);
}

function vpTokenPathForDcqlId(dcqlId) {
  if (typeof dcqlId !== "string" || !dcqlId.length) return "$.vp_token";
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(dcqlId)) return `$.vp_token.${dcqlId}`;
  return `$['vp_token'][${JSON.stringify(dcqlId)}]`;
}

function buildPresentationSubmissionDcql(
  presentationDefinition,
  dcqlQuery,
  perEntryFormats,
) {
  if (!presentationDefinition) return undefined;
  const inputDescriptors = presentationDefinition.input_descriptors || [];
  const creds = (dcqlQuery && dcqlQuery.credentials) || [];
  if (inputDescriptors.length === creds.length && inputDescriptors.length > 0) {
    const descriptorMap = inputDescriptors.map((d, i) => {
      const fmt =
        perEntryFormats[i] || inferRootFormat(presentationDefinition);
      const submissionFmt = fmt === "jwt_vc_json" ? "jwt_vp" : fmt;
      return {
        id: d.id,
        format: submissionFmt,
        path: vpTokenPathForDcqlId(creds[i].id),
      };
    });
    const submission = {
      definition_id: presentationDefinition.id || "pd",
      descriptor_map: descriptorMap,
    };
    console.log(
      "[present] Built presentation_submission (DCQL-aware):",
      JSON.stringify(submission, null, 2),
    );
    return JSON.stringify(submission);
  }
  const singleFmt =
    perEntryFormats[0] || inferRootFormat(presentationDefinition);
  const submissionFmt = singleFmt === "jwt_vc_json" ? "jwt_vp" : singleFmt;
  return buildPresentationSubmission(presentationDefinition, submissionFmt);
}

function inferRootFormat(presentationDefinition) {
  // Infer format from presentation definition
  const fmt = presentationDefinition.format || {};
  if (fmt["mso_mdoc"]) return "mso_mdoc"; // mdoc format
  if (fmt["dc+sd-jwt"]) return "dc+sd-jwt";
  if (fmt["vc+sd-jwt"]) return "vc+sd-jwt";
  if (fmt["jwt_vc_json"]) return "jwt_vc_json";
  return "dc+sd-jwt";
}

function decodeDisclosureJsonFromSegment(encoded) {
  const raw = Buffer.from(encoded, "base64url").toString("utf8");
  return JSON.parse(raw);
}

function buildAllowedDisclosureKeysFromDcql(segmentLists) {
  const keys = new Set();
  for (const segs of segmentLists) {
    for (const s of segs) {
      if (typeof s === "string" && s.length) keys.add(s);
    }
  }
  return keys;
}

/**
 * Split SD-JWT into issuer JWT and disclosure segments. Strips a trailing KB JWT segment if present
 * (last ~ part with three dot-separated substrings) so filtering only sees disclosures.
 */
function splitSdJwtJwtDisclosuresAndKb(sdJwt) {
  let token = sdJwt;
  while (token.endsWith("~")) token = token.slice(0, -1);
  const parts = token.split("~");
  const jwtPart = parts[0];
  const tail = parts.slice(1);
  const disclosureParts = [...tail];
  if (disclosureParts.length > 0) {
    const last = disclosureParts[disclosureParts.length - 1];
    if (last.split(".").length === 3) disclosureParts.pop();
  }
  return { jwtPart, disclosureParts };
}

/**
 * When DCQL `credentials[].claims` is set, keep only object-property disclosures (3-element)
 * whose claim name appears in the allowed key set derived from those paths.
 * Omits 2-element array disclosures when filtering is active (narrow DCQL requests).
 * If `claims` is missing or empty, returns `sdJwt` unchanged (including any trailing KB JWT).
 *
 * @param {string} sdJwt
 * @param {object | undefined} dcqlEntry - dcql_query.credentials[] element
 */
export function filterSdJwtDisclosuresForDcqlClaims(sdJwt, dcqlEntry) {
  if (!sdJwt || typeof sdJwt !== "string" || !sdJwt.includes("~")) return sdJwt;
  const segmentLists = normalizeDcqlClaimsToSegmentLists(dcqlEntry?.claims);
  if (segmentLists.length === 0) return sdJwt;

  const allowedKeys = buildAllowedDisclosureKeysFromDcql(segmentLists);
  if (allowedKeys.size === 0) return sdJwt;

  const { jwtPart, disclosureParts } = splitSdJwtJwtDisclosuresAndKb(sdJwt);
  const kept = [jwtPart];
  let matched = 0;
  for (const enc of disclosureParts) {
    if (!enc) continue;
    try {
      const arr = decodeDisclosureJsonFromSegment(enc);
      if (Array.isArray(arr) && arr.length === 3 && typeof arr[1] === "string") {
        if (allowedKeys.has(arr[1])) {
          kept.push(enc);
          matched++;
        }
      }
    } catch {
      // skip malformed segment
    }
  }

  if (disclosureParts.length > 0 && matched === 0) {
    throw new Error(
      `DCQL claims ${JSON.stringify(dcqlEntry.claims)} matched no disclosures in the SD-JWT`,
    );
  }

  return kept.join("~");
}

function attachKbJwtToSdJwt(sdJwt, kbJwt) {
  if (!sdJwt || typeof sdJwt !== "string")
    throw new Error("Invalid sd-jwt to present");
  // Trim any trailing '~' to avoid creating empty disclosure segments
  let token = sdJwt;
  while (token.endsWith("~")) token = token.slice(0, -1);
  const parts = token.split("~");
  // kb-jwt is a JWT (has dots) and is appended as the last segment.
  const hasKbJwt = parts.slice(1).some((p) => p.includes("."));
  if (hasKbJwt) return token; // already present
  return `${token}~${kbJwt}`;
}

async function buildJwtVpToken({
  credentialJwt,
  privateJwk,
  publicJwk,
  issuer,
  audience,
  nonce,
  alg = "ES256",
}) {
  const { SignJWT } = await import("jose");
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    aud: audience,
    iat: now,
    nbf: now - 5,
    exp: now + 300,
    jti: Buffer.from(crypto.randomBytes(16)).toString("base64url"),
    nonce,
    vp: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiablePresentation"],
      verifiableCredential: [credentialJwt],
    },
  };
  const key = await importJWK(privateJwk, alg);
  return new SignJWT(payload)
    .setProtectedHeader({ alg, typ: "openid4vp+jwt", jwk: publicJwk })
    .sign(key);
}

function ecPublicJwksEqual(a, b) {
  if (!a || !b) return false;
  if (a.kty !== b.kty) return false;
  if (a.crv && b.crv && a.crv !== b.crv) return false;
  return !!(a.x && b.x && a.y && b.y && a.x === b.x && a.y === b.y);
}

function extractCredentialString(credentialEnvelope) {
  if (!credentialEnvelope) return null;
  if (typeof credentialEnvelope === "string") return credentialEnvelope;
  if (typeof credentialEnvelope === "object") {
    console.log(
      "[present] Credential envelope keys:",
      Object.keys(credentialEnvelope),
    );
    console.log(
      "[present] Credential envelope types:",
      Object.fromEntries(
        Object.entries(credentialEnvelope).map(([k, v]) => [k, typeof v]),
      ),
    );
    // Common OID4VCI response: { credential: "<sd-jwt>" }
    if (typeof credentialEnvelope.credential === "string")
      return credentialEnvelope.credential;
    // Handle { credentials: { ... } } structure
    if (
      credentialEnvelope.credentials &&
      typeof credentialEnvelope.credentials === "object"
    ) {
      console.log(
        "[present] Found credentials object, keys:",
        Object.keys(credentialEnvelope.credentials),
      );
      // Look for SD-JWT, JWT, or mdoc in credentials object
      for (const [key, value] of Object.entries(
        credentialEnvelope.credentials,
      )) {
        console.log(
          "[present] credentials[" + key + "] type:",
          typeof value,
          "value:",
          typeof value === "string" ? value : JSON.stringify(value),
        );
        if (
          typeof value === "string" &&
          (value.includes("~") || value.split(".").length >= 3)
        ) {
          console.log("[present] Found token in credentials." + key);
          return value;
        }
        // If it's an object, look deeper
        if (typeof value === "object" && value !== null) {
          console.log(
            "[present] credentials[" + key + "] object keys:",
            Object.keys(value),
          );
          for (const [subKey, subValue] of Object.entries(value)) {
            if (typeof subValue === "string") {
              // Check for SD-JWT, JWT, or mdoc (base64 string)
              if (
                subValue.includes("~") ||
                subValue.split(".").length >= 3 ||
                isMdocCredential(subValue)
              ) {
                console.log(
                  "[present] Found token in credentials." + key + "." + subKey,
                );
                return subValue;
              }
            }
          }
        }
      }
    }
    // Try to find first string value that looks like token
    for (const v of Object.values(credentialEnvelope)) {
      if (
        typeof v === "string" &&
        (v.includes("~") || v.split(".").length >= 3 || isMdocCredential(v))
      )
        return v;
    }
  }
  return null;
}

/** @param {string | undefined} format */
export function normalizeDcqlCredentialFormat(format) {
  if (typeof format !== "string" || !format.trim()) return null;
  const f = format.trim().toLowerCase();
  if (f === "mso_mdoc") return "mso_mdoc";
  if (f === "dc+sd-jwt") return "dc+sd-jwt";
  if (f === "vc+sd-jwt") return "vc+sd-jwt";
  if (f === "jwt_vc_json" || f === "vc+jwt") return "jwt_vc_json";
  return f;
}

/**
 * @param {object} entry - dcql_query.credentials[]
 * @param {string} configurationId - wallet Redis key (configuration id)
 * @param {string} rawToken - extracted credential string
 * @param {string} wantFmt - normalized format from {@link normalizeDcqlCredentialFormat}
 */
export function storedRawMatchesDcqlEntry(entry, configurationId, rawToken, wantFmt) {
  if (wantFmt === "mso_mdoc") {
    return storedCredentialMatchesDcqlQuery(entry, rawToken);
  }
  if (wantFmt === "dc+sd-jwt" || wantFmt === "vc+sd-jwt") {
    return storedCredentialMatchesDcqlQuery(entry, rawToken);
  }
  const isMdoc = isMdocCredential(rawToken);
  if (wantFmt === "jwt_vc_json" || wantFmt === "jwt_vp") {
    if (isMdoc) return false;
    if (rawToken.includes("~")) return false;
    return rawToken.split(".").length >= 3;
  }
  return false;
}

/**
 * @returns {Promise<{ configurationId: string, stored: object, rawToken: string, pickedEntry: object } | null>}
 */
async function findWalletStoredForDcqlEntry(entry, usedConfigurationIds) {
  const wantFmt = normalizeDcqlCredentialFormat(entry.format);
  if (!wantFmt) return null;
  const candidateTypes = await listWalletCredentialTypes();
  for (const configurationId of candidateTypes) {
    if (usedConfigurationIds.has(configurationId)) continue;
    const stored = await getWalletCredentialByType(configurationId);
    if (!stored || (!stored.credential && !(stored.multi && stored.entries?.length)))
      continue;

    const candidates = [];
    if (stored.multi && Array.isArray(stored.entries)) {
      for (const ent of stored.entries) {
        const raw = extractCredentialString(ent.credential);
        if (raw)
          candidates.push({
            raw,
            pick: ent,
          });
      }
    } else {
      const raw = extractCredentialString(stored.credential);
      if (raw)
        candidates.push({
          raw,
          pick: { credential: stored.credential, keyBinding: stored.keyBinding },
        });
    }
    for (const { raw, pick } of candidates) {
      if (!storedRawMatchesDcqlEntry(entry, configurationId, raw, wantFmt)) continue;
      return { configurationId, stored, rawToken: raw, pickedEntry: pick };
    }
  }
  return null;
}

async function resolveKeysEnvelopeAndRawFromPick(stored, keyPath, pickedEntry) {
  const resolvedDevicePath = resolveDeviceKeyPath(keyPath);
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(resolvedDevicePath);
  let envelope = pickedEntry.credential;
  if (stored.multi && Array.isArray(stored.entries)) {
    const match = stored.entries.find((e) =>
      ecPublicJwksEqual(e?.keyBinding?.publicJwk, publicJwk),
    );
    envelope = (match || pickedEntry).credential;
  }
  const rawToken = extractCredentialString(envelope);
  return { privateJwk, publicJwk, credentialEnvelopeForVp: envelope, rawToken };
}

function docTypeForMdocPresentation(dcqlEntry, selectedType, presentationDefinition) {
  const metaDt = dcqlEntry?.meta?.doctype_value;
  if (typeof metaDt === "string" && metaDt.length > 0) {
    return metaDt.replace(/:mso_mdoc$/i, "");
  }
  if (presentationDefinition?.input_descriptors?.[0]?.id) {
    const descriptorId = presentationDefinition.input_descriptors[0].id;
    if (descriptorId.includes(".") || descriptorId.includes(":")) return descriptorId;
    if (descriptorId.includes("pid") || descriptorId.includes("PID"))
      return "eu.europa.ec.eudi.pid.1";
    if (descriptorId.includes("mdl") || descriptorId.includes("mDL"))
      return "org.iso.18013.5.1.mDL";
  }
  return selectedType || "org.iso.18013.5.1.mDL";
}

/**
 * Build one presentation string (SD-JWT+KB, mdoc DeviceResponse, or JWT VP) from wallet material.
 */
async function buildVpTokenFromPickedEntry({
  stored,
  pickedEntry,
  keyPath,
  clientId,
  responseUri,
  verifierBase,
  nonce,
  presentationDefinition,
  selectedType,
  dcqlEntry,
  slog,
  authorizationRequestPayload = null,
  mdocSessionNonce = null,
}) {
  const { privateJwk, publicJwk, rawToken: vpToken } =
    await resolveKeysEnvelopeAndRawFromPick(stored, keyPath, pickedEntry);
  if (!vpToken) {
    throw new Error("Unable to extract presentable credential token from wallet cache");
  }

  const isMdoc = isMdocCredential(vpToken);
  const isSdJwt = !isMdoc && typeof vpToken === "string" && vpToken.includes("~");

  let sdJwtForPresentation = vpToken;
  if (isSdJwt) {
    sdJwtForPresentation = filterSdJwtDisclosuresForDcqlClaims(vpToken, dcqlEntry);
  }

  const didJwk = generateDidJwkFromPrivateJwk(publicJwk);
  const kbAudience = clientId || responseUri || verifierBase;
  if (!kbAudience) {
    throw new Error(
      "Unable to determine audience for key-binding JWT (missing client_id/response_uri)",
    );
  }
  const txKb =
    isSdJwt && authorizationRequestPayload
      ? transactionDataBindingForSdJwtKb(authorizationRequestPayload)
      : null;
  const kbJwt = await createProofJwt({
    privateJwk,
    publicJwk,
    audience: kbAudience,
    nonce,
    issuer: didJwk,
    typ: isSdJwt ? "kb+jwt" : "openid4vp-proof+jwt",
    sdJwt: isSdJwt ? sdJwtForPresentation : undefined,
    transaction_data_hashes: txKb?.transaction_data_hashes,
    transaction_data_hashes_alg: txKb?.transaction_data_hashes_alg,
  });
  try {
    slog("[present] kbJwt created", { length: kbJwt.length });
  } catch {}

  let out = vpToken;
  let mdocGeneratedNonce = null;
  if (isMdoc) {
    const docType = docTypeForMdocPresentation(
      dcqlEntry,
      selectedType,
      presentationDefinition,
    );
    try {
      slog("[present] docType", { docType, selectedType });
    } catch {}
    const built = await buildMdocPresentation(vpToken, {
      docType,
      clientId,
      responseUri,
      verifierGeneratedNonce: nonce,
      devicePrivateJwk: stored?.keyBinding?.privateJwk || privateJwk,
      presentationDefinition,
      dcqlEntry,
      ...(mdocSessionNonce
        ? { mdocGeneratedNonceOverride: mdocSessionNonce }
        : {}),
    });
    out = built.vpToken;
    mdocGeneratedNonce = built.mdocGeneratedNonce;
  } else if (typeof vpToken === "string" && vpToken.includes("~")) {
    out = attachKbJwtToSdJwt(sdJwtForPresentation, kbJwt);
  } else {
    out = await buildJwtVpToken({
      credentialJwt: vpToken,
      privateJwk,
      publicJwk,
      issuer: didJwk,
      audience: kbAudience,
      nonce,
    });
  }
  return { vpToken: out, mdocGeneratedNonce };
}

export async function performPresentation(
  { deepLink, verifierBase, credentialType, keyPath },
  logSessionId,
) {
  const slog = logSessionId ? makeSessionLogger(logSessionId) : () => {};
  let requestJwt = null;
  let payload = null;
  let parsedVerifierInfo = null;
  let clientIdFromDeepLink = null;
  try {
    try {
      slog("[PRESENTATION] [START] Presentation flow", {
        deepLink,
        verifierBase,
        credentialType,
      });
    } catch {}
    const { requestUri, clientId, method } = parseOpenId4VpDeepLink(deepLink);
    clientIdFromDeepLink = clientId;
    try {
      slog("[PRESENTATION] Parsed deep link", { requestUri, clientId, method });
    } catch {}
    let walletMetadataForJar = null;
    let mdocSessionNonce = null;
    if (method && method.toLowerCase() === "post") {
      const resolvedForMeta = resolveDeviceKeyPath(keyPath);
      const { publicJwk } = await ensureOrCreateEcKeyPair(resolvedForMeta);
      mdocSessionNonce = crypto.randomBytes(16).toString("base64url");
      walletMetadataForJar = buildWalletMetadataForVpRequest({
        publicJwk,
        mdocGeneratedNonce: mdocSessionNonce,
      });
    }
    requestJwt = await fetchAuthorizationRequestJwt(requestUri, method, {
      walletMetadata: walletMetadataForJar,
    });
    const verified = await verifyAuthorizationRequestJwt(requestJwt, {
      expectedClientId: clientId,
    });
    payload = verified.payload;
    parsedVerifierInfo = parseVerifierInfo(payload);

    let responseMode = payload.response_mode || "direct_post";
    const responseUri = payload.response_uri; // our routes embed this
    // If the response_uri suggests direct_post.jwt, force that mode for compatibility
    if (responseUri && /direct_post\.jwt/i.test(responseUri)) {
      console.log(
        "[present] Forcing response_mode to direct_post.jwt based on response_uri",
      );
      responseMode = "direct_post.jwt";
    }
    const nonce = payload.nonce;
    const state = payload.state;
    const presentationDefinition = payload.presentation_definition;
    console.log("[present] Request payload summary →", {
      responseMode,
      hasResponseUri: !!responseUri,
      hasNonce: !!nonce,
      hasPD: !!presentationDefinition,
      state,
    });
    try {
      slog("[present] request payload", {
        responseMode,
        hasResponseUri: !!responseUri,
        hasNonce: !!nonce,
        hasPD: !!presentationDefinition,
        state,
      });
    } catch {}

    await storeWalletPresentationSession(logSessionId, payload, clientIdFromDeepLink);
    try {
      slog("[PRESENTATION] Persisted presentation session (RFC002)", {
        client_id: payload.client_id ?? clientIdFromDeepLink,
        response_uri: responseUri,
        response_mode: responseMode,
      });
    } catch {}

    // Validate transaction_data vs DCQL query, if present
    // Per OpenID4VP 5.1.2.8.2.2, credential_ids in transaction_data MUST match
    // the id fields from the DCQL credential query.
    const dcqlQuery = payload.dcql_query;
    const txData = payload.transaction_data;
    if (
      dcqlQuery &&
      Array.isArray(dcqlQuery.credentials) &&
      Array.isArray(txData) &&
      txData.length > 0
    ) {
      const dcqlIds = dcqlQuery.credentials
        .map((c) => c && c.id)
        .filter((id) => typeof id === "string" && id.length > 0);

      if (dcqlIds.length > 0) {
        for (const entry of txData) {
          if (typeof entry !== "string") continue;
          try {
            const decoded = JSON.parse(
              Buffer.from(entry, "base64url").toString("utf8"),
            );
            if (Array.isArray(decoded.credential_ids)) {
              if (decoded.credential_ids.length === 0) {
                throw new Error(
                  "credential_ids in transaction_data must be a non-empty array per OpenID4VP 5.1.2.8.2.2",
                );
              }
              const invalid = decoded.credential_ids.filter(
                (id) => !dcqlIds.includes(id),
              );
              if (invalid.length > 0) {
                throw new Error(
                  `Invalid credential_ids in transaction_data: ${invalid.join(
                    ", ",
                  )}. credential_ids must match id fields from dcql_query.credentials[].id. Expected one of: ${dcqlIds.join(
                    ", ",
                  )}, Found: ${decoded.credential_ids.join(", ")}`,
                );
              }
            }
          } catch (e) {
            // Use structured logging for transaction_data validation failures
            try {
              slog("[PRESENTATION] [ERROR] Invalid transaction_data entry", {
                error: e?.message || String(e),
                dcqlCredentialIds: dcqlIds,
                rawEntry: typeof entry === "string" ? entry : null,
              });
            } catch {}
            // Also emit to console for local debugging
            console.log(
              "[present] Warning: could not decode/validate transaction_data entry:",
              e?.message || String(e),
            );
            // Treat decoding/validation errors as fatal so the wallet
            // does not act on an invalid authorization request.
            throw e;
          }
        }
      }
    }

    const dcqlCredEntries = Array.isArray(dcqlQuery?.credentials)
      ? dcqlQuery.credentials
      : [];
    if (dcqlCredEntries.length > 0) {
      const missingId = dcqlCredEntries.some(
        (c) => !c || typeof c.id !== "string" || !c.id.length,
      );
      if (missingId) {
        throw new Error(
          "dcql_query.credentials[] requires each entry to have a non-empty id",
        );
      }
    }
    const hasDcql = dcqlCredEntries.length > 0;

    if (!responseUri) throw new Error("Missing response_uri in request");
    if (!nonce) throw new Error("Missing nonce in request");

    const cs03Request = extractCs03Request(payload);
    if (cs03Request) {
      if ((responseMode || "direct_post") !== "direct_post") {
        throw new Error("CS-03 wallet flow currently supports response_mode=direct_post only");
      }

      const signer = selectMatchingCs03Signer({
        credentialQueries: cs03Request.credentialQueries,
        signer: loadLocalCs03Signer(),
      });
      const credentialIds = cs03Request.credentialQueries
        .map((cred) => cred.id)
        .filter((id) => typeof id === "string" && id.length > 0);
      if (credentialIds.length === 0) {
        throw new Error("CS-03 request does not contain credential query ids");
      }

      const signatureRequests = Array.isArray(cs03Request.qesRequest.signatureRequests)
        ? cs03Request.qesRequest.signatureRequests
        : [];
      if (signatureRequests.length === 0) {
        throw new Error("CS-03 qesRequest.signatureRequests is required");
      }

      try {
        slog("[present] CS-03 request detected", {
          credentialIds,
          signatureRequestCount: signatureRequests.length,
          hasResponseURI: !!signatureRequests[0]?.responseURI,
        });
      } catch {}

      const documents = await fetchCs03Documents(signatureRequests);
      const qesResponse = buildCs03SignatureObject({ signer, documents });
      const responseURI = signatureRequests[0]?.responseURI;
      const vpTokenValue = responseURI
        ? buildOobCs03VpToken({ credentialIds })
        : buildInlineCs03VpToken({ credentialIds, qesResponse });

      if (responseURI) {
        await sendCs03OobResponse(responseURI, qesResponse, {
          clientId,
          clientMetadata: payload.client_metadata || payload.clientMetadata || null,
        });
        try {
          slog("[present] CS-03 OOB qesResponse sent", {
            responseURI,
            signatureCount: qesResponse.signatureObject?.length || 0,
          });
        } catch {}
      }

      const body = {
        vp_token: vpTokenValue,
        ...(state ? { state } : {}),
      };
      const formParams = new URLSearchParams();
      formParams.append("vp_token", JSON.stringify(vpTokenValue));
      if (state) {
        formParams.append("state", state);
      }
      const bodyContent = formParams.toString();
      const contentType = "application/x-www-form-urlencoded";

      const presRequestId = `pres_req_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
      const logBody = {
        ...body,
        vp_token: Object.fromEntries(
          Object.keys(vpTokenValue).map((key) => [key, vpTokenValue[key]]),
        ),
      };

      try {
        slog("[PRESENTATION] [REQUEST] Sending CS-03 response to verifier", {
          requestId: presRequestId,
          method: "POST",
          url: responseUri,
          contentType,
          headers: { "content-type": contentType },
          body: logBody,
        });
      } catch {}

      const res = await fetch(responseUri, {
        method: "POST",
        headers: { "content-type": contentType },
        body: bodyContent,
      });
      const resText = await res.text().catch(() => "");
      let responseBody = null;
      try {
        responseBody = resText ? JSON.parse(resText) : null;
      } catch {}

      try {
        slog("[PRESENTATION] [RESPONSE] Verifier response", {
          requestId: presRequestId,
          url: responseUri,
          status: res.status,
          statusText: res.statusText,
          headers: Object.fromEntries(res.headers.entries()),
          body: responseBody || resText,
        });
      } catch {}

      if (!res.ok) {
        throw new Error(
          `Verifier direct_post error ${res.status}${resText ? `: ${resText}` : ""}`,
        );
      }

      return attachVerifierInfoToResult(
        {
          status: "ok",
          mode: responseURI ? "cs03_oob" : "cs03_inline",
          credentialIds,
          verifierStatus: res.status,
          response: responseBody || resText,
        },
        parsedVerifierInfo,
      );
    }

    let vpTokenValue;
    let presentation_submission;
    let didJwk;
    const mdocGeneratedNonces = [];

    if (hasDcql) {
      const usedConfigurationIds = new Set();
      const vpTokenObject = {};
      const perEntryFormats = [];
      for (const credQuery of dcqlCredEntries) {
        const found = await findWalletStoredForDcqlEntry(
          credQuery,
          usedConfigurationIds,
        );
        if (!found) {
          throw new Error(
            `DCQL credential query "${credQuery.id}" could not be satisfied: no wallet credential matches format ${credQuery.format}`,
          );
        }
        usedConfigurationIds.add(found.configurationId);
        const { vpToken: vpStr, mdocGeneratedNonce: entryMdocNonce } =
          await buildVpTokenFromPickedEntry({
            stored: found.stored,
            pickedEntry: found.pickedEntry,
            keyPath,
            clientId,
            responseUri,
            verifierBase,
            nonce,
            presentationDefinition,
            selectedType: found.configurationId,
            dcqlEntry: credQuery,
            slog,
            authorizationRequestPayload: payload,
            mdocSessionNonce,
          });
        if (entryMdocNonce) mdocGeneratedNonces.push(entryMdocNonce);
        perEntryFormats.push(presentationFormatFromDcqlQuery(credQuery));
        vpTokenObject[credQuery.id] = [vpStr];
      }
      vpTokenValue = vpTokenObject;
      console.log("[present] Built vp_token as DCQL object (per-query VPs)", {
        credentialIds: Object.keys(vpTokenObject),
      });
      try {
        slog("[present] vp_token DCQL format", {
          credentialIds: Object.keys(vpTokenObject),
        });
      } catch {}

      const resolvedDevicePath = resolveDeviceKeyPath(keyPath);
      const { publicJwk } = await ensureOrCreateEcKeyPair(resolvedDevicePath);
      didJwk = generateDidJwkFromPrivateJwk(publicJwk);

      presentation_submission = buildPresentationSubmissionDcql(
        presentationDefinition,
        dcqlQuery,
        perEntryFormats,
      );
      if (presentation_submission) {
        console.log(
          "[present] Built presentation_submission len:",
          presentation_submission.length,
        );
        try {
          slog("[present] submission built", {
            length: presentation_submission.length,
          });
        } catch {}
      }
    } else {
      let selectedType = credentialType;
      if (!selectedType) {
        const candidateTypes = await listWalletCredentialTypes();
        try {
          slog("[present] wallet types", { count: candidateTypes.length });
        } catch {}
        console.log(
          "[present] Available wallet credential types:",
          candidateTypes,
        );
        if (candidateTypes.length === 0)
          throw new Error("No credentials available in wallet cache");
        const defText = JSON.stringify(presentationDefinition || {});
        selectedType =
          candidateTypes.find((t) => defText.includes(t)) || candidateTypes[0];
      }
      try {
        slog("[present] selected type", { selectedType });
      } catch {}
      console.log("[present] Selected credential type:", selectedType);

      const stored = await getWalletCredentialByType(selectedType);
      console.log(
        "[present] Stored credential found:",
        !!stored,
        "has.credential=",
        !!stored?.credential,
      );
      try {
        slog("[present] stored credential", {
          found: !!stored,
          hasCredential: !!stored?.credential,
        });
      } catch {}
      if (!stored || (!stored.credential && !(stored.multi && Array.isArray(stored.entries))))
        throw new Error("Credential not found in wallet cache");

      const resolvedDevicePath = resolveDeviceKeyPath(keyPath);
      const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(resolvedDevicePath);

      let credentialEnvelopeForVp = stored.credential;
      if (stored.multi && Array.isArray(stored.entries) && stored.entries.length > 0) {
        const match = stored.entries.find((e) => ecPublicJwksEqual(e?.keyBinding?.publicJwk, publicJwk));
        const pick = match || stored.entries[0];
        credentialEnvelopeForVp = pick.credential;
      }

    // Extract the credential token from the wallet cache
    let vpToken = extractCredentialString(credentialEnvelopeForVp);
    console.log(
      "[present] Extracted credential string present=",
      typeof vpToken === "string",
      vpToken ? (vpToken.includes("~") ? "sd-jwt" : "jwt/other") : "none",
    );
    try {
      slog("[present] token extracted", { present: !!vpToken });
    } catch {}
    if (!vpToken)
      throw new Error(
        "Unable to extract presentable credential token from wallet cache",
      );

    // Check if this is an mdoc credential or SD-JWT
    const isMdoc = isMdocCredential(vpToken);
    const isSdJwt =
      !isMdoc && typeof vpToken === "string" && vpToken.includes("~");
    console.log(
      "[present] Credential type detected:",
      isMdoc ? "mdoc" : isSdJwt ? "sd-jwt" : "jwt",
    );
    try {
      slog("[present] credential type", { isMdoc, isSdJwt });
    } catch {}

    // Build key-binding JWT. For SD-JWT, include sd_hash per SD-JWT spec and use typ "kb+jwt".
    didJwk = generateDidJwkFromPrivateJwk(publicJwk);
    const kbAudience = clientId || responseUri || verifierBase;
    if (!kbAudience) {
      throw new Error(
        "Unable to determine audience for key-binding JWT (missing client_id/response_uri)",
      );
    }
    const txKbMain = isSdJwt ? transactionDataBindingForSdJwtKb(payload) : null;
    const kbJwt = await createProofJwt({
      privateJwk,
      publicJwk,
      audience: kbAudience,
      nonce,
      issuer: didJwk,
      typ: isSdJwt ? "kb+jwt" : "openid4vp-proof+jwt",
      sdJwt: isSdJwt ? vpToken : undefined,
      transaction_data_hashes: txKbMain?.transaction_data_hashes,
      transaction_data_hashes_alg: txKbMain?.transaction_data_hashes_alg,
    });
    console.log("[present] Built kbJwt len:", kbJwt.length);
    try {
      slog("[present] kbJwt created", { length: kbJwt.length });
    } catch {}

    // Debug: decode kbJwt to verify nonce (and optionally sd_hash presence)
    try {
      const kbPayload = decodeJwt(kbJwt).payload;
      console.log(
        "[present] kbJwt payload nonce:",
        kbPayload.nonce,
        "expected:",
        nonce,
        "has sd_hash:",
        !!kbPayload.sd_hash,
        "has transaction_data_hashes:",
        Array.isArray(kbPayload.transaction_data_hashes),
      );
      try {
        slog("[present] kbJwt payload", {
          hasNonce: !!kbPayload?.nonce,
          hasSdHash: !!kbPayload?.sd_hash,
          hasTransactionDataHashes: Array.isArray(kbPayload?.transaction_data_hashes),
        });
      } catch {}
    } catch (e) {
      console.log("[present] Could not decode kbJwt for debugging:", e.message);
      try {
        slog("[present] kbJwt decode failed", {
          error: e?.message || String(e),
        });
      } catch {}
    }

    if (isMdoc) {
      // RFC002 transaction_data binding for mdoc is via SessionTranscript (wallet-client P2-W-3), not KB-JWT claims.
      // For mdoc, construct proper DeviceResponse structure
      console.log("[present] Processing mdoc credential for presentation");
      try {
        slog("[present] processing mdoc");
      } catch {}

      // Determine docType from credential type, presentation definition, or descriptor ID
      let docType = selectedType || "org.iso.18013.5.1.mDL"; // Use selected credential type as default
      if (presentationDefinition?.input_descriptors?.[0]?.id) {
        const descriptorId = presentationDefinition.input_descriptors[0].id;

        // If descriptor ID looks like a docType (has dots/colons), use it directly
        if (descriptorId.includes(".") || descriptorId.includes(":")) {
          docType = descriptorId;
        }
        // Otherwise, try to infer from known patterns
        else if (descriptorId.includes("pid") || descriptorId.includes("PID")) {
          docType = "eu.europa.ec.eudi.pid.1";
        } else if (
          descriptorId.includes("mdl") ||
          descriptorId.includes("mDL")
        ) {
          docType = "org.iso.18013.5.1.mDL";
        }
      }

      console.log(
        "[present] Using docType:",
        docType,
        "from selectedType:",
        selectedType,
      );
      try {
        slog("[present] docType", { docType, selectedType });
      } catch {}

      // Build proper DeviceResponse for presentation
      const mdocBuilt = await buildMdocPresentation(vpToken, {
        docType,
        clientId,
        responseUri,
        verifierGeneratedNonce: nonce,
        devicePrivateJwk: stored?.keyBinding?.privateJwk || privateJwk,
        presentationDefinition,
        ...(mdocSessionNonce
          ? { mdocGeneratedNonceOverride: mdocSessionNonce }
          : {}),
      });
      vpToken = mdocBuilt.vpToken;
      if (mdocBuilt.mdocGeneratedNonce) {
        mdocGeneratedNonces.push(mdocBuilt.mdocGeneratedNonce);
      }
      console.log("[present] Built DeviceResponse, length:", vpToken.length);
      try {
        slog("[present] DeviceResponse built", { length: vpToken.length });
      } catch {}
    } else if (typeof vpToken === "string" && vpToken.includes("~")) {
      // For SD-JWT, ensure the key-binding JWT is appended if missing
      const before = vpToken;
      vpToken = attachKbJwtToSdJwt(vpToken, kbJwt);
      if (before !== vpToken) {
        console.log("[present] Appended kbJwt to SD-JWT");
        try {
          slog("[present] kbJwt appended");
        } catch {}
      } else {
        console.log("[present] SD-JWT already had kbJwt attached");
        try {
          slog("[present] kbJwt already attached");
        } catch {}
      }
    } else {
      // For plain JWT credentials, present a signed JWT VP so the verifier
      // receives the request nonce inside the submitted vp_token.
      vpToken = await buildJwtVpToken({
        credentialJwt: vpToken,
        privateJwk,
        publicJwk,
        issuer: didJwk,
        audience: kbAudience,
        nonce,
      });
      console.log("[present] Wrapped JWT VC in JWT VP");
      try {
        slog("[present] jwt-vc wrapped as jwt_vp");
      } catch {}
    }

    // Descriptor format for presentation_submission: use DCQL when available
    const credentialFormat = isMdoc
      ? "mso_mdoc"
      : vpToken.includes("~")
        ? "dc+sd-jwt"
        : "jwt_vp";
    console.log(
      "[present] Credential format for submission:",
      credentialFormat,
    );
    try {
      slog("[present] credential format", { format: credentialFormat });
    } catch {}

    presentation_submission = buildPresentationSubmission(
      presentationDefinition,
      credentialFormat,
    );
    if (presentation_submission) {
      console.log(
        "[present] Built presentation_submission len:",
        presentation_submission.length,
      );
      try {
        slog("[present] submission built", {
          length: presentation_submission.length,
        });
      } catch {}
    }

    vpTokenValue = vpToken;
    console.log("[present] No DCQL query, using string format for vp_token");
    try {
      slog("[present] vp_token string format");
    } catch {}

    }

    const walletMetadataStr =
      mdocGeneratedNonces.length > 0
        ? JSON.stringify({
            mdoc_generated_nonce:
              mdocGeneratedNonces.length === 1
                ? mdocGeneratedNonces[0]
                : mdocGeneratedNonces,
          })
        : null;
    const mdocNonceForJwt =
      mdocGeneratedNonces.length === 0
        ? {}
        : {
            mdoc_generated_nonce:
              mdocGeneratedNonces.length === 1
                ? mdocGeneratedNonces[0]
                : mdocGeneratedNonces,
          };

    // Send the credential token (SD-JWT, mdoc DeviceResponse, or JWT VC)
    // Per OpenID4VP spec:
    // - direct_post: application/x-www-form-urlencoded with vp_token (+ optional presentation_submission)
    // - direct_post.jwt: application/x-www-form-urlencoded with 'response' containing a JWE/JWT
    let body;
    let bodyContent;
    let contentType;

    if (presentation_submission) {
      // Use presentation_submission format
      body = {
        vp_token: vpTokenValue,
        presentation_submission, // Send as JSON string (as expected by verifier)
        ...(state ? { state } : {}),
        ...(walletMetadataStr ? { wallet_metadata: walletMetadataStr } : {}),
      };
      console.log("[present] Using presentation_submission format");
      try {
        slog("[present] using submission format");
      } catch {}
    } else {
      // Direct format
      body = {
        vp_token: vpTokenValue,
        ...(state ? { state } : {}),
        ...(walletMetadataStr ? { wallet_metadata: walletMetadataStr } : {}),
      };
      console.log("[present] Using direct format");
      try {
        slog("[present] using direct format");
      } catch {}
    }

    if ((responseMode || "direct_post") === "direct_post.jwt") {
      // Build a compact JWT payload and encrypt to JWE if verifier provides JWKS
      // Wallet signs nothing here to avoid verifier signature mismatch; use JWE per spec branch in verifier
      let responseJwtOrJwe = null;
      try {
        const clientMetadata =
          payload.client_metadata || payload.clientMetadata || {};
        const jwks =
          clientMetadata.jwks ||
          (clientMetadata.jwks_uri
            ? await (await fetch(clientMetadata.jwks_uri)).json()
            : null);
        const encKey = jwks?.keys?.find(
          (k) =>
            (k.use === "enc" || !k.use) &&
            (k.kty === "EC" || k.kty === "OKP" || k.kty === "RSA"),
        );

        // Build signed JWT payload per OpenID4VP direct_post.jwt
        const now = Math.floor(Date.now() / 1000);
        let presentationSubmissionObj = undefined;
        if (presentation_submission) {
          try {
            presentationSubmissionObj = JSON.parse(presentation_submission);
          } catch {}
        }
        const jwtPayload = {
          vp_token: vpTokenValue, // Use the DCQL-formatted vp_token value (object or string)
          ...(presentationSubmissionObj
            ? { presentation_submission: presentationSubmissionObj }
            : {}),
          ...(state ? { state } : {}),
          ...(nonce ? { nonce } : {}),
          ...mdocNonceForJwt,
          iat: now,
          exp: now + 300,
          iss: didJwk,
          // OID4VP direct_post.jwt aligns with JARM: aud SHOULD be the verifier's client_id
          aud: clientId || responseUri,
        };

        // Sign with wallet key (ES256)
        const { importJWK, SignJWT, CompactEncrypt, EncryptJWT } =
          await import("jose");

        if (encKey) {
          // Encrypt to JWE so verifier follows its JWE branch

          // Prioritize encryption settings from client_metadata
          let alg =
            clientMetadata.authorization_encrypted_response_alg ||
            encKey.alg ||
            "ECDH-ES+A256KW";
          if (alg === "ECDH-ES") alg = "ECDH-ES+A256KW"; // Ensure key wrapping alg is included

          let enc = "A256GCM"; // Default enc
          if (clientMetadata.authorization_encrypted_response_enc) {
            enc = clientMetadata.authorization_encrypted_response_enc;
          } else if (
            Array.isArray(
              clientMetadata.encrypted_response_enc_values_supported,
            )
          ) {
            const supportedEnc =
              clientMetadata.encrypted_response_enc_values_supported;
            const preferredEnc = supportedEnc.find((e) =>
              [
                "A256GCM",
                "A192GCM",
                "A128GCM",
                "A256CBC-HS512",
                "A192CBC-HS384",
                "A128CBC-HS256",
              ].includes(e),
            );
            if (preferredEnc) enc = preferredEnc;
          }

          const publicKey = await importJWK(
            encKey,
            alg.startsWith("ECDH-ES") ? "ECDH-ES" : undefined,
          );
          const jweProtectedHeader = { alg, enc, kid: encKey.kid };
          console.log("[present] JWE protected header:", jweProtectedHeader);

          // OID4VP-15: "The Authorization Response is returned as a JSON object, which MUST be encrypted as the payload of a JWE"
          // Encrypt the JSON payload directly, not a nested signed JWT.
          responseJwtOrJwe = await new EncryptJWT(jwtPayload)
            .setProtectedHeader(jweProtectedHeader)
            .encrypt(publicKey);

          console.log("[present] Created JWE:", responseJwtOrJwe);
        } else {
          // Fallback: send signed JWT directly if no enc key is provided
          const signingKey = await importJWK(privateJwk, "ES256");
          responseJwtOrJwe = await new SignJWT(jwtPayload)
            .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: didJwk })
            .setIssuer(jwtPayload.iss)
            .setAudience(jwtPayload.aud)
            .setIssuedAt(jwtPayload.iat)
            .setExpirationTime(jwtPayload.exp)
            .sign(signingKey);
        }

        const formParams = new URLSearchParams();
        formParams.append("response", responseJwtOrJwe);
        if (state) formParams.append("state", state);
        if (walletMetadataStr) {
          formParams.append("wallet_metadata", walletMetadataStr);
        }
        bodyContent = formParams.toString();
        contentType = "application/x-www-form-urlencoded";
      } catch (e) {
        console.log(
          "[present] Failed to build direct_post.jwt response, falling back to direct_post:",
          e.message,
        );
      }
    }

    if (!bodyContent) {
      // Default: direct_post
      const formParams = new URLSearchParams();
      // When vp_token is an object (DCQL format), serialize it as JSON string
      if (typeof vpTokenValue === "object" && vpTokenValue !== null) {
        formParams.append("vp_token", JSON.stringify(vpTokenValue));
      } else {
        formParams.append("vp_token", vpTokenValue);
      }
      if (presentation_submission) {
        formParams.append("presentation_submission", presentation_submission);
      }
      if (state) {
        formParams.append("state", state);
      }
      if (walletMetadataStr) {
        formParams.append("wallet_metadata", walletMetadataStr);
      }
      bodyContent = formParams.toString();
      contentType = "application/x-www-form-urlencoded";
    }

    const presRequestId = `pres_req_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
    console.log(
      "[present] Posting to response_uri:",
      responseUri,
      "body.keys=",
      Object.keys(body),
    );

    // Log the request body being sent (with redaction for sensitive tokens)
    const logBody = { ...body };
    if (logBody.vp_token) {
      if (typeof logBody.vp_token === "string") {
        logBody.vp_token =
          logBody.vp_token.substring(0, 200) + "...<truncated for size>";
      } else if (
        typeof logBody.vp_token === "object" &&
        logBody.vp_token !== null
      ) {
        // For DCQL object format, show structure but truncate values
        const truncated = {};
        for (const [key, value] of Object.entries(logBody.vp_token)) {
          if (typeof value === "string") {
            truncated[key] = value.substring(0, 50) + "...<truncated>";
          } else if (Array.isArray(value)) {
            truncated[key] = value.map((v) =>
              typeof v === "string" ? v.substring(0, 50) + "...<truncated>" : v,
            );
          } else {
            truncated[key] = value;
          }
        }
        logBody.vp_token = truncated;
      }
    }
    if (logBody.response && typeof logBody.response === "string") {
      logBody.response =
        logBody.response.substring(0, 200) + "...<truncated for size>";
    }

    try {
      slog("[PRESENTATION] [REQUEST] Sending to verifier", {
        requestId: presRequestId,
        method: "POST",
        url: responseUri,
        contentType,
        headers: { "content-type": contentType },
        body: logBody,
      });
    } catch {}

    const res = await fetch(responseUri, {
      method: "POST",
      headers: { "content-type": contentType },
      body: bodyContent,
    });
    const resText = await res.text().catch(() => "");
    let responseBody = null;
    try {
      responseBody = resText ? JSON.parse(resText) : null;
    } catch {}

    console.log(
      "[present] Verifier response status:",
      res.status,
      "body.len=",
      resText?.length,
    );
    try {
      slog("[PRESENTATION] [RESPONSE] Verifier response", {
        requestId: presRequestId,
        url: responseUri,
        status: res.status,
        statusText: res.statusText,
        headers: Object.fromEntries(res.headers.entries()),
        body: responseBody || resText,
      });
    } catch {}
    console.log(
      "[present] Sent vp_token:",
      typeof vpTokenValue === "object"
        ? JSON.stringify(vpTokenValue, null, 2)
        : vpTokenValue.substring(0, 100) + "...",
    );
    console.log(
      "[present] Sent presentation_submission:",
      presentation_submission,
    );
    console.log(
      "[present] presentation_submission type:",
      typeof presentation_submission,
    );
    console.log("[present] Full request body:", JSON.stringify(body, null, 2));
    if (!res.ok) {
      // Compatibility fallback for some verifiers expecting JWE payload object instead of JWT inside direct_post.jwt

      if ((responseMode || "direct_post") === "direct_post.jwt") {
        try {
          console.log(
            "[present] direct_post.jwt failed (" +
              res.status +
              ") – retrying with payload-object JWE fallback",
          );
          const clientMetadata =
            payload.client_metadata || payload.clientMetadata || {};
          const jwks =
            clientMetadata.jwks ||
            (clientMetadata.jwks_uri
              ? await (await fetch(clientMetadata.jwks_uri)).json()
              : null);
          const encKey = jwks?.keys?.find(
            (k) =>
              (k.use === "enc" || !k.use) &&
              (k.kty === "EC" || k.kty === "OKP" || k.kty === "RSA"),
          );
          if (encKey) {
            const { importJWK, EncryptJWT } = await import("jose");
            const alg = encKey.alg || "ECDH-ES+A256KW";
            const supportedEnc = Array.isArray(
              clientMetadata.encrypted_response_enc_values_supported,
            )
              ? clientMetadata.encrypted_response_enc_values_supported
              : [];
            const preferredEnc = supportedEnc.find((e) =>
              [
                "A256GCM",
                "A192GCM",
                "A128GCM",
                "A256CBC-HS512",
                "A192CBC-HS384",
                "A128CBC-HS256",
              ].includes(e),
            );
            const enc = preferredEnc || "A256GCM";
            const publicKey = await importJWK(
              encKey,
              alg.startsWith("ECDH-ES") ? "ECDH-ES" : undefined,
            );
            const fallbackPayload = {
              vp_token: vpTokenValue,
              ...(presentation_submission
                ? {
                    presentation_submission: JSON.parse(
                      presentation_submission,
                    ),
                  }
                : {}),
              ...(state ? { state } : {}),
            };
            // Build a JWE with JSON payload (so jwtDecrypt returns { payload })
            const jwe = await new EncryptJWT(fallbackPayload)
              .setProtectedHeader({ alg, enc, kid: encKey.kid })
              .encrypt(publicKey);
            const formParams2 = new URLSearchParams();
            formParams2.append("response", jwe);
            try {
              slog("[present] sending fallback to verifier", {
                responseUri,
                hasResponse: true,
                responseLength: jwe?.length,
              });
            } catch {}
            const res2 = await fetch(responseUri, {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: formParams2.toString(),
            });
            const res2Text = await res2.text().catch(() => "");
            console.log(
              "[present] Fallback verifier response status:",
              res2.status,
              "body.len=",
              res2Text?.length,
            );
            if (!res2.ok) {
              let parsed2 = null;
              try {
                parsed2 = JSON.parse(res2Text);
              } catch {}
              throw new Error(
                `Verifier response error ${res2.status}${parsed2 ? ": " + JSON.stringify(parsed2) : res2Text ? ": " + res2Text : ""}`,
              );
            }
            try {
              return attachVerifierInfoToResult(
                JSON.parse(res2Text),
                parsedVerifierInfo,
              );
            } catch {
              return attachVerifierInfoToResult(
                { status: "ok" },
                parsedVerifierInfo,
              );
            }
          }
        } catch (e) {
          console.log(
            "[present] Fallback attempt failed:",
            e?.message || String(e),
          );
        }
      }

      let parsed = null;
      try {
        parsed = JSON.parse(resText);
      } catch {}
      try {
        slog("[PRESENTATION] [ERROR] Verifier response error", {
          status: res.status,
          error: parsed || resText,
        });
      } catch {}
      throw new Error(
        `Verifier response error ${res.status}${parsed ? ": " + JSON.stringify(parsed) : resText ? ": " + resText : ""}`,
      );
    }
    const result = (() => {
      try {
        return JSON.parse(resText);
      } catch {
        return { status: "ok" };
      }
    })();
    try {
      slog("[PRESENTATION] [COMPLETE] Presentation flow", {
        success: true,
        verifierResponse: result,
      });
    } catch {}
    return attachVerifierInfoToResult(result, parsedVerifierInfo);
  } catch (e) {
    if (isVerifierHttpRejectionError(e)) {
      try {
        slog("[PRESENTATION] [ERROR] Verifier rejected VP response", {
          error: e?.message,
        });
      } catch {}
      throw e;
    }
    if (!payload && requestJwt) {
      try {
        payload = decodeRequestJwtPayloadQuiet(requestJwt);
      } catch {
        /* ignore */
      }
    }
    if (payload && logSessionId) {
      await storeWalletPresentationSession(
        logSessionId,
        payload,
        clientIdFromDeepLink,
      );
    }
    let vi = parsedVerifierInfo;
    if (!vi && payload) {
      try {
        vi = parseVerifierInfo(payload);
      } catch {
        vi = null;
      }
    }
    try {
      slog("[PRESENTATION] [ERROR] Local presentation failure", {
        error: e?.message || String(e),
      });
    } catch {}
    return await finalizeWalletPresentationFailure(
      e,
      payload,
      vi,
      slog,
      logSessionId,
    );
  }
}

export async function resolveDeepLinkFromEndpoint(verifierBase, path) {
  const url = new URL(
    (verifierBase || "http://localhost:3000").replace(/\/$/, "") + path,
  );
  console.log("[present] Resolving deepLink from:", url.toString());
  const res = await fetch(url.toString());
  if (!res.ok) throw new Error(`Fetch VP request error ${res.status}`);
  const body = await res.json();
  // Expect { deepLink } shape
  if (body.deepLink) return body.deepLink;
  // Some endpoints return { request: jwt } or raw JWT; build openid4vp link ourselves if needed
  if (body.request) {
    // No request_uri; not supported here
    throw new Error(
      "Received inline request JWT; provide an openid4vp://, mdoc-openid4vp://, or eu-eaap:// deep link instead",
    );
  }
  throw new Error("Unexpected response from verifier when fetching VP request");
}
