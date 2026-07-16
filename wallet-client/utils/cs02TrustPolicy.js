/**
 * WE BUILD CS-02 shared trust and metadata policy for wallet and verifier.
 *
 * Trust-anchor, verifier-attestation issuer, and trust-registry enforcement remain
 * placeholders until configured. DID key rules and metadata schema checks are enforced now.
 */

export const CS02_ENFORCED_JAR_ALG = "ES256";
export const CS02_ENFORCED_KB_JWT_ALGS = new Set(["ES256"]);
export const CS02_ENFORCED_SD_JWT_ALGS = new Set(["ES256", "ES384"]);
export const CS02_ENFORCED_VP_FORMATS = new Set(["dc+sd-jwt", "vc+sd-jwt", "mso_mdoc"]);
export const CS02_ENFORCED_RESPONSE_MODES = new Set([
  "direct_post",
  "direct_post.jwt",
  "dc_api",
  "dc_api.jwt",
]);
export const CS02_ENFORCED_JWE_ALGS = new Set([
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW",
]);
export const CS02_ENFORCED_JWE_ENCS = new Set([
  "A128GCM",
  "A192GCM",
  "A256GCM",
  "A128CBC-HS256",
  "A192CBC-HS384",
  "A256CBC-HS512",
]);

export class Cs02TrustPolicyError extends Error {
  constructor(message, errorCode = "invalid_request") {
    super(message);
    this.name = "Cs02TrustPolicyError";
    this.errorCode = errorCode;
  }
}

let trustPlaceholderRecorder = null;

export function setCs02TrustPlaceholderRecorder(recorder) {
  trustPlaceholderRecorder = typeof recorder === "function" ? recorder : null;
}

function recordTrustPlaceholder(kind, details) {
  try {
    trustPlaceholderRecorder?.({
      kind,
      enforced: false,
      placeholder: true,
      ...details,
    });
  } catch {}
}

function truthyEnv(value) {
  if (value == null || value === "") return false;
  const normalized = String(value).trim().toLowerCase();
  return normalized === "true" || normalized === "1" || normalized === "yes";
}

export function resolveCs02TrustPolicyOptions(env = process.env) {
  return {
    strictStatus: truthyEnv(env.CS02_STRICT_STATUS_VALIDATION),
    hasConfiguredTrustAnchors: false,
    hasTrustedVerifierAttestationIssuers: false,
    hasTrustRegistry: false,
  };
}

export function getCs02EnforcedMetadataProfile() {
  return {
    jar_alg: CS02_ENFORCED_JAR_ALG,
    vp_formats_supported: Array.from(CS02_ENFORCED_VP_FORMATS),
    response_modes_supported: Array.from(CS02_ENFORCED_RESPONSE_MODES),
    encrypted_response_alg_values_supported: Array.from(CS02_ENFORCED_JWE_ALGS),
    encrypted_response_enc_values_supported: Array.from(CS02_ENFORCED_JWE_ENCS),
    compatibilityNote:
      "Legacy formats/algorithms remain available when CS02_COMPATIBILITY=true or VERIFIER_CS02_COMPATIBILITY=true.",
  };
}

export function buildStrictCs02ClientMetadata(clientMetadata = {}, responseMode = "direct_post") {
  const metadata = filterClientMetadataForCs02Enforcement(clientMetadata, responseMode, { strict: true });
  if (metadata?.vp_formats_supported && typeof metadata.vp_formats_supported === "object") {
    metadata.vp_formats_supported = Object.fromEntries(
      Object.entries(metadata.vp_formats_supported)
        .filter(([format]) => CS02_ENFORCED_VP_FORMATS.has(format))
        .map(([format, config]) => {
          if ((format === "dc+sd-jwt" || format === "vc+sd-jwt") && isPlainObject(config)) {
            return [
              format,
              {
                ...config,
                "sd-jwt_alg_values": Array.isArray(config["sd-jwt_alg_values"])
                  ? config["sd-jwt_alg_values"].filter((alg) => CS02_ENFORCED_SD_JWT_ALGS.has(alg))
                  : Array.from(CS02_ENFORCED_SD_JWT_ALGS),
                "kb-jwt_alg_values": Array.isArray(config["kb-jwt_alg_values"])
                  ? config["kb-jwt_alg_values"].filter((alg) => CS02_ENFORCED_KB_JWT_ALGS.has(alg))
                  : Array.from(CS02_ENFORCED_KB_JWT_ALGS),
              },
            ];
          }
          return [format, config];
        }),
    );
  }

  return metadata;
}

export function assertEs256P256Jwk(jwk, context = "JWK") {
  if (!jwk || typeof jwk !== "object") {
    throw new Cs02TrustPolicyError(`${context} must be an object`, "invalid_client");
  }
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new Cs02TrustPolicyError(`${context} must use EC/P-256`, "invalid_client");
  }
  if (jwk.alg && jwk.alg !== CS02_ENFORCED_JAR_ALG) {
    throw new Cs02TrustPolicyError(`${context} must use alg ES256 when specified`, "invalid_client");
  }
}

export function validateDidJwkTrustRules(jwk, context = "did:jwk") {
  assertEs256P256Jwk(jwk, context);
  return { ok: true };
}

function canonicalDidWebVerificationMethodId(kid, did) {
  if (!kid || typeof kid !== "string") return null;
  if (kid.startsWith("did:")) {
    const kidDid = kid.split("#")[0];
    if (kidDid !== did) {
      throw new Cs02TrustPolicyError("did:web JAR kid must belong to the client_id DID", "invalid_client");
    }
    return kid;
  }
  const fragment = kid.startsWith("#") ? kid.slice(1) : kid;
  if (!fragment) return null;
  return `${did}#${fragment}`;
}

export function validateDidWebKidResolution(
  didDocument,
  kid,
  did,
  { resolutionUrl, resolvedOverHttps } = {},
) {
  if (resolutionUrl != null) {
    let parsed;
    try {
      parsed = new URL(resolutionUrl);
    } catch {
      throw new Cs02TrustPolicyError("did:web resolution URL must be absolute", "invalid_client");
    }
    if (parsed.protocol !== "https:") {
      throw new Cs02TrustPolicyError("did:web document must be resolved over HTTPS", "invalid_client");
    }
  } else if (resolvedOverHttps !== true) {
    throw new Cs02TrustPolicyError("did:web resolution must occur over HTTPS", "invalid_client");
  }

  if (didDocument?.id != null && didDocument.id !== did) {
    throw new Cs02TrustPolicyError("did:web document id must match client_id DID", "invalid_client");
  }

  const vms = Array.isArray(didDocument?.verificationMethod)
    ? didDocument.verificationMethod
    : [];
  if (vms.length === 0) {
    throw new Cs02TrustPolicyError("did:web document has no verification methods", "invalid_client");
  }
  if (!kid) {
    throw new Cs02TrustPolicyError("did:web JAR must include kid", "invalid_client");
  }

  const canonicalKid = canonicalDidWebVerificationMethodId(kid, did);
  const match = vms.find((vm) => {
    if (!vm?.id) return false;
    if (vm.id === kid) return true;
    if (canonicalKid && vm.id === canonicalKid) return true;
    return false;
  });
  if (!match?.publicKeyJwk) {
    throw new Cs02TrustPolicyError("did:web kid does not resolve to a verification method", "invalid_client");
  }
  assertEs256P256Jwk(match.publicKeyJwk, "did:web verification method");
  return { ok: true, verificationMethod: match };
}

export async function validateX509SanDnsTrustAnchor(_clientId, _header, _leafCertPem) {
  // TODO(CS-02 x509 trust framework): load CS02_X509_TRUST_ANCHORS_PATH.
  // TODO(CS-02 x509 trust framework): parse full x5c chain and validate against trust anchors.
  // TODO(CS-02 x509 trust framework): verify certificate validity period and P-256/ES256 leaf key.
  // TODO(CS-02 x509 trust framework): require SAN DNS match to x509_san_dns client_id host.
  // TODO(CS-02 x509 trust framework): reject wildcard or missing SAN DNS unless policy allows it.
  const result = {
    trusted: true,
    placeholder: true,
    enforced: false,
    trustConfigured: false,
    futureBehavior:
      "Validate x5c chain, certificate validity, ES256/P-256 leaf key, and SAN DNS against configured trust anchors.",
    clientId: _clientId ?? null,
    hasX5c: Array.isArray(_header?.x5c) && _header.x5c.length > 0,
  };
  recordTrustPlaceholder("x509_san_dns", result);
  return result;
}

export async function validateVerifierAttestationTrust(_header, _clientId) {
  // TODO(CS-02 verifier-attestation trust framework): load CS02_VERIFIER_ATTESTATION_ISSUERS_PATH.
  // TODO(CS-02 verifier-attestation trust framework): verify VA-JWT signature and trusted issuer.
  // TODO(CS-02 verifier-attestation trust framework): enforce sub, exp, iat, and JAR signing-key binding.
  // TODO(CS-02 verifier-attestation trust framework): reject development/self-signed attestation when trust is configured.
  let parsedHeader = null;
  let parsedPayload = null;
  let structureValid = false;
  const parts = typeof _header?.jwt === "string" ? _header.jwt.split(".") : [];
  if (parts.length === 3 && parts.every((part) => part.length > 0)) {
    try {
      parsedHeader = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
      parsedPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      structureValid = isPlainObject(parsedHeader) && isPlainObject(parsedPayload) &&
        typeof parsedPayload.iss === "string" && typeof parsedPayload.sub === "string" &&
        Number.isFinite(Number(parsedPayload.iat)) && Number.isFinite(Number(parsedPayload.exp));
    } catch {}
  }
  const result = {
    trusted: true,
    placeholder: true,
    enforced: false,
    trustConfigured: false,
    nonProduction: true,
    futureBehavior:
      "Verify verifier-attestation JWT issuer, subject, expiry, issuance time, and JAR signing-key binding against configured trusted issuers.",
    clientId: _clientId ?? null,
    hasJwtHeader: typeof _header?.jwt === "string" && _header.jwt.length > 0,
    structureValid,
    parsedHeader,
    parsedPayload,
    clientBindingValid: structureValid && (_clientId == null ||
      parsedPayload.sub === _clientId ||
      parsedPayload.sub === String(_clientId).replace(/^[^:]+:/, "") ||
      parsedPayload.aud === _clientId),
  };
  recordTrustPlaceholder("verifier_attestation", result);
  return result;
}

export async function validateCs02TrustedAuthoritiesPolicy(credQuery, log = () => {}) {
  // TODO(CS-02 trust registry): enforce trusted_authorities against configured trust registry.
  try {
    log?.("[CS02] trusted_authorities ignored (no trust registry configured)", {
      credentialId: credQuery?.id,
      trustedAuthorities:
        credQuery?.trusted_authorities ?? credQuery?.meta?.trusted_authorities ?? null,
    });
  } catch {}
  return { enforced: false, placeholder: true };
}

export async function validateCs02IssuerTrust(_issuer, _options = resolveCs02TrustPolicyOptions()) {
  // TODO(CS-02 trust framework): enforce configured SD-JWT-VC issuer trust once anchors exist.
  return { ok: true, trusted: null, placeholder: true, issuer: _issuer ?? null };
}

function isPlainObject(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.prototype.toString.call(value) === "[object Object]"
  );
}

export function validateCs02ClientMetadata(metadata, { responseMode, strict = true } = {}) {
  if (metadata == null) return metadata;
  if (!isPlainObject(metadata)) {
    throw new Cs02TrustPolicyError("client_metadata must be an object", "invalid_request");
  }

  if (strict && metadata.vp_formats_supported != null) {
    if (!isPlainObject(metadata.vp_formats_supported)) {
      throw new Cs02TrustPolicyError("client_metadata.vp_formats_supported must be an object", "invalid_request");
    }
    for (const format of Object.keys(metadata.vp_formats_supported)) {
      if (!CS02_ENFORCED_VP_FORMATS.has(format)) {
        throw new Cs02TrustPolicyError(
          `client_metadata advertises unsupported vp format "${format}"`,
          "vp_formats_not_supported",
        );
      }
    }
    for (const [format, config] of Object.entries(metadata.vp_formats_supported)) {
      if (!isPlainObject(config)) continue;
      if (format === "dc+sd-jwt" || format === "vc+sd-jwt") {
        for (const alg of config["sd-jwt_alg_values"] || []) {
          if (!CS02_ENFORCED_SD_JWT_ALGS.has(alg)) {
            throw new Cs02TrustPolicyError(
              `client_metadata advertises unsupported SD-JWT alg "${alg}"`,
              "invalid_request",
            );
          }
        }
        for (const alg of config["kb-jwt_alg_values"] || []) {
          if (!CS02_ENFORCED_KB_JWT_ALGS.has(alg)) {
            throw new Cs02TrustPolicyError(
              `client_metadata advertises unsupported KB-JWT alg "${alg}"`,
              "invalid_request",
            );
          }
        }
      }
    }
  }

  if (metadata.jwks != null) {
    if (!isPlainObject(metadata.jwks) || !Array.isArray(metadata.jwks.keys)) {
      throw new Cs02TrustPolicyError("client_metadata.jwks must contain a keys array", "invalid_request");
    }
  }

  if (responseMode === "direct_post" && strict) {
    if (
      metadata.authorization_encrypted_response_alg ||
      metadata.authorization_encrypted_response_enc ||
      metadata.encrypted_response_alg_values_supported ||
      metadata.encrypted_response_enc_values_supported
    ) {
      throw new Cs02TrustPolicyError(
        "client_metadata must not advertise encrypted response settings for direct_post",
        "invalid_request",
      );
    }
  }

  if (responseMode === "direct_post.jwt" && strict) {
    for (const alg of metadata.encrypted_response_alg_values_supported || []) {
      if (!CS02_ENFORCED_JWE_ALGS.has(alg)) {
        throw new Cs02TrustPolicyError(
          `client_metadata advertises unsupported encrypted response alg "${alg}"`,
          "invalid_request",
        );
      }
    }
    for (const enc of metadata.encrypted_response_enc_values_supported || []) {
      if (!CS02_ENFORCED_JWE_ENCS.has(enc)) {
        throw new Cs02TrustPolicyError(
          `client_metadata advertises unsupported encrypted response enc "${enc}"`,
          "invalid_request",
        );
      }
    }
  }

  return metadata;
}

export function filterClientMetadataForCs02Enforcement(clientMetadata, responseMode, { strict = true } = {}) {
  const metadata = { ...(clientMetadata || {}) };

  if (metadata.vp_formats_supported && typeof metadata.vp_formats_supported === "object") {
    metadata.vp_formats_supported = Object.fromEntries(
      Object.entries(metadata.vp_formats_supported)
        .filter(([format]) => (strict ? CS02_ENFORCED_VP_FORMATS.has(format) : true))
        .map(([format, config]) => [
          format,
          isPlainObject(config)
            ? {
                ...config,
                ...(Array.isArray(config["sd-jwt_alg_values"])
                  ? { "sd-jwt_alg_values": [...config["sd-jwt_alg_values"]] }
                  : {}),
                ...(Array.isArray(config["kb-jwt_alg_values"])
                  ? { "kb-jwt_alg_values": [...config["kb-jwt_alg_values"]] }
                  : {}),
              }
            : config,
        ]),
    );
  }

  if (strict) {
    if (metadata.vp_formats_supported) {
      for (const [format, config] of Object.entries(metadata.vp_formats_supported)) {
        if (!isPlainObject(config)) continue;
        if (format === "dc+sd-jwt" || format === "vc+sd-jwt") {
          if (Array.isArray(config["sd-jwt_alg_values"])) {
            config["sd-jwt_alg_values"] = config["sd-jwt_alg_values"].filter((alg) =>
              CS02_ENFORCED_SD_JWT_ALGS.has(alg),
            );
          }
          if (Array.isArray(config["kb-jwt_alg_values"])) {
            config["kb-jwt_alg_values"] = config["kb-jwt_alg_values"].filter((alg) =>
              CS02_ENFORCED_KB_JWT_ALGS.has(alg),
            );
          }
        }
      }
    }

    if (Array.isArray(metadata.encrypted_response_alg_values_supported)) {
      metadata.encrypted_response_alg_values_supported =
        metadata.encrypted_response_alg_values_supported.filter((alg) =>
          CS02_ENFORCED_JWE_ALGS.has(alg),
        );
    }
    if (Array.isArray(metadata.encrypted_response_enc_values_supported)) {
      metadata.encrypted_response_enc_values_supported =
        metadata.encrypted_response_enc_values_supported.filter((enc) =>
          CS02_ENFORCED_JWE_ENCS.has(enc),
        );
    }
  }

  if (responseMode === "direct_post") {
    delete metadata.encrypted_response_alg_values_supported;
    delete metadata.encrypted_response_enc_values_supported;
    delete metadata.authorization_encrypted_response_alg;
    delete metadata.authorization_encrypted_response_enc;
  }

  return metadata;
}

export const CS02_CLIENT_METADATA_FETCH_TIMEOUT_MS = 5000;
export const CS02_CLIENT_METADATA_MAX_BYTES = 64 * 1024;
export const CS02_CLIENT_METADATA_MAX_REDIRECTS = 3;

export function summarizeClientMetadataForLog(metadata) {
  if (!isPlainObject(metadata)) return { present: false };
  return {
    present: true,
    hasJwks: !!metadata.jwks,
    hasJwksUri: !!metadata.jwks_uri,
    vpFormatCount: metadata.vp_formats_supported
      ? Object.keys(metadata.vp_formats_supported).length
      : 0,
    hasEncryptedResponseAlgs: Array.isArray(metadata.encrypted_response_alg_values_supported),
    hasEncryptedResponseEncs: Array.isArray(metadata.encrypted_response_enc_values_supported),
    hasAuthorizationEncryptedResponseAlg: !!metadata.authorization_encrypted_response_alg,
    hasAuthorizationEncryptedResponseEnc: !!metadata.authorization_encrypted_response_enc,
  };
}

function isJsonMetadataContentType(contentType) {
  if (!contentType || typeof contentType !== "string") return true;
  const normalized = contentType.split(";")[0].trim().toLowerCase();
  return normalized === "application/json" || normalized.endsWith("+json");
}

function assertClientMetadataUriShape(metadataUri, { strict = true } = {}) {
  if (metadataUri == null) return null;
  if (typeof metadataUri !== "string" || metadataUri.length === 0) {
    throw new Cs02TrustPolicyError("client_metadata_uri must be a non-empty string", "invalid_request");
  }

  let parsed;
  try {
    parsed = new URL(metadataUri);
  } catch {
    throw new Cs02TrustPolicyError("client_metadata_uri must be an absolute URI", "invalid_request");
  }
  if (!parsed.hostname) {
    throw new Cs02TrustPolicyError("client_metadata_uri must be an absolute URI", "invalid_request");
  }
  if (strict && parsed.protocol !== "https:") {
    throw new Cs02TrustPolicyError("client_metadata_uri must use HTTPS", "invalid_request");
  }
  return parsed.toString();
}

function parseFetchedClientMetadata(body) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Cs02TrustPolicyError("client_metadata_uri response must be valid JSON", "invalid_request");
  }
  if (!isPlainObject(parsed)) {
    throw new Cs02TrustPolicyError("client_metadata_uri response must be a JSON object", "invalid_request");
  }
  return parsed;
}

async function readBoundedResponseBody(response, maxBytes) {
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new Cs02TrustPolicyError(
      "client_metadata_uri response exceeds maximum allowed size",
      "invalid_request",
    );
  }

  const body = await response.text();
  if (Buffer.byteLength(body, "utf8") > maxBytes) {
    throw new Cs02TrustPolicyError(
      "client_metadata_uri response exceeds maximum allowed size",
      "invalid_request",
    );
  }
  return body;
}

async function fetchClientMetadataResponse(
  metadataUri,
  fetchImpl,
  {
    timeoutMs = CS02_CLIENT_METADATA_FETCH_TIMEOUT_MS,
    maxBytes = CS02_CLIENT_METADATA_MAX_BYTES,
    maxRedirects = CS02_CLIENT_METADATA_MAX_REDIRECTS,
  } = {},
) {
  let currentUrl = metadataUri;
  let redirectCount = 0;

  while (redirectCount <= maxRedirects) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetchImpl(currentUrl, {
        method: "GET",
        headers: { Accept: "application/json" },
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (error) {
      if (error?.name === "AbortError") {
        throw new Cs02TrustPolicyError("client_metadata_uri fetch timed out", "invalid_request");
      }
      throw new Cs02TrustPolicyError("client_metadata_uri could not be fetched", "invalid_request");
    } finally {
      clearTimeout(timeout);
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) {
        throw new Cs02TrustPolicyError("client_metadata_uri redirect is missing location", "invalid_request");
      }
      let redirectUrl;
      try {
        redirectUrl = new URL(location, currentUrl);
      } catch {
        throw new Cs02TrustPolicyError("client_metadata_uri redirect location is invalid", "invalid_request");
      }
      if (redirectUrl.protocol !== "https:") {
        throw new Cs02TrustPolicyError(
          "client_metadata_uri redirects must remain on HTTPS",
          "invalid_request",
        );
      }
      redirectCount += 1;
      if (redirectCount > maxRedirects) {
        throw new Cs02TrustPolicyError("client_metadata_uri exceeded redirect limit", "invalid_request");
      }
      currentUrl = redirectUrl.toString();
      continue;
    }

    if (!response.ok) {
      throw new Cs02TrustPolicyError(
        `client_metadata_uri fetch failed with status ${response.status}`,
        "invalid_request",
      );
    }

    const contentType = response.headers.get("content-type") || "";
    if (contentType && !isJsonMetadataContentType(contentType)) {
      throw new Cs02TrustPolicyError(
        "client_metadata_uri response must use JSON content type",
        "invalid_request",
      );
    }

    const body = await readBoundedResponseBody(response, maxBytes);
    return { metadata: parseFetchedClientMetadata(body), finalUrl: currentUrl, contentType };
  }

  throw new Cs02TrustPolicyError("client_metadata_uri exceeded redirect limit", "invalid_request");
}

export function mergeCs02ClientMetadata(inlineMetadata, remoteMetadata) {
  const inline = isPlainObject(inlineMetadata) ? inlineMetadata : null;
  const remote = isPlainObject(remoteMetadata) ? remoteMetadata : null;
  if (!inline && !remote) return null;
  if (!remote) return { ...inline };
  if (!inline) return { ...remote };

  const merged = { ...remote, ...inline };
  if (inline.jwks || remote.jwks) {
    merged.jwks = inline.jwks ?? remote.jwks;
  }
  if (inline.jwks_uri || remote.jwks_uri) {
    merged.jwks_uri = inline.jwks_uri ?? remote.jwks_uri;
  }
  if (inline.vp_formats_supported || remote.vp_formats_supported) {
    merged.vp_formats_supported = inline.vp_formats_supported ?? remote.vp_formats_supported;
  }
  if (
    inline.encrypted_response_alg_values_supported ||
    remote.encrypted_response_alg_values_supported
  ) {
    merged.encrypted_response_alg_values_supported =
      inline.encrypted_response_alg_values_supported ??
      remote.encrypted_response_alg_values_supported;
  }
  if (
    inline.encrypted_response_enc_values_supported ||
    remote.encrypted_response_enc_values_supported
  ) {
    merged.encrypted_response_enc_values_supported =
      inline.encrypted_response_enc_values_supported ??
      remote.encrypted_response_enc_values_supported;
  }
  if (inline.authorization_encrypted_response_alg || remote.authorization_encrypted_response_alg) {
    merged.authorization_encrypted_response_alg =
      inline.authorization_encrypted_response_alg ?? remote.authorization_encrypted_response_alg;
  }
  if (inline.authorization_encrypted_response_enc || remote.authorization_encrypted_response_enc) {
    merged.authorization_encrypted_response_enc =
      inline.authorization_encrypted_response_enc ?? remote.authorization_encrypted_response_enc;
  }
  return merged;
}

export async function validateCs02ClientMetadataUri(
  metadataUri,
  {
    fetchImpl = fetch,
    responseMode,
    strict = true,
    timeoutMs = CS02_CLIENT_METADATA_FETCH_TIMEOUT_MS,
    maxBytes = CS02_CLIENT_METADATA_MAX_BYTES,
    maxRedirects = CS02_CLIENT_METADATA_MAX_REDIRECTS,
    log = () => {},
  } = {},
) {
  const normalizedUri = assertClientMetadataUriShape(metadataUri, { strict });
  if (normalizedUri == null) return { ok: true, skipped: true };
  const { metadata, finalUrl, contentType } = await fetchClientMetadataResponse(
    normalizedUri,
    fetchImpl,
    { timeoutMs, maxBytes, maxRedirects },
  );
  validateCs02ClientMetadata(metadata, { responseMode, strict });
  try {
    log?.("[CS02] client_metadata_uri resolved", {
      uri: normalizedUri,
      finalUrl,
      contentType: contentType || null,
      metadata: summarizeClientMetadataForLog(metadata),
    });
  } catch {}
  return { ok: true, metadata, uri: normalizedUri, finalUrl };
}

export async function resolveCs02EffectiveClientMetadata(
  jarPayload,
  {
    fetchImpl = fetch,
    strict = true,
    timeoutMs = CS02_CLIENT_METADATA_FETCH_TIMEOUT_MS,
    maxBytes = CS02_CLIENT_METADATA_MAX_BYTES,
    maxRedirects = CS02_CLIENT_METADATA_MAX_REDIRECTS,
    log = () => {},
  } = {},
) {
  const responseMode = jarPayload?.response_mode;
  const inlineMetadata = jarPayload?.client_metadata ?? null;
  const metadataUri = jarPayload?.client_metadata_uri ?? null;

  if (inlineMetadata != null && strict) {
    validateCs02ClientMetadata(inlineMetadata, { responseMode, strict: true });
  }

  let remoteMetadata = null;
  if (metadataUri != null) {
    if (strict) {
      const resolved = await validateCs02ClientMetadataUri(metadataUri, {
        fetchImpl,
        responseMode,
        strict: true,
        timeoutMs,
        maxBytes,
        maxRedirects,
        log,
      });
      remoteMetadata = resolved.metadata;
    } else {
      try {
        const normalizedUri = assertClientMetadataUriShape(metadataUri, { strict: false });
        const fetched = await fetchClientMetadataResponse(normalizedUri, fetchImpl, {
          timeoutMs,
          maxBytes,
          maxRedirects,
        });
        remoteMetadata = fetched.metadata;
        validateCs02ClientMetadata(remoteMetadata, { responseMode, strict: false });
      } catch (error) {
        try {
          log?.("[CS02] client_metadata_uri fetch skipped in compatibility mode", {
            uri: metadataUri,
            message: error?.message || String(error),
          });
        } catch {}
      }
    }
  }

  const effectiveMetadata = mergeCs02ClientMetadata(inlineMetadata, remoteMetadata);
  return {
    effectiveMetadata,
    inlineMetadata,
    remoteMetadata,
    sources: {
      inline: inlineMetadata != null,
      remote: remoteMetadata != null,
    },
  };
}

const PRECEDENCE_QUERY_KEYS = new Set([
  "client_id",
  "request_uri",
  "request_uri_method",
  "response_mode",
  "response_type",
]);

export function extractDeepLinkQueryParams(deepLinkUrl) {
  const params = {};
  if (!deepLinkUrl) return params;
  const url = typeof deepLinkUrl === "string" ? new URL(deepLinkUrl) : deepLinkUrl;
  for (const key of PRECEDENCE_QUERY_KEYS) {
    const value = url.searchParams.get(key);
    if (value != null && value !== "") params[key] = value;
  }
  return params;
}

export function validateCs02RequestUriQueryPrecedence(deepLinkUrl, jarPayload, log = () => {}) {
  const queryParams = extractDeepLinkQueryParams(deepLinkUrl);
  const contradictions = [];

  for (const [key, queryValue] of Object.entries(queryParams)) {
    if (jarPayload?.[key] == null || jarPayload[key] === "") continue;
    if (String(jarPayload[key]) !== String(queryValue)) {
      contradictions.push({ key, queryValue, jarValue: jarPayload[key] });
    }
  }

  if (contradictions.length > 0) {
    try {
      log?.("[CS02] deep-link query contradicts signed JAR", { contradictions });
    } catch {}
    throw new Cs02TrustPolicyError(
      "Deep link query parameters must not contradict signed authorization request values",
      "invalid_request",
    );
  }

  return { ok: true, queryParams };
}
