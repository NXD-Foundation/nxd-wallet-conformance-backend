/**
 * WE BUILD CS-02 verifier-side presentation response validation.
 */

import {
  decodeProtectedHeader,
  decodeJwt,
  importJWK,
  jwtVerify,
} from "jose";
import { createHash } from "crypto";
import {
  extractKeyBindingJwtFromSdJwt,
  validateSdJwtKeyBindingMatchesCredential,
} from "./sdJwtKeyBinding.js";
import { resolveVerifierCs02Options } from "./cs02VerifierRequest.js";
import { validateCs02CredentialStatusList, Cs02StatusListError } from "./cs02StatusList.js";
import {
  validateCs02IssuerTrust,
  resolveCs02TrustPolicyOptions,
} from "./cs02TrustPolicy.js";
import { extractMdocDocType } from "../wallet-client/src/lib/mdocDocType.js";

export { resolveVerifierCs02Options, isVerifierCs02StrictMode } from "./cs02VerifierRequest.js";

export const CS02_KB_JWT_TYP = "kb+jwt";
export const CS02_DEFAULT_JWE_ALGS = [
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW",
  "RSA-OAEP",
  "RSA-OAEP-256",
];
export const CS02_DEFAULT_JWE_ENCS = [
  "A256GCM",
  "A192GCM",
  "A128GCM",
  "A256CBC-HS512",
  "A192CBC-HS384",
  "A128CBC-HS256",
];

export class Cs02VerifierResponseError extends Error {
  constructor(message, errorCode = "invalid_request") {
    super(message);
    this.name = "Cs02VerifierResponseError";
    this.errorCode = errorCode;
  }
}

function isPlainObject(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.prototype.toString.call(value) === "[object Object]"
  );
}

const SD_JWT_FORMATS = new Set(["dc+sd-jwt", "vc+sd-jwt"]);
const CS02_ISSUER_SD_JWT_ALGS = new Set(["ES256", "ES384"]);
const MDOC_FORMAT = "mso_mdoc";

export function normalizeDcqlVpToken(vpToken) {
  if (vpToken == null) return vpToken;
  if (typeof vpToken === "string" && vpToken.trim().startsWith("{")) {
    try {
      return JSON.parse(vpToken);
    } catch {
      return vpToken;
    }
  }
  return vpToken;
}

export function detectWalletProtocolError(body) {
  if (!body || typeof body !== "object" || !body.error) return null;
  return {
    error: body.error,
    error_description: body.error_description,
  };
}

export function validateCs02ResponseSubmission(body, session, options = { strict: true }) {
  const walletError = detectWalletProtocolError(body);
  if (walletError) return { walletError };

  if (!options.strict) return null;

  const responseMode = session?.response_mode || "direct_post";
  const hasResponse = body?.response != null && body.response !== "";
  const hasVpToken = body?.vp_token != null && body.vp_token !== "";

  if (responseMode === "direct_post.jwt") {
    if (hasVpToken && !hasResponse) {
      throw new Cs02VerifierResponseError(
        "bare vp_token submission is not allowed when the session expects direct_post.jwt",
        "invalid_request",
      );
    }
    if (!hasResponse && !walletError) {
      throw new Cs02VerifierResponseError(
        "direct_post.jwt response requires a response parameter",
        "invalid_request",
      );
    }
    return null;
  }

  if (responseMode === "direct_post") {
    if (hasResponse && !hasVpToken) {
      throw new Cs02VerifierResponseError(
        "direct_post.jwt response is not allowed when the session expects direct_post",
        "invalid_request",
      );
    }
    if (!hasVpToken) {
      throw new Cs02VerifierResponseError(
        "direct_post response requires vp_token",
        "invalid_request",
      );
    }
    if (body?.state == null || body?.state === "") {
      throw new Cs02VerifierResponseError(
        "direct_post response requires state",
        "invalid_request",
      );
    }
  }

  return null;
}

function credentialQueryById(dcqlQuery, id) {
  return (dcqlQuery?.credentials || []).find((entry) => entry?.id === id) || null;
}

function validateCredentialPresentationValue(value, multiple, credentialId) {
  if (multiple === true) {
    if (!Array.isArray(value)) {
      throw new Cs02VerifierResponseError(
        `DCQL credential "${credentialId}" requires an array when multiple=true`,
        "invalid_vp_token",
      );
    }
    if (value.length === 0) {
      throw new Cs02VerifierResponseError(
        `DCQL credential "${credentialId}" returned an empty array`,
        "invalid_vp_token",
      );
    }
    for (const entry of value) {
      if (typeof entry !== "string" || entry.length === 0) {
        throw new Cs02VerifierResponseError(
          `DCQL credential "${credentialId}" array entries must be non-empty strings`,
          "invalid_vp_token",
        );
      }
    }
    return;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      throw new Cs02VerifierResponseError(
        `DCQL credential "${credentialId}" returned an empty array`,
        "invalid_vp_token",
      );
    }
    if (value.length > 1) {
      throw new Cs02VerifierResponseError(
        `DCQL credential "${credentialId}" returned multiple presentations without multiple=true`,
        "invalid_vp_token",
      );
    }
    if (typeof value[0] !== "string" || value[0].length === 0) {
      throw new Cs02VerifierResponseError(
        `DCQL credential "${credentialId}" presentation must be a non-empty string`,
        "invalid_vp_token",
      );
    }
    return;
  }

  if (typeof value !== "string" || value.length === 0) {
    throw new Cs02VerifierResponseError(
      `DCQL credential "${credentialId}" presentation must be a non-empty string`,
      "invalid_vp_token",
    );
  }
}

function requiredCredentialSetsSatisfied(requiredSets, vpTokenObject) {
  for (const set of requiredSets) {
    const options = Array.isArray(set?.options) ? set.options : [];
    const satisfied = options.some(
      (option) =>
        Array.isArray(option) &&
        option.length > 0 &&
        option.every((id) => Object.prototype.hasOwnProperty.call(vpTokenObject, id)),
    );
    if (!satisfied) {
      return false;
    }
  }
  return true;
}

function allowedCredentialIdsForResponse(dcqlQuery, vpTokenObject) {
  const credentials = Array.isArray(dcqlQuery?.credentials) ? dcqlQuery.credentials : [];
  const knownIds = new Set(credentials.map((cred) => cred.id).filter(Boolean));
  const credentialSets = Array.isArray(dcqlQuery?.credential_sets)
    ? dcqlQuery.credential_sets
    : [];
  const requiredSets = credentialSets.filter((set) => set?.required !== false);

  if (requiredSets.length === 0) {
    return knownIds;
  }

  const allowed = new Set();
  for (const set of requiredSets) {
    for (const option of set.options || []) {
      if (
        Array.isArray(option) &&
        option.every((id) => Object.prototype.hasOwnProperty.call(vpTokenObject, id))
      ) {
        for (const id of option) allowed.add(id);
      }
    }
  }
  return allowed;
}

export function validateCs02DcqlVpTokenResponse(
  vpTokenInput,
  dcqlQuery,
  options = { strict: true },
) {
  const vpTokenObject = normalizeDcqlVpToken(vpTokenInput);
  if (!isPlainObject(vpTokenObject)) {
    throw new Cs02VerifierResponseError(
      "DCQL vp_token must be a JSON object mapping credential query ids to presentations",
      "invalid_vp_token",
    );
  }

  const credentials = Array.isArray(dcqlQuery?.credentials) ? dcqlQuery.credentials : [];
  const knownIds = new Set(credentials.map((cred) => cred.id).filter(Boolean));
  const receivedKeys = Object.keys(vpTokenObject);

  for (const key of receivedKeys) {
    if (!knownIds.has(key)) {
      throw new Cs02VerifierResponseError(
        `Unknown DCQL credential id "${key}" in vp_token`,
        "invalid_vp_token",
      );
    }
  }

  const credentialSets = Array.isArray(dcqlQuery?.credential_sets)
    ? dcqlQuery.credential_sets
    : [];
  const requiredSets = credentialSets.filter((set) => set?.required !== false);

  if (requiredSets.length === 0) {
    for (const id of knownIds) {
      if (!Object.prototype.hasOwnProperty.call(vpTokenObject, id)) {
        if (options.strict) {
          throw new Cs02VerifierResponseError(
            `DCQL vp_token is missing required credential id "${id}"`,
            "invalid_vp_token",
          );
        }
      }
    }
  } else if (options.strict && !requiredCredentialSetsSatisfied(requiredSets, vpTokenObject)) {
    throw new Cs02VerifierResponseError(
      "DCQL vp_token does not satisfy required credential_sets options",
      "invalid_vp_token",
    );
  }

  if (options.strict && requiredSets.length > 0) {
    const allowedIds = allowedCredentialIdsForResponse(dcqlQuery, vpTokenObject);
    for (const key of receivedKeys) {
      if (!allowedIds.has(key)) {
        throw new Cs02VerifierResponseError(
          `Unexpected DCQL credential id "${key}" in vp_token for the satisfied credential_sets`,
          "invalid_vp_token",
        );
      }
    }
  }

  for (const key of receivedKeys) {
    const credQuery = credentialQueryById(dcqlQuery, key);
    validateCredentialPresentationValue(
      vpTokenObject[key],
      credQuery?.multiple === true,
      key,
    );
  }

  return vpTokenObject;
}

export function validateCs02JweResponseHeader(header, clientMetadata = {}) {
  if (!header || typeof header !== "object") {
    throw new Cs02VerifierResponseError("JWE protected header is missing", "invalid_response");
  }

  const allowedAlgs = Array.isArray(clientMetadata.authorization_encrypted_response_alg)
    ? clientMetadata.authorization_encrypted_response_alg
    : clientMetadata.authorization_encrypted_response_alg
      ? [clientMetadata.authorization_encrypted_response_alg]
      : clientMetadata.encrypted_response_alg_values_supported || CS02_DEFAULT_JWE_ALGS;

  const allowedEncs = clientMetadata.authorization_encrypted_response_enc
    ? [clientMetadata.authorization_encrypted_response_enc]
    : clientMetadata.encrypted_response_enc_values_supported || CS02_DEFAULT_JWE_ENCS;

  if (!header.alg || !allowedAlgs.includes(header.alg)) {
    throw new Cs02VerifierResponseError(
      `Unsupported JWE alg "${header.alg ?? "missing"}"`,
      "invalid_response",
    );
  }
  if (!header.enc || !allowedEncs.includes(header.enc)) {
    throw new Cs02VerifierResponseError(
      `Unsupported JWE enc "${header.enc ?? "missing"}"`,
      "invalid_response",
    );
  }
  if (!header.kid) {
    throw new Cs02VerifierResponseError("JWE protected header must include kid", "invalid_response");
  }
}

export async function verifyCs02OuterResponseJwt(
  jwtCompact,
  {
    clientId,
    state,
    clockTolerance = 300,
    resolveVerificationKey,
  } = {},
) {
  if (typeof jwtCompact !== "string" || jwtCompact.split(".").length !== 3) {
    throw new Cs02VerifierResponseError("Response JWT must be a compact signed JWT", "invalid_response");
  }

  const header = decodeProtectedHeader(jwtCompact);
  if (!header.alg || header.alg.toLowerCase() === "none") {
    throw new Cs02VerifierResponseError("Response JWT must use a supported signing algorithm", "invalid_response");
  }

  let verificationKey;
  if (header.jwk) {
    verificationKey = await importJWK(header.jwk, header.alg);
  } else if (typeof resolveVerificationKey === "function") {
    verificationKey = await resolveVerificationKey(header);
  } else {
    throw new Cs02VerifierResponseError(
      "Unable to resolve verification key for response JWT",
      "invalid_response",
    );
  }

  let verified;
  try {
    verified = await jwtVerify(jwtCompact, verificationKey, { clockTolerance });
  } catch (error) {
    throw new Cs02VerifierResponseError(
      "Response JWT signature verification failed",
      "invalid_response",
    );
  }
  const payload = verified.payload;

  if (typeof payload.iss !== "string" || payload.iss.length === 0) {
    throw new Cs02VerifierResponseError("Response JWT is missing iss", "invalid_response");
  }

  if (!clientId) {
    throw new Cs02VerifierResponseError(
      "Verifier client_id is required to validate response JWT aud",
      "invalid_response",
    );
  }

  if (payload.aud == null) {
    throw new Cs02VerifierResponseError("Response JWT is missing aud", "invalid_audience");
  }
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(clientId)) {
    throw new Cs02VerifierResponseError(
      `Response JWT aud does not match verifier client_id`,
      "invalid_audience",
    );
  }

  if (payload.iat == null || typeof payload.iat !== "number") {
    throw new Cs02VerifierResponseError("Response JWT is missing iat", "invalid_response");
  }
  if (payload.exp == null || typeof payload.exp !== "number") {
    throw new Cs02VerifierResponseError("Response JWT is missing exp", "invalid_response");
  }

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(payload.iat - now) > clockTolerance) {
    throw new Cs02VerifierResponseError(
      "Response JWT iat is outside accepted clock skew",
      "invalid_response",
    );
  }

  if (state == null || state === "") {
    throw new Cs02VerifierResponseError(
      "Session state is required to validate response JWT state",
      "invalid_state",
    );
  }
  if (payload.state !== state) {
    throw new Cs02VerifierResponseError("Response JWT state does not match session state", "invalid_state");
  }

  return {
    header: verified.protectedHeader,
    payload,
  };
}

export function validateCs02KeyBindingJwtClaims({
  kbHeader,
  kbPayload,
  sessionNonce,
  clientId,
  options = { strict: true },
}) {
  if (!options.strict) return;

  if (!kbHeader || kbHeader.typ !== CS02_KB_JWT_TYP) {
    throw new Cs02VerifierResponseError(
      `Key Binding JWT must use typ ${CS02_KB_JWT_TYP}`,
      "invalid_key_binding_jwt",
    );
  }
  if (!kbPayload?.nonce) {
    throw new Cs02VerifierResponseError(
      "Key Binding JWT is missing nonce",
      "invalid_key_binding_jwt",
    );
  }
  if (sessionNonce != null && kbPayload.nonce !== sessionNonce) {
    throw new Cs02VerifierResponseError(
      "Key Binding JWT nonce does not match session nonce",
      "invalid_nonce",
    );
  }
  if (clientId && !kbPayload.aud) {
    throw new Cs02VerifierResponseError(
      "Key Binding JWT is missing aud",
      "invalid_key_binding_jwt",
    );
  }
  if (clientId && kbPayload.aud !== clientId) {
    throw new Cs02VerifierResponseError(
      "Key Binding JWT aud does not match verifier client_id",
      "invalid_audience",
    );
  }
  if (kbPayload.iat == null) {
    throw new Cs02VerifierResponseError(
      "Key Binding JWT is missing iat",
      "invalid_key_binding_jwt",
    );
  }
  if (!kbPayload.sd_hash) {
    throw new Cs02VerifierResponseError(
      "Key Binding JWT is missing sd_hash",
      "invalid_key_binding_jwt",
    );
  }
}

function parseSdJwtPresentation(sdJwt) {
  if (typeof sdJwt !== "string" || sdJwt.length === 0) {
    throw new Cs02VerifierResponseError("SD-JWT-VC presentation must be a non-empty string", "invalid_vp_token");
  }
  const [issuerJwt, ...tail] = sdJwt.split("~");
  if (!issuerJwt || issuerJwt.split(".").length !== 3) {
    throw new Cs02VerifierResponseError("SD-JWT-VC issuer-signed JWT must be compact JWS", "invalid_credential");
  }

  const nonEmptyTail = tail.filter((part) => part.length > 0);
  const last = nonEmptyTail[nonEmptyTail.length - 1];
  const hasKbJwt = last && last.split(".").length === 3;
  return {
    issuerJwt,
    disclosures: hasKbJwt ? nonEmptyTail.slice(0, -1) : nonEmptyTail,
    kbJwt: hasKbJwt ? last : null,
  };
}

function decodeDisclosure(disclosure) {
  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(disclosure, "base64url").toString("utf8"));
  } catch {
    throw new Cs02VerifierResponseError("SD-JWT disclosure is not valid base64url JSON", "invalid_credential");
  }
  if (!Array.isArray(decoded) || decoded.length < 3 || typeof decoded[1] !== "string") {
    throw new Cs02VerifierResponseError("SD-JWT disclosure must contain salt, claim name, and value", "invalid_credential");
  }
  return {
    salt: decoded[0],
    claimName: decoded[1],
    value: decoded[2],
  };
}

function digestDisclosure(disclosure, sdAlg = "sha-256") {
  const normalized = String(sdAlg || "sha-256").toLowerCase();
  if (normalized !== "sha-256") {
    throw new Cs02VerifierResponseError(
      `Unsupported SD-JWT disclosure digest algorithm "${sdAlg}"`,
      "invalid_credential",
    );
  }
  return createHash("sha256").update(disclosure, "ascii").digest("base64url");
}

function reconstructTopLevelSdJwtClaims(issuerPayload, disclosures) {
  const reconstructed = { ...(issuerPayload || {}) };
  const expectedDigests = new Set(Array.isArray(issuerPayload?._sd) ? issuerPayload._sd : []);
  const disclosedClaimNames = [];

  for (const disclosure of disclosures) {
    const digest = digestDisclosure(disclosure, issuerPayload?._sd_alg);
    if (!expectedDigests.has(digest)) {
      throw new Cs02VerifierResponseError(
        "SD-JWT disclosure digest does not match issuer-signed payload",
        "invalid_credential",
      );
    }
    const { claimName, value } = decodeDisclosure(disclosure);
    reconstructed[claimName] = value;
    disclosedClaimNames.push(claimName);
  }

  delete reconstructed._sd;
  delete reconstructed._sd_alg;
  return { claims: reconstructed, disclosedClaimNames };
}

function requestedTopLevelClaimNames(credQuery) {
  const names = new Set();
  for (const claim of credQuery?.claims || []) {
    const path = claim?.path;
    if (!Array.isArray(path) || path.length === 0) continue;
    if (path.every((segment) => typeof segment === "string" && segment.length > 0)) {
      names.add(path[0]);
    }
  }
  return names;
}

function assertSupportedSdJwtClaimPaths(credQuery) {
  for (const claim of credQuery?.claims || []) {
    if (Array.isArray(claim?.path) && claim.path.length !== 1) {
      throw new Cs02VerifierResponseError(
        `Unsupported SD-JWT DCQL claim path "${claim.path.join(".")}": only top-level claim paths are currently supported`,
        "invalid_request",
      );
    }
  }
}

function getPathValue(object, path) {
  if (!Array.isArray(path) || path.length === 0) return undefined;
  let current = object;
  for (const segment of path) {
    if (typeof segment !== "string" || segment.length === 0) return undefined;
    if (!current || typeof current !== "object") return undefined;
    current = current[segment];
  }
  return current;
}

function validateIssuerCredentialClaims({
  issuerPayload,
  reconstructedClaims,
  disclosedClaimNames,
  credQuery,
  holderBindingRequired = true,
  rejectUnsolicitedDisclosures = true,
  clockTolerance = 300,
}) {
  if (typeof issuerPayload?.iss !== "string" || issuerPayload.iss.length === 0) {
    throw new Cs02VerifierResponseError("SD-JWT-VC issuer payload is missing iss", "invalid_credential");
  }

  const now = Math.floor(Date.now() / 1000);
  if (issuerPayload.iat != null) {
    if (typeof issuerPayload.iat !== "number" || issuerPayload.iat > now + clockTolerance) {
      throw new Cs02VerifierResponseError("SD-JWT-VC issuer iat is outside accepted clock skew", "invalid_credential");
    }
  }
  if (issuerPayload.exp != null) {
    if (typeof issuerPayload.exp !== "number" || issuerPayload.exp <= now - clockTolerance) {
      throw new Cs02VerifierResponseError("SD-JWT-VC issuer exp is expired", "invalid_credential");
    }
  }

  if (holderBindingRequired && !issuerPayload.cnf?.jwk) {
    throw new Cs02VerifierResponseError("SD-JWT-VC issuer payload is missing cnf.jwk", "invalid_credential");
  }

  const vctValues = Array.isArray(credQuery?.meta?.vct_values) ? credQuery.meta.vct_values : [];
  if (vctValues.length > 0 && !vctValues.includes(reconstructedClaims?.vct)) {
    throw new Cs02VerifierResponseError("SD-JWT-VC vct does not satisfy DCQL request", "invalid_credential");
  }

  assertSupportedSdJwtClaimPaths(credQuery);
  const requestedClaimNames = requestedTopLevelClaimNames(credQuery);
  for (const claim of credQuery?.claims || []) {
    if (Array.isArray(claim?.path) && getPathValue(reconstructedClaims, claim.path) === undefined) {
      throw new Cs02VerifierResponseError(
        `SD-JWT-VC is missing requested claim path "${claim.path.join(".")}"`,
        "invalid_credential",
      );
    }
  }

  if (rejectUnsolicitedDisclosures && requestedClaimNames.size > 0) {
    for (const claimName of disclosedClaimNames) {
      if (!requestedClaimNames.has(claimName)) {
        throw new Cs02VerifierResponseError(
          `SD-JWT-VC includes unsolicited disclosed claim "${claimName}"`,
          "invalid_credential",
        );
      }
    }
  }
}

async function resolveIssuerVerificationKey({ header, payload, options }) {
  if (options?.issuerVerificationKey) return options.issuerVerificationKey;
  if (options?.issuerVerificationJwk) return importJWK(options.issuerVerificationJwk, header.alg);
  if (typeof options?.resolveIssuerVerificationKey === "function") {
    const key = await options.resolveIssuerVerificationKey({ header, payload });
    if (!key) return null;
    if (key.type === "public" || key.type === "private" || key.constructor?.name?.includes("Key")) return key;
    return importJWK(key, header.alg);
  }
  if (Array.isArray(options?.issuerJwks?.keys)) {
    const jwk = options.issuerJwks.keys.find((candidate) => {
      if (header.kid && candidate.kid && candidate.kid !== header.kid) return false;
      if (candidate.use && candidate.use !== "sig") return false;
      if (candidate.alg && candidate.alg !== header.alg) return false;
      return true;
    });
    if (jwk) return importJWK(jwk, header.alg);
  }
  return null;
}

export async function validateCs02SdJwtIssuerAuthenticity({
  sdJwt,
  credQuery,
  options = { strict: true },
} = {}) {
  if (!options.strict) return { ok: true, skipped: true };

  const { issuerJwt, disclosures } = parseSdJwtPresentation(sdJwt);
  const header = decodeProtectedHeader(issuerJwt);
  if (!header.alg || String(header.alg).toLowerCase() === "none") {
    throw new Cs02VerifierResponseError("SD-JWT-VC issuer JWT must use a supported alg", "invalid_credential");
  }
  if (!CS02_ISSUER_SD_JWT_ALGS.has(header.alg)) {
    throw new Cs02VerifierResponseError(
      `Unsupported SD-JWT-VC issuer alg "${header.alg}"`,
      "invalid_credential",
    );
  }

  const issuerPayload = decodeJwt(issuerJwt);
  const verificationKey = await resolveIssuerVerificationKey({ header, payload: issuerPayload, options });
  let issuerSignature = {
    verified: false,
    enforced: false,
    placeholder: true,
    reason: "no issuer verification key source configured",
  };
  if (verificationKey) {
    try {
      await jwtVerify(issuerJwt, verificationKey, { clockTolerance: options.clockTolerance ?? 300 });
    } catch {
      throw new Cs02VerifierResponseError(
        "SD-JWT-VC issuer signature verification failed",
        "invalid_credential",
      );
    }
    issuerSignature = {
      verified: true,
      enforced: true,
      placeholder: false,
      alg: header.alg,
      kid: header.kid ?? null,
    };
  }

  const { claims, disclosedClaimNames } = reconstructTopLevelSdJwtClaims(issuerPayload, disclosures);
  validateIssuerCredentialClaims({
    issuerPayload,
    reconstructedClaims: claims,
    disclosedClaimNames,
    credQuery,
    holderBindingRequired: options.holderBindingRequired !== false,
    rejectUnsolicitedDisclosures: options.rejectUnsolicitedDisclosures !== false,
    clockTolerance: options.clockTolerance ?? 300,
  });

  return {
    ok: true,
    header,
    issuerPayload,
    claims,
    disclosedClaimNames,
    issuerSignature,
  };
}

export async function validateCs02SdJwtPresentation({
  sdJwt,
  sessionNonce,
  clientId,
  computeSdHash,
  credQuery,
  options = { strict: true },
}) {
  if (!options.strict || typeof sdJwt !== "string" || sdJwt.length === 0) {
    return { ok: true };
  }

  const issuerAuthenticity = await validateCs02SdJwtIssuerAuthenticity({
    sdJwt,
    credQuery,
    options,
  });

  const kbJwt = extractKeyBindingJwtFromSdJwt(sdJwt);
  if (!kbJwt) {
    throw new Cs02VerifierResponseError(
      "SD-JWT-VC presentation is missing Key Binding JWT",
      "invalid_key_binding_jwt",
    );
  }

  const kbHeader = decodeProtectedHeader(kbJwt);
  const kbPayload = decodeJwt(kbJwt);
  let verified;
  try {
    verified = await validateSdJwtKeyBindingMatchesCredential({ sdJwt });
  } catch (error) {
    throw new Cs02VerifierResponseError(
      error?.message || "SD-JWT key binding validation failed",
      "invalid_key_binding_jwt",
    );
  }

  validateCs02KeyBindingJwtClaims({
    kbHeader,
    kbPayload,
    sessionNonce,
    clientId,
    options,
  });

  if (typeof computeSdHash === "function") {
    const expectedSdHash = computeSdHash(sdJwt);
    if (!expectedSdHash || kbPayload.sd_hash !== expectedSdHash) {
      throw new Cs02VerifierResponseError(
        "Key Binding JWT sd_hash does not match presented SD-JWT",
        "invalid_key_binding_jwt",
      );
    }
  }

  const issuerPayload = issuerAuthenticity.issuerPayload;
  const trustPolicyOptions = options.trustPolicyOptions || resolveCs02TrustPolicyOptions(options.env);
  const issuerTrust = await validateCs02IssuerTrust(issuerPayload?.iss, trustPolicyOptions);
  let credentialStatus;
  try {
    credentialStatus = await validateCs02CredentialStatusList(sdJwt, {
      env: options.env,
      trustPolicyOptions,
      log: options.log,
    });
  } catch (error) {
    if (error instanceof Cs02StatusListError) {
      throw new Cs02VerifierResponseError(error.message, error.errorCode);
    }
    throw error;
  }

  return {
    ...verified,
    issuerAuthenticity,
    issuerTrust,
    credentialStatus,
  };
}

export async function validateCs02SdJwtEntriesInVpToken(
  vpTokenObject,
  dcqlQuery,
  context,
  options = { strict: true },
) {
  if (!options.strict || !isPlainObject(vpTokenObject)) return;

  for (const credQuery of dcqlQuery?.credentials || []) {
    const value = vpTokenObject[credQuery.id];
    if (value == null) continue;

    const presentations = Array.isArray(value) ? value : [value];
    if (String(credQuery?.format || "") === MDOC_FORMAT) {
      for (const presentation of presentations) {
        validateCs02MdocPresentation({
          presentation,
          credQuery,
        });
      }
      continue;
    }

    if (!SD_JWT_FORMATS.has(String(credQuery?.format || ""))) continue;
    for (const presentation of presentations) {
      await validateCs02SdJwtPresentation({
        sdJwt: presentation,
        sessionNonce: context.sessionNonce,
        clientId: context.clientId,
        computeSdHash: context.computeSdHash,
        credQuery,
        options: {
          ...options,
          resolveIssuerVerificationKey: context.resolveIssuerVerificationKey,
          issuerVerificationKey: context.issuerVerificationKey,
          issuerVerificationJwk: context.issuerVerificationJwk,
          issuerJwks: context.issuerJwks,
          rejectUnsolicitedDisclosures: context.rejectUnsolicitedDisclosures,
          trustPolicyOptions: context.trustPolicyOptions,
          env: context.env,
          log: context.log,
        },
      });
    }
  }
}

export function validateCs02MdocPresentation({ presentation, credQuery } = {}) {
  if (typeof presentation !== "string" || presentation.length === 0) {
    throw new Cs02VerifierResponseError(
      `DCQL credential "${credQuery?.id || "unknown"}" mdoc presentation must be a non-empty string`,
      "invalid_vp_token",
    );
  }

  const expectedDocType = credQuery?.meta?.doctype_value;
  if (typeof expectedDocType !== "string" || expectedDocType.length === 0) {
    return { ok: true, skipped: true };
  }

  let actualDocType;
  try {
    actualDocType = extractMdocDocType(presentation);
  } catch {
    throw new Cs02VerifierResponseError(
      `Unable to decode mso_mdoc presentation for DCQL credential "${credQuery?.id || "unknown"}"`,
      "invalid_credential",
    );
  }

  if (actualDocType !== expectedDocType) {
    throw new Cs02VerifierResponseError(
      `mso_mdoc doctype does not satisfy DCQL request for credential "${credQuery?.id || "unknown"}"`,
      "invalid_credential",
    );
  }

  return { ok: true, doctype: actualDocType };
}

export { validateCs02IssuerTrust } from "./cs02TrustPolicy.js";

export function buildCs02FailedSessionPatch(errorCode, errorDescription) {
  return {
    status: "failed",
    error: errorCode,
    error_description: errorDescription,
  };
}

export function resolveCs02ResponseOptions(env = process.env) {
  return resolveVerifierCs02Options(env);
}
