/**
 * WE BUILD CS-02 verifier-side presentation response validation.
 */

import {
  decodeProtectedHeader,
  decodeJwt,
  importJWK,
  importX509,
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
import { isStrictCs02EcP256Jwk } from "./cs02Encoding.js";
import {
  claimSatisfiesMdocConstraints,
  extractMdocClaimsByNamespace,
  selectSatisfiedMdocClaimSet,
  extractMdocIssuerCertificate,
} from "./mdocClaims.js";
import {
  getSdJwtPathValue,
  parseSdJwtClaims,
  selectSatisfiedSdJwtClaimSet,
} from "./sdJwtClaims.js";
import { isSupportedCs02ClaimPathSegment, validateSupportedCs02ClaimPath, evaluateCs02CredentialSets } from "./cs02DcqlCore.js";
import { checkVerifierCredentialTrust, isTrustFrameworkSession } from "./trustFrameworkPolicy.js";

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

function assertNoSessionInValidationOptions(options) {
  if (options && Object.prototype.hasOwnProperty.call(options, "session")) {
    throw new TypeError("Validation options must not contain session; use context.session");
  }
}

export function validateCs02EncryptedAuthorizationResponse(payload, session) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Cs02VerifierResponseError(
      "Encrypted authorization response must decrypt to a JSON object",
      "invalid_request",
    );
  }
  if (payload.vp_token == null || payload.vp_token === "") {
    throw new Cs02VerifierResponseError(
      "Encrypted authorization response must include vp_token",
      "invalid_request",
    );
  }
  if (session?.state && (typeof payload.state !== "string" || payload.state.length === 0)) {
    throw new Cs02VerifierResponseError(
      "Encrypted authorization response must include state",
      "invalid_request",
    );
  }
  if (session?.state && payload.state !== session.state) {
    throw new Cs02VerifierResponseError(
      "State mismatch in encrypted authorization response",
      "invalid_state",
    );
  }
  return payload;
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

export const CS02_WALLET_ERROR_CODES = new Set([
  "access_denied",
  "invalid_request",
  "invalid_client",
  "invalid_scope",
  "temporarily_unavailable",
  "server_error",
]);

export function detectWalletProtocolError(body) {
  if (!body || typeof body !== "object" || typeof body.error !== "string" || body.error.length === 0) return null;
  const error = CS02_WALLET_ERROR_CODES.has(body.error) ? body.error : "access_denied";
  return {
    error,
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
    if (hasResponse && typeof body.response !== "string") {
      throw new Cs02VerifierResponseError(
        "direct_post.jwt response parameter must be a non-empty string",
        "invalid_request",
      );
    }
    if (hasResponse && body.response.split(".").length !== 5) {
      throw new Cs02VerifierResponseError(
        "direct_post.jwt response parameter must be a compact JWE",
        "invalid_request",
      );
    }
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
    if (typeof body?.state !== "string" || body.state.length === 0) {
      throw new Cs02VerifierResponseError(
        "direct_post response requires a non-empty string state",
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
  const { knownIds, requiredSets } = evaluateCs02CredentialSets(dcqlQuery, vpTokenObject);
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

  const { knownIds, requiredSets, satisfied, allowedIds, unknownOptionIds } = evaluateCs02CredentialSets(dcqlQuery, vpTokenObject);
  if (options.strict && unknownOptionIds.length > 0) {
    throw new Cs02VerifierResponseError(
      `DCQL credential_sets references unknown credential id(s): ${unknownOptionIds.join(", ")}`,
      "invalid_vp_token",
    );
  }
  const receivedKeys = Object.keys(vpTokenObject);

  for (const key of receivedKeys) {
    if (!knownIds.has(key)) {
      throw new Cs02VerifierResponseError(
        `Unknown DCQL credential id "${key}" in vp_token`,
        "invalid_vp_token",
      );
    }
  }

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
  } else if (options.strict && !satisfied) {
    throw new Cs02VerifierResponseError(
      "DCQL vp_token does not satisfy required credential_sets options",
      "invalid_vp_token",
    );
  }

  if (options.strict && requiredSets.length > 0) {
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

export function validateCs02JweResponseHeader(header, clientMetadata = {}, sessionKey = null) {
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

  if (sessionKey) {
    if (sessionKey.kid !== header.kid || sessionKey.alg !== header.alg || sessionKey.use !== "enc") {
      throw new Cs02VerifierResponseError(
        "JWE header does not match the session-selected verifier encryption key",
        "invalid_response",
      );
    }
  }

  const configuredKeys = clientMetadata?.jwks?.keys;
  if (Array.isArray(configuredKeys)) {
    const selectedKey = configuredKeys.find((key) => key?.kid === header.kid);
    if (!selectedKey) {
      throw new Cs02VerifierResponseError("JWE kid does not identify a verifier encryption key", "invalid_response");
    }
    if (
      selectedKey.use !== "enc" ||
      !isStrictCs02EcP256Jwk(selectedKey) ||
      typeof selectedKey.alg !== "string" ||
      selectedKey.alg !== header.alg
    ) {
      throw new Cs02VerifierResponseError(
        "JWE header does not match the selected verifier encryption JWK",
        "invalid_response",
      );
    }
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
  expectedAudience = clientId,
  transactionData,
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
  if (expectedAudience && !kbPayload.aud) {
    throw new Cs02VerifierResponseError(
      "Key Binding JWT is missing aud",
      "invalid_key_binding_jwt",
    );
  }
  if (expectedAudience && kbPayload.aud !== expectedAudience) {
    throw new Cs02VerifierResponseError(
      "Key Binding JWT aud does not match the expected verifier audience",
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
  if (Array.isArray(transactionData) && transactionData.length > 0) {
    if (kbPayload.transaction_data_hashes_alg !== "sha-256" || !Array.isArray(kbPayload.transaction_data_hashes)) {
      throw new Cs02VerifierResponseError("Key Binding JWT is missing transaction_data_hashes", "invalid_key_binding_jwt");
    }
    const expected = transactionData.map((entry) => createHash("sha256")
      .update(Buffer.from(entry, "base64url"))
      .digest("base64url"));
    if (expected.length !== kbPayload.transaction_data_hashes.length ||
        expected.some((hash, index) => hash !== kbPayload.transaction_data_hashes[index])) {
      throw new Cs02VerifierResponseError("Key Binding JWT transaction_data_hashes do not match the request", "invalid_key_binding_jwt");
    }
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
    if (path.every(isSupportedCs02ClaimPathSegment)) {
      names.add(path[0]);
    }
  }
  return names;
}

function assertSupportedSdJwtClaimPaths(credQuery) {
  for (const claim of credQuery?.claims || []) {
    try {
      validateSupportedCs02ClaimPath(claim?.path);
    } catch {
      throw new Cs02VerifierResponseError(
        `Unsupported SD-JWT DCQL claim path "${Array.isArray(claim?.path) ? claim.path.join(".") : "unknown"}"`,
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
  disclosureKeymap,
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
  const satisfiedClaimSet = selectSatisfiedSdJwtClaimSet(credQuery, reconstructedClaims);
  const claimsById = new Map(
    (credQuery?.claims || [])
      .filter((claim) => typeof claim?.id === "string" && claim.id.length > 0)
      .map((claim) => [claim.id, claim]),
  );
  const claimsToCheck = satisfiedClaimSet
    ? Array.from(satisfiedClaimSet).map((id) => claimsById.get(id)).filter(Boolean)
    : (credQuery?.claims || []);
  if (Array.isArray(credQuery?.claim_sets) && credQuery.claim_sets.length > 0 && !satisfiedClaimSet) {
    throw new Cs02VerifierResponseError(
      "SD-JWT-VC does not satisfy any DCQL claim_sets option",
      "invalid_credential",
    );
  }
  for (const claim of claimsToCheck) {
    if (Array.isArray(claim?.path) && getSdJwtPathValue(reconstructedClaims, claim.path) === undefined) {
      throw new Cs02VerifierResponseError(
        `SD-JWT-VC is missing requested claim path "${claim.path.join(".")}"`,
        "invalid_credential",
      );
    }
    if (Array.isArray(claim?.values) && claim.values.length > 0) {
      const actualValue = getSdJwtPathValue(reconstructedClaims, claim.path);
      if (typeof actualValue !== "string" || !claim.values.includes(actualValue)) {
        throw new Cs02VerifierResponseError(
          `SD-JWT-VC claim "${claim.path.join(".")}" does not satisfy requested DCQL values constraint`,
          "invalid_credential",
        );
      }
    }
  }

  if (rejectUnsolicitedDisclosures && Object.keys(disclosureKeymap || {}).length > 0) {
    const allowedPaths = new Set(
      claimsToCheck
        .filter((claim) => Array.isArray(claim?.path) && claim.path.length > 0)
        .map((claim) => claim.path.join(".")),
    );
    for (const disclosedPath of Object.keys(disclosureKeymap || {})) {
      const allowed = Array.from(allowedPaths).some(
        (path) => disclosedPath === path || disclosedPath.startsWith(`${path}.`) || path.startsWith(`${disclosedPath}.`),
      );
      if (!allowed) {
        throw new Cs02VerifierResponseError(
          `SD-JWT-VC includes unsolicited disclosed claim "${disclosedPath}"`,
          "invalid_credential",
        );
      }
    }
  }
}

async function resolveIssuerVerificationKey({ header, payload, context = {}, options = {} }) {
  const source = { ...options, ...context };
  if (source.issuerVerificationKey) return source.issuerVerificationKey;
  if (source.issuerVerificationJwk) return importJWK(source.issuerVerificationJwk, header.alg);
  if (typeof source.resolveIssuerVerificationKey === "function") {
    const key = await source.resolveIssuerVerificationKey({ header, payload });
    if (!key) return null;
    if (key.type === "public" || key.type === "private" || key.constructor?.name?.includes("Key")) return key;
    return importJWK(key, header.alg);
  }
  if (Array.isArray(source.issuerJwks?.keys)) {
    const jwk = source.issuerJwks.keys.find((candidate) => {
      if (header.kid && candidate.kid && candidate.kid !== header.kid) return false;
      if (candidate.use && candidate.use !== "sig") return false;
      if (candidate.alg && candidate.alg !== header.alg) return false;
      return true;
    });
    if (jwk) return importJWK(jwk, header.alg);
  }
  if (Array.isArray(header?.x5c) && typeof header.x5c[0] === "string" && header.x5c[0].length > 0) {
    const validChainEncoding = header.x5c.every((entry) =>
      typeof entry === "string" && entry.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(entry) && (() => {
        try { return Buffer.from(entry, "base64").length > 0; } catch { return false; }
      })(),
    );
    if (!validChainEncoding) {
      throw new Cs02VerifierResponseError(
        "SD-JWT-VC issuer x5c chain is malformed",
        "invalid_credential",
      );
    }
    const leafPem = `-----BEGIN CERTIFICATE-----\n${header.x5c[0].match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
    try {
      return await importX509(leafPem, header.alg);
    } catch {
      throw new Cs02VerifierResponseError(
        "SD-JWT-VC issuer x5c leaf cannot be used for signature verification",
        "invalid_credential",
      );
    }
  }
  return null;
}

export async function validateCs02SdJwtIssuerAuthenticity({
  sdJwt,
  credQuery,
  context = {},
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
  const verificationKey = await resolveIssuerVerificationKey({ header, payload: issuerPayload, context, options });
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

  let parsedClaims;
  try {
    parsedClaims = parseSdJwtClaims(sdJwt);
  } catch {
    throw new Cs02VerifierResponseError(
      "SD-JWT disclosure digest does not match issuer-signed payload",
      "invalid_credential",
    );
  }
  for (const disclosure of disclosures) {
    const digest = digestDisclosure(disclosure, issuerPayload?._sd_alg);
    if (!Object.values(parsedClaims.disclosureKeymap || {}).includes(digest)) {
      throw new Cs02VerifierResponseError(
        "SD-JWT disclosure digest does not match issuer-signed payload",
        "invalid_credential",
      );
    }
  }
  validateIssuerCredentialClaims({
    issuerPayload,
    reconstructedClaims: parsedClaims.claims,
    disclosureKeymap: parsedClaims.disclosureKeymap,
    credQuery,
    holderBindingRequired: options.holderBindingRequired !== false,
    rejectUnsolicitedDisclosures: options.rejectUnsolicitedDisclosures !== false,
    clockTolerance: options.clockTolerance ?? 300,
  });

  return {
    ok: true,
    header,
    issuerPayload,
    claims: parsedClaims.claims,
    disclosedClaimNames: Object.keys(parsedClaims.disclosureKeymap || {}),
    issuerSignature,
  };
}

export async function validateCs02SdJwtPresentation({
  sdJwt,
  sessionNonce,
  clientId,
  expectedAudience = clientId,
  transactionData,
  computeSdHash,
  credQuery,
  context = {},
  options = { strict: true },
}) {
  assertNoSessionInValidationOptions(options);
  if (!options.strict || typeof sdJwt !== "string" || sdJwt.length === 0) {
    return { ok: true };
  }

  const issuerAuthenticity = await validateCs02SdJwtIssuerAuthenticity({
    sdJwt,
    credQuery,
    context,
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
    expectedAudience,
    transactionData,
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
  const trustPolicyOptions = context.trustPolicyOptions || options.trustPolicyOptions || resolveCs02TrustPolicyOptions(context.env || options.env);
  const issuerTrust = await validateCs02IssuerTrust(issuerPayload?.iss, trustPolicyOptions);
  let credentialTrust = null;
  if (isTrustFrameworkSession(context.session)) {
    credentialTrust = await checkVerifierCredentialTrust({
      session: context.session,
      payload: issuerPayload,
      header: issuerAuthenticity.header,
      format: credQuery?.format || "dc+sd-jwt",
      vct: issuerPayload?.vct,
      operation: "verify-credential",
    });
    if (!credentialTrust?.trusted) {
      const trustError = new Cs02VerifierResponseError(
        `Credential issuer trust rejected: ${credentialTrust?.reasonCode || "TRUST_EVALUATION_INDETERMINATE"}`,
        "invalid_credential",
      );
      trustError.trustDecision = credentialTrust;
      throw trustError;
    }
  }
  let credentialStatus;
  try {
    credentialStatus = await validateCs02CredentialStatusList(sdJwt, {
      env: context.env || options.env,
      trustPolicyOptions,
      log: context.log || options.log,
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
    credentialTrust,
    credentialStatus,
  };
}

export function createCs02VerificationContext(input = {}) {
  const session = input.session || null;
  return {
    ...input,
    session,
    sessionNonce: input.sessionNonce ?? session?.nonce,
    clientId: input.clientId ?? session?.client_id,
    expectedAudience: input.expectedAudience ?? session?.expected_audience ?? session?.client_id,
    transactionData: input.transactionData ?? session?.transaction_data,
  };
}

export async function validateCs02SdJwtEntriesInVpToken(
  vpTokenObject,
  dcqlQuery,
  context,
  options = { strict: true },
) {
  assertNoSessionInValidationOptions(options);
  if (!options.strict || !isPlainObject(vpTokenObject)) return [];
  const verificationContext = createCs02VerificationContext(context);

  const decisions = [];

  for (const credQuery of dcqlQuery?.credentials || []) {
    const value = vpTokenObject[credQuery.id];
    if (value == null) continue;

    const presentations = Array.isArray(value) ? value : [value];
    if (String(credQuery?.format || "") === MDOC_FORMAT) {
      for (const presentation of presentations) {
        const mdocResult = validateCs02MdocPresentation({
          presentation,
          credQuery,
        });
        let credentialTrust = null;
        if (isTrustFrameworkSession(verificationContext.session)) {
          credentialTrust = await checkVerifierCredentialTrust({
            session: verificationContext.session,
            certificatePem: mdocResult?.issuerCertificate?.certificatePem,
            format: MDOC_FORMAT,
            doctype: credQuery?.meta?.doctype_value,
            operation: "verify-credential",
          });
          if (!credentialTrust?.trusted) {
            const trustError = new Cs02VerifierResponseError(
              `Credential issuer trust rejected: ${credentialTrust?.reasonCode || "TRUST_EVALUATION_INDETERMINATE"}`,
              "invalid_credential",
            );
            trustError.trustDecision = credentialTrust;
            throw trustError;
          }
        }
        decisions.push({ id: credQuery.id, format: MDOC_FORMAT, trust: credentialTrust });
      }
      continue;
    }

    if (!SD_JWT_FORMATS.has(String(credQuery?.format || ""))) continue;
    for (const presentation of presentations) {
      const result = await validateCs02SdJwtPresentation({
        sdJwt: presentation,
        sessionNonce: verificationContext.sessionNonce,
        clientId: verificationContext.clientId,
        expectedAudience: verificationContext.expectedAudience,
        transactionData: verificationContext.transactionData,
        computeSdHash: verificationContext.computeSdHash,
        credQuery,
        context: verificationContext,
        options,
      });
      decisions.push({ id: credQuery.id, format: credQuery.format, trust: result.credentialTrust || null });
    }
  }
  return decisions;
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

  const claimConstraints = Array.isArray(credQuery?.claims) ? credQuery.claims : [];
  if (claimConstraints.length > 0) {
    let claimsByNamespace;
    try {
      claimsByNamespace = extractMdocClaimsByNamespace(presentation, {
        fallbackDocType: actualDocType,
      }).claimsByNamespace;
    } catch {
      throw new Cs02VerifierResponseError(
        `Unable to decode mso_mdoc claims for DCQL credential "${credQuery?.id || "unknown"}"`,
        "invalid_credential",
      );
    }

    const satisfiedClaimSet = selectSatisfiedMdocClaimSet(credQuery, claimsByNamespace);
    const claimsById = new Map(
      claimConstraints
        .filter((claim) => typeof claim?.id === "string" && claim.id.length > 0)
        .map((claim) => [claim.id, claim]),
    );
    const claimsToCheck = satisfiedClaimSet
      ? Array.from(satisfiedClaimSet).map((id) => claimsById.get(id)).filter(Boolean)
      : claimConstraints;

    if (Array.isArray(credQuery?.claim_sets) && credQuery.claim_sets.length > 0 && !satisfiedClaimSet) {
      throw new Cs02VerifierResponseError(
        `mso_mdoc presentation does not satisfy any DCQL claim_sets option for credential "${credQuery?.id || "unknown"}"`,
        "invalid_credential",
      );
    }

    for (const claim of claimsToCheck) {
      if (!claimSatisfiesMdocConstraints(claim, claimsByNamespace)) {
        const path = Array.isArray(claim?.path) ? claim.path.join(".") : "unknown";
        if (Array.isArray(claim?.values) && claim.values.length > 0) {
          throw new Cs02VerifierResponseError(
            `mso_mdoc claim "${path}" does not satisfy requested DCQL values constraint`,
            "invalid_credential",
          );
        }
        throw new Cs02VerifierResponseError(
          `mso_mdoc is missing requested claim path "${path}"`,
          "invalid_credential",
        );
      }
    }
  }

  return {
    ok: true,
    doctype: actualDocType,
    issuerCertificate: extractMdocIssuerCertificate(presentation),
  };
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
