/**
 * WE BUILD CS-02 verifier-side presentation response validation.
 */

import {
  decodeProtectedHeader,
  decodeJwt,
  importJWK,
  jwtVerify,
} from "jose";
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

export async function validateCs02SdJwtPresentation({
  sdJwt,
  sessionNonce,
  clientId,
  computeSdHash,
  options = { strict: true },
}) {
  if (!options.strict || typeof sdJwt !== "string" || sdJwt.length === 0) {
    return { ok: true };
  }

  const kbJwt = extractKeyBindingJwtFromSdJwt(sdJwt);
  if (!kbJwt) {
    throw new Cs02VerifierResponseError(
      "SD-JWT-VC presentation is missing Key Binding JWT",
      "invalid_key_binding_jwt",
    );
  }

  const kbHeader = decodeProtectedHeader(kbJwt);
  const kbPayload = decodeJwt(kbJwt);
  const verified = await validateSdJwtKeyBindingMatchesCredential({ sdJwt });

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

  const issuerPayload = decodeJwt(sdJwt.split("~")[0]);
  await validateCs02IssuerTrust(issuerPayload?.iss, resolveCs02TrustPolicyOptions());
  try {
    await validateCs02CredentialStatusList(sdJwt);
  } catch (error) {
    if (error instanceof Cs02StatusListError) {
      throw new Cs02VerifierResponseError(error.message, error.errorCode);
    }
    throw error;
  }

  return verified;
}

export async function validateCs02SdJwtEntriesInVpToken(
  vpTokenObject,
  dcqlQuery,
  context,
  options = { strict: true },
) {
  if (!options.strict || !isPlainObject(vpTokenObject)) return;

  for (const credQuery of dcqlQuery?.credentials || []) {
    if (!SD_JWT_FORMATS.has(String(credQuery?.format || ""))) continue;
    const value = vpTokenObject[credQuery.id];
    if (value == null) continue;

    const presentations = Array.isArray(value) ? value : [value];
    for (const presentation of presentations) {
      await validateCs02SdJwtPresentation({
        sdJwt: presentation,
        sessionNonce: context.sessionNonce,
        clientId: context.clientId,
        computeSdHash: context.computeSdHash,
        options,
      });
    }
  }
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
