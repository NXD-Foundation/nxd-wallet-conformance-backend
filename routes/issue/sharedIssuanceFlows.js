import express from "express";
import fs from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";
import {
  pemToJWK,
  generateNonce,
  base64UrlEncodeSha256,
  jarOAutTokenResponse,
} from "../../utils/cryptoUtils.js";
import { resolveProofJwtPublicJwk } from "../../utils/proofJwtResolver.js";
import {
  buildAccessToken,
  generateRefreshToken,
  buildIdToken,
} from "../../utils/tokenUtils.js";

import {
  getAuthCodeSessions,
  getAuthCodeAuthorizationDetail,
} from "../../services/cacheService.js";

import {
  storePreAuthSession,
  getPreAuthSession,
  getSessionKeyFromAccessToken,
  getCodeFlowSession,
  storeCodeFlowSession,
  getSessionKeyAuthCode,
  getSessionAccessToken,
  resolveDeferredIssuanceContext,
  storeNonce,
  checkNonce,
  deleteNonce,
  checkAndSetPollTime,
  clearPollTime,
  logError,
  logInfo,
  logWarn,
  setSessionContext,
  clearSessionContext,
} from "../../services/cacheServiceRedis.js";
import { makeSessionLogger, logHttpRequest, logHttpResponse } from "../../utils/sessionLogger.js";

import * as jose from "jose";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import {
  createSignerVerifier,
  digest,
  generateSalt,
  createSignerVerifierX509,
  pemToBase64Der,
} from "../../utils/sdjwtUtils.js";
import jwt from "jsonwebtoken";

import {
  handleCredentialGenerationBasedOnFormat,
  handleCredentialGenerationBasedOnFormatDeferred,
} from "../../utils/credGenerationUtils.js";
import {
  validateWIA,
  validateWUA,
  extractWIAFromTokenRequest,
  extractWUAFromCredentialRequest,
  proofKeyMatchesWUAAttestedKeys,
  credentialConfigRequiresJwtProofKeyAttestation,
  assertOpenidCredentialAuthorizationDetails,
  resolveCredentialIdentifierFromOpenidCredentialEntry,
  getPublicIssuerBaseUrl,
} from "../../utils/routeUtils.js";
import {
  decryptCredentialRequestJwe,
  encryptCredentialResponseToJwe,
  validateCredentialResponseEncryptionForRequest,
  validateCredentialResponseEncryptionParams,
  getCredentialResponseEncryptionMetadata,
  INVALID_ENCRYPTION_PARAMETERS,
} from "../../utils/credentialResponseEncryption.js";
import {
  validateOAuthClientAttestationFromRequest,
  getTrustedClientAttesterJwks,
  assertWiaCnfMatchesClientAttestation,
} from "../../utils/oauthClientAttestation.js";
import {
  parseProofAttestationJwtFromCredentialProofs,
  verifyKeyAttestationProofChain,
} from "../../utils/keyAttestationProof.js";

const sharedRouter = express.Router();

// Configuration constants
const TOKEN_EXPIRES_IN = 86400;
const NONCE_EXPIRES_IN = 86400;

/** RFC001 P1-12 — one credential per distinct JWK in WUA / key-attestation `attested_keys`. */
async function dedupeAttestedKeysToCnfList(attestedKeys) {
  if (!Array.isArray(attestedKeys) || attestedKeys.length === 0) return [];
  const seen = new Set();
  const out = [];
  for (const jwk of attestedKeys) {
    if (!jwk || typeof jwk !== "object" || !jwk.kty) continue;
    try {
      const jkt = await jose.calculateJwkThumbprint(jwk, "sha256");
      if (seen.has(jkt)) continue;
      seen.add(jkt);
      out.push({ jwk });
    } catch {
      continue;
    }
  }
  return out;
}
const DPOP_MAX_IAT_SKEW_SECONDS = 300; // 5 minutes clock skew window
const DPOP_MAX_FUTURE_IAT_SKEW_SECONDS = 60; // allow small future skew

// OID4VCI 1.0 §9 / RFC001 §6.3, §7.6 — deferred credential polling policy.
//   DEFERRED_INTERVAL_SECONDS: retry hint returned in `interval` on both the
//     initial 202 from /credential and on subsequent `issuance_pending` errors.
//   DEFERRED_EXPIRES_IN_SECONDS: how long a `transaction_id` remains usable
//     before returning `expired_transaction_id`.
//   DEFERRED_PENDING_POLLS: number of polls to answer with `issuance_pending`
//     before the credential is declared ready. Defaults to 0 so that the
//     synchronous-on-poll generation path remains the default behavior.
const parseIntEnv = (name, fallback) => {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};
const getDeferredIntervalSeconds = () => parseIntEnv("DEFERRED_INTERVAL_SECONDS", 5);
const getDeferredExpiresInSeconds = () => parseIntEnv("DEFERRED_EXPIRES_IN_SECONDS", 900);
const getDeferredPendingPolls = () => parseIntEnv("DEFERRED_PENDING_POLLS", 0);

/** OpenID4VCI1.0 §8.2 — JWT proof header type */
const OID4VCI_PROOF_JWT_TYP = "openid4vci-proof+jwt";

// In-memory cache for DPoP jti replay detection (per-process)
// Maps jti -> iat (seconds since epoch)
const usedDpopJtis = new Map();
const dpopNonces = new Map(); // nonce -> { endpoint: string, used: boolean }

const isDpopJtiReplay = (jti, iatSeconds) => {
  const nowSeconds = Math.floor(Date.now() / 1000);

  // Garbage collect old entries outside replay window
  for (const [storedJti, storedIat] of usedDpopJtis.entries()) {
    if (storedIat < nowSeconds - DPOP_MAX_IAT_SKEW_SECONDS) {
      usedDpopJtis.delete(storedJti);
    }
  }

  const existingIat = usedDpopJtis.get(jti);
  if (existingIat && existingIat >= nowSeconds - DPOP_MAX_IAT_SKEW_SECONDS) {
    return true;
  }

  usedDpopJtis.set(jti, iatSeconds);
  return false;
};

/** @returns {string|null} JWK thumbprint from access token JWT `cnf.jkt`, or null if not DPoP-bound */
function getDpopBoundJktFromAccessToken(accessToken) {
  if (typeof accessToken !== "string" || !accessToken.trim()) return null;
  try {
    const parts = accessToken.split(".");
    if (parts.length !== 3) return null;
    const decoded = jwt.decode(accessToken, { complete: false });
    if (!decoded || typeof decoded !== "object") return null;
    const jkt = decoded.cnf?.jkt;
    return typeof jkt === "string" && jkt.trim() !== "" ? jkt.trim() : null;
  } catch {
    return null;
  }
}

/**
 * RFC 9449 / RFC001 P0-4 / P0-5 — DPoP proof for sender-constrained access token at a resource path (e.g. `/credential`, `/credential_deferred`).
 * @param {string} resourcePath — must start with `/` (e.g. `/credential_deferred`)
 * @throws {Error} `errorCode` `invalid_token` + `httpStatus` 401 (missing header), or `invalid_dpop_proof` (400)
 */
async function validateDpopProofForResourceRequest(
  req,
  accessToken,
  expectedJkt,
  resourcePath = "/credential",
) {
  const path =
    typeof resourcePath === "string" && resourcePath.startsWith("/")
      ? resourcePath
      : `/${resourcePath || "credential"}`;
  const dpopHeaderRaw = req.headers["dpop"];
  if (typeof dpopHeaderRaw !== "string" || !dpopHeaderRaw.trim()) {
    const err = new Error(
      `DPoP proof is required when using a sender-constrained (DPoP-bound) access token at this endpoint (${path}) (RFC 9449; RFC001 §7.5).`,
    );
    err.errorCode = "invalid_token";
    err.httpStatus = 401;
    throw err;
  }
  const dpopHeader = dpopHeaderRaw.trim();

  const protectedHeader = jose.decodeProtectedHeader(dpopHeader);
  if (!protectedHeader?.jwk) {
    const err = new Error(
      "DPoP proof protected header must include public key in 'jwk' (RFC 9449)"
    );
    err.errorCode = "invalid_dpop_proof";
    throw err;
  }

  const publicKey = await jose.importJWK(
    protectedHeader.jwk,
    protectedHeader.alg || "ES256",
  );

  const { payload } = await jose.jwtVerify(dpopHeader, publicKey, {
    clockTolerance: DPOP_MAX_FUTURE_IAT_SKEW_SECONDS,
  });

  const { htm, htu, iat, jti, ath } = payload;

  if (!htm || !htu || typeof iat === "undefined" || !jti) {
    const err = new Error(
      "DPoP proof is missing required claims (htm, htu, iat, jti)"
    );
    err.errorCode = "invalid_dpop_proof";
    throw err;
  }

  const expectedHtm = (req.method || "POST").toUpperCase();
  if (htm !== expectedHtm) {
    const err = new Error(
      `DPoP proof htm claim mismatch. Received: '${htm}', expected: '${expectedHtm}'`,
    );
    err.errorCode = "invalid_dpop_proof";
    throw err;
  }

  const expectedHtu = `${getPublicIssuerBaseUrl(req)}${path}`;
  if (htu !== expectedHtu) {
    const err = new Error(
      `DPoP proof htu claim mismatch. Received: '${htu}', expected: '${expectedHtu}'`,
    );
    err.errorCode = "invalid_dpop_proof";
    throw err;
  }

  const expectedAth = await base64UrlEncodeSha256(accessToken);
  if (ath !== expectedAth) {
    const err = new Error(
      "DPoP proof ath claim does not match SHA-256 hash of the access token (RFC 9449).",
    );
    err.errorCode = "invalid_dpop_proof";
    throw err;
  }

  const iatSeconds = typeof iat === "number" ? iat : parseInt(iat, 10);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(iatSeconds)) {
    const err = new Error(
      "DPoP proof iat claim is not a valid number of seconds since epoch",
    );
    err.errorCode = "invalid_dpop_proof";
    throw err;
  }
  if (
    iatSeconds < nowSeconds - DPOP_MAX_IAT_SKEW_SECONDS ||
    iatSeconds > nowSeconds + DPOP_MAX_FUTURE_IAT_SKEW_SECONDS
  ) {
    const err = new Error(
      "DPoP proof iat claim is outside the accepted time window",
    );
    err.errorCode = "invalid_dpop_proof";
    throw err;
  }

  if (isDpopJtiReplay(jti, iatSeconds)) {
    const err = new Error(
      "DPoP proof jti has already been used within the replay window",
    );
    err.errorCode = "invalid_dpop_proof";
    throw err;
  }

  const jkt = await jose.calculateJwkThumbprint(protectedHeader.jwk, "sha256");
  if (jkt !== expectedJkt) {
    const err = new Error(
      "DPoP proof key thumbprint does not match access token cnf.jkt binding (RFC001 §7.5).",
    );
    err.errorCode = "invalid_dpop_proof";
    throw err;
  }
}

// Specification references
const SPEC_REFS = {
  VCI_1_0: "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html",
  VCI_CREDENTIAL_REQUEST: "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request",
  VCI_PROOF: "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types",
  VP_1_0: "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html",
};

/** OAuth request string params (client_id, redirect_uri, …): trim; empty/absent → null */
function normalizeOAuthParam(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return s === "" ? null : s;
}

// Error messages
const ERROR_MESSAGES = {
  INVALID_REQUEST: "The request is missing the 'code' or 'pre-authorized_code' parameter.",
  INVALID_GRANT: "Invalid or expired pre-authorized code.",
  INVALID_GRANT_CODE: "Invalid or expired authorization code or session not found.",
  CLIENT_ID_MISMATCH_AUTHZ: "client_id does not match the client_id from the authorization request (PAR/authorize).",
  REDIRECT_URI_MISMATCH_AUTHZ:
    "redirect_uri does not match the redirect_uri from the authorization request (PAR/authorize).",
  PKCE_FAILED: "PKCE verification failed.",
  UNSUPPORTED_GRANT: "Grant type is not supported.",
  INVALID_CREDENTIAL_REQUEST: "Must provide exactly one of credential_identifier or credential_configuration_id",
  INVALID_CREDENTIAL_IDENTIFIER: "Credential identifier is not supported",
  INVALID_CREDENTIAL_CONFIGURATION_ID: "Credential configuration ID is not supported",
  INVALID_PROOF: "No proof information found",
  INVALID_PROOF_MALFORMED: "Proof JWT is malformed or missing algorithm.",
  INVALID_PROOF_ALGORITHM: "Proof JWT uses an unsupported algorithm",
  INVALID_PROOF_PUBLIC_KEY: "Public key for proof verification not found in JWT header.",
  INVALID_PROOF_UNABLE: "Unable to determine public key for proof verification.",
  INVALID_PROOF_SIGNATURE: "Proof JWT signature verification failed",
  INVALID_PROOF_ISS: "Proof JWT is missing sender identifier (iss claim).",
  INVALID_PROOF_TYP: "Proof JWT must use typ openid4vci-proof+jwt in the JWT header (OpenID4VCI1.0 §8.2)",
  INVALID_PROOF_NONCE: "Proof JWT nonce is invalid, expired, or already used.",
  INVALID_TRANSACTION: "Invalid transaction ID",
  SERVER_ERROR: "An error occurred during proof validation.",
  SESSION_LOST: "Session lost after proof validation.",
  CREDENTIAL_DENIED: "Credential request denied",
  STORAGE_FAILED: "Storage operation failed",
  NONCE_GENERATION_FAILED: "Nonce generation failed",
  AUTHORIZATION_PENDING: "Authorization pending",
  SLOW_DOWN: "Slow down"
};


/** OAuth/OID4VCI error names attached as `errorCode` on Errors from validateCredentialRequest */
const CREDENTIAL_REQUEST_ERROR_CODES = {
  INVALID_CREDENTIAL_REQUEST: "invalid_credential_request",
  UNKNOWN_CREDENTIAL_CONFIGURATION: "unknown_credential_configuration",
  UNKNOWN_CREDENTIAL_IDENTIFIER: "unknown_credential_identifier",
};


/** OID4VCI 1.0 §8.3.1 — error code invalid_nonce + optional fresh c_nonce for retry */
async function respondInvalidNonceCredentialError(res, error, ctx) {
  const { sessionObject, sessionKey, flowType, sessionId } = ctx;
  const errorResponse = {
    error: "invalid_nonce",
    error_description: error.message,
  };
  try {
    const refreshedNonce = generateNonce();
    await storeNonce(refreshedNonce, NONCE_EXPIRES_IN);
    if (sessionObject && sessionKey) {
      sessionObject.c_nonce = refreshedNonce;
      if (flowType === "code") {
        await storeCodeFlowSession(sessionKey, sessionObject);
      } else {
        await storePreAuthSession(sessionKey, sessionObject);
      }
    }
    errorResponse.c_nonce = refreshedNonce;
    errorResponse.c_nonce_expires_in = NONCE_EXPIRES_IN;
  } catch (nonceError) {
    console.error("Failed to issue refreshed c_nonce after invalid_nonce:", nonceError);
    if (sessionId) {
      await logError(sessionId, "Failed to issue refreshed c_nonce after invalid_nonce", {
        error: nonceError.message,
      }).catch(() => {});
    }
  }
  return res.status(400).json(errorResponse);
}


function credentialValidationError(message, errorCode) {
  const err = new Error(message);
  err.errorCode = errorCode;
  return err;
}

// Helper function to extract sessionId from sessionKey
// sessionKey can be in format "code-flow-sessions:uuid" or just "uuid"
const extractSessionId = (sessionKey) => {
  if (!sessionKey) return null;
  // If sessionKey contains a colon, extract the part after it
  const parts = sessionKey.split(':');
  return parts.length > 1 ? parts[parts.length - 1] : sessionKey;
};

// Helper to load issuer configuration
const loadIssuerConfig = () => {
  try {
    const configPath = path.join(process.cwd(), "data", "issuer-config.json");
    const configFile = fs.readFileSync(configPath, "utf-8");
    return JSON.parse(configFile);
  } catch (error) {
    console.error("Error loading issuer config:", error);
    throw new Error("Failed to load issuer configuration");
  }
};

// Load cryptographic keys
const loadCryptographicKeys = () => {
  try {
    const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
    const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
    const privateKeyPemX509 = fs.readFileSync("./x509EC/ec_private_pkcs8.key", "utf8");
    const certificatePemX509 = fs.readFileSync("./x509EC/client_certificate.crt", "utf8");

    return {
      privateKey,
      publicKeyPem,
      privateKeyPemX509,
      certificatePemX509
    };
  } catch (error) {
    console.error("Error loading cryptographic keys:", error);
    throw new Error("Failed to load cryptographic keys");
  }
};

// Initialize cryptographic components
const initializeCrypto = async () => {
  try {
    const keys = loadCryptographicKeys();
    const { signer, verifier } = await createSignerVerifierX509(
      keys.privateKeyPemX509,
      keys.certificatePemX509
    );
    return { signer, verifier, keys };
  } catch (error) {
    console.error("Error initializing crypto:", error);
    throw new Error("Failed to initialize cryptographic components");
  }
};

// Parse authorization details (token endpoint). When the client sends
// authorization_details, validation failures use OAuth invalid_request.
const parseAuthorizationDetails = (authorizationDetails) => {
  if (!authorizationDetails) return null;

  let parsedAuthDetails;
  try {
    parsedAuthDetails = authorizationDetails;

    // If it's a string, it might be URL-encoded JSON
    if (typeof parsedAuthDetails === "string") {
      parsedAuthDetails = JSON.parse(decodeURIComponent(parsedAuthDetails));
    }
  } catch (error) {
    const err = new Error(
      `Invalid authorization_details JSON: ${error.message}. See ${SPEC_REFS.VCI_1_0}`
    );
    err.errorCode = "invalid_request";
    throw err;
  }

  try {
    assertOpenidCredentialAuthorizationDetails(parsedAuthDetails);
  } catch (e) {
    const err = new Error(e.message);
    err.errorCode = e.errorCode || e.oauthErrorCode || "invalid_request";
    throw err;
  }

  return parsedAuthDetails;
};

/** Token response echoes authorization_details with credential_identifiers on each element (explicit own properties for JSON serialization). */
const buildTokenResponseAuthorizationDetails = (parsedAuthDetails) => {
  if (!parsedAuthDetails || !Array.isArray(parsedAuthDetails)) {
    return undefined;
  }
  return parsedAuthDetails.map((entry) => {
    const chosenId = resolveCredentialIdentifierFromOpenidCredentialEntry(entry);
    if (!chosenId) {
      const err = new Error(
        `authorization_details entry is missing a credential identifier (credential_configuration_id or equivalent). See ${SPEC_REFS.VCI_1_0}`,
      );
      err.errorCode = "invalid_request";
      throw err;
    }
    return {
      ...entry,
      credential_identifiers: [chosenId],
    };
  });
};

  // Validate credential request parameters
const validateCredentialRequest = (requestBody, sessionId = null) => {
  const { credential_identifier, credential_configuration_id } = requestBody;

  if ((credential_identifier && credential_configuration_id) ||
      (!credential_identifier && !credential_configuration_id)) {
    const received = credential_identifier && credential_configuration_id
      ? "both credential_identifier and credential_configuration_id"
      : "neither credential_identifier nor credential_configuration_id";
    throw credentialValidationError(
      `${ERROR_MESSAGES.INVALID_CREDENTIAL_REQUEST}. Received: ${received}, expected: exactly one`,
      CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST
    );
  }

  const issuerConfigForCredentialId = loadIssuerConfig();
  const credConfig =
    issuerConfigForCredentialId.credential_configurations_supported[
      credential_configuration_id
    ] ||
    issuerConfigForCredentialId.credential_configurations_supported[
      credential_identifier
    ];
  if (!credConfig) {
    if (credential_configuration_id) {
      throw credentialValidationError(
        `${ERROR_MESSAGES.INVALID_CREDENTIAL_CONFIGURATION_ID}. Received: credential_configuration_id '${credential_configuration_id}' not found in issuer metadata`,
        CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_CONFIGURATION
      );
    }
    throw credentialValidationError(
      `${ERROR_MESSAGES.INVALID_CREDENTIAL_IDENTIFIER}. Received: credential_identifier '${credential_identifier}' not found in issuer metadata`,
      CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_IDENTIFIER
    );
  }

 



  // Log credential request validation details
  if (sessionId) {
    logInfo(sessionId, "Validating credential request", {
      credential_configuration_id,
      credential_identifier,
      hasProofs: !!requestBody.proofs,
      hasProof: !!requestBody.proof,
      proofTypes: requestBody.proofs ? Object.keys(requestBody.proofs) : []
    }).catch(() => {});
  }

  // V1.0 requires proofs (plural) - reject legacy proof (singular)
  if (requestBody.proof) {
    if (sessionId) {
      logError(sessionId, "Invalid proof format: received 'proof' (singular), expected 'proofs' (plural)", {
        receivedProofType: "singular",
        expectedProofType: "plural",
        specRef: SPEC_REFS.VCI_PROOF
      }).catch(() => {});
    }
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}: V1.0 requires 'proofs' (plural), not 'proof' (singular). See ${SPEC_REFS.VCI_PROOF}`);
  }

  if (!requestBody.proofs) {
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}. Received: proofs is ${typeof requestBody.proofs}, expected: non-null object. See ${SPEC_REFS.VCI_CREDENTIAL_REQUEST}`);
  }
  
  if (typeof requestBody.proofs !== 'object' || Array.isArray(requestBody.proofs)) {
    const receivedType = Array.isArray(requestBody.proofs) ? 'array' : typeof requestBody.proofs;
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}. Received: proofs is ${receivedType}, expected: non-array object. See ${SPEC_REFS.VCI_CREDENTIAL_REQUEST}`);
  }

  // V1.0 requires exactly one proof type
  const proofTypes = Object.keys(requestBody.proofs);
  if (proofTypes.length !== 1) {
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}: V1.0 requires exactly one proof type in proofs object. Received: ${proofTypes.length} proof type(s) [${proofTypes.join(', ')}], expected: exactly 1. See ${SPEC_REFS.VCI_PROOF}`);
  }

  // Get the proof type (jwt, mso_mdoc, etc.)
  const proofType = proofTypes[0];
  const proofValue = requestBody.proofs[proofType];

  // Ensure proof value exists
  if (!proofValue || (typeof proofValue === 'string' && proofValue.trim() === '')) {
    const received = !proofValue ? 'null/undefined' : 'empty string';
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}: proof value is missing or empty. Received: ${received}, expected: non-empty string or array`);
  }

  // Proof kind routing (see /credential handler for intuition: jwt PoP vs jwt+attestation vs proofs.attestation).
  // RFC001 §7.5.1 / OID4VCI 1.0 — proofs.jwt MUST be a JSON array containing exactly one JWT string.
  if (proofType === "jwt") {
    requestBody.credentialRequestProofKind = "jwt";
    if (typeof proofValue === "string") {
      throw new Error(
        `${ERROR_MESSAGES.INVALID_PROOF}: proofs.jwt MUST be a JSON array containing exactly one proof JWT (RFC001 §7.5.1). Received: string, expected: array of length 1. See ${SPEC_REFS.VCI_PROOF}`
      );
    }
    if (!Array.isArray(proofValue)) {
      throw new Error(
        `${ERROR_MESSAGES.INVALID_PROOF}: proofs.jwt must be an array. Received: ${typeof proofValue}, expected: array with exactly 1 element. See ${SPEC_REFS.VCI_PROOF}`
      );
    }
    if (proofValue.length !== 1) {
      const received =
        proofValue.length === 0 ? "empty array" : `array with ${proofValue.length} elements`;
      throw new Error(
        `${ERROR_MESSAGES.INVALID_PROOF}: proofs.jwt MUST contain exactly one JWT. Received: ${received}, expected: array of length 1 (RFC001 §7.5.1). See ${SPEC_REFS.VCI_PROOF}`
      );
    }
    const singleJwt = proofValue[0];
    if (typeof singleJwt !== "string" || singleJwt.trim() === "") {
      throw new Error(
        `${ERROR_MESSAGES.INVALID_PROOF}: proofs.jwt[0] must be a non-empty compact JWT string. See ${SPEC_REFS.VCI_PROOF}`
      );
    }
    requestBody.proofJwt = singleJwt;
  } else if (proofType === "attestation") {
    // Key attestation as its own proof type (not holder PoP in proofs.jwt); credential must advertise attestation support.
    if (!credConfig?.proof_types_supported?.attestation) {
      const id = credential_configuration_id || credential_identifier;
      throw new Error(
        `${ERROR_MESSAGES.INVALID_PROOF}: Credential configuration '${id}' does not support proof type 'attestation'. See ${SPEC_REFS.VCI_PROOF}`
      );
    }
    requestBody.credentialRequestProofKind = "attestation";
    requestBody.proofAttestationJwt = parseProofAttestationJwtFromCredentialProofs(
      proofValue,
      SPEC_REFS.VCI_PROOF
    );
  } else {
    // For other proof types, store as-is for now
    requestBody.proofJwt = proofValue;
  }

  validateCredentialResponseEncryptionForRequest(requestBody, loadIssuerConfig());

  return credential_configuration_id || credential_identifier;
};

/** OID4VCI 1.0: JWE credential request (application/jwt) or JSON (application/json). */
async function parseCredentialEndpointBody(req) {
  const raw = req.body;
  if (typeof raw === "string" && raw.trim().length > 0) {
    const pem = loadCryptographicKeys().privateKey;
    return await decryptCredentialRequestJwe(raw.trim(), pem);
  }
  if (typeof raw === "object" && raw !== null) {
    return raw;
  }
  throw credentialValidationError(
    "Invalid credential request body",
    CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST
  );
}

/** Success responses: JSON, or compact JWE with Content-Type application/jwt when encryption requested. */
async function sendCredentialSuccessResponse(res, statusCode, payload, requestBody) {
  const cre = requestBody?.credential_response_encryption;
  res.set("Cache-Control", "no-store");
  if (cre) {
    const issuerConfig = loadIssuerConfig();
    const jwe = await encryptCredentialResponseToJwe(payload, cre, issuerConfig);
    res.type("application/jwt");
    return res.status(statusCode).send(jwe);
  }
  return res.status(statusCode).json(payload);
}

// Validate proof JWT (OpenID4VCI1.0 §8.2 / RFC001 §7.5): typ openid4vci-proof+jwt always; signing alg allow-list when metadata defines it.
const validateProofJWT = (proofJwt, effectiveConfigurationId, sessionId = null) => {
  const issuerConfig = loadIssuerConfig();
  const credConfig = issuerConfig.credential_configurations_supported[effectiveConfigurationId];

  if (!credConfig) {
    throw new Error(`Credential configuration ID '${effectiveConfigurationId}' not found.`);
  }

  const decodedProofHeader = jwt.decode(proofJwt, { complete: true })?.header;
  if (!decodedProofHeader || !decodedProofHeader.alg) {
    const received = !decodedProofHeader ? 'missing header' : `header without alg (header keys: ${Object.keys(decodedProofHeader || {}).join(', ')})`;
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_MALFORMED}. Received: ${received}, expected: header with alg property. See ${SPEC_REFS.VCI_PROOF}`);
  }

  const proofTyp = decodedProofHeader.typ;
  if (proofTyp !== OID4VCI_PROOF_JWT_TYP) {
    const received =
      proofTyp === undefined || proofTyp === null ? "missing typ" : `'${proofTyp}'`;
    throw new Error(
      `${ERROR_MESSAGES.INVALID_PROOF_TYP}. Received: ${received}, expected: '${OID4VCI_PROOF_JWT_TYP}'. See ${SPEC_REFS.VCI_PROOF}`
    );
  }

  if (!credConfig.proof_types_supported?.jwt) {
    if (sessionId) {
      logWarn(sessionId, "No JWT proof type configuration found, skipping proof signing algorithm allow-list check", {
        effectiveConfigurationId,
        availableProofTypes: Object.keys(credConfig.proof_types_supported || {})
      }).catch(() => {});
    }
    return decodedProofHeader;
  }

  const supportedAlgs = credConfig.proof_types_supported.jwt.proof_signing_alg_values_supported;
  if (!supportedAlgs || supportedAlgs.length === 0) {
    if (sessionId) {
      logWarn(sessionId, "No proof signing algorithms defined, skipping proof signing algorithm allow-list check", {
        effectiveConfigurationId,
        supportedAlgorithms: supportedAlgs
      }).catch(() => {});
    }
    return decodedProofHeader;
  }

  if (!supportedAlgs.includes(decodedProofHeader.alg)) {
    throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_ALGORITHM}. Received: '${decodedProofHeader.alg}', expected: one of [${supportedAlgs.join(", ")}]. See ${SPEC_REFS.VCI_PROOF}`);
  }

  return decodedProofHeader;
};

// Verify proof JWT signature and claims
const verifyProofJWT = async (
  proofJwt,
  publicKeyForProof,
  flowType,
  sessionId = null,
  httpReq = null,
) => {
  try {
    // Verify signature and other claims
    // Note: Nonce validation is done earlier in the credential endpoint handler
    // to prioritize PoP failure recovery
    const proofPayload = jwt.verify(
      proofJwt,
      await publicKeyToPem(publicKeyForProof),
      {
        algorithms: [jwt.decode(proofJwt, { complete: true })?.header?.alg],
        audience: getPublicIssuerBaseUrl(httpReq),
      }
    );

    // Holder PoP in proofs.jwt (OpenID4VCI1.0 §8.2; RFC001 §7.5): iss required in every flow.
    // proofs.attestation uses verifyKeyAttestationProofChain (key-attestation JWT), not this path.
    if (!proofPayload.iss) {
      throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_ISS}. Received: payload without iss claim, expected: payload with iss claim. See ${SPEC_REFS.VCI_PROOF}`);
    }

    if (sessionId) {
      logInfo(sessionId, "Proof JWT signature and claims validated successfully", {
        walletIssuer: proofPayload.iss,
        nonceVerified: true,
        flowType
      }).catch(() => {});
    }
    return proofPayload;
  } catch (error) {
    if (error.message.includes("signature verification failed")) {
      throw new Error(`${ERROR_MESSAGES.INVALID_PROOF_SIGNATURE}: ${error.message}`);
    }
    
    throw error;
  }
};

// Get session object from token
const getSessionFromToken = async (token) => {
  let sessionObject;
  let flowType = "pre-auth";
  let sessionKey;

  const preAuthsessionKey = await getSessionKeyFromAccessToken(token);
  if (preAuthsessionKey) {
    const preAuthSession = await getPreAuthSession(preAuthsessionKey);
    if (preAuthSession) {
      sessionObject = preAuthSession;
      sessionKey = preAuthsessionKey;
    } else {
      const codeSession = await getCodeFlowSession(preAuthsessionKey);
      if (codeSession) {
        sessionObject = codeSession;
        sessionKey = preAuthsessionKey;
        flowType = "code";
      }
    }
  }

  if (!sessionObject) {
    const codeSessionKey = await getSessionAccessToken(token);
    if (codeSessionKey) {
      const codeSession = await getCodeFlowSession(codeSessionKey);
      if (codeSession) {
        sessionObject = codeSession;
        sessionKey = codeSessionKey;
        flowType = "code";
      }
    }
  }

  return { sessionObject, flowType, sessionKey };
};


// Handle pre-authorized code flow
const handlePreAuthorizedCodeFlow = async (
  preAuthorizedCode,
  authorizationDetails,
  dpopCnf = null,
  txCodeFromRequest = undefined,
  httpReq = null,
) => {
  const existingPreAuthSession = await getPreAuthSession(preAuthorizedCode);
  
  if (!existingPreAuthSession) {
    throw new Error(`${ERROR_MESSAGES.INVALID_GRANT}. Received: pre-authorized_code '${preAuthorizedCode}' not found or expired, expected: valid, unexpired pre-authorized_code`);
  }

  if (existingPreAuthSession.requireTxCode) {
    const normalizedTxCode =
      txCodeFromRequest === undefined || txCodeFromRequest === null
        ? ""
        : String(txCodeFromRequest).trim();
    if (!normalizedTxCode) {
      throw new Error(
        `${ERROR_MESSAGES.INVALID_GRANT} Received: missing or empty tx_code, expected: non-empty tx_code in token request because the credential offer included tx_code (RFC001 §6.2.6 / OID4VCI 1.0).`,
      );
    }
  }

  // Check if authorization is still pending external completion
  if (existingPreAuthSession.status === 'pending_external') {
    // Atomically check and set poll time using Redis (thread-safe)
    // Returns false if polled too recently (within minPollIntervalSeconds)
    const minPollIntervalSeconds = 5;
    const pollAllowed = await checkAndSetPollTime(preAuthorizedCode, minPollIntervalSeconds);
    
    if (!pollAllowed) {
      const error = new Error(ERROR_MESSAGES.SLOW_DOWN);
      error.errorCode = 'slow_down';
      throw error;
    }
    
    // Return authorization_pending error
    const error = new Error(ERROR_MESSAGES.AUTHORIZATION_PENDING);
    error.errorCode = 'authorization_pending';
    throw error;
  }

  const parsedAuthDetails = parseAuthorizationDetails(authorizationDetails);

  const generatedAccessToken = buildAccessToken(
    getPublicIssuerBaseUrl(httpReq),
    loadCryptographicKeys().privateKey,
    dpopCnf
  );
  const cNonceForSession = generateNonce();
  await storeNonce(cNonceForSession, NONCE_EXPIRES_IN);

  // Update session
  existingPreAuthSession.accessToken = generatedAccessToken;
  existingPreAuthSession.c_nonce = cNonceForSession;

  await storePreAuthSession(preAuthorizedCode, existingPreAuthSession);

  // Clear poll tracking for successful issuance
  await clearPollTime(preAuthorizedCode);

  // Prepare response (OpenID4VCI1.0 §6.1.5 / §7.4 — c_nonce for proof construction)
  const tokenResponse = {
    access_token: generatedAccessToken,
    refresh_token: generateRefreshToken(),
    token_type: "DPoP",
    expires_in: TOKEN_EXPIRES_IN,
    c_nonce: cNonceForSession,
    c_nonce_expires_in: NONCE_EXPIRES_IN,
  };

  if (parsedAuthDetails) {
    tokenResponse.authorization_details =
      buildTokenResponseAuthorizationDetails(parsedAuthDetails);
  }

  return tokenResponse;
};

// Handle authorization code flow
const handleAuthorizationCodeFlow = async (
  code,
  code_verifier,
  authorizationDetails,
  dpopCnf = null,
  tokenRequestClientId = undefined,
  tokenRequestRedirectUri = undefined,
  httpReq = null,
) => {
  const issuanceSessionId = await getSessionKeyAuthCode(code);
  
  if (!issuanceSessionId) {
    throw new Error(`${ERROR_MESSAGES.INVALID_GRANT_CODE}. Received: authorization code '${code}' not found or expired, expected: valid, unexpired authorization code`);
  }

  const existingCodeSession = await getCodeFlowSession(issuanceSessionId);
  
  if (!existingCodeSession) {
    throw new Error(`${ERROR_MESSAGES.INVALID_GRANT_CODE}. Received: session '${issuanceSessionId}' not found for authorization code '${code}', expected: valid session`);
  }

  // RFC001 §7.3–7.4 / P0-2: client_id at token MUST match PAR/authorize when bound
  const boundClientId = normalizeOAuthParam(
    existingCodeSession.authorizationRequestClientId,
  );
  const presentedClientId = normalizeOAuthParam(tokenRequestClientId);
  if (boundClientId !== null) {
    if (presentedClientId === null || presentedClientId !== boundClientId) {
      try {
        existingCodeSession.status = "failed";
        if (existingCodeSession.results) {
          existingCodeSession.results.status = "failed";
        }
        existingCodeSession.error = "invalid_grant";
        existingCodeSession.error_description =
          ERROR_MESSAGES.CLIENT_ID_MISMATCH_AUTHZ;
        await storeCodeFlowSession(
          existingCodeSession.results?.issuerState || issuanceSessionId,
          existingCodeSession,
        );
      } catch (storageError) {
        console.error(
          "Failed to update session after client_id mismatch:",
          storageError,
        );
      }
      throw new Error(
        `${ERROR_MESSAGES.INVALID_GRANT_CODE} ${ERROR_MESSAGES.CLIENT_ID_MISMATCH_AUTHZ}`,
      );
    }
  }

  // RFC001 §6.1.5 / §7.4 / P0-3: redirect_uri at token MUST match PAR/authorize when bound
  const boundRedirectUri = normalizeOAuthParam(
    existingCodeSession.requests?.redirectUri,
  );
  const presentedRedirectUri = normalizeOAuthParam(tokenRequestRedirectUri);
  if (boundRedirectUri !== null) {
    if (
      presentedRedirectUri === null ||
      presentedRedirectUri !== boundRedirectUri
    ) {
      try {
        existingCodeSession.status = "failed";
        if (existingCodeSession.results) {
          existingCodeSession.results.status = "failed";
        }
        existingCodeSession.error = "invalid_grant";
        existingCodeSession.error_description =
          ERROR_MESSAGES.REDIRECT_URI_MISMATCH_AUTHZ;
        await storeCodeFlowSession(
          existingCodeSession.results?.issuerState || issuanceSessionId,
          existingCodeSession,
        );
      } catch (storageError) {
        console.error(
          "Failed to update session after redirect_uri mismatch:",
          storageError,
        );
      }
      throw new Error(
        `${ERROR_MESSAGES.INVALID_GRANT_CODE} ${ERROR_MESSAGES.REDIRECT_URI_MISMATCH_AUTHZ}`,
      );
    }
  }

  // Verify PKCE
  const pkceVerified = await validatePKCE(
    existingCodeSession,
    code_verifier,
    existingCodeSession.requests?.challenge,
    issuanceSessionId
  );

  if (!pkceVerified) {
    // Mark session as failed when PKCE verification fails
    try {
      existingCodeSession.status = "failed";
      existingCodeSession.results.status = "failed";
      existingCodeSession.error = "invalid_grant";
      existingCodeSession.error_description = ERROR_MESSAGES.PKCE_FAILED;
      
      await storeCodeFlowSession(
        existingCodeSession.results.issuerState,
        existingCodeSession
      );
    } catch (storageError) {
      console.error("Failed to update session status after PKCE failure:", storageError);
    }
    
    throw new Error(ERROR_MESSAGES.PKCE_FAILED);
  }

  const parsedAuthDetails = parseAuthorizationDetails(authorizationDetails);

  // RFC001 §7.4 / RFC 9449: sender-constrained access tokens are mandatory.
  // When the authorization/PAR phase recorded an expected DPoP thumbprint for this code,
  // the DPoP key presented at the token endpoint MUST match that thumbprint.
  if (
    existingCodeSession.expectedDpopJkt &&
    dpopCnf &&
    typeof dpopCnf.jkt === "string"
  ) {
    if (dpopCnf.jkt !== existingCodeSession.expectedDpopJkt) {
      const err = new Error(
        "DPoP key thumbprint does not match expected session binding (RFC001 §7.4)"
      );
      err.errorCode = "invalid_dpop_proof";
      throw err;
    }
  }

  const generatedAccessToken = buildAccessToken(
    getPublicIssuerBaseUrl(httpReq),
    loadCryptographicKeys().privateKey,
    dpopCnf
  );
  const cNonceForSession = generateNonce();
  await storeNonce(cNonceForSession, NONCE_EXPIRES_IN);

  // Update session
  existingCodeSession.requests.accessToken = generatedAccessToken;
  existingCodeSession.c_nonce = cNonceForSession;

  await storeCodeFlowSession(
    existingCodeSession.results.issuerState,
    existingCodeSession
  );

  // Prepare response (OpenID4VCI1.0 §6.1.5 / §7.4 — c_nonce for proof construction)
  const tokenResponse = {
    access_token: generatedAccessToken,
    refresh_token: generateRefreshToken(),
    token_type: "DPoP",
    expires_in: TOKEN_EXPIRES_IN,
    c_nonce: cNonceForSession,
    c_nonce_expires_in: NONCE_EXPIRES_IN,
  };

  if (parsedAuthDetails) {
    tokenResponse.authorization_details =
      buildTokenResponseAuthorizationDetails(parsedAuthDetails);
  }

  return tokenResponse;
};

// Handle immediate credential issuance
const handleImmediateCredentialIssuance = async (
  requestBody,
  sessionObject,
  effectiveConfigurationId,
  sessionId = null,
  httpReq = null,
) => {
  // Determine format from credential configuration (VCI v1.0 requirement)
  const issuerConfig = loadIssuerConfig();
  const credConfig = issuerConfig.credential_configurations_supported[effectiveConfigurationId];
  if (!credConfig) {
    const availableConfigs = Object.keys(issuerConfig.credential_configurations_supported || {}).join(', ') || 'none';
    throw new Error(`Credential configuration not found. Received: '${effectiveConfigurationId}', expected: one of [${availableConfigs}]`);
  }

  requestBody.vct =
    credConfig.vct || credConfig.doctype || effectiveConfigurationId;

  // Determine format - default to 'dc+sd-jwt' for backward compatibility
  let format = credConfig.format || 'dc+sd-jwt';

  // RFC001 ETSI `vc+jwt` (JSON-LD VC + JOSE) uses the same path as OID4VCI `jwt_vc_json`.
  if (format === 'vc+jwt') {
    format = 'jwt_vc_json';
  }

  // Map VCI v1.0 format identifiers to internal format identifiers
  if (format === 'mso_mdoc') {
    format = 'mDL'; // Use 'mDL' for internal processing
  }

  const cnfList = requestBody._credentialBindingCnfList;
  if (Array.isArray(cnfList) && cnfList.length > 0) {
    const credentials = [];
    for (const holderCnf of cnfList) {
      const credential = await handleCredentialGenerationBasedOnFormat(
        { ...requestBody, _overrideHolderCnf: holderCnf, _credentialBindingCnfList: undefined },
        sessionObject,
        getPublicIssuerBaseUrl(httpReq),
        format
      );
      credentials.push({ credential });
    }
    if (sessionId) {
      logInfo(sessionId, "Credentials generated (multi-key)", {
        credentialFormat: format,
        count: credentials.length,
        effectiveConfigurationId,
      }).catch(() => {});
    }
    return { credentials, notification_id: uuidv4() };
  }

  const credential = await handleCredentialGenerationBasedOnFormat(
    requestBody,
    sessionObject,
    getPublicIssuerBaseUrl(httpReq),
    format
  );

  if (sessionId) {
    logInfo(sessionId, "Credential generated successfully", {
      credentialFormat: format,
      credentialLength: credential.length,
      effectiveConfigurationId
    }).catch(() => {});
  }

  // Generate notification_id for this issuance flow
  const notification_id = uuidv4();

  return {
    credentials: [{ credential }],
    notification_id
  };
};

// Handle deferred credential issuance
const handleDeferredCredentialIssuance = async (requestBody, sessionObject, sessionKey, flowType) => {
  const transaction_id = generateNonce();
  const notification_id = uuidv4();

  if (!requestBody.vct) {
    requestBody.vct =
      requestBody.credential_configuration_id || requestBody.credential_identifier;
  }

  const nowSeconds = Math.floor(Date.now() / 1000);

  sessionObject.transaction_id = transaction_id;
  sessionObject.notification_id = notification_id;
  sessionObject.requestBody = requestBody;
  // RFC001 §6.3 / OID4VCI 1.0 §9 — readiness is tracked per session; defaults
  // to "not ready" so /credential_deferred responds with `issuance_pending`
  // until the backend flips this flag (or, under the default policy below,
  // after DEFERRED_PENDING_POLLS polls have elapsed).
  sessionObject.isCredentialReady = false;
  sessionObject.deferred_poll_count = 0;
  sessionObject.deferred_created_at = nowSeconds;
  sessionObject.deferred_expires_at = nowSeconds + getDeferredExpiresInSeconds();
  sessionObject.attempt = 0;

  if (flowType === "code") {
    await storeCodeFlowSession(sessionKey, sessionObject);
  } else {
    await storePreAuthSession(sessionKey, sessionObject);
  }

  return {
    transaction_id,
    interval: getDeferredIntervalSeconds() // OID4VCI 1.0 §9 / RFC001 §6.3, §7.6
  };
};

// *****************************************************************
// ************* TOKEN ENDPOINTS ***********************************
// *****************************************************************

sharedRouter.post("/token_endpoint", async (req, res) => {
  let sessionId = null;
  let slog = null;
  let requestId = null;

  try {
    const {
      grant_type,
      code,
      "pre-authorized_code": preAuthorizedCode,
      code_verifier,
      authorization_details,
      redirect_uri,
      tx_code,
    } = req.body;

    // Extract sessionId early for logging
    if (preAuthorizedCode) {
      sessionId = preAuthorizedCode;
    } else if (code) {
      sessionId = await getSessionKeyAuthCode(code);
    }
    
    // Create session logger if we have a sessionId
    if (sessionId) {
      slog = makeSessionLogger(sessionId);
      setSessionContext(sessionId);
      res.on("finish", () => clearSessionContext());
      res.on("close", () => clearSessionContext());
      
      // Log HTTP request
      const logParams = { ...req.body };
      if (logParams.code) logParams.code = "<redacted>";
      if (logParams["pre-authorized_code"]) logParams["pre-authorized_code"] = "<redacted>";
      if (logParams.code_verifier) logParams.code_verifier = "<redacted>";
      if (logParams.tx_code) logParams.tx_code = "<redacted>";
      if (logParams.client_assertion) logParams.client_assertion = "<redacted>";
      
      requestId = logHttpRequest(slog, "POST", "/token_endpoint", req.headers, logParams);
      try { slog("[TOKEN] [START] Token endpoint request", { grant_type, hasCode: !!code, hasPreAuthCode: !!preAuthorizedCode }); } catch {}
    }

    // RFC001 §7.4 — Wallet Instance Attestation (WIA) is mandatory at the token endpoint
    // (client_assertion + jwt-bearer type). JWS signature is verified; Wallet Provider trust list is not used.
    const wiaJwt = extractWIAFromTokenRequest(req.body, req.headers);
    if (!wiaJwt) {
      if (slog) {
        try {
          slog(
            "[TOKEN] [ERROR] Missing WIA (client_assertion)",
            { grant_type },
          );
        } catch {}
      }
      return res.status(400).json({
        error: "invalid_client",
        error_description:
          "Wallet Instance Attestation (WIA) is required: send client_assertion with client_assertion_type urn:ietf:params:oauth:client-assertion-type:jwt-bearer (RFC001 §7.4).",
      });
    }
    if (slog) {
      try {
        const decoded = jwt.decode(wiaJwt, { complete: true });
        const p = decoded?.payload;
        slog("[TOKEN] WIA received", {
          length: wiaJwt.length,
          iss: p?.iss,
          aud: p?.aud,
          iat: p?.iat,
          exp: p?.exp,
          jti: p?.jti,
        });
      } catch {}
    }
    const wiaValidation = await validateWIA(wiaJwt, sessionId);
    if (!wiaValidation.valid) {
      if (slog) {
        try {
          slog("[TOKEN] [ERROR] WIA validation failed", {
            error: wiaValidation.error,
          });
        } catch {}
      }
      return res.status(400).json({
        error: "invalid_client",
        error_description: wiaValidation.error || "Invalid Wallet Instance Attestation",
      });
    }
    if (slog) {
      try {
        slog("[TOKEN] WIA validated successfully", {
          wiaIssuer: wiaValidation.payload?.iss,
          wiaExp: wiaValidation.payload?.exp,
        });
      } catch {}
    }

    const attestationResult = await validateOAuthClientAttestationFromRequest({
      headers: req.headers,
      clientId: req.body?.client_id,
      authorizationServerIssuer: getPublicIssuerBaseUrl(req),
      trustedJwks: getTrustedClientAttesterJwks(),
    });
    if (!attestationResult.skip && !attestationResult.ok) {
      if (slog) {
        try {
          slog("[TOKEN] Client attestation rejected", {
            error: attestationResult.errorDescription,
          });
        } catch {}
      }
      return res.status(attestationResult.statusCode || 401).json({
        error: attestationResult.oauthError || "invalid_client",
        error_description: attestationResult.errorDescription,
      });
    }

    if (attestationResult.skip) {
      return res.status(400).json({
        error: "invalid_client",
        error_description:
          "OAuth-Client-Attestation and OAuth-Client-Attestation-PoP headers are required with Wallet Instance Attestation (RFC001 §7.4).",
      });
    }
    try {
      await assertWiaCnfMatchesClientAttestation(
        wiaValidation.payload,
        attestationResult.attestationPayload
      );
    } catch (e) {
      return res.status(400).json({
        error: "invalid_client",
        error_description: e?.message || "WIA client attestation binding failed",
      });
    }

    // TODO: Implement Wallet Unit Attestation (WUA) based client authentication for token endpoint requests
    //       as profiled in CS-01 (token endpoint and PAR MUST be client-authenticated using WUA;
    //       see https://github.com/webuild-consortium/wp4-architecture/blob/main/conformance-specs/cs-01-credential-issuance.md#624-wu-processes-the-offer).

    // Validate required parameters
    if (!(code || preAuthorizedCode)) {
      if (slog) {
        try { slog("[TOKEN] [ERROR] Missing required parameters", { hasCode: !!code, hasPreAuthCode: !!preAuthorizedCode }); } catch {}
      }
      return res.status(400).json({
        error: "invalid_request",
        error_description: ERROR_MESSAGES.INVALID_REQUEST,
      });
    }

    // Attempt to extract DPoP confirmation (cnf.jkt) from DPoP header if present
    let dpopCnf = null;
    const dpopHeader = req.headers["dpop"];
    if (typeof dpopHeader === "string") {
      try {
        // Per RFC 9449, the public key used for DPoP is carried in the JWS header as "jwk"
        const protectedHeader = jose.decodeProtectedHeader(dpopHeader);
        if (protectedHeader && protectedHeader.jwk) {
          // Verify the DPoP proof using the embedded JWK (self-signed)
          const publicKey = await jose.importJWK(
            protectedHeader.jwk,
            protectedHeader.alg || "ES256"
          );

          const { payload } = await jose.jwtVerify(dpopHeader, publicKey, {
            clockTolerance: DPOP_MAX_FUTURE_IAT_SKEW_SECONDS,
          });

          const { htm, htu, iat, jti, nonce: dpopNonce } = payload;

          // DPOP-03 — required claims (htm, htu, iat, jti)
          if (!htm || !htu || typeof iat === "undefined" || !jti) {
            throw new Error(
              "DPoP proof is missing required claims (htm, htu, iat, jti)"
            );
          }

          // DPOP-04 — HTTP method and URI binding
          const expectedHtm = req.method.toUpperCase();
          if (htm !== expectedHtm) {
            throw new Error(
              `DPoP proof htm claim mismatch. Received: '${htm}', expected: '${expectedHtm}'`
            );
          }

          const expectedHtu = `${getPublicIssuerBaseUrl(req)}/token_endpoint`;
          if (htu !== expectedHtu) {
            throw new Error(
              `DPoP proof htu claim mismatch. Received: '${htu}', expected: '${expectedHtu}'`
            );
          }

          // DPOP-05 — iat freshness
          const iatSeconds =
            typeof iat === "number" ? iat : parseInt(iat, 10);
          const nowSeconds = Math.floor(Date.now() / 1000);
          if (!Number.isFinite(iatSeconds)) {
            throw new Error(
              "DPoP proof iat claim is not a valid number of seconds since epoch"
            );
          }
          if (
            iatSeconds < nowSeconds - DPOP_MAX_IAT_SKEW_SECONDS ||
            iatSeconds > nowSeconds + DPOP_MAX_FUTURE_IAT_SKEW_SECONDS
          ) {
            throw new Error(
              "DPoP proof iat claim is outside the accepted time window"
            );
          }

          // DPOP-06 — replay detection via jti
          if (isDpopJtiReplay(jti, iatSeconds)) {
            throw new Error(
              "DPoP proof jti has already been used within the replay window"
            );
          }

          // Optional DPoP nonce challenge/validation for token endpoint
          const requireDpopNonce =
            process.env.REQUIRE_DPOP_NONCE_FOR_TOKEN === "true";
          if (requireDpopNonce) {
            const endpoint = "/token_endpoint";

            // NONCE-01 / NONCE-03 — missing or wrong nonce -> issue (or re-issue) challenge
            if (!dpopNonce) {
              const newNonce = generateNonce();
              dpopNonces.set(newNonce, { endpoint, used: false });
              if (slog) {
                try {
                  slog("[TOKEN] DPoP nonce required but missing, issuing challenge", {
                    endpoint,
                  });
                } catch {}
              }
              res.set("DPoP-Nonce", newNonce);
              return res.status(400).json({
                error: "use_dpop_nonce",
                error_description:
                  "DPoP nonce required for token endpoint. Retry the request with the DPoP-Nonce value in the DPoP proof.",
              });
            }

            const existing = dpopNonces.get(dpopNonce);
            if (
              !existing ||
              existing.endpoint !== endpoint ||
              existing.used
            ) {
              const newNonce = generateNonce();
              dpopNonces.set(newNonce, { endpoint, used: false });
              if (slog) {
                try {
                  slog(
                    "[TOKEN] DPoP nonce invalid, expired, or already used, issuing new challenge",
                    { endpoint }
                  );
                } catch {}
              }
              res.set("DPoP-Nonce", newNonce);
              return res.status(400).json({
                error: "use_dpop_nonce",
                error_description:
                  "DPoP nonce is invalid, expired, or already used. Retry with the new DPoP-Nonce value.",
              });
            }

            // NONCE-04 — mark nonce as used (single-use per policy)
            existing.used = true;
          }

          // DPOP-07 — Signature and JWK binding are enforced by jwtVerify above.
          // If verification fails or the JWK does not match the signing key,
          // jwtVerify will throw and be mapped to invalid_dpop_proof below.

          // If all checks pass, compute cnf.jkt for sender-constrained access token
          const jkt = await jose.calculateJwkThumbprint(
            protectedHeader.jwk,
            "sha256"
          );
          dpopCnf = { jkt };
          if (slog) {
            try {
              slog(
                "[TOKEN] DPoP header validated, issuing DPoP-bound token",
                {
                  hasJkt: true,
                  htm,
                  htu,
                  iat,
                  jti,
                }
              );
            } catch {}
          }
        } else {
          throw new Error(
            "DPoP proof protected header must include public key in 'jwk' (RFC 9449)"
          );
        }
      } catch (e) {
        if (slog) {
          try { slog("[TOKEN] [ERROR] Invalid DPoP proof", { error: e.message }); } catch {}
        }
        // If DPoP proof is malformed, respond with an error specific to DPoP
        return res.status(400).json({
          error: "invalid_dpop_proof",
          error_description: `Invalid DPoP proof: ${e.message}`,
        });
      }
    } else {
      // RFC001 §7.4 / OpenID4VC-HAIP §5.3 / RFC 9449 — the issuer MUST issue
      // sender-constrained access tokens. Since DPoP is the only supported
      // sender-constraining mechanism here, the DPoP header is mandatory for
      // every `authorization_code` and `pre-authorized_code` exchange and the
      // pre-2026 "Bearer fallback" is no longer permitted.
      const rfc001RequiresDpopGrant =
        grant_type === "authorization_code" ||
        grant_type ===
          "urn:ietf:params:oauth:grant-type:pre-authorized_code";
      if (rfc001RequiresDpopGrant) {
        if (slog) {
          try {
            slog(
              "[TOKEN] [ERROR] RFC001 requires DPoP for token endpoint but DPoP header is missing",
              { grant_type }
            );
          } catch {}
        }
        return res.status(400).json({
          error: "invalid_dpop_proof",
          error_description:
            "DPoP proof is required for token requests (RFC001 §7.4; applies to authorization_code and pre-authorized_code grants).",
        });
      }
    }

    let tokenResponse;

    if (
      grant_type ===
      "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ) {
      if (slog) {
        try { slog("[TOKEN] Processing pre-authorized code flow"); } catch {}
      }
      tokenResponse = await handlePreAuthorizedCodeFlow(
        preAuthorizedCode,
        authorization_details,
        dpopCnf,
        tx_code,
        req,
      );
    } else if (grant_type === "authorization_code") {
      if (slog) {
        try { slog("[TOKEN] Processing authorization code flow"); } catch {}
      }
      tokenResponse = await handleAuthorizationCodeFlow(
        code,
        code_verifier,
        authorization_details,
        dpopCnf,
        req.body?.client_id,
        redirect_uri,
        req,
      );
    } else {
      if (slog) {
        try { slog("[TOKEN] [ERROR] Unsupported grant type", { grant_type }); } catch {}
      }
      return res.status(400).json({
        error: "unsupported_grant_type",
        error_description: `${ERROR_MESSAGES.UNSUPPORTED_GRANT}: '${grant_type}'`,
      });
    }

    // Log HTTP response
    if (slog) {
      const logResponse = { ...tokenResponse };
      if (logResponse.access_token) logResponse.access_token = "<redacted>";
      if (logResponse.refresh_token) logResponse.refresh_token = "<redacted>";
      logHttpResponse(slog, requestId, "/token_endpoint", 200, "OK", res.getHeaders(), logResponse);
      try { slog("[TOKEN] [COMPLETE] Token endpoint request", { success: true, hasAccessToken: !!tokenResponse.access_token }); } catch {}
    }

    res.json(tokenResponse);
  } catch (error) {
    if (slog) {
      try { slog("[TOKEN] [ERROR] Token endpoint error", { error: error.message, errorCode: error.errorCode }); } catch {}
    }

    // Handle authorization_pending and slow_down errors
    if (error.errorCode === "authorization_pending") {
      return res.status(400).json({
        error: "authorization_pending",
        error_description: error.message,
      });
    }

    if (error.errorCode === "slow_down") {
      return res.status(400).json({
        error: "slow_down",
        error_description: error.message,
      });
    }

    if (error.errorCode === "invalid_request") {
      return res.status(400).json({
        error: "invalid_request",
        error_description: error.message,
      });
    }

    if (error.errorCode === "unknown_credential_configuration") {
      return res.status(400).json({
        error: "unknown_credential_configuration",
        error_description: error.message,
      });
    }

    if (error.errorCode === "unknown_credential_identifier") {
      return res.status(400).json({
        error: "unknown_credential_identifier",
        error_description: error.message,
      });
    }


    // HAIP / DPoP-specific failures (e.g., key binding mismatch)
    if (error.errorCode === "invalid_dpop_proof") {
      return res.status(400).json({
        error: "invalid_dpop_proof",
        error_description: error.message,
      });
    }

    if (
      error.message.includes(ERROR_MESSAGES.INVALID_GRANT) ||
      error.message.includes(ERROR_MESSAGES.INVALID_GRANT_CODE) ||
      error.message.includes(ERROR_MESSAGES.PKCE_FAILED)
    ) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description: error.message,
      });
    }

    res.status(500).json({
      error: "server_error",
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* CREDENTIAL ENDPOINTS ******************************
// *****************************************************************

sharedRouter.post("/credential", async (req, res) => {
  let sessionObject;
  let sessionKey;
  let flowType;
  let sessionId = null;
  let slog = null;
  let requestId = null;
  
  try {
    const requestBody = await parseCredentialEndpointBody(req);
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    // RFC001 P0-4 / RFC 9449 — sender-constrained access tokens require a DPoP proof at `/credential`
    // before request-shape validation so clients get `invalid_token` / `invalid_dpop_proof` consistently.
    const dpopBoundJkt = getDpopBoundJktFromAccessToken(token);
    if (dpopBoundJkt) {
      await validateDpopProofForResourceRequest(req, token, dpopBoundJkt);
    }

    // Validate credential request BEFORE we do any session lookup so that
    // malformed requests can return the appropriate 4xx without requiring
    // a stored session (useful for unit tests and spec compliance checks).
    const effectiveConfigurationId = validateCredentialRequest(requestBody, sessionId);

    // Get session after request validation
    const sessionData = await getSessionFromToken(token);
    sessionObject = sessionData.sessionObject;
    flowType = sessionData.flowType;
    sessionKey = sessionData.sessionKey;
    sessionId = extractSessionId(sessionKey);
    
    // Create session logger if we have a sessionId
    if (sessionId) {
      slog = makeSessionLogger(sessionId);
      setSessionContext(sessionId);
      res.on('finish', () => clearSessionContext());
      res.on('close', () => clearSessionContext());
      
      // Log HTTP request
      const logBody = { ...requestBody };
      if (logBody.proof) logBody.proof = "<redacted>";
      if (logBody.proofs) logBody.proofs = "<redacted>";
      if (logBody.proofJwt) logBody.proofJwt = "<redacted>";
      if (logBody.proofAttestationJwt) logBody.proofAttestationJwt = "<redacted>";
      
      requestId = logHttpRequest(slog, "POST", "/credential", req.headers, logBody);
      try { slog("[CREDENTIAL] [START] Credential request", { credential_configuration_id: requestBody.credential_configuration_id, credential_identifier: requestBody.credential_identifier }); } catch {}
    }
    
    if (!sessionObject) {
      if (slog) {
        try { slog("[CREDENTIAL] [ERROR] Session not found for credential request", { error: ERROR_MESSAGES.SESSION_LOST }); } catch {}
      }
      return res.status(500).json({
        error: "server_error",
        error_description: ERROR_MESSAGES.SESSION_LOST,
      });
    }

    const issuerConfigForCredential = loadIssuerConfig();
    const credConfigForCredential =
      effectiveConfigurationId &&
      issuerConfigForCredential.credential_configurations_supported[effectiveConfigurationId];
    const jwtProofRequiresKeyAttestation =
      requestBody.credentialRequestProofKind === "jwt" &&
      credentialConfigRequiresJwtProofKeyAttestation(credConfigForCredential);

    // Optional key-attestation alongside JWT proof (mode 2): in EUDI this object is the WUA (Wallet
    // Provider–signed). Issuer trust for the WP (e.g. Trusted List) is not enforced yet — see
    // routeUtils.isWuaWalletProviderTrustedByPolicy (stub true). Combined with proofs.jwt PoP → possession + assurance.
    // TS3: https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
    //
    // RFC001 §7.5.1 device-bound path: WUA is mandatory in proofs.jwt protected header and validated in the proof pipeline (not here).
    const wuaJwt = extractWUAFromCredentialRequest(requestBody);
    let wuaValidationResult = null;
    if (jwtProofRequiresKeyAttestation) {
      if (slog) {
        try {
          slog(
            "[CREDENTIAL] RFC001 §7.5.1 device-bound proofs.jwt: WUA will be validated from key_attestation; proof signature MUST verify with attested_keys[0]"
          );
        } catch {}
      }
    } else if (wuaJwt) {
      if (slog) {
        try {
          const decoded = jwt.decode(wuaJwt, { complete: true });
          const p = decoded?.payload;
          slog("[CREDENTIAL] WUA received", { length: wuaJwt.length, iss: p?.iss, aud: p?.aud, iat: p?.iat, exp: p?.exp, jti: p?.jti, hasAttestedKeys: Array.isArray(p?.attested_keys) && p.attested_keys.length > 0 });
        } catch {}
      }
      wuaValidationResult = await validateWUA(wuaJwt, sessionId, issuerConfigForCredential);
      if (wuaValidationResult.valid) {
        if (slog) {
          try { slog("[CREDENTIAL] WUA validated successfully", { wuaIssuer: wuaValidationResult.payload?.iss, wuaExp: wuaValidationResult.payload?.exp, hasAttestedKeys: Array.isArray(wuaValidationResult.payload?.attested_keys) && wuaValidationResult.payload.attested_keys.length > 0 }); } catch {}
        }
      } else {
        if (slog) {
          try { slog("[CREDENTIAL] [WARN] WUA validation failed (continuing without WUA)", { error: wuaValidationResult.error }); } catch {}
        }
      }
    } else {
      if (slog) {
        try { slog("[CREDENTIAL] WUA not found in credential request (continuing without WUA)"); } catch {}
      }
    }

    // Validate proof if configuration ID is available
    //
    // Intuition for OID4VCI proof shapes (what the wallet is asserting):
    //
    // 1) JWT proof without key attestation (proofs.jwt only, no separate attestation object):
    //    "I control this key right now." — issuer gets holder binding via PoP; enough when only
    //    possession matters.
    //
    // 2) JWT proof with key attestation (e.g. key material in header, or WUA / attested_keys
    //    validated alongside proofs.jwt):
    //    "I control this key right now, and here is trusted evidence that this key has certain
    //    security properties." — present possession plus assurance about the nature of the key.
    //
    // 3) Attestation proof type (proofs.attestation — key attestation JWT, not a holder PoP JWT):
    //    "Here is trusted evidence about the key; I am not doing a proof-of-possession step for
    //    that key in this proof format." — OID4VCI defines this as key attestation without using
    //    PoP of the attested key in this request; issuance binds from attested_keys instead.
    if (effectiveConfigurationId) {
      try {
        const issuerConfigForProof = loadIssuerConfig();
        const credConfigForProof =
          issuerConfigForProof.credential_configurations_supported[effectiveConfigurationId];

        const isAttestationProof = requestBody.credentialRequestProofKind === "attestation";
        const jwtForNonce = isAttestationProof
          ? requestBody.proofAttestationJwt
          : requestBody.proofJwt;

        if (isAttestationProof) {
          if (!requestBody.proofAttestationJwt) {
            throw new Error(
              `${ERROR_MESSAGES.INVALID_PROOF}. Received: proofAttestationJwt is missing, expected: compact JWT from proofs.attestation`
            );
          }
        } else {
          if (!requestBody.proofJwt) {
            throw new Error(`${ERROR_MESSAGES.INVALID_PROOF}. Received: proofJwt is ${typeof requestBody.proofJwt}, expected: proofJwt string or array`);
          }
        }

        // First, check nonce validity BEFORE any other validation
        const decodedPayloadForNonce = jwt.decode(jwtForNonce, { complete: false });

        if (!decodedPayloadForNonce || !decodedPayloadForNonce.nonce) {
          const received = !decodedPayloadForNonce ? "unable to decode JWT payload" : "payload without nonce claim";
          throw new Error(
            `${ERROR_MESSAGES.INVALID_PROOF_NONCE}. Received: ${received}, expected: JWT payload with nonce claim. See ${SPEC_REFS.VCI_PROOF}`
          );
        }

        // RFC001 §6.1.6 / §8.6 — proof nonce MUST be the current c_nonce for this issuance session
        // (token response or POST /nonce), not merely any unexpired nonce in the shared store.
        const proofNonce = String(decodedPayloadForNonce.nonce).trim();
        const sessionNonceRaw = sessionObject.c_nonce;
        const sessionNonce =
          sessionNonceRaw === undefined || sessionNonceRaw === null
            ? ""
            : String(sessionNonceRaw).trim();
        if (!sessionNonce) {
          throw new Error(
            `${ERROR_MESSAGES.INVALID_PROOF_NONCE}. Received: issuance session has no c_nonce; obtain one via token response or POST /nonce. See ${SPEC_REFS.VCI_PROOF}`
          );
        }
        if (proofNonce !== sessionNonce) {
          throw new Error(
            `${ERROR_MESSAGES.INVALID_PROOF_NONCE}. Received: proof nonce does not match this session's c_nonce (RFC001 §6.1.6 / §8.6). See ${SPEC_REFS.VCI_PROOF}`
          );
        }

        const nonceExists = await checkNonce(proofNonce);
        if (!nonceExists) {
          throw new Error(
            `${ERROR_MESSAGES.INVALID_PROOF_NONCE}. Received: nonce '${proofNonce}' (invalid, expired, or already used), expected: valid, unexpired, unused nonce. See ${SPEC_REFS.VCI_PROOF}`
          );
        }

        const nonceValue = proofNonce;

        // Mode (3): attestation proof — verify key-attestation JWT and bind credential to attested_keys (no holder PoP JWT).
        if (isAttestationProof) {
          const { cnf, attestedKeys } = await verifyKeyAttestationProofChain(
            requestBody.proofAttestationJwt,
            credConfigForProof,
            issuerConfigForProof,
            SPEC_REFS.VCI_PROOF
          );
          requestBody._credentialBindingCnf = cnf;
          requestBody._attestedKeys = attestedKeys;
          requestBody._credentialBindingCnfList = await dedupeAttestedKeysToCnfList(attestedKeys);
          if (sessionId) {
            await logInfo(sessionId, "Key attestation proof validated", {
              effectiveConfigurationId,
              attestedKeysCount: attestedKeys.length,
            }).catch(() => {});
          }
        } else {
          // Mode (1) baseline: JWT proof — verify holder PoP ("I control this key right now") for cnf binding.
          // RFC001 §7.5.1 device-bound: require key_attestation (WUA), validate WUA, verify proof with attested_keys[0].
          const headerForVerification = validateProofJWT(
            requestBody.proofJwt,
            effectiveConfigurationId,
            sessionId
          );

          let publicKeyForProof;
          if (jwtProofRequiresKeyAttestation) {
            const wuaCompact = headerForVerification.key_attestation;
            if (typeof wuaCompact !== "string" || !wuaCompact.trim()) {
              throw new Error(
                `${ERROR_MESSAGES.INVALID_PROOF}: proofs.jwt MUST include protected-header parameter 'key_attestation' (Wallet Unit Attestation) for this credential configuration (RFC001 §7.5.1). See ${SPEC_REFS.VCI_PROOF}`
              );
            }
            const wuaStrict = await validateWUA(wuaCompact, sessionId, issuerConfigForProof);
            if (!wuaStrict.valid) {
              throw new Error(
                `${ERROR_MESSAGES.INVALID_PROOF}: Wallet Unit Attestation in key_attestation could not be validated. ${wuaStrict.error || ""}`.trim()
              );
            }
            const attested = wuaStrict.payload?.attested_keys;
            if (!Array.isArray(attested) || !attested[0] || typeof attested[0] !== "object") {
              throw new Error(
                `${ERROR_MESSAGES.INVALID_PROOF}: WUA attested_keys[0] is required for device-bound issuance (RFC001 §7.5.1). See ${SPEC_REFS.VCI_PROOF}`
              );
            }
            publicKeyForProof = await resolveProofJwtPublicJwk(headerForVerification, {
              sessionId,
              messages: ERROR_MESSAGES,
              specRefVciProof: SPEC_REFS.VCI_PROOF,
            });
            if (!proofKeyMatchesWUAAttestedKeys(publicKeyForProof, wuaStrict.payload)) {
              throw new Error(
                `${ERROR_MESSAGES.INVALID_PROOF}: proof signing key MUST match WUA attested_keys[0] (RFC001 §7.5.1). See ${SPEC_REFS.VCI_PROOF}`
              );
            }
            await verifyProofJWT(
              requestBody.proofJwt,
              publicKeyForProof,
              flowType,
              sessionId,
              req,
            );
            requestBody._credentialBindingCnfList = await dedupeAttestedKeysToCnfList(attested);
            if (slog) {
              try {
                slog("[CREDENTIAL] Device-bound proof verified; multi-key cnf list", {
                  wuaIssuer: wuaStrict.payload?.iss,
                  attestedKeyCount: requestBody._credentialBindingCnfList?.length ?? 0,
                });
              } catch {}
            }
          } else {
            publicKeyForProof = await resolveProofJwtPublicJwk(headerForVerification, {
              sessionId,
              messages: ERROR_MESSAGES,
              specRefVciProof: SPEC_REFS.VCI_PROOF,
            });
            await verifyProofJWT(
              requestBody.proofJwt,
              publicKeyForProof,
              flowType,
              sessionId,
              req,
            );

            // Mode (2): JWT proof + validated WUA — PoP key must match the first attested key ("possession + assurance").
            // EUDI Wallet ARF / ETSI-style binding: credential cnf aligns with the primary attested key.
            if (wuaJwt && wuaValidationResult?.valid && wuaValidationResult?.payload) {
              if (slog) {
                try {
                  const attestedKeysCount = Array.isArray(wuaValidationResult.payload.attested_keys)
                    ? wuaValidationResult.payload.attested_keys.length
                    : 0;
                  slog("[CREDENTIAL] Checking proof key against WUA first attested key", {
                    proofKeyKty: publicKeyForProof?.kty,
                    proofKeyCrv: publicKeyForProof?.crv,
                    attestedKeysCount,
                    wuaIssuer: wuaValidationResult.payload?.iss,
                  });
                } catch {}
              }
              if (!proofKeyMatchesWUAAttestedKeys(publicKeyForProof, wuaValidationResult.payload)) {
                const attestedKeysCount = Array.isArray(wuaValidationResult.payload.attested_keys)
                  ? wuaValidationResult.payload.attested_keys.length
                  : 0;
                const errorMsg = `invalid_proof: The key used in the proof (credential binding/cnf) must match the first key in the Wallet Unit Attestation attested_keys array (primary attested key).`;
                if (slog) {
                  try {
                    slog("[CREDENTIAL] [ERROR] Proof key does not match WUA first attested key", {
                      proofKeyKty: publicKeyForProof?.kty,
                      proofKeyCrv: publicKeyForProof?.crv,
                      proofKeyX: publicKeyForProof?.x?.substring(0, 16) + "...",
                      attestedKeysCount,
                      wuaIssuer: wuaValidationResult.payload?.iss,
                      error: errorMsg,
                    });
                  } catch {}
                }
                throw new Error(errorMsg);
              }
              if (slog) {
                try {
                  slog("[CREDENTIAL] Proof key validated against WUA first attested key", {
                    proofKeyKty: publicKeyForProof?.kty,
                    proofKeyCrv: publicKeyForProof?.crv,
                    attestedKeysCount: Array.isArray(wuaValidationResult.payload.attested_keys)
                      ? wuaValidationResult.payload.attested_keys.length
                      : 0,
                  });
                } catch {}
              }
            }
          }
        }

        await deleteNonce(nonceValue);
        
        // Log successful proof validation
        if (sessionId) {
          await logInfo(sessionId, "Proof validation successful", {
            effectiveConfigurationId
          }).catch(() => {});
        }
      } catch (error) {
        console.error("Proof validation error:", error);
        if (sessionId) {
          await logError(sessionId, "Proof validation error", {
            error: error.message,
            stack: error.stack,
            proofValidationError: true
          }).catch(err => console.error("Failed to log proof validation error:", err));
        }

        if (error.message.includes(ERROR_MESSAGES.INVALID_PROOF_NONCE)) {
          return respondInvalidNonceCredentialError(res, error, {
            sessionObject,
            sessionKey,
            flowType,
            sessionId,
          });
        }

        if (error.message.includes(ERROR_MESSAGES.INVALID_PROOF)) {
          return res.status(400).json({
            error: "invalid_proof",
            error_description: error.message,
          });
        }
        
        if (error.errorCode === CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST) {
          return res.status(400).json({
            error: CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST,
            error_description: error.message,
          });
        }

        if (error.errorCode === CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_CONFIGURATION) {
          return res.status(400).json({
            error: CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_CONFIGURATION,
            error_description: error.message,
          });
        }
        if (error.errorCode === CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_IDENTIFIER) {
          return res.status(400).json({
            error: CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_IDENTIFIER,
            error_description: error.message,
          });
        }

        error.proofValidationError = true;
        throw error;
      }
    }

    // Handle credential issuance
    if (sessionObject.isDeferred) {
      const response = await handleDeferredCredentialIssuance(requestBody, sessionObject, sessionKey, flowType);
      if (slog) {
        try { slog("[CREDENTIAL] Deferred credential issuance initiated", { transaction_id: response.transaction_id }); } catch {}
        logHttpResponse(slog, requestId, "/credential", 202, "Accepted", res.getHeaders(), response);
        try { slog("[CREDENTIAL] [COMPLETE] Credential request (deferred)", { success: true }); } catch {}
      }
      return sendCredentialSuccessResponse(res, 202, response, requestBody);
    } else {
      try {
        const response = await handleImmediateCredentialIssuance(
          requestBody,
          sessionObject,
          effectiveConfigurationId,
          sessionId,
          req,
        );
        if (slog) {
          try { slog("[CREDENTIAL] Credential issued successfully", { effectiveConfigurationId, notification_id: response.notification_id }); } catch {}
          const logResponse = { ...response };
          if (logResponse.credential) logResponse.credential = "<redacted>";
          logHttpResponse(slog, requestId, "/credential", 200, "OK", res.getHeaders(), logResponse);
          try { slog("[CREDENTIAL] [COMPLETE] Credential request", { success: true }); } catch {}
        }

        // Mark session as successful after credential issuance and store notification_id
        if (sessionObject && sessionKey) {
          try {
            sessionObject.status = "success";
            sessionObject.notification_id = response.notification_id;

            if (flowType === "code") {
              await storeCodeFlowSession(sessionKey, sessionObject);
            } else {
              await storePreAuthSession(sessionKey, sessionObject);
            }
          } catch (storageError) {
            console.error("Failed to update session status after successful credential issuance:", storageError);
            if (slog) {
              try { slog("[CREDENTIAL] [WARN] Failed to update session status after successful credential issuance", { error: storageError.message }); } catch {}
            }
          }
        }

        return sendCredentialSuccessResponse(res, 200, response, requestBody);
      } catch (credError) {
        console.error("Credential generation error:", credError);
        if (slog) {
          try { slog("[CREDENTIAL] [ERROR] Credential generation error", { error: credError.message }); } catch {}
        }
        
        // Mark session as failed when credential generation fails
        if (sessionObject && sessionKey) {
          try {
            sessionObject.status = "failed";
            sessionObject.error = "server_error";
            sessionObject.error_description = credError.message || "Failed to generate credential";

            if (flowType === "code") {
              await storeCodeFlowSession(sessionKey, sessionObject);
            } else {
              await storePreAuthSession(sessionKey, sessionObject);
            }
          } catch (storageError) {
            console.error("Failed to update session status after credential generation failure:", storageError);
            if (slog) {
              try { slog("[CREDENTIAL] [WARN] Failed to update session status after credential generation failure", { error: storageError.message }); } catch {}
            }
          }
        }
        
        if (slog) {
          logHttpResponse(slog, requestId, "/credential", 500, "Internal Server Error", res.getHeaders(), { error: "server_error", error_description: credError.message });
          try { slog("[CREDENTIAL] [COMPLETE] Credential request", { success: false, error: credError.message }); } catch {}
        }
        
        // If credential generation fails, it's a server error, not a client error
        return res.status(500).json({
          error: "server_error",
          error_description: credError.message || "Failed to generate credential",
        });
      }
    }
  } catch (error) {
    console.error("Credential endpoint error:", error);
    if (slog) {
      try { slog("[CREDENTIAL] [ERROR] Credential endpoint error", { error: error.message, errorCode: error.errorCode }); } catch {}
    }

    if (error.errorCode === INVALID_ENCRYPTION_PARAMETERS) {
      return res.status(400).json({
        error: INVALID_ENCRYPTION_PARAMETERS,
        error_description: error.message,
      });
    }

    if (error.errorCode === "invalid_token" && error.httpStatus === 401) {
      if (slog) {
        try {
          slog("[CREDENTIAL] [ERROR] invalid_token (DPoP-bound token)", {
            error: error.message,
          });
        } catch {}
        if (requestId) {
          logHttpResponse(
            slog,
            requestId,
            "/credential",
            401,
            "Unauthorized",
            res.getHeaders(),
            { error: "invalid_token" },
          );
        }
      }
      return res.status(401).json({
        error: "invalid_token",
        error_description: error.message,
      });
    }

    if (error.errorCode === "invalid_dpop_proof") {
      if (slog) {
        try {
          slog("[CREDENTIAL] [ERROR] invalid_dpop_proof", {
            error: error.message,
          });
        } catch {}
        if (requestId) {
          logHttpResponse(
            slog,
            requestId,
            "/credential",
            400,
            "Bad Request",
            res.getHeaders(),
            { error: "invalid_dpop_proof" },
          );
        }
      }
      return res.status(400).json({
        error: "invalid_dpop_proof",
        error_description: error.message,
      });
    }

    if (error.message.includes(ERROR_MESSAGES.INVALID_PROOF_NONCE)) {
      return respondInvalidNonceCredentialError(res, error, {
        sessionObject,
        sessionKey,
        flowType,
        sessionId,
      });
    }

    const proofRelatedErrors = [
      ERROR_MESSAGES.INVALID_PROOF,
      ERROR_MESSAGES.INVALID_PROOF_MALFORMED,
      ERROR_MESSAGES.INVALID_PROOF_ALGORITHM,
      ERROR_MESSAGES.INVALID_PROOF_TYP,
      ERROR_MESSAGES.INVALID_PROOF_PUBLIC_KEY,
      ERROR_MESSAGES.INVALID_PROOF_UNABLE,
      ERROR_MESSAGES.INVALID_PROOF_SIGNATURE,
      ERROR_MESSAGES.INVALID_PROOF_ISS,
    ];

    if (
      error.proofValidationError ||
      proofRelatedErrors.some((msg) => error.message.includes(msg))
    ) {
      const errorResponse = {
        error: "invalid_proof",
        error_description: error.message,
      };

      if (sessionObject && sessionKey) {
        try {
          sessionObject.status = "failed";
          sessionObject.error = "invalid_proof";
          sessionObject.error_description = error.message;

          if (flowType === "code") {
            await storeCodeFlowSession(sessionKey, sessionObject);
          } else {
            await storePreAuthSession(sessionKey, sessionObject);
          }
        } catch (storageError) {
          console.error("Failed to update session status after proof validation failure:", storageError);
          if (sessionId) {
            await logError(sessionId, "Failed to update session status after proof validation failure", {
              error: storageError.message
            }).catch(() => {});
          }
        }
      }

      return res.status(400).json(errorResponse);
    }

    if (error.errorCode === CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST) {
      // Mark session as failed when credential request validation fails
      if (sessionObject && sessionKey) {
        try {
          sessionObject.status = "failed";
          sessionObject.error = CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST;
          sessionObject.error_description = error.message;

          if (flowType === "code") {
            await storeCodeFlowSession(sessionKey, sessionObject);
          } else {
            await storePreAuthSession(sessionKey, sessionObject);
          }
        } catch (storageError) {
          console.error("Failed to update session status after validation failure:", storageError);
          if (sessionId) {
            await logError(sessionId, "Failed to update session status after validation failure", {
              error: storageError.message
            }).catch(() => {});
          }
        }
      }

      return res.status(400).json({
        error: CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST,
        error_description: error.message,
      });
    }

    if (error.errorCode === CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_CONFIGURATION) {
      return res.status(400).json({
        error: CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_CONFIGURATION,
        error_description: error.message,
      });
    }

    if (error.errorCode === CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_IDENTIFIER) {
      return res.status(400).json({
        error: CREDENTIAL_REQUEST_ERROR_CODES.UNKNOWN_CREDENTIAL_IDENTIFIER,
        error_description: error.message,
      });
    }

    // Mark session as failed for other credential request errors (OID4VCI 1.0 §8.3)
    if (sessionObject && sessionKey && error.message.includes("credential")) {
      try {
        sessionObject.status = "failed";
        sessionObject.error =
          CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST;
        sessionObject.error_description = error.message;

        if (flowType === "code") {
          await storeCodeFlowSession(sessionKey, sessionObject);
        } else {
          await storePreAuthSession(sessionKey, sessionObject);
        }
      } catch (storageError) {
        console.error("Failed to update session status after credential error:", storageError);
        if (sessionId) {
          await logError(sessionId, "Failed to update session status after credential error", {
            error: storageError.message
          }).catch(() => {});
        }
      }
    }

    return res.status(400).json({
      error: CREDENTIAL_REQUEST_ERROR_CODES.INVALID_CREDENTIAL_REQUEST,
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* DEFERRED ENDPOINTS ******************************
// *****************************************************************

sharedRouter.post("/credential_deferred", async (req, res) => {
  let sessionId = null;
  let deferredFlowType = "code";
  try {
    const { transaction_id } = req.body;

    if (!transaction_id) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing transaction_id",
      });
    }

    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return res.status(401).json({
        error: "invalid_token",
        error_description:
          "Missing Authorization header. Expected: Bearer <access_token> or DPoP <access_token> (RFC 9449).",
      });
    }
    let accessToken;
    if (authHeader.startsWith("Bearer ")) {
      accessToken = authHeader.slice(7).trim();
    } else if (authHeader.startsWith("DPoP ")) {
      accessToken = authHeader.slice(5).trim();
    } else {
      return res.status(401).json({
        error: "invalid_token",
        error_description:
          "Unsupported Authorization scheme. Expected: Bearer or DPoP.",
      });
    }
    if (!accessToken) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Empty access token in Authorization header.",
      });
    }

    const dpopBoundJkt = getDpopBoundJktFromAccessToken(accessToken);
    if (dpopBoundJkt) {
      await validateDpopProofForResourceRequest(
        req,
        accessToken,
        dpopBoundJkt,
        "/credential_deferred",
      );
    }

    const tokenSession = await getSessionFromToken(accessToken);
    if (!tokenSession.sessionObject || !tokenSession.sessionKey) {
      return res.status(401).json({
        error: "invalid_token",
        error_description:
          "Access token is not associated with an active issuance session.",
      });
    }

    const deferredCtx = await resolveDeferredIssuanceContext(transaction_id);
    if (!deferredCtx) {
      return res.status(400).json({
        error: "invalid_transaction_id",
        error_description: ERROR_MESSAGES.INVALID_TRANSACTION,
      });
    }

    if (deferredCtx.sessionKey !== tokenSession.sessionKey) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description:
          "The access token does not match the issuance session for this transaction_id.",
      });
    }

    sessionId = deferredCtx.sessionKey;
    deferredFlowType = deferredCtx.flowType;

    if (sessionId) {
      setSessionContext(sessionId);
      res.on("finish", () => {
        clearSessionContext();
      });
      res.on("close", () => {
        clearSessionContext();
      });
    }

    const sessionObject =
      deferredFlowType === "code"
        ? await getCodeFlowSession(sessionId)
        : await getPreAuthSession(sessionId);

    if (!sessionObject) {
      return res.status(400).json({
        error: "invalid_transaction_id",
        error_description: ERROR_MESSAGES.INVALID_TRANSACTION,
      });
    }

    // RFC001 §6.3, §7.6 / OID4VCI 1.0 §9 — transaction_id has a lifetime.
    // Once elapsed, the wallet is expected to restart the flow.
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (
      typeof sessionObject.deferred_expires_at === "number" &&
      sessionObject.deferred_expires_at > 0 &&
      nowSeconds > sessionObject.deferred_expires_at
    ) {
      return res.status(400).json({
        error: "expired_transaction_id",
        error_description: "The transaction_id has expired; start a new issuance.",
      });
    }

    const issuerConfig = loadIssuerConfig();
    const encParams =
      req.body.credential_response_encryption !== undefined
        ? req.body.credential_response_encryption
        : sessionObject.requestBody?.credential_response_encryption;
    if (encParams) {
      validateCredentialResponseEncryptionParams(
        encParams,
        getCredentialResponseEncryptionMetadata(issuerConfig)
      );
    }

    // RFC001 §6.3, §7.6 / OID4VCI 1.0 §9 — if the credential is not yet ready,
    // respond with `issuance_pending` and tell the wallet how long to wait.
    // Readiness is driven either explicitly (`sessionObject.isCredentialReady`)
    // or, by default policy, after N polls have been observed on this
    // transaction_id. N comes from the session override
    // `deferred_pending_polls_override` when set, otherwise from the
    // environment via DEFERRED_PENDING_POLLS (default 0).
    sessionObject.deferred_poll_count = (sessionObject.deferred_poll_count || 0) + 1;
    sessionObject.attempt = (sessionObject.attempt || 0) + 1;

    const pendingBudget =
      typeof sessionObject.deferred_pending_polls_override === "number"
        ? sessionObject.deferred_pending_polls_override
        : getDeferredPendingPolls();

    const explicitlyReady = sessionObject.isCredentialReady === true;
    const pollsSatisfied = sessionObject.deferred_poll_count > pendingBudget;
    const credentialReady = explicitlyReady || pollsSatisfied;

    if (!credentialReady) {
      try {
        if (deferredFlowType === "code") {
          await storeCodeFlowSession(sessionId, sessionObject);
        } else {
          await storePreAuthSession(sessionId, sessionObject);
        }
      } catch (persistErr) {
        console.error("Failed to persist deferred poll state:", persistErr);
      }
      res.set("Cache-Control", "no-store");
      return res.status(400).json({
        error: "issuance_pending",
        error_description:
          "The credential is not yet ready. Retry after the suggested interval.",
        interval: getDeferredIntervalSeconds(),
      });
    }

    const deferredBody = sessionObject.requestBody || {};
    const deferredCnfList = deferredBody._credentialBindingCnfList;
    const notification_id = sessionObject.notification_id || uuidv4();

    let payload;
    if (Array.isArray(deferredCnfList) && deferredCnfList.length > 0) {
      const credentials = [];
      for (const holderCnf of deferredCnfList) {
        const credential = await handleCredentialGenerationBasedOnFormatDeferred(
          sessionObject,
          getPublicIssuerBaseUrl(req),
          holderCnf,
        );
        credentials.push({ credential });
      }
      payload = { credentials, notification_id };
    } else {
      const credential = await handleCredentialGenerationBasedOnFormatDeferred(
        sessionObject,
        getPublicIssuerBaseUrl(req),
      );
      payload = {
        credentials: [{ credential }],
        notification_id,
      };
    }

    try {
      sessionObject.isCredentialReady = true;
      sessionObject.status = "success";
      sessionObject.notification_id = notification_id;
      if (deferredFlowType === "code") {
        await storeCodeFlowSession(sessionId, sessionObject);
      } else {
        await storePreAuthSession(sessionId, sessionObject);
      }
    } catch (persistErr) {
      console.error("Failed to persist deferred success state:", persistErr);
    }

    res.set("Cache-Control", "no-store");
    if (encParams) {
      const jwe = await encryptCredentialResponseToJwe(payload, encParams, issuerConfig);
      res.type("application/jwt");
      return res.status(200).send(jwe);
    }

    return res.status(200).json(payload);
  } catch (error) {
    if (error.errorCode === "invalid_token" && error.httpStatus === 401) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: error.message,
      });
    }
    if (error.errorCode === "invalid_dpop_proof") {
      return res.status(400).json({
        error: "invalid_dpop_proof",
        error_description: error.message,
      });
    }
    if (error.errorCode === INVALID_ENCRYPTION_PARAMETERS) {
      return res.status(400).json({
        error: INVALID_ENCRYPTION_PARAMETERS,
        error_description: error.message,
      });
    }
    // Proof / request-shape problems raised by the deferred generator surface
    // as Errors with `status === 400`. Map them to `invalid_credential_request`
    // per OID4VCI 1.0 rather than leaking them as 500s.
    if (error && error.status === 400) {
      if (sessionId) {
        logError(sessionId, "Deferred credential request invalid", {
          error: error.message,
          transaction_id: req.body.transaction_id,
        }).catch(() => {});
      }
      return res.status(400).json({
        error: "invalid_credential_request",
        error_description: error.message,
      });
    }
    if (sessionId) {
      logError(sessionId, "Deferred credential endpoint error", {
        error: error.message,
        stack: error.stack,
        transaction_id: req.body.transaction_id,
      }).catch(() => {});
    }
    return res.status(500).json({
      error: "server_error",
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* NONCE ENDPOINT ************************************
// *****************************************************************

sharedRouter.post("/nonce", async (req, res) => {
  res.set("Cache-Control", "no-store");
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return res.status(401).json({
        error: "invalid_token",
        error_description:
          "Missing Authorization header. Expected: Bearer <access_token> or DPoP <access_token> (RFC 9449).",
      });
    }

    let accessToken;
    if (authHeader.startsWith("Bearer ")) {
      accessToken = authHeader.slice(7).trim();
    } else if (authHeader.startsWith("DPoP ")) {
      accessToken = authHeader.slice(5).trim();
    } else {
      return res.status(401).json({
        error: "invalid_token",
        error_description:
          "Unsupported Authorization scheme. Expected: Bearer or DPoP.",
      });
    }

    if (!accessToken) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Empty access token in Authorization header.",
      });
    }

    const { sessionObject, flowType, sessionKey } = await getSessionFromToken(accessToken);
    if (!sessionObject || !sessionKey) {
      return res.status(401).json({
        error: "invalid_token",
        error_description:
          "Access token is not associated with an active issuance session.",
      });
    }

    const newCNonce = generateNonce();
    await storeNonce(newCNonce, NONCE_EXPIRES_IN);

    sessionObject.c_nonce = newCNonce;
    try {
      if (flowType === "code") {
        await storeCodeFlowSession(sessionKey, sessionObject);
      } else {
        await storePreAuthSession(sessionKey, sessionObject);
      }
    } catch (persistErr) {
      console.error("Nonce endpoint: failed to persist session c_nonce", persistErr);
      return res.status(500).json({
        error: "server_error",
        error_description: ERROR_MESSAGES.STORAGE_FAILED,
      });
    }

    res.status(200).json({
      c_nonce: newCNonce,
      c_nonce_expires_in: NONCE_EXPIRES_IN,
    });
  } catch (error) {
    console.error("Nonce endpoint error:", error);
    res.status(500).json({
      error: "server_error",
      error_description: ERROR_MESSAGES.STORAGE_FAILED,
    });
  }
});

// *****************************************************************
// ************* Notification ENDPOINT ********************************
// *****************************************************************

sharedRouter.post("/notification", async (req, res) => {
  let sessionId = null;

  try {
    const { notification_id, event, event_description } = req.body;

    // Validate required parameters
    if (!notification_id) {
      return res.status(400).json({
        error: "invalid_notification_request",
        error_description: "Missing required parameter: notification_id",
      });
    }

    if (!event) {
      return res.status(400).json({
        error: "invalid_notification_request",
        error_description: "Missing required parameter: event",
      });
    }

  
    // Validate Authorization header with Bearer token
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Missing or invalid Authorization header. Expected: Bearer <access_token>",
      });
    }

    const accessToken = authHeader.substring(7); // Remove "Bearer " prefix

    // Find session associated with the access token
    const sessionData = await getSessionFromToken(accessToken);
    const sessionObject = sessionData.sessionObject;
    const sessionKey = sessionData.sessionKey;

    if (!sessionObject) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Invalid or expired access token",
      });
    }

    // RFC001 §8.7 / OID4VCI — notification_id MUST match the value issued with
    // the credential response for this access token's session (prevents cross-session notification spam).
    const storedNotificationId = sessionObject.notification_id;
    if (storedNotificationId == null || storedNotificationId === "") {
      return res.status(400).json({
        error: "invalid_notification_request",
        error_description:
          "No notification_id has been issued for this session yet. Complete credential issuance (response includes notification_id) before posting notification events.",
      });
    }
    if (String(notification_id) !== String(storedNotificationId)) {
      return res.status(403).json({
        error: "invalid_notification_id",
        error_description:
          "The notification_id does not match the credential issuance bound to this access token.",
      });
    }

    sessionId = extractSessionId(sessionKey);

    // Set session context for console interception to capture all logs
    if (sessionId) {
      setSessionContext(sessionId);
      // Clear context when response finishes
      res.on('finish', () => {
        clearSessionContext();
      });
      res.on('close', () => {
        clearSessionContext();
      });
    }

      // Log the notification event
    if (sessionId) {
      const logData = {
        notification_id,
        event,
        event_description: event_description || null
      };
      await logInfo(sessionId, `Notification received: ${event}`, logData).catch(() => {});
    }

    if(event === "credential_failure" || event === "credential_deleted") {
      const sessionObject = await getCodeFlowSession(sessionId);
      if (sessionObject) {

        sessionObject.status = "failed";
        console.error("Credential failure or deletion detected. Marking session as failed. Reason: " + event_description);
        
        if(sessionObject.flowType === "code") {
         
          await storeCodeFlowSession(sessionKey, sessionObject);
          return res.status(204).send();
        }else{
          await storePreAuthSession(sessionKey, sessionObject);
          return res.status(204).send();
        }

        
      }
    }
    if(event === "credential_accepted") {
      const sessionObject = await getCodeFlowSession(sessionId);
      if (sessionObject) {
        sessionObject.status = "success";
        console.error("credential accepted event received. Marking session as successful.");
         if(sessionObject.flowType === "code") {
        await storeCodeFlowSession(sessionKey, sessionObject);
        
        }else{
          await storePreAuthSession(sessionKey, sessionObject);
        }
      }
    }


    // Successfully processed notification - return 204 No Content
    res.status(204).send();

  } catch (error) {
    console.error("Notification endpoint error:", error);

    if (sessionId) {
      await logError(sessionId, "Notification endpoint error", {
        error: error.message,
        stack: error.stack
      }).catch(err => console.error("Failed to log notification error:", err));
    }

    // For unexpected server errors, return 500
    res.status(500).json({
      error: "server_error",
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* STATUS ENDPOINT ***********************************
// *****************************************************************

sharedRouter.get("/issueStatus", async (req, res) => {
  try {
    const { sessionId } = req.query;
    
    if (!sessionId) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing sessionId parameter",
      });
    }

    const existingPreAuthSession = await getPreAuthSession(sessionId);
    const perAuthStatus = existingPreAuthSession ? existingPreAuthSession.status : null;

    const codeFlowSession = await getCodeFlowSession(sessionId);
    const codeFlowStatus = codeFlowSession ? codeFlowSession.status : null;

    const result = perAuthStatus || codeFlowStatus;
    
    if (result) {
      res.json({
        status: result,
        reason: "ok",
        sessionId: sessionId,
      });
    } else {
      res.json({
        status: "failed",
        reason: "not found",
        sessionId: sessionId,
      });
    }
  } catch (error) {
    console.error("Issue status endpoint error:", error);
    res.status(500).json({
      error: "server_error",
      error_description: error.message,
    });
  }
});

// *****************************************************************
// ************* HELPER FUNCTIONS **********************************
// *****************************************************************

async function validatePKCE(session, code_verifier, stored_code_challenge, sessionId = null) {
  if (!stored_code_challenge) {
    if (sessionId) {
      logError(sessionId, "PKCE validation failed: missing stored code challenge", {
        reason: "no_stored_code_challenge",
        hasCodeVerifier: !!code_verifier,
        hasStoredChallenge: false
      }).catch(() => {});
    }
    return false;
  }

  if (!code_verifier) {
    if (sessionId) {
      logError(sessionId, "PKCE validation failed: missing code verifier", {
        reason: "no_code_verifier",
        hasCodeVerifier: false,
        hasStoredChallenge: !!stored_code_challenge
      }).catch(() => {});
    }
    return false;
  }

  const tester = await base64UrlEncodeSha256(code_verifier);
  if (tester === stored_code_challenge) {
    if (sessionId) {
      logInfo(sessionId, "PKCE verification successful", {
        codeChallengeMatch: true
      }).catch(() => {});
    }
    return true;
  }

  if (sessionId) {
    logError(sessionId, "PKCE verification failed: code challenge mismatch", {
      reason: "challenge_mismatch",
      receivedChallenge: tester,
      expectedChallenge: stored_code_challenge,
      codeVerifierPresent: true,
      storedChallengePresent: true
    }).catch(() => {});
  }
  return false;
}

function getPersonaPart(inputString) {
  const personaKey = "persona=";
  const personaIndex = inputString.indexOf(personaKey);

  if (personaIndex === -1) {
    return null;
  }

  const parts = inputString.split(personaKey);
  return parts[1] || null;
}

export const publicKeyToPem = async (jwk) => {
  if (!jwk) {
    throw new Error("JWK is undefined or null.");
  }
  
  try {
    const publicKey = await jose.importJWK(jwk);
    const pem = await jose.exportSPKI(publicKey);
    return pem;
  } catch (err) {
    console.error("Error converting JWK to PEM:", err);
    console.error("Problematic JWK:", JSON.stringify(jwk));
    throw new Error(`Failed to convert JWK to PEM: ${err.message}`);
  }
};

// Initialize crypto components on module load
let cryptoComponents;
initializeCrypto()
  .then(components => {
    cryptoComponents = components;
    console.log("Cryptographic components initialized successfully");
  })
  .catch(error => {
    console.error("Failed to initialize cryptographic components:", error);
    process.exit(1);
  });

export default sharedRouter;
