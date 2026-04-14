import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import qr from "qr-image";
import imageDataURI from "image-data-uri";
import { streamToBuffer } from "@jorgeferrero/stream-to-buffer";
import { generateNonce, buildVpRequestJWT } from "./cryptoUtils.js";
import { getSDsFromPresentationDef } from "./vpHeplers.js";
import {
  storeVPSession,
  getVPSession,
  logInfo,
  logWarn,
  logError,
  logDebug,
  setSessionContext,
  clearSessionContext,
} from "../services/cacheServiceRedis.js";
import { createHash, createPublicKey } from "crypto";
import base64url from "base64url";
import jwt from "jsonwebtoken";
import path from "path";
import * as jose from "jose";

const WUA_SPEC_REF =
  "TS3 Wallet Unit Attestation";
const OID4VCI_WALLET_ATTESTATION_SPEC_REF =
  "OpenID4VCI 1.0 Appendix E";

function withSpecRef(message, ...refs) {
  const present = refs.filter(Boolean);
  if (present.length === 0) return message;
  return `${message}${message.endsWith(".") ? "" : "."} See ${present.join(" and ")}.`;
}

// ============================================================================
// SHARED CONSTANTS
// ============================================================================

export const SERVER_URL = process.env.SERVER_URL || "http://localhost:3000";
export const PROXY_PATH = process.env.PROXY_PATH || null;

export const DEFAULT_CREDENTIAL_TYPE = "VerifiablePortableDocumentA2SDJWT";
export const DEFAULT_SIGNATURE_TYPE = "jwt";
export const DEFAULT_CLIENT_ID_SCHEME = "redirect_uri";
export const DEFAULT_REDIRECT_URI = "openid4vp://";

export const QR_CONFIG = {
  type: "png",
  ec_level: "H",
  size: 10,
  margin: 10,
};

export const CLIENT_METADATA = {
  client_name: "UAegean WE BUILD Verifier",
  logo_uri: "https://studyingreece.edu.gr/wp-content/uploads/2023/03/25.png",
  location: "Greece",
  cover_uri: "string",
  description: "WE BUILD pilot case verification",
  vp_formats_supported: {
    "dc+sd-jwt": {
      "sd-jwt_alg_values": ["ES256", "ES384"],
      "kb-jwt_alg_values": ["ES256", "ES384"],
    },
    "https://cloudsignatureconsortium.org/2025/x509": {},
  },
};

export const TX_CODE_CONFIG = {
  length: 4,
  input_mode: "numeric",
  description: "Please provide the one-time code that was sent via e-mail or offline",
};

export const URL_SCHEMES = {
  STANDARD: "openid-credential-offer://",
  HAIP: "haip://",
  OPENID4VP: "openid4vp://",
};

export const ERROR_MESSAGES = {
  // Common errors
  SESSION_CREATION_FAILED: "Failed to create session",
  QR_GENERATION_FAILED: "Failed to generate QR code",
  INVALID_SESSION_ID: "Invalid session ID",
  INVALID_CREDENTIAL_TYPE: "Invalid credential type",
  STORAGE_ERROR: "Storage operation failed",
  QR_ENCODING_ERROR: "QR code encoding failed",
  CRYPTO_KEY_LOAD_ERROR: "Failed to load cryptographic keys",
  
  // Code flow specific errors
  ITB_SESSION_EXPIRED: "ITB session expired",
  INVALID_RESPONSE_TYPE: "Invalid response_type",
  NO_CREDENTIALS_REQUESTED: "no credentials requested",
  PARSE_AUTHORIZATION_DETAILS_ERROR: "error parsing authorization details",
  MISSING_RESPONSE_TYPE: "authorizationDetails missing response_type",
  MISSING_CODE_CHALLENGE: "authorizationDetails missing code_challenge",
  PAR_REQUEST_NOT_FOUND: "ERROR: request_uri present in authorization endpoint, but no par request cached for request_uri",
  ISSUANCE_SESSION_NOT_FOUND: "issuance session not found",
  NO_JWT_PRESENTED: "no jwt presented",
};

// Configuration constants for x509 routes
export const CONFIG = {
  SERVER_URL: process.env.SERVER_URL || "http://localhost:3000",
  get CLIENT_ID() {
    const hostname = new URL(this.SERVER_URL).hostname;
    return `x509_san_dns:${hostname}`;
  },
  get VERIFIER_ATTESTATION_CLIENT_ID() {
    const hostname = new URL(this.SERVER_URL).hostname;
    return `verifier_attestation:${hostname}`;
  },
  DEFAULT_RESPONSE_MODE: "direct_post",
  // Default JAR signature algorithm for VP requests (x509 flows)
  // RS256 is kept as default for backward compatibility; can be overridden per-request.
  DEFAULT_JAR_ALG: "ES256",
  DEFAULT_NONCE_LENGTH: 16,
  QR_CONFIG: {
    type: "png",
    ec_level: "M",
    size: 20,
    margin: 10,
  },
  MEDIA_TYPE: "PNG",
  CONTENT_TYPE: "application/oauth-authz-req+jwt",
  SESSION_STATUS: {
    PENDING: "pending",
  },
  ERROR_MESSAGES: {
    INVALID_SESSION: "Invalid session ID",
    FILE_READ_ERROR: "Failed to read configuration file",
    QR_GENERATION_ERROR: "Failed to generate QR code",
    SESSION_STORE_ERROR: "Failed to store session",
    JWT_BUILD_ERROR: "Failed to build JWT",
    JWK_GENERATION_ERROR: "Failed to generate JWK",
  },
};

// Default DCQL query configuration
export const DEFAULT_DCQL_QUERY = {
  credentials: [
    {
      id: "cmwallet",
      format: "dc+sd-jwt",
      meta: {
        vct_values: ["urn:eu.europa.ec.eudi:pid:1"],
      },
      claims: [
        {
          path: ["family_name"],
        },
      ],
    },
  ],
};

/** CS-03 / CSC remote signing: DCQL credential id must match qesRequest.credential_ids */
export const CS03_SIGNING_CREDENTIAL_ID = "signing-cert-01";

/** DCQL query for CSC X.509 (WE BUILD CS-03) */
export const CS03_DCQL_QUERY = {
  credentials: [
    {
      id: CS03_SIGNING_CREDENTIAL_ID,
      format: "https://cloudsignatureconsortium.org/2025/x509",
      meta: {
        certificatePolicies: ["0.4.0.2042.1"],
      },
    },
  ],
};

/**
 * Parse CS-03 mode from query string (?cs03=1 | ?isCS03=true | ?cs03_oob=1 for out-of-band qesResponse POST).
 * @param {Record<string, unknown>} query - req.query
 */
export function parseCs03Query(query) {
  if (!query || typeof query !== "object") {
    return { enabled: false, oob: false };
  }
  const truthy = (val) => {
    if (val === undefined || val === null) return false;
    const s = String(val).toLowerCase();
    return s === "1" || s === "true" || s === "yes";
  };
  return {
    enabled: truthy(query.cs03) || truthy(query.isCS03) || truthy(query.is_cs03),
    oob: truthy(query.cs03_oob) || truthy(query.cs03Oob) || truthy(query.cs03ResponseUri),
  };
}

/**
 * Build CSC qesRequest object (decoded JSON before base64url encoding into transaction_data).
 * Checksum is computed over {@code data/cs03-sample.pdf}.
 *
 * @param {string} serverURL - Verifier base URL (e.g. CONFIG.SERVER_URL)
 * @param {string} [sessionId] - Required when oob is true (for responseURI path)
 * @param {{ oob?: boolean }} [options]
 */
export function buildCs03QesRequestPayload(serverURL, sessionId, options = {}) {
  const { oob = false, callbackToken = null } = options;
  const base = String(serverURL || "").replace(/\/$/, "");
  const pdfPath = path.join(process.cwd(), "data", "cs03-sample.pdf");
  const pdfBytes = fs.readFileSync(pdfPath);
  const hashB64 = createHash("sha256").update(pdfBytes).digest("base64");
  const checksum = `sha256-${hashB64}`;
  const documentHref = `${base}/x509/cs03-document`;

  const signatureRequest = {
    label: "CS-03 sample document",
    access: { type: "public" },
    href: documentHref,
    checksum,
    signature_format: "P",
    conformance_level: "AdES-B-B",
    signed_envelope_property: "Certification",
  };

  const qes = {
    type: "https://cloudsignatureconsortium.org/2025/qes",
    credential_ids: [CS03_SIGNING_CREDENTIAL_ID],
    signatureQualifier: "eu_eidas_qes",
    signatureRequests: [signatureRequest],
  };

  if (oob && sessionId) {
    const callbackUrl = new URL(`${base}/x509/qes-callback/${sessionId}`);
    if (callbackToken) {
      callbackUrl.searchParams.set("callback_token", callbackToken);
    }
    qes.signatureRequests[0].responseURI = callbackUrl.toString();
  }

  return qes;
}

/** Base64url-encode a qesRequest for OpenID4VP transaction_data[] */
export function encodeCs03TransactionData(qesRequestObj) {
  return Buffer.from(JSON.stringify(qesRequestObj)).toString("base64url");
}

function getHostnameFromX509ClientId(clientId) {
  if (typeof clientId !== "string" || !clientId.startsWith("x509_san_dns:")) {
    return null;
  }
  return clientId.slice("x509_san_dns:".length);
}

export function validateCs03ResponseUriAlignment({ serverURL, clientId, responseURI }) {
  let serverHost;
  let responseHost;
  try {
    serverHost = new URL(serverURL).hostname;
    responseHost = new URL(responseURI).hostname;
  } catch (error) {
    return {
      ok: false,
      error: `invalid CS-03 URL configuration: ${error.message}`,
    };
  }

  const clientIdHost = getHostnameFromX509ClientId(clientId);
  if (!clientIdHost) {
    return {
      ok: false,
      error: "CS-03 requires an x509_san_dns client_id",
    };
  }

  if (responseHost !== serverHost) {
    return {
      ok: false,
      error: `CS-03 responseURI host '${responseHost}' must match verifier SERVER_URL host '${serverHost}'`,
    };
  }

  if (responseHost !== clientIdHost) {
    return {
      ok: false,
      error: `CS-03 responseURI host '${responseHost}' must match x509_san_dns client_id host '${clientIdHost}'`,
    };
  }

  return { ok: true };
}

function isNonEmptyStringArray(value) {
  return Array.isArray(value) && value.length > 0 && value.every((entry) => typeof entry === "string" && entry.length > 0);
}

export function validateCs03QesResponse(qesResponse) {
  if (!qesResponse || typeof qesResponse !== "object" || Array.isArray(qesResponse)) {
    return { ok: false, error: "qes response must be a JSON object" };
  }

  const hasDocumentWithSignature = qesResponse.documentWithSignature !== undefined;
  const hasSignatureObject = qesResponse.signatureObject !== undefined;

  if (!hasDocumentWithSignature && !hasSignatureObject) {
    return { ok: false, error: "qes response must include documentWithSignature or signatureObject" };
  }

  if (hasDocumentWithSignature && hasSignatureObject) {
    return { ok: false, error: "qes response must not include both documentWithSignature and signatureObject" };
  }

  if (hasDocumentWithSignature && !isNonEmptyStringArray(qesResponse.documentWithSignature)) {
    return { ok: false, error: "documentWithSignature must be a non-empty array of base64 strings" };
  }

  if (hasSignatureObject && !isNonEmptyStringArray(qesResponse.signatureObject)) {
    return { ok: false, error: "signatureObject must be a non-empty array of base64 strings" };
  }

  return { ok: true };
}

export function processCs03PresentationResponse(vpTokenRaw, options = {}) {
  const {
    expectedCredentialIds = [CS03_SIGNING_CREDENTIAL_ID],
    oobRequested = false,
    oobResponse = null,
  } = options;

  if (vpTokenRaw === undefined || vpTokenRaw === null) {
    return {
      ok: false,
      error: "invalid_request",
      error_description: "vp_token required for CS-03 signing flow",
    };
  }

  let parsed = vpTokenRaw;
  if (typeof vpTokenRaw === "string") {
    if (!vpTokenRaw.trim().startsWith("{")) {
      return {
        ok: false,
        error: "invalid_request",
        error_description: "vp_token must be a JSON object for CS-03",
      };
    }
    try {
      parsed = JSON.parse(vpTokenRaw);
    } catch (e) {
      return {
        ok: false,
        error: "invalid_request",
        error_description: `vp_token JSON parse failed: ${e.message}`,
      };
    }
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return {
      ok: false,
      error: "invalid_request",
      error_description: "vp_token must be a JSON object for CS-03",
    };
  }

  const responseCredentialIds = Object.keys(parsed);
  const expectedSet = new Set(expectedCredentialIds);
  const unexpectedIds = responseCredentialIds.filter((credId) => !expectedSet.has(credId));
  if (unexpectedIds.length > 0) {
    return {
      ok: false,
      error: "invalid_request",
      error_description: `vp_token contains unexpected credential ids for CS-03: ${unexpectedIds.join(", ")}`,
    };
  }

  const missingIds = expectedCredentialIds.filter((credId) => !(credId in parsed));
  if (missingIds.length > 0) {
    return {
      ok: false,
      error: "invalid_request",
      error_description: `vp_token missing expected credential ids for CS-03: ${missingIds.join(", ")}`,
    };
  }

  const qesByCredentialId = {};
  for (const credId of expectedCredentialIds) {
    const entry = parsed[credId];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return {
        ok: false,
        error: "invalid_request",
        error_description: `CS-03 credential response for '${credId}' must be a JSON object`,
      };
    }

    const hasQes = Object.prototype.hasOwnProperty.call(entry, "qes");
    const isEmptyObject = Object.keys(entry).length === 0;

    if (oobRequested) {
      if (!isEmptyObject) {
        return {
          ok: false,
          error: "invalid_request",
          error_description: `CS-03 credential response for '${credId}' must be empty when responseURI is used`,
        };
      }
      qesByCredentialId[credId] = {
        empty_credential_response: true,
        note: "Wallet POSTed signed output to qesRequest.signatureRequests[].responseURI",
      };
      continue;
    }

    if (!hasQes) {
      return {
        ok: false,
        error: "invalid_request",
        error_description: `CS-03 credential response for '${credId}' must include qes when responseURI is not used`,
      };
    }

    const qesValidation = validateCs03QesResponse(entry.qes);
    if (!qesValidation.ok) {
      return {
        ok: false,
        error: "invalid_request",
        error_description: `Invalid qes response for '${credId}': ${qesValidation.error}`,
      };
    }
    qesByCredentialId[credId] = entry.qes;
  }

  const result = {
    ok: true,
    qes: qesByCredentialId,
    claims: {
      cs03: true,
      credentialIds: expectedCredentialIds,
    },
  };

  if (oobResponse) {
    result.qes_combined = {
      inline: qesByCredentialId,
      oob: oobResponse,
    };
  }

  return result;
}

// Default transaction data configuration
export const DEFAULT_TRANSACTION_DATA = {
  type: "qes_authorization",
  transaction_data_hashes_alg: ["sha-256"],
  purpose: "Verification of identity",
  documentDigests: [
    {
      hash: "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
      label: "Example Contract",
      hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
      documentLocations: [
        {
          uri: "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
          method: {
            type: "public",
          },
        },
      ],
      dtbsr: "VYDl4oTeJ5TmIPCXKdTX1MSWRLI9CKYcyMRz6xlaGg",
    },
  ],
};

// Default mDL DCQL query configuration
export const DEFAULT_MDL_DCQL_QUERY = {
  credentials: [
    {
      claims: [
        {
          path: ["urn:eu.europa.ec.eudi:pid:1:mso_mdoc", "family_name"],
        },
        {
          path: ["urn:eu.europa.ec.eudi:pid:1:mso_mdoc", "given_name"],
        },
        {
          path: ["urn:eu.europa.ec.eudi:pid:1:mso_mdoc", "age_over_18"],
        },
      ],
      format: "mso_mdoc",
      id: "cred1",
      meta: {
        doctype_value: "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
      },
    },
  ],
};

// ============================================================================
// LOGGING AND SESSION CONTEXT UTILITIES
// ============================================================================

/**
 * Log utility-level errors so they're captured by the console interception middleware.
 * @param {string} context - Logical context (e.g., function name)
 * @param {Error} error - Error object
 * @param {Object} metadata - Additional metadata to log
 */
export const logUtilityError = (context, error = {}, metadata = {}) => {
  const payload = {
    message: error?.message || "Unknown error",
    stack: error?.stack,
    ...metadata,
  };
  console.error(`[${context}]`, payload);
};

/**
 * Attempt to extract an existing sessionId from request sources.
 * @param {Object} req - Express request
 * @param {string|null} fallback - Fallback sessionId
 * @returns {string|null}
 */
export const extractSessionIdFromRequest = (req, fallback = null) => {
  if (!req) {
    return fallback;
  }

  return (
    req.sessionLoggingId ||
    req.query?.sessionId ||
    req.params?.sessionId ||
    req.params?.id ||
    req.body?.sessionId ||
    req.headers?.["x-session-id"] ||
    fallback
  );
};

/**
 * Bind a sessionId to the current request/response lifecycle so console interception
 * can associate logs with the correct session.
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {string} sessionId - Session identifier
 * @returns {string|null} - The bound sessionId (or null if not provided)
 */
export const bindSessionLoggingContext = (req, res, sessionId) => {
  if (!sessionId) {
    return null;
  }

  if (req) {
    req.sessionLoggingId = sessionId;
  }

  if (res) {
    res.locals = res.locals || {};
    res.locals.sessionLoggingId = sessionId;

    if (!res.locals.sessionLoggingCleanupBound) {
      const cleanup = () => {
        clearSessionContext();
        res.off("finish", cleanup);
        res.off("close", cleanup);
        res.locals.sessionLoggingCleanupBound = false;
      };

      res.on("finish", cleanup);
      res.on("close", cleanup);
      res.locals.sessionLoggingCleanupBound = true;
    }
  }

  setSessionContext(sessionId);
  return sessionId;
};

// ============================================================================
// CRYPTOGRAPHIC UTILITIES
// ============================================================================

/**
 * Load cryptographic keys from files
 * @returns {Object} Object containing privateKey and publicKeyPem
 */
export const loadCryptographicKeys = () => {
  try {
    const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
    const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
    return { privateKey, publicKeyPem };
  } catch (error) {
    logUtilityError("loadCryptographicKeys", error);
    throw new Error(ERROR_MESSAGES.CRYPTO_KEY_LOAD_ERROR);
  }
};

/**
 * Load presentation definition from file
 * @returns {Object} Presentation definition object
 */
export const loadPresentationDefinition = () => {
  return JSON.parse(fs.readFileSync("./data/presentation_definition_sdjwt.json", "utf-8"));
};

/**
 * Load private key from file
 * @returns {string} Private key content
 */
export const loadPrivateKey = () => {
  return fs.readFileSync("./didjwks/did_private_pkcs8.key", "utf8");
};

// ============================================================================
// PARAMETER EXTRACTION UTILITIES
// ============================================================================

/**
 * Extract session ID from request with fallback to UUID
 * @param {Object} req - Express request object
 * @returns {string} Session ID
 */
export const getSessionId = (req) => {
  return req.query.sessionId || uuidv4();
};

/**
 * Extract credential type from request with default fallback
 * @param {Object} req - Express request object
 * @returns {string} Credential type
 */
export const getCredentialType = (req) => {
  return req.query.credentialType || req.query.type || DEFAULT_CREDENTIAL_TYPE;
};

/**
 * Extract signature type from request with default fallback
 * @param {Object} req - Express request object
 * @returns {string} Signature type
 */
export const getSignatureType = (req) => {
  return req.query.signatureType || DEFAULT_SIGNATURE_TYPE;
};

/**
 * Extract client ID scheme from request with default fallback
 * @param {Object} req - Express request object
 * @returns {string} Client ID scheme
 */
export const getClientIdScheme = (req) => {
  return req.query.client_id_scheme || DEFAULT_CLIENT_ID_SCHEME;
};

// ============================================================================
// SESSION MANAGEMENT UTILITIES
// ============================================================================

/**
 * Create base session object with common properties
 * @param {string} flowType - Type of flow (pre-auth, code, etc.)
 * @param {boolean} isHaip - Whether this is a HAIP flow
 * @param {string} signatureType - Signature type
 * @param {Object} additionalProps - Additional properties to add
 * @returns {Object} Base session object
 */
export const createBaseSession = (flowType = "pre-auth", isHaip = false, signatureType = null, additionalProps = {}) => {
  const session = {
    status: "pending",
    flowType,
    isHaip,
    ...additionalProps
  };

  if (signatureType) {
    session.signatureType = signatureType;
  }

  return session;
};

/**
 * Create session with credential payload
 * @param {Object} credentialPayload - Credential payload data
 * @param {boolean} isHaip - Whether this is a HAIP flow
 * @returns {Object} Session object with credential payload
 */
export const createSessionWithPayload = (credentialPayload, isHaip = true) => {
  return {
    ...createBaseSession("pre-auth", isHaip),
    credentialPayload
  };
};

/**
 * Create code flow session object
 * @param {string} client_id_scheme - Client ID scheme
 * @param {string} flowType - Flow type
 * @param {boolean} isDynamic - Whether this is a dynamic flow
 * @param {boolean} isDeferred - Whether this is a deferred flow
 * @param {string} signatureType - Signature type
 * @returns {Object} Code flow session object
 */
export const createCodeFlowSession = (client_id_scheme, flowType, isDynamic = false, isDeferred = false, signatureType = null) => {
  const session = {
    walletSession: null,
    requests: null,
    results: null,
    status: "pending",
    client_id_scheme: client_id_scheme,
    flowType: flowType,
  };

  if (isDynamic) session.isDynamic = true;
  if (isDeferred) session.isDeferred = true;
  if (signatureType) session.signatureType = signatureType;

  return session;
};

// ============================================================================
// QR CODE AND URL GENERATION UTILITIES
// ============================================================================

/**
 * Generate QR code from credential offer
 * @param {string} credentialOffer - Credential offer string
 * @returns {Promise<string>} Base64 encoded QR code
 */
export const generateQRCode = async (credentialOffer, sessionId = null) => {
  try {
    if (sessionId) {
      await logDebug(sessionId, "Generating QR code", {
        offerLength: credentialOffer?.length
      });
    }
    
    const code = qr.image(credentialOffer, QR_CONFIG);
    const mediaType = "PNG";
    const encodedQR = imageDataURI.encode(await streamToBuffer(code), mediaType);
    
    if (sessionId) {
      await logInfo(sessionId, "QR code generated successfully", {
        encodedLength: encodedQR?.length
      });
    }
    
    return encodedQR;
  } catch (error) {
    if (sessionId) {
      await logError(sessionId, "QR code generation error", {
        error: error.message,
        stack: error.stack
      });
    } else {
      logUtilityError("generateQRCode", error);
    }
    throw new Error(ERROR_MESSAGES.QR_GENERATION_FAILED);
  }
};

/**
 * Build credential offer URL with parameters
 * @param {string} sessionId - Session ID
 * @param {string} credentialType - Credential type
 * @param {string} endpointPath - Endpoint path
 * @param {string} urlScheme - URL scheme to use
 * @param {Object} additionalParams - Additional query parameters
 * @returns {string} Encoded credential offer URL
 */
export const buildCredentialOfferUrl = (sessionId, credentialType, endpointPath, urlScheme = URL_SCHEMES.STANDARD, additionalParams = {}) => {
  const params = new URLSearchParams();
  params.append('type', credentialType);
  
  // Add additional parameters
  Object.entries(additionalParams).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      params.append(key, value);
    }
  });
  
  const queryString = params.toString();
  const fullUrl = `${SERVER_URL}${endpointPath}/${sessionId}${queryString ? `?${queryString}` : ''}`;
  
  return encodeURIComponent(fullUrl);
};

/**
 * Create pre-auth credential offer URI
 * @param {string} sessionId - Session ID
 * @param {string} credentialType - Credential type
 * @param {string} endpointPath - Endpoint path
 * @param {string} urlScheme - URL scheme to use
 * @param {Object} additionalParams - Additional query parameters
 * @returns {string} Proper OpenID4VCI credential offer URI
 */
export const createPreAuthCredentialOfferUri = (sessionId, credentialType, endpointPath, urlScheme = URL_SCHEMES.STANDARD, additionalParams = {}) => {
  const encodedCredentialOfferUri = buildCredentialOfferUrl(sessionId, credentialType, endpointPath, urlScheme, additionalParams);
  const credentialOffer = `${urlScheme}?credential_offer_uri=${encodedCredentialOfferUri}`;
  return credentialOffer;
};

/**
 * Create credential offer response with QR code
 * @param {string} credentialOffer - Credential offer string
 * @param {string} sessionId - Session ID
 * @returns {Promise<Object>} Response object with QR code and deep link
 */
export const createCredentialOfferResponse = async (credentialOffer, sessionId) => {
  try {
    const qr = await generateQRCode(credentialOffer);
    return {
      qr,
      deepLink: credentialOffer,
      sessionId,
    };
  } catch (error) {
    logUtilityError("createCredentialOfferResponse", error);
    throw error;
  }
};

/**
 * Create credential offer configuration object
 * @param {string} credentialType - Credential type
 * @param {string} sessionId - Session ID
 * @param {boolean} includeTxCode - Whether to include transaction code
 * @param {string} grantType - Grant type to use
 * @returns {Object} Credential offer configuration
 */
export const createCredentialOfferConfig = (credentialType, sessionId, includeTxCode = false, grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code") => {
  const config = {
    credential_issuer: SERVER_URL,
    credential_configuration_ids: [credentialType],
    grants: {
      [grantType]: {},
    },
  };

  // For authorization code flow, use issuer_state
  if (grantType === "authorization_code") {
    config.grants[grantType].issuer_state = sessionId;
    config.grants[grantType].scope = credentialType
  } else {
    // For pre-authorized code flow, use pre-authorized_code
    config.grants[grantType]["pre-authorized_code"] = sessionId;
  }

  if (includeTxCode) {
    config.grants[grantType].tx_code = TX_CODE_CONFIG;
  }

  return config;
};

/**
 * Build code flow credential offer URL
 * @param {string} uuid - Session UUID
 * @param {string} credentialType - Credential type
 * @param {string} client_id_scheme - Client ID scheme
 * @param {boolean} includeCredentialType - Whether to include credential type in URL
 * @returns {string} Encoded credential offer URL
 */
export const buildCodeFlowCredentialOfferUrl = (uuid, credentialType, client_id_scheme, includeCredentialType = true) => {
  const baseUrl = `${SERVER_URL}/credential-offer-code-sd-jwt/${uuid}`;
  const params = new URLSearchParams();
  
  if (includeCredentialType) {
    params.append('credentialType', credentialType);
  }
  params.append('scheme', client_id_scheme);
  
  const queryString = params.toString();
  const fullUrl = queryString ? `${baseUrl}?${queryString}` : baseUrl;
  
  return encodeURIComponent(fullUrl);
};

/**
 * Create code flow credential offer response
 * @param {string} uuid - Session UUID
 * @param {string} credentialType - Credential type
 * @param {string} client_id_scheme - Client ID scheme
 * @param {boolean} includeCredentialType - Whether to include credential type in URL
 * @param {string} urlScheme - Wallet invocation scheme (e.g., openid-credential-offer://, haip://)
 * @returns {string} Credential offer string
 */
export const createCodeFlowCredentialOfferResponse = (
  uuid,
  credentialType,
  client_id_scheme,
  includeCredentialType = true,
  urlScheme = URL_SCHEMES.STANDARD
) => {
  const encodedCredentialOfferUri = buildCodeFlowCredentialOfferUrl(
    uuid,
    credentialType,
    client_id_scheme,
    includeCredentialType
  );
  const credentialOffer = `${urlScheme}?credential_offer_uri=${encodedCredentialOfferUri}`;
  return credentialOffer;
};

// ============================================================================
// DID UTILITIES
// ============================================================================

/**
 * Build DID controller string
 * @returns {string} DID controller string
 */
export const buildDidController = () => {
  let controller = SERVER_URL;
  if (PROXY_PATH) {
    controller = SERVER_URL.replace("/" + PROXY_PATH, "") + ":" + PROXY_PATH;
  }
  return controller.replace("https://", "");
};

// ============================================================================
// ERROR HANDLING UTILITIES
// ============================================================================

/**
 * Create standardized error response
 * @param {string} error - Error code
 * @param {string} description - Error description
 * @param {number} status - HTTP status code
 * @returns {Object} Standardized error response
 */
export const createErrorResponse = (error, description, status = 500, sessionId = null) => {
  if (sessionId) {
    logError(sessionId, "Creating error response", {
      error: error || "server_error",
      description: description || "An unexpected error occurred",
      status
    }).catch(err => logUtilityError("createErrorResponse.logError", err));
  }
  
  return {
    status,
    body: {
      error: error || "server_error",
      error_description: description || "An unexpected error occurred"
    }
  };
};

/**
 * Handle route errors consistently
 * @param {Error} error - Error object
 * @param {string} context - Error context for logging
 * @param {Object} res - Express response object
 */
export const handleRouteError = (error, context, res, sessionId = null) => {
  const effectiveSessionId = sessionId || res?.locals?.sessionLoggingId || null;

  if (effectiveSessionId) {
    logError(effectiveSessionId, `${context} error`, {
      error: error.message,
      stack: error.stack,
      context
    }).catch(err => logUtilityError("handleRouteError.logError", err));
  } else {
    logUtilityError(`${context} error`, error);
  }
  
  const errorResponse = createErrorResponse("server_error", error.message, 500, effectiveSessionId);
  res.status(errorResponse.status).json(errorResponse.body);
};

// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

/**
 * Validate session ID
 * @param {string} sessionId - Session ID to validate
 * @returns {boolean} Whether session ID is valid
 */
export const isValidSessionId = (sessionId) => {
  return sessionId && typeof sessionId === 'string' && sessionId.trim().length > 0;
};

/**
 * Validate credential payload
 * @param {Object} payload - Credential payload to validate
 * @returns {boolean} Whether payload is valid
 */
export const isValidCredentialPayload = (payload) => {
  return payload && typeof payload === 'object' && Object.keys(payload).length > 0;
};

// ============================================================================
// RESPONSE UTILITIES
// ============================================================================

/**
 * Send standardized success response
 * @param {Object} res - Express response object
 * @param {Object} data - Response data
 * @param {number} status - HTTP status code
 */
export const sendSuccessResponse = (res, data, status = 200) => {
  res.status(status).json(data);
};

/**
 * Send standardized error response
 * @param {Object} res - Express response object
 * @param {string} error - Error code
 * @param {string} description - Error description
 * @param {number} status - HTTP status code
 */
export const sendErrorResponse = (res, error, description, status = 500) => {
  const errorResponse = createErrorResponse(error, description, status);
  res.status(errorResponse.status).json(errorResponse.body);
};

// ============================================================================
// X509 ROUTES UTILITIES
// ============================================================================

/**
 * Load configuration files safely
 * @param {string} presentationDefPath - Path to presentation definition file
 * @param {string} clientMetadataPath - Path to client metadata file
 * @param {string} privateKeyPath - Path to private key file (optional)
 * @returns {Object} - Object containing loaded configurations
 */
export function loadConfigurationFiles(presentationDefPath, clientMetadataPath, privateKeyPath = null) {
  try {
    const presentationDefinition = JSON.parse(
      fs.readFileSync(presentationDefPath, "utf-8")
    );
    const clientMetadata = JSON.parse(
      fs.readFileSync(clientMetadataPath, "utf-8")
    );

    const result = {
      presentationDefinition,
      clientMetadata,
    };

    if (privateKeyPath) {
      result.privateKey = fs.readFileSync(privateKeyPath, "utf8");
    }

    return result;
  } catch (error) {
    logUtilityError("loadConfigurationFiles", error, {
      presentationDefPath,
      clientMetadataPath,
      privateKeyPath,
    });
    throw new Error(CONFIG.ERROR_MESSAGES.FILE_READ_ERROR);
  }
}

/**
 * Generate VP request with common parameters
 * @param {Object} params - Parameters for VP request generation
 * @returns {Promise<Object>} - The VP request result
 */
export async function generateVPRequest(params) {
  // update this for verifier attestation to include in the jose header the verifier attestation jwt
  const {
    sessionId,
    responseMode,
    jarAlg,
    presentationDefinition,
    clientId,
    clientMetadata,
    kid,
    serverURL,
    dcqlQuery = null,
    transactionData = null,
    usePostMethod = false,
    routePath,
    cs03Signing = false,
    cs03Oob = false,
    cs03CallbackToken = null,
  } = params;

  await logInfo(sessionId, "Starting VP request generation in routeUtils", {
    responseMode,
    jarAlg: jarAlg || CONFIG.DEFAULT_JAR_ALG,
    clientId,
    hasDcqlQuery: !!dcqlQuery,
    hasTransactionData: !!transactionData,
    cs03Signing,
    cs03Oob,
    usePostMethod,
    routePath
  });

  const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
  const state = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
  const responseUri = `${serverURL}/direct_post/${sessionId}`;
  
  await logDebug(sessionId, "Generated nonce and response URI", {
    nonce,
    state,
    responseUri
  });

  // Prepare session data
  const sessionData = {
    nonce,
    response_mode: responseMode,
    state,
    jar_alg: jarAlg || CONFIG.DEFAULT_JAR_ALG,
  };

  if (presentationDefinition) {
    sessionData.presentation_definition = presentationDefinition;
    sessionData.sdsRequested = getSDsFromPresentationDef(presentationDefinition);
    await logDebug(sessionId, "Added presentation definition to session", {
      inputDescriptors: presentationDefinition.input_descriptors?.length || 0
    });
  }

  if (dcqlQuery) {
    sessionData.dcql_query = dcqlQuery;
    await logDebug(sessionId, "Added DCQL query to session", {
      credentialsCount: dcqlQuery.credentials?.length || 0
    });
  }

  if (transactionData) {
    sessionData.transaction_data = [transactionData];
    await logDebug(sessionId, "Added transaction data to session", {
      transactionType:
        typeof transactionData === "string"
          ? "base64url-encoded"
          : transactionData?.type,
    });
  }

  if (cs03Signing) {
    sessionData.cs03_signing = true;
    sessionData.cs03_oob = cs03Oob;
    sessionData.cs03_callback_token = cs03CallbackToken;
    sessionData.cs03_expected_credential_ids =
      dcqlQuery?.credentials?.map((cred) => cred.id).filter(Boolean) || [CS03_SIGNING_CREDENTIAL_ID];
    await logDebug(sessionId, "CS-03 remote signing flow flagged on session");
  }

  // Store session data
  await logDebug(sessionId, "Storing VP session data");
  await storeVPSessionData(sessionId, sessionData);
  await logInfo(sessionId, "VP session data stored successfully");

  // Build VP request JWT (key is determined from client_id scheme)
  await logDebug(sessionId, "Building VP request JWT");
  await buildVpRequestJWT(
    clientId,
    responseUri,
    presentationDefinition,
    null, // privateKey - only used for verifier_attestation scheme
    clientMetadata,
    kid,
    serverURL,
    "vp_token",
    nonce,
    dcqlQuery,
    transactionData ? [transactionData] : null,
    responseMode,
    undefined,
    undefined,
    state,
    jarAlg || CONFIG.DEFAULT_JAR_ALG
  );
  await logInfo(sessionId, "VP request JWT built successfully");

  // Create OpenID4VP request URL
  const requestUri = `${serverURL}${routePath}/${sessionId}`;
  const vpRequest = createOpenID4VPRequestUrl(requestUri, clientId, usePostMethod);
  
  await logDebug(sessionId, "Created OpenID4VP request URL", {
    requestUri,
    vpRequest: vpRequest.substring(0, 100) + "..."
  });

  // Generate QR code
  const qrCode = await generateQRCode(vpRequest, sessionId);

  const response = createVPRequestResponse(qrCode, vpRequest, sessionId);
  await logInfo(sessionId, "VP request generation completed successfully", {
    hasQrCode: !!response.qr,
    deepLinkLength: response.deepLink?.length
  });
  
  return response;
}

/**
 * Helper function to process VP Request
 * @param {Object} params - Parameters for VP request processing
 * @returns {Promise<Object>} - The result object with JWT or error
 */
export async function processVPRequest(params) {
  const {
    sessionId,
    clientMetadata,
    serverURL,
    clientId,
    kid,
    audience,
    walletNonce,
    walletMetadata,
  } = params;

  await logInfo(sessionId, "Starting VP request processing in routeUtils", {
    clientId,
    hasAudience: !!audience,
    hasWalletNonce: !!walletNonce,
    hasWalletMetadata: !!walletMetadata
  });

  try {
    await logDebug(sessionId, "Retrieving VP session data");
    const vpSession = await getVPSession(sessionId);

    if (!vpSession) {
      await logError(sessionId, "VP session not found", {
        sessionId,
        error: CONFIG.ERROR_MESSAGES.INVALID_SESSION
      });
      return { error: CONFIG.ERROR_MESSAGES.INVALID_SESSION, status: 400 };
    }
    
    await logInfo(sessionId, "VP session retrieved successfully", {
      hasNonce: !!vpSession.nonce,
      hasPresentationDefinition: !!vpSession.presentation_definition,
      hasDcqlQuery: !!vpSession.dcql_query,
      hasTransactionData: !!vpSession.transaction_data,
      responseMode: vpSession.response_mode
    });

    const responseUri = `${serverURL}/direct_post/${sessionId}`;
    
    await logDebug(sessionId, "Building VP request JWT", {
      responseUri,
      responseMode: vpSession.response_mode
    });

    const vpRequestJWT = await buildVpRequestJWT(
      clientId,
      responseUri,
      vpSession.presentation_definition,
      null, // privateKey - only used for verifier_attestation scheme
      clientMetadata,
      kid,
      serverURL,
      "vp_token",
      vpSession.nonce,
      vpSession.dcql_query || null,
      vpSession.transaction_data || null,
      vpSession.response_mode,
      audience,
      walletNonce,
      walletMetadata,
      null, // va_jwt - Verifier Attestation JWT (not used in response processing)
      vpSession.state,
      vpSession.jar_alg || CONFIG.DEFAULT_JAR_ALG
    );
    
    await logInfo(sessionId, "VP request JWT built successfully", {
      jwtLength: vpRequestJWT?.length
    });

    console.log("vpRequestJWT", vpRequestJWT);
    await logDebug(sessionId, "VP request JWT details", {
      jwt: vpRequestJWT
    });
    
    await logInfo(sessionId, "VP request processing completed successfully");
    return { jwt: vpRequestJWT, status: 200 };
  } catch (error) {
    logUtilityError("processVPRequest", error);
    await logError(sessionId, "Error in processVPRequest", {
      error: error.message,
      stack: error.stack
    });
    throw new Error(CONFIG.ERROR_MESSAGES.JWT_BUILD_ERROR);
  }
}

/**
 * Create transaction data object with credential IDs
 * @param {Object} presentationDefinitionOrDcqlQuery - The presentation definition or DCQL query
 * @returns {Object} - The transaction data object
 */
export function createTransactionData(presentationDefinitionOrDcqlQuery) {
  let credentialIds = [];
  
  // Handle Presentation Definition (PEX)
  if (presentationDefinitionOrDcqlQuery?.input_descriptors) {
    credentialIds = presentationDefinitionOrDcqlQuery.input_descriptors.map(
      (descriptor) => descriptor.id
    );
  }
  // Handle DCQL Query
  else if (presentationDefinitionOrDcqlQuery?.credentials) {
    credentialIds = presentationDefinitionOrDcqlQuery.credentials.map(
      (credential) => credential.id
    );
  }
  
  return {
    ...DEFAULT_TRANSACTION_DATA,
    credential_ids: credentialIds,
    timestamp: new Date().toISOString(),
    transaction_id: uuidv4(),
  };
}

/**
 * Create an OpenID4VP request URL
 * @param {string} requestUri - The request URI
 * @param {string} clientId - The client ID
 * @param {boolean} usePostMethod - Whether to use POST method
 * @returns {string} - The OpenID4VP request URL
 */
export function createOpenID4VPRequestUrl(requestUri, clientId, usePostMethod = false) {
  const baseUrl = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
  return usePostMethod ? `${baseUrl}&request_uri_method=post` : baseUrl;
}

/**
 * Store VP session data
 * @param {string} sessionId - The session ID
 * @param {Object} sessionData - The session data to store
 * @returns {Promise<void>}
 */
export async function storeVPSessionData(sessionId, sessionData) {
  try {
    await logDebug(sessionId, "Storing VP session data", {
      hasNonce: !!sessionData.nonce,
      hasPresentationDefinition: !!sessionData.presentation_definition,
      hasDcqlQuery: !!sessionData.dcql_query,
      hasTransactionData: !!sessionData.transaction_data,
      responseMode: sessionData.response_mode
    });
    
    await storeVPSession(sessionId, {
      uuid: sessionId,
      status: CONFIG.SESSION_STATUS.PENDING,
      claims: null,
      ...sessionData,
    });
    
    await logInfo(sessionId, "VP session data stored successfully");
  } catch (error) {
    logUtilityError("storeVPSessionData", error);
    await logError(sessionId, "Failed to store VP session", {
      error: error.message,
      stack: error.stack
    });
    throw new Error(CONFIG.ERROR_MESSAGES.SESSION_STORE_ERROR);
  }
}

/**
 * Create a standard VP request response
 * @param {string} qrCode - The QR code data URI
 * @param {string} deepLink - The deep link URL
 * @param {string} sessionId - The session ID
 * @returns {Object} - The response object
 */
export function createVPRequestResponse(qrCode, deepLink, sessionId) {
  return {
    qr: qrCode,
    deepLink,
    sessionId,
  };
}

/**
 * Handle session creation for GET requests when no session exists
 * @param {string} sessionId - The session ID
 * @param {Object} presentationDefinition - The presentation definition
 * @param {string} responseMode - The response mode
 * @returns {Promise<void>}
 */
export async function handleSessionCreation(sessionId, presentationDefinition, responseMode) {
  await logInfo(sessionId, "Creating new VP session", {
    responseMode,
    hasPresentation: !!presentationDefinition
  });
  
  const nonce = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
  const state = generateNonce(CONFIG.DEFAULT_NONCE_LENGTH);
  
  await logDebug(sessionId, "Generated nonce and state for new session", {
    nonce,
    state
  });

  await storeVPSessionData(sessionId, {
    presentation_definition: presentationDefinition,
    nonce,
    state,
    sdsRequested: getSDsFromPresentationDef(presentationDefinition),
    response_mode: responseMode,
  });
  
  await logInfo(sessionId, "VP session created successfully");
}

// ============================================================================
// DID UTILITIES
// ============================================================================

/**
 * Generate DID JWK identifier from private key
 * @param {string} privateKey - The private key in PEM format
 * @returns {string} - The DID JWK identifier
 */
export function generateDidJwkIdentifier(privateKey) {
  try {
    const publicKey = createPublicKey(privateKey);
    const jwk = publicKey.export({ format: 'jwk' });
    return `did:jwk:${base64url(JSON.stringify(jwk))}`;
  } catch (error) {
    logUtilityError("generateDidJwkIdentifier", error);
    throw new Error(CONFIG.ERROR_MESSAGES.JWK_GENERATION_ERROR);
  }
}

/**
 * Create DID controller from server URL
 * @param {string} serverURL - The server URL
 * @returns {string} - The DID controller
 */
export function createDidController(serverURL) {
  let controller = serverURL;
  if (process.env.PROXY_PATH) {
    controller = serverURL.replace("/" + process.env.PROXY_PATH, "") + ":" + process.env.PROXY_PATH;
  }
  controller = controller.replace("https://", "");
  return controller;
}

/**
 * Generate DID-based client ID and key ID
 * @param {string} serverURL - The server URL
 * @returns {Object} - Object containing client_id and kid
 */
export function generateDidIdentifiers(serverURL) {
  const controller = createDidController(serverURL);
  const client_id = `decentralized_identifier:did:web:${controller}`;
  const kid = `did:web:${controller}#keys-1`;
  return { client_id, kid };
}

/**
 * Generate DID JWK identifiers
 * @param {string} didJwkIdentifier - The DID JWK identifier
 * @returns {Object} - Object containing client_id and kid
 */
export function generateDidJwkIdentifiers(didJwkIdentifier) {
  const client_id = `decentralized_identifier:${didJwkIdentifier}`;
  const kid = `${didJwkIdentifier}#0`; // did:jwk uses #0 as default key ID
  return { client_id, kid };
}

// ---------------------------------------------------------------------------
// Wallet Unit Attestation (WUA) — verification helpers
// ---------------------------------------------------------------------------
//
// Context (EUDI / ARF / ETSI TS 119 472-3):
// - WUA is issued by the Wallet Provider (WP), not the end user. During activation the WP issues
//   one or more WUAs to the Wallet Unit; the WUA is a JWT signed by the WP.
// - The PID/EAA Provider is expected to accept a WUA only if it can trust the WP — typically by
//   resolving the WP signing key via the EU Trusted List (or equivalent trust framework), not by
//   treating the attester as an arbitrary device key.
// - In the current EUDI issuance profile the same WUA object appears in both paths:
//   • proofs.jwt + protected-header key_attestation = WUA (WP-signed); the proof JWT itself is
//     signed by the Wallet Unit with the private key for the *first* entry in WUA attested_keys
//     (PoP). We validate that PoP binding separately in the credential route.
//   • proofs.attestation = [ WUA ] — still WP-signed WUA; that proof type does not assert PoP of
//     the attested key in that request (key-attestation-only path in keyAttestationProof.js).
//
// What we implement here vs. not yet:
// - We verify the JWS cryptographically (using issuer wallet_unit_attestation_jwks or, for dev,
//   header.jwk) and run structural checks (eudi_wallet_info, exp, etc.).
// - We do NOT yet validate that payload.iss identifies a Wallet Provider that is on the Trusted
//   List or otherwise policy-approved. That is isolated in isWuaWalletProviderTrustedByPolicy()
//   below (currently stubs true) so the trust framework can be plugged in later.

function loadIssuerMetadataForWua() {
  try {
    const configPath = path.join(process.cwd(), "data", "issuer-config.json");
    const raw = fs.readFileSync(configPath, "utf-8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/**
 * Public key for verifying the WUA JWS. Prefers configured JWKS; falls back to header.jwk (dev / self-contained WUAs).
 * @param {object} decodedHeader - jwt.decode complete.header
 * @param {object} issuerMetadata - issuer-config root (optional wallet_unit_attestation_jwks)
 * @returns {object} JWK
 */
export function resolveWuaVerificationJwk(decodedHeader, issuerMetadata) {
  const jwks = issuerMetadata?.wallet_unit_attestation_jwks;
  if (jwks?.keys?.length) {
    const kid = decodedHeader?.kid;
    if (kid) {
      const match = jwks.keys.find((k) => k.kid === kid);
      if (match) return match;
    }
    return jwks.keys[0];
  }
  if (decodedHeader?.jwk) return decodedHeader.jwk;
  throw new Error(
    withSpecRef(
      "Cannot verify WUA signature: set issuer wallet_unit_attestation_jwks or send WUA with jwk in protected header",
      WUA_SPEC_REF,
      OID4VCI_WALLET_ATTESTATION_SPEC_REF
    )
  );
}

/**
 * @param {string} wuaJwt
 * @param {object} decodedHeader
 * @param {object} [issuerMetadata] - issuer-config JSON root; loaded from disk if omitted
 */
export async function verifyWuaJwtSignature(wuaJwt, decodedHeader, issuerMetadata = null) {
  const meta = issuerMetadata ?? loadIssuerMetadataForWua();
  const alg = decodedHeader?.alg || "ES256";
  if (!alg) {
    return { ok: false, error: withSpecRef("WUA JWT header missing alg", WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
  }
  try {
    const verificationJwk = resolveWuaVerificationJwk(decodedHeader, meta);
    const key = await jose.importJWK(verificationJwk, alg);
    await jose.jwtVerify(wuaJwt, key, { algorithms: [alg] });
    return { ok: true };
  } catch (e) {
    const msg = e?.message || String(e);
    return {
      ok: false,
      error: withSpecRef(`WUA signature verification failed: ${msg}`, WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF),
    };
  }
}

/**
 * Policy gate: is the WUA issuer (`iss` = Wallet Provider) trusted by this credential issuer?
 *
 * Stub: always returns true. Replace with Trusted List lookup, WP registry, allow-lists keyed by
 * `iss`, certificate policy, etc., when the trust framework is available.
 *
 * @param {object} wuaPayload - Decoded WUA JWT payload (after successful JWS verification)
 * @param {object} decodedHeader - Decoded WUA JWT protected header
 * @param {object} issuerMetadata - Issuer configuration root (future: trusted list URIs, pinned WP JWKS)
 * @returns {boolean}
 */
export function isWuaWalletProviderTrustedByPolicy(wuaPayload, decodedHeader, issuerMetadata) {
  void decodedHeader;
  void issuerMetadata;
  void wuaPayload;
  return true;
}

// ============================================================================
// WIA AND WUA VALIDATION UTILITIES
// ============================================================================

/**
 * Validates Wallet Instance Attestation (WIA) JWT
 * Based on TS3 Wallet Unit Attestation spec:
 * https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
 * 
 * @param {string} wiaJwt - The WIA JWT string
 * @param {string} sessionId - Session ID for logging
 * @returns {Promise<{valid: boolean, payload?: object, error?: string}>}
 */
export const validateWIA = async (wiaJwt, sessionId = null) => {
  try {
    if (!wiaJwt || typeof wiaJwt !== 'string') {
      return { valid: false, error: withSpecRef('WIA JWT is missing or invalid', WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
    }

    // Decode JWT to check structure
    const decoded = jwt.decode(wiaJwt, { complete: true });
    if (!decoded || !decoded.header || !decoded.payload) {
      return { valid: false, error: withSpecRef('WIA JWT is malformed', WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (decoded.payload.exp && decoded.payload.exp < now) {
      return { valid: false, error: withSpecRef('WIA JWT has expired', WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
    }

    // Check required claims (basic structure check)
    if (!decoded.payload.iss) {
      return { valid: false, error: withSpecRef('WIA JWT missing iss claim', WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
    }

    // Per spec: WIA SHALL have a time-to-live of less than 24 hours
    // I.e., the difference between expiration time exp and the time of issuance SHALL be less than 24 hours
    if (decoded.payload.exp && decoded.payload.iat) {
      const ttlInSeconds = decoded.payload.exp - decoded.payload.iat;
      const ttlInHours = ttlInSeconds / 3600;
      const maxTtlHours = 24;
      
      if (ttlInSeconds < 0) {
        return { valid: false, error: withSpecRef('WIA JWT has invalid expiration (exp < iat)', WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
      }
      
      if (ttlInHours >= maxTtlHours) {
        return {
          valid: false,
          error: withSpecRef(
            `WIA JWT TTL (${ttlInHours.toFixed(2)} hours) exceeds maximum allowed (${maxTtlHours} hours)`,
            WUA_SPEC_REF,
            OID4VCI_WALLET_ATTESTATION_SPEC_REF
          ),
        };
      }
    } else if (!decoded.payload.exp || !decoded.payload.iat) {
      return {
        valid: false,
        error: withSpecRef(
          'WIA JWT missing exp or iat claim required for TTL validation',
          WUA_SPEC_REF,
          OID4VCI_WALLET_ATTESTATION_SPEC_REF
        ),
      };
    }

    // TODO: Verify signature against Wallet Provider's JWKS
    // The WIA SHALL be signed by the Wallet Provider
    // This requires fetching the JWKS from the issuer (decoded.payload.iss)
    // For now, we'll log the WIA but note that signature verification is pending
    
    if (sessionId) {
      const ttlInHours = decoded.payload.exp && decoded.payload.iat 
        ? ((decoded.payload.exp - decoded.payload.iat) / 3600).toFixed(2)
        : 'unknown';
      await logInfo(sessionId, "WIA extracted and basic validation passed", {
        wiaIssuer: decoded.payload.iss,
        wiaExp: decoded.payload.exp,
        wiaIat: decoded.payload.iat,
        ttlHours: ttlInHours,
        signatureVerification: 'pending'
      }).catch(() => {});
    }

    return { valid: true, payload: decoded.payload };
  } catch (error) {
    const errorMsg = `WIA validation error: ${error.message}`;
    if (sessionId) {
      await logError(sessionId, errorMsg, { error: error.message, stack: error.stack }).catch(() => {});
    }
    return { valid: false, error: errorMsg };
  }
};

/**
 * Validates Wallet Unit Attestation (WUA) JWT
 * Based on TS3 Wallet Unit Attestation spec:
 * https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
 *
 * Trust: see module comment above — JWS verification is performed; Wallet Provider / `iss` trust
 * via Trusted List is not (yet); use {@link isWuaWalletProviderTrustedByPolicy} for that hook.
 *
 * @param {string} wuaJwt - The WUA JWT string
 * @param {string} sessionId - Session ID for logging
 * @param {object} [issuerMetadata] - issuer-config root (wallet_unit_attestation_jwks); defaults to data/issuer-config.json
 * @returns {Promise<{valid: boolean, payload?: object, error?: string}>}
 */
export const validateWUA = async (wuaJwt, sessionId = null, issuerMetadata = null) => {
  try {
    if (!wuaJwt || typeof wuaJwt !== 'string') {
      return { valid: false, error: withSpecRef('WUA JWT is missing or invalid', WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
    }

    // Decode JWT to check structure
    const decoded = jwt.decode(wuaJwt, { complete: true });
    if (!decoded || !decoded.header || !decoded.payload) {
      return { valid: false, error: withSpecRef('WUA JWT is malformed', WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (decoded.payload.exp && decoded.payload.exp < now) {
      return { valid: false, error: withSpecRef('WUA JWT has expired', WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
    }

    // Check required claims
    if (!decoded.payload.iss) {
      return { valid: false, error: withSpecRef('WUA JWT missing iss claim', WUA_SPEC_REF, OID4VCI_WALLET_ATTESTATION_SPEC_REF) };
    }

    // Check for eudi_wallet_info (optional but recommended)
    const hasEudiWalletInfo = !!decoded.payload.eudi_wallet_info;
    let generalInfo;
    let keyStorageInfo;
    if (!hasEudiWalletInfo) {
      return { valid: false, error: withSpecRef('eudi_wallet_info claim is missing', WUA_SPEC_REF) };
    }else{
      generalInfo = decoded.payload.eudi_wallet_info.general_info;
      keyStorageInfo = decoded.payload.eudi_wallet_info.key_storage_info;
      if (!generalInfo || !keyStorageInfo) {
        return { valid: false, error: withSpecRef('general_info or key_storage_info claim is missing', WUA_SPEC_REF) };
      }
    }
    
    // Check for attested_keys (required per spec)
    const hasAttestedKeys = Array.isArray(decoded.payload.attested_keys) && decoded.payload.attested_keys.length > 0;
    
    // Check for status/revocation information (required per spec)
    const hasStatus = !!decoded.payload.status && !!decoded.payload.status.status_list;

    const meta = issuerMetadata ?? loadIssuerMetadataForWua();
    // Cryptographic: WUA must be a valid JWS from a key we resolve (JWKS or dev header.jwk).
    const sigResult = await verifyWuaJwtSignature(wuaJwt, decoded.header, meta);
    if (!sigResult.ok) {
      if (sessionId) {
        await logError(sessionId, "WUA signature verification failed", { error: sigResult.error }).catch(() => {});
      }
      return { valid: false, error: sigResult.error };
    }

    // Policy: Wallet Provider (`iss`) trusted via Trusted List / registry — not implemented; stub always allows.
    if (!isWuaWalletProviderTrustedByPolicy(decoded.payload, decoded.header, meta)) {
      const msg = withSpecRef(
        "WUA rejected: Wallet Provider (iss) not trusted by issuer policy",
        WUA_SPEC_REF,
        OID4VCI_WALLET_ATTESTATION_SPEC_REF
      );
      if (sessionId) {
        await logError(sessionId, msg, { wuaIss: decoded.payload.iss }).catch(() => {});
      }
      return { valid: false, error: msg };
    }

    // TODO: Check revocation status using status_list if present

    if (sessionId) {
      await logInfo(sessionId, "WUA validated (structure + signature + trust stub)", {
        wuaIssuer: decoded.payload.iss,
        wuaExp: decoded.payload.exp,
        wuaIat: decoded.payload.iat,
        hasEudiWalletInfo,
        hasAttestedKeys,
        hasStatus,
        generalInfo,
        keyStorageInfo,
        attestedKeysCount: decoded.payload.attested_keys?.length || 0,
        signatureVerification: 'verified',
        walletProviderTrustPolicy: 'stub_true (Trusted List not wired)',
        revocationCheck: 'pending'
      }).catch(() => {});
    }

    // Warn if required elements are missing
    if (!hasAttestedKeys) {
      if (sessionId) {
        await logWarn(sessionId, "WUA missing attested_keys", {}).catch(() => {});
      }
    }
    if (!hasStatus) {
      if (sessionId) {
        await logWarn(sessionId, "WUA missing status/revocation information", {}).catch(() => {});
      }
    }

    return { valid: true, payload: decoded.payload };
  } catch (error) {
    const errorMsg = `WUA validation error: ${error.message}`;
    if (sessionId) {
      await logError(sessionId, errorMsg, { error: error.message, stack: error.stack }).catch(() => {});
    }
    return { valid: false, error: errorMsg };
  }
};

/**
 * Extracts WIA from token endpoint request or Pushed Authorization Request (PAR)
 * 
 * Per spec: WIA SHALL be sent to the Authorization Server in the Pushed Authorization Request 
 * and the Token Request as client_assertion with client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
 * 
 * The WIA SHALL be sent along with a Proof-of-Possession (PoP), as specified in Appendix E 
 * of OpenID for Verifiable Credential Issuance v1.0.
 * 
 * @param {object} reqBody - Request body
 * @param {object} reqHeaders - Request headers (unused, kept for API compatibility)
 * @returns {string|null} - WIA JWT or null if not found
 */
export const extractWIAFromTokenRequest = (reqBody, reqHeaders) => {
  // WIA is sent as client_assertion in the request body (OAuth 2.0 client assertion)
  // Per OAuth 2.0 spec, client assertions are sent in the body, not in Authorization header
  if (reqBody.client_assertion && reqBody.client_assertion_type === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
    return reqBody.client_assertion;
  }
  
  return null;
};

/**
 * Extracts WUA from credential request
 * WUA can be in proofs.attestation or in the header of proofs.jwt
 * 
 * @param {object} requestBody - Credential request body
 * @returns {string|null} - WUA JWT or null if not found
 */
export const extractWUAFromCredentialRequest = (requestBody) => {
  // Check for key_attestation in proofs.attestation
  if (requestBody.proofs && requestBody.proofs.attestation) {
    const attestation = requestBody.proofs.attestation;
    if (Array.isArray(attestation) && attestation.length > 0) {
      const first = attestation[0];
      if (typeof first === 'string') return first;
    }
    // Can be string (JWT) or object with jwt property
    if (typeof attestation === 'string') {
      return attestation;
    } else if (attestation && typeof attestation === 'object' && attestation.jwt) {
      return attestation.jwt;
    }
  }
  
  // Check for key_attestation in proofs.jwt header
  if (requestBody.proofs && requestBody.proofs.jwt) {
    const jwtProof = Array.isArray(requestBody.proofs.jwt) 
      ? requestBody.proofs.jwt[0] 
      : requestBody.proofs.jwt;
    
    if (typeof jwtProof === 'string') {
      try {
        const decoded = jwt.decode(jwtProof, { complete: true });
        if (decoded && decoded.header && decoded.header.key_attestation) {
          return decoded.header.key_attestation;
        }
      } catch (e) {
        // Not a valid JWT, ignore
      }
    }
  }
  
  return null;
};

/**
 * Whether the proof's public key matches the first attested key in the WUA (ETSI / ARF-style binding:
 * the credential is bound to the primary attested key, not any key in the list).
 *
 * @param {object} proofPublicKeyJwk - Resolved JWK from the proof JWT (header jwk or from kid)
 * @param {object} wuaPayload - Decoded WUA JWT payload (must have attested_keys array)
 * @returns {boolean}
 */
export function proofKeyMatchesWUAAttestedKeys(proofPublicKeyJwk, wuaPayload) {
  const attested = wuaPayload?.attested_keys;
  if (!Array.isArray(attested) || attested.length === 0) return false;
  const first = attested[0];
  const norm = (jwk) => {
    if (!jwk || jwk.kty !== proofPublicKeyJwk?.kty) return null;
    if (jwk.kty === 'EC') {
      return [jwk.kty, jwk.crv, jwk.x, jwk.y].filter(Boolean).join('|');
    }
    if (jwk.kty === 'RSA') {
      return [jwk.kty, jwk.n, jwk.e].filter(Boolean).join('|');
    }
    return JSON.stringify(jwk);
  };
  const proofNorm = norm(proofPublicKeyJwk);
  if (!proofNorm) return false;
  return norm(first) === proofNorm;
} 
