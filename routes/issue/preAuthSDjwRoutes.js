import express from "express";
import {
  storePreAuthSession,
  getPreAuthSession,
  getSessionKeyFromAccessToken,
  getCodeFlowSession,
  storeCodeFlowSession,
  getSessionKeyAuthCode,
} from "../../services/cacheServiceRedis.js";

import {
  // Shared constants
  SERVER_URL,
  DEFAULT_CREDENTIAL_TYPE,
  QR_CONFIG,
  TX_CODE_CONFIG,
  URL_SCHEMES,
  getCredentialOfferSchemeFromRequest,
  ERROR_MESSAGES,
  
  // Cryptographic utilities
  loadCryptographicKeys,
  
  // Parameter extraction utilities
  getSessionId,
  getCredentialType,
  getSignatureType,
  
  // Session management utilities
  createBaseSession,
  createSessionWithPayload,
  createSessionWithMultiCredentialPayloads,
  parseMultiCredentialOfferRequest,
  preAuthOfferSessionStateMatches,
  loadIssuerConfiguration,
  
  // QR code and URL generation utilities
  generateQRCode,
  buildCredentialOfferUrl,
  createPreAuthCredentialOfferUri,
  createCredentialOfferResponse,
  createCredentialOfferConfig,
  applyPreAuthTxCode,
  
  // Error handling utilities
  handleRouteError,
  bindSessionLoggingContext,
  isValidSessionId,
  isValidCredentialPayload,
  sendErrorResponse,
} from "../../utils/routeUtils.js";

const router = express.Router();

// Initialize cryptographic keys
const { privateKey, publicKeyPem } = loadCryptographicKeys();

// Helper function to manage session creation
const manageSession = async (sessionId, sessionData) => {
  try {
    const existingSession = await getPreAuthSession(sessionId);
    if (!existingSession) {
      await storePreAuthSession(sessionId, sessionData);
      return sessionData; // Return the newly created session data
    }
    return existingSession;
  } catch (error) {
    console.error(`[preAuth][${sessionId}] Session management error`, {
      message: error?.message,
      stack: error?.stack,
    });
    throw new Error(ERROR_MESSAGES.SESSION_CREATION_FAILED);
  }
};

// Idempotent offer session creation; rejects conflicting reuse of sessionId
const manageOfferSession = async (sessionId, sessionData) => {
  try {
    const existingSession = await getPreAuthSession(sessionId);
    if (!existingSession) {
      await storePreAuthSession(sessionId, sessionData);
      return sessionData;
    }
    if (preAuthOfferSessionStateMatches(existingSession, sessionData)) {
      return existingSession;
    }
    const err = new Error(
      "Session already exists with different offer data for this sessionId",
    );
    err.errorCode = "invalid_request";
    err.status = 409;
    throw err;
  } catch (error) {
    if (error?.errorCode === "invalid_request" && error?.status === 409) {
      throw error;
    }
    console.error(`[preAuth][${sessionId}] Offer session management error`, {
      message: error?.message,
      stack: error?.stack,
    });
    throw new Error(ERROR_MESSAGES.SESSION_CREATION_FAILED);
  }
};

// ******************************************************************
// ************* CREDENTIAL OFFER ENDPOINTS *************************
// ******************************************************************

/**
 * Pre-auth flow with transaction code
 * Generates a VCI request with pre-authorized flow with a transaction code
 */
router.get("/offer-tx-code", async (req, res) => {
  let sessionId;
  try {
    sessionId = getSessionId(req);
    bindSessionLoggingContext(req, res, sessionId);

    const credentialType = getCredentialType(req);
    const signatureType = getSignatureType(req);

    const sessionData = applyPreAuthTxCode(createBaseSession("pre-auth", false, signatureType, {
      requireTxCode: true,
    }));
    const storedSession = await manageSession(sessionId, sessionData);

    const invocationScheme = getCredentialOfferSchemeFromRequest(req);
    const credentialOffer = createPreAuthCredentialOfferUri(
      sessionId,
      credentialType,
      "/credential-offer-tx-code",
      invocationScheme,
    );

    const response = await createCredentialOfferResponse(
      credentialOffer,
      sessionId,
      storedSession.expectedTxCode,
    );

    res.json(response);
  } catch (error) {
    handleRouteError(error, "Offer tx-code", res, sessionId);
  }
});

/**
 * Pre-authorized flow with transaction code - credential offer configuration
 */
router.get("/credential-offer-tx-code/:id", (req, res) => {
  const sessionId = req.params.id;
  try {
    bindSessionLoggingContext(req, res, sessionId);
    const credentialType = getCredentialType(req);

    if (!isValidSessionId(sessionId)) {
      return sendErrorResponse(res, "invalid_request", ERROR_MESSAGES.INVALID_SESSION_ID, 400);
    }

    const config = createCredentialOfferConfig(credentialType, sessionId, true);
    res.json(config);
  } catch (error) {
    handleRouteError(error, "Credential offer tx-code config", res, sessionId);
  }
});

/**
 * Pre-authorized flow without transaction code
 */
router.get("/offer-no-code", async (req, res) => {
  let sessionId;
  try {
    sessionId = getSessionId(req);
    bindSessionLoggingContext(req, res, sessionId);

    const credentialType = getCredentialType(req);
    const signatureType = getSignatureType(req);

    const sessionData = createBaseSession("pre-auth", false, signatureType);
    await manageSession(sessionId, sessionData);

    const invocationScheme = getCredentialOfferSchemeFromRequest(req);
    const credentialOffer = createPreAuthCredentialOfferUri(
      sessionId,
      credentialType,
      "/credential-offer-no-code",
      invocationScheme,
    );

    const response = await createCredentialOfferResponse(credentialOffer, sessionId);
    res.json(response);
  } catch (error) {
    handleRouteError(error, "Offer no-code", res, sessionId);
  }
});

/**
 * Pre-authorized flow without transaction code with request body
 */
router.post("/offer-no-code", async (req, res) => {
  let sessionId;
  try {
    sessionId = getSessionId(req);
    bindSessionLoggingContext(req, res, sessionId);

    const credentialType = getCredentialType(req);
    const credentialPayload = req.body;

    if (!isValidCredentialPayload(credentialPayload)) {
      return sendErrorResponse(res, "invalid_request", "Credential payload is required", 400);
    }

    const sessionData = createSessionWithPayload(credentialPayload, true);
    await manageSession(sessionId, sessionData);

    const invocationScheme = getCredentialOfferSchemeFromRequest(req);
    const credentialOffer = createPreAuthCredentialOfferUri(
      sessionId,
      credentialType,
      "/credential-offer-no-code",
      invocationScheme,
    );

    const response = await createCredentialOfferResponse(credentialOffer, sessionId);
    res.json(response);
  } catch (error) {
    handleRouteError(error, "Offer no-code POST", res, sessionId);
  }
});

/**
 * Pre-authorized flow without transaction code — multi-configuration offer with payloads.
 *
 * Body:
 * {
 *   "signatureType": "x509",
 *   "credentials": [
 *     { "credential_configuration_id": "VerifiableStudentIDSDJWT", "payload": { ... } },
 *     { "credential_configuration_id": "LoyaltyCard", "payload": { ... } }
 *   ]
 * }
 *
 * `signatureType` may also be supplied as a query parameter (same as `/vci/offer`).
 */
router.post("/offer-no-code-batch", async (req, res) => {
  let sessionId;
  try {
    sessionId = getSessionId(req);
    bindSessionLoggingContext(req, res, sessionId);

    const issuerConfig = loadIssuerConfiguration();
    const { offeredConfigurationIds, credentialPayloads } =
      parseMultiCredentialOfferRequest(req.body, issuerConfig);
    const signatureType = getSignatureType(req);

    const sessionData = createSessionWithMultiCredentialPayloads(
      offeredConfigurationIds,
      credentialPayloads,
      true,
      signatureType,
    );
    await manageOfferSession(sessionId, sessionData);

    const invocationScheme = getCredentialOfferSchemeFromRequest(req);
    const credentialOffer = createPreAuthCredentialOfferUri(
      sessionId,
      null,
      "/credential-offer-no-code-batch",
      invocationScheme,
    );

    const response = await createCredentialOfferResponse(credentialOffer, sessionId);
    res.json({
      ...response,
      offeredConfigurationIds,
    });
  } catch (error) {
    if (error?.errorCode === "invalid_request") {
      const status = error.status || 400;
      return sendErrorResponse(
        res,
        "invalid_request",
        error.message,
        status,
      );
    }
    handleRouteError(error, "Offer no-code batch POST", res, sessionId);
  }
});

/**
 * Pre-authorized flow without transaction code - credential offer configuration
 */
router.get("/credential-offer-no-code/:id", async (req, res) => {
  const sessionId = req.params.id;
  try {
    bindSessionLoggingContext(req, res, sessionId);
    const credentialType = getCredentialType(req);

    if (!isValidSessionId(sessionId)) {
      return sendErrorResponse(res, "invalid_request", ERROR_MESSAGES.INVALID_SESSION_ID, 400);
    }

    // Check if session exists in Redis
    const sessionData = await getPreAuthSession(sessionId);
    if (!sessionData) {
      return sendErrorResponse(res, "invalid_request", "Session not found", 404);
    }

    const config = createCredentialOfferConfig(credentialType, sessionId, false);
    res.json(config);
  } catch (error) {
    handleRouteError(error, "Credential offer no-code config", res, sessionId);
  }
});

// ******************************************************************
// ************* HAIP ENDPOINTS *************************************
// ******************************************************************

/**
 * HAIP pre-authorized flow with transaction code
 * 
 * The Grant Types authorization_code and urn:ietf:params:oauth:grant-type:pre-authorized_code 
 * MUST be supported as defined in Section 4.1.1 in [OIDF.OID4VCI]
 * 
 * For Grant Type urn:ietf:params:oauth:grant-type:pre-authorized_code, the pre-authorized 
 * code is used by the issuer to identify the credential type(s).
 * As a way to invoke the Wallet, at least a custom URL scheme haip:// MUST be supported. 
 * Implementations MAY support other ways to invoke the wallets as agreed by trust 
 * frameworks/ecosystems/jurisdictions, not limited to using other custom URL schemes.
 */
router.get("/haip-offer-tx-code", async (req, res) => {
  let sessionId;
  try {
    sessionId = getSessionId(req);
    bindSessionLoggingContext(req, res, sessionId);

    const credentialType = getCredentialType(req);

    const sessionData = applyPreAuthTxCode(createBaseSession("pre-auth", true, null, {
      requireTxCode: true,
    }));
    const storedSession = await manageSession(sessionId, sessionData);

    const credentialOffer = createPreAuthCredentialOfferUri(
      sessionId,
      credentialType,
      "/haip-credential-offer-tx-code",
      URL_SCHEMES.HAIP
    );

    const response = await createCredentialOfferResponse(
      credentialOffer,
      sessionId,
      storedSession.expectedTxCode,
    );
    res.json(response);
  } catch (error) {
    handleRouteError(error, "HAIP offer tx-code", res, sessionId);
  }
});

/**
 * HAIP pre-authorized flow with transaction code - credential offer configuration
 */
router.get("/haip-credential-offer-tx-code/:id", (req, res) => {
  const sessionId = req.params.id;
  try {
    bindSessionLoggingContext(req, res, sessionId);
    const credentialType = getCredentialType(req);

    if (!isValidSessionId(sessionId)) {
      return sendErrorResponse(res, "invalid_request", ERROR_MESSAGES.INVALID_SESSION_ID, 400);
    }

    const config = createCredentialOfferConfig(credentialType, sessionId, true);
    res.json(config);
  } catch (error) {
    handleRouteError(error, "HAIP credential offer config", res, sessionId);
  }
});

export default router;
