import express from "express";
import path from "path";
import { v4 as uuidv4 } from "uuid";
import {
  CONFIG,
  DEFAULT_DCQL_QUERY,
  loadConfigurationFiles,
  generateVPRequest,
  processVPRequest,
  createTransactionData,
  createErrorResponse,
  resolveVerifierX509ClientId,
  resolveVerifierResponseMode,
  resolveVerifierInfoFromRequest,
  parseCs03Query,
  CS03_DCQL_QUERY,
  CS03_SIGNING_CREDENTIAL_ID,
  buildCs03QesRequestPayload,
  encodeCs03TransactionData,
  validateCs03QesResponse,
  validateCs03ResponseUriAlignment,
} from "../../utils/routeUtils.js";
import {
  summarizeCs03ValidationForLog,
  validateCs03CredentialResponses,
} from "../../utils/cs03Validation.js";
import {
  logInfo,
  logWarn,
  logError,
  logDebug,
  setSessionContext,
  clearSessionContext,
} from "../../services/cacheServiceRedis.js";
import { makeSessionLogger, logHttpRequest, logHttpResponse } from "../../utils/sessionLogger.js";

const x509Router = express.Router();

/**
 * CS-03 (remote qualified signing): DCQL for CSC X.509 + qesRequest in transaction_data.
 * Query: cs03=1 or isCS03=true; optional cs03_oob=1 to set qesRequest.responseURI to POST here.
 * @param {import("express").Request["query"]} query
 * @param {string} sessionId
 */
function resolveCs03VpOptions(query, sessionId, slog = null) {
  const { enabled, oob } = parseCs03Query(query);
  if (!enabled) {
    return { dcqlQuery: null, transactionData: null, cs03Signing: false, cs03Oob: false, callbackToken: null };
  }
  const callbackToken = oob ? uuidv4() : null;
  const qes = buildCs03QesRequestPayload(CONFIG.SERVER_URL, sessionId, { oob, callbackToken });
  if (oob) {
    const responseURI = qes.signatureRequests?.[0]?.responseURI;
    const alignment = validateCs03ResponseUriAlignment({
      serverURL: CONFIG.SERVER_URL,
      clientId: CONFIG.CLIENT_ID,
      responseURI,
    });
    if (!alignment.ok) {
      try {
        slog?.("[VERIFIER] CS-03 responseURI alignment check failed", {
          error: alignment.error,
          responseURI,
        });
      } catch {}
      throw new Error(alignment.error);
    }
    try {
      slog?.("[VERIFIER] CS-03 out-of-band qesResponse URI configured", {
        responseURI,
        hasCallbackToken: !!callbackToken,
      });
    } catch {}
  }
  try {
    slog?.("[VERIFIER] CS-03 qesRequest built for VP authorization", {
      sessionId,
      oob,
      signatureRequests: qes.signatureRequests?.length ?? 0,
      documentHref: qes.signatureRequests?.[0]?.href,
      hasChecksum: !!qes.signatureRequests?.[0]?.checksum,
    });
  } catch {}
  return {
    dcqlQuery: CS03_DCQL_QUERY,
    transactionData: encodeCs03TransactionData(qes),
    cs03Signing: true,
    cs03Oob: oob,
    callbackToken,
  };
}

/**
 * SESSION-BASED LOGGING SYSTEM
 * 
 * This router implements session-based logging that captures all logs/warnings
 * for each session ID and stores them in Redis cache.
 * 
 * Usage:
 * 1. All endpoints automatically log their activities with session context
 * 2. Get logs: GET /x509/logs/:sessionId
 * 3. Clear logs: DELETE /x509/logs/:sessionId
 * 4. To enable console interception globally, call enableConsoleInterception()
 * 
 * Features:
 * - Automatic session context detection from query params or URL params
 * - Structured logging with timestamps and metadata
 * - 30-minute TTL for log entries
 * - Maximum 100 log entries per session to prevent memory issues
 */

// Middleware to set session context for console interception
x509Router.use((req, res, next) => {
  const sessionId = req.query.sessionId || req.params.sessionId || req.params.id;
  if (sessionId) {
    setSessionContext(sessionId);
    // Clear context when response finishes
    res.on('finish', () => {
      clearSessionContext();
    });
  }
  next();
});

// Load configuration files
const { presentationDefinition, clientMetadata, verifierInfo } = loadConfigurationFiles(
  "./data/presentation_definition_pid.json",
  "./data/verifier-config.json"
);

/**
 * Generate VP request with presentation definition
 */
x509Router.get("/generateVPRequest", async (req, res) => {
  const sessionId = req.query.sessionId || uuidv4();
  const slog = makeSessionLogger(sessionId);
  let requestId = null;
  
  try {
    const responseMode = resolveVerifierResponseMode(req.query.response_mode, true);
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    const clientId = resolveVerifierX509ClientId(req.query.client_id_scheme, { responseMode, jarAlg });
    const effectiveVerifierInfo = resolveVerifierInfoFromRequest(req, verifierInfo);
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequest", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation", { responseMode, jarAlg, clientId }); } catch {}

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition,
      clientId,
      clientMetadata,
      verifierInfo: effectiveVerifierInfo,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      usePostMethod: true,
      routePath: "/x509/x509VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequest", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] VP request generation", { success: true, hasDeepLink: !!result.deepLink }); } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error generating VP request", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/generateVPRequest", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(error.message, "generateVPRequest", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request for GET method
 */
x509Router.get("/generateVPRequestGet", async (req, res) => {
  const sessionId = req.query.sessionId || uuidv4();
  const slog = makeSessionLogger(sessionId);
  let requestId = null;
  
  try {
    const responseMode = resolveVerifierResponseMode(req.query.response_mode, true);
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    const clientId = resolveVerifierX509ClientId(req.query.client_id_scheme, { responseMode, jarAlg });
    const effectiveVerifierInfo = resolveVerifierInfoFromRequest(req, verifierInfo);
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestGet", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation (GET method)", { responseMode, jarAlg, clientId }); } catch {}

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition,
      clientId,
      clientMetadata,
      verifierInfo: effectiveVerifierInfo,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      usePostMethod: false,
      routePath: "/x509/x509VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestGet", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] VP request generation (GET method)", { success: true }); } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error generating VP request (GET method)", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/generateVPRequestGet", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(error.message, "generateVPRequestGet", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with DCQL query
 */
x509Router.get("/generateVPRequestDCQL", async (req, res) => {
  const sessionId = req.query.sessionId || uuidv4();
  const slog = makeSessionLogger(sessionId);
  let requestId = null;
  
  try {
    const responseMode = resolveVerifierResponseMode(req.query.response_mode, true);
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    const clientId = resolveVerifierX509ClientId(req.query.client_id_scheme, { responseMode, jarAlg });
    const effectiveVerifierInfo = resolveVerifierInfoFromRequest(req, verifierInfo);
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestDCQL", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation with DCQL", { responseMode, jarAlg, clientId }); } catch {}

    const cs03 = resolveCs03VpOptions(req.query, sessionId, slog);
    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition: null,
      clientId,
      clientMetadata,
      verifierInfo: effectiveVerifierInfo,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: cs03.dcqlQuery ?? DEFAULT_DCQL_QUERY,
      transactionData: cs03.transactionData,
      cs03Signing: cs03.cs03Signing,
      cs03Oob: cs03.cs03Oob,
      cs03CallbackToken: cs03.callbackToken,
      usePostMethod: true,
      routePath: "/x509/x509VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestDCQL", 200, "OK", res.getHeaders(), result);
    try {
      slog("[VERIFIER] [COMPLETE] VP request generation with DCQL", {
        success: true,
        cs03Signing: cs03.cs03Signing,
        cs03Oob: cs03.cs03Oob,
      });
    } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error generating VP request with DCQL", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/generateVPRequestDCQL", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(error.message, "generateVPRequestDCQL", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with DCQL query for GET method
 */
x509Router.get("/generateVPRequestDCQLGET", async (req, res) => {
  const sessionId = req.query.sessionId || uuidv4();
  const slog = makeSessionLogger(sessionId);
  let requestId = null;
  
  try {
    const responseMode = resolveVerifierResponseMode(req.query.response_mode, true);
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    const clientId = resolveVerifierX509ClientId(req.query.client_id_scheme, { responseMode, jarAlg });
    const effectiveVerifierInfo = resolveVerifierInfoFromRequest(req, verifierInfo);
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestDCQLGET", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation with DCQL (GET method)", { responseMode, jarAlg, clientId }); } catch {}

    const cs03 = resolveCs03VpOptions(req.query, sessionId, slog);
    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition: null,
      clientId,
      clientMetadata,
      verifierInfo: effectiveVerifierInfo,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: cs03.dcqlQuery ?? DEFAULT_DCQL_QUERY,
      transactionData: cs03.transactionData,
      cs03Signing: cs03.cs03Signing,
      cs03Oob: cs03.cs03Oob,
      cs03CallbackToken: cs03.callbackToken,
      usePostMethod: false,
      routePath: "/x509/x509VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestDCQLGET", 200, "OK", res.getHeaders(), result);
    try {
      slog("[VERIFIER] [COMPLETE] VP request generation with DCQL (GET method)", {
        success: true,
        cs03Signing: cs03.cs03Signing,
        cs03Oob: cs03.cs03Oob,
      });
    } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error generating VP request with DCQL (GET method)", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/generateVPRequestDCQLGET", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(error.message, "generateVPRequestDCQLGET", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with transaction data
 */
x509Router.get("/generateVPRequestTransaction", async (req, res) => {
  const sessionId = req.query.sessionId || uuidv4();
  const slog = makeSessionLogger(sessionId);
  let requestId = null;
  
  try {
    const responseMode = resolveVerifierResponseMode(req.query.response_mode, true);
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    const clientId = resolveVerifierX509ClientId(req.query.client_id_scheme, { responseMode, jarAlg });
    const effectiveVerifierInfo = resolveVerifierInfoFromRequest(req, verifierInfo);
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestTransaction", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation with transaction data", { responseMode, jarAlg, clientId }); } catch {}

    const cs03 = resolveCs03VpOptions(req.query, sessionId, slog);
    let base64UrlEncodedTxData;
    let dcqlForTx = DEFAULT_DCQL_QUERY;
    let cs03Signing = false;
    if (cs03.dcqlQuery) {
      dcqlForTx = cs03.dcqlQuery;
      base64UrlEncodedTxData = cs03.transactionData;
      cs03Signing = true;
      try {
        slog("[VERIFIER] CS-03 transaction_data path (generateVPRequestTransaction)", {
          cs03Oob: cs03.cs03Oob,
        });
      } catch {}
    } else {
      // IMPORTANT: When using DCQL, credential_ids in transaction_data MUST
      // match the ids from the DCQL query (DEFAULT_DCQL_QUERY.credentials[].id)
      // per OpenID4VP 5.1.2.8.2.2.
      const transactionDataObj = createTransactionData(DEFAULT_DCQL_QUERY);
      base64UrlEncodedTxData = Buffer.from(JSON.stringify(transactionDataObj)).toString(
        "base64url"
      );
    }

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition: null,
      clientId,
      clientMetadata,
      verifierInfo: effectiveVerifierInfo,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: dcqlForTx,
      transactionData: base64UrlEncodedTxData,
      cs03Signing,
      cs03Oob: cs03.cs03Oob,
      cs03CallbackToken: cs03.callbackToken,
      usePostMethod: true,
      routePath: "/x509/x509VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestTransaction", 200, "OK", res.getHeaders(), result);
    try {
      slog("[VERIFIER] [COMPLETE] VP request generation with transaction data", {
        success: true,
        cs03Signing,
        cs03Oob: cs03.cs03Oob,
      });
    } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error generating VP request with transaction data", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/generateVPRequestTransaction", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(error.message, "generateVPRequestTransaction", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * CS-03: public PDF for signatureRequests[].href (same host as client_id for wallet fetch).
 */
x509Router.get("/cs03-document", (req, res) => {
  const correlationId = req.query.sessionId || req.query.correlationId;
  const docSlog = correlationId ? makeSessionLogger(String(correlationId)) : null;
  try {
    docSlog?.("[VERIFIER] CS-03 sample PDF request (document href)", {
      userAgent: req.headers["user-agent"]?.slice(0, 120),
    });
  } catch {}
  const pdfPath = path.join(process.cwd(), "data", "cs03-sample.pdf");
  res.type("application/pdf");
  res.sendFile(pdfPath, (err) => {
    if (err && !res.headersSent) {
      try {
        docSlog?.("[VERIFIER] CS-03 sample PDF send failed", { error: err.message });
      } catch {}
      res.status(404).json({ error: "cs03-sample.pdf missing (see data/cs03-sample.pdf)" });
    } else if (!err) {
      try {
        docSlog?.("[VERIFIER] CS-03 sample PDF served OK", {});
      } catch {}
    }
  });
});

/**
 * CS-03: optional out-of-band qesResponse delivery (when qesRequest includes responseURI).
 */
x509Router.post(
  "/qes-callback/:sessionId",
  express.json({ limit: "50mb" }),
  async (req, res) => {
    const sessionId = req.params.sessionId;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    try {
      requestId = logHttpRequest(slog, "POST", `/x509/qes-callback/${sessionId}`, req.headers, {
        query: req.query,
        contentType: req.headers["content-type"],
        contentLength: req.headers["content-length"],
      });
    } catch {}
    try {
      const { getVPSession, storeVPSession } = await import(
        "../../services/cacheServiceRedis.js"
      );
      const vpSession = await getVPSession(sessionId);
      if (!vpSession) {
        try {
          slog("[VERIFIER] CS-03 qes-callback rejected: session not found", { sessionId });
        } catch {}
        if (requestId != null) {
          logHttpResponse(slog, requestId, `/x509/qes-callback/${sessionId}`, 404, "Not Found", res.getHeaders(), {
            error: "session not found",
          });
        }
        return res.status(404).json({ error: "session not found" });
      }
      if (!vpSession.cs03_signing || !vpSession.cs03_oob) {
        try {
          slog("[VERIFIER] CS-03 qes-callback rejected: session not OOB CS-03", {
            cs03_signing: !!vpSession.cs03_signing,
            cs03_oob: !!vpSession.cs03_oob,
          });
        } catch {}
        if (requestId != null) {
          logHttpResponse(slog, requestId, `/x509/qes-callback/${sessionId}`, 400, "Bad Request", res.getHeaders(), {
            error: "not CS-03 OOB session",
          });
        }
        return res.status(400).json({ error: "session is not configured for CS-03 out-of-band response" });
      }
      if (!vpSession.cs03_callback_token || req.query.callback_token !== vpSession.cs03_callback_token) {
        try {
          slog("[VERIFIER] CS-03 qes-callback rejected: invalid or missing callback_token", {
            queryHadToken: typeof req.query.callback_token === "string",
          });
        } catch {}
        if (requestId != null) {
          logHttpResponse(slog, requestId, `/x509/qes-callback/${sessionId}`, 403, "Forbidden", res.getHeaders(), {
            error: "invalid callback token",
          });
        }
        return res.status(403).json({ error: "invalid callback token" });
      }
      const qesValidation = validateCs03QesResponse(req.body);
      if (!qesValidation.ok) {
        try {
          slog("[VERIFIER] CS-03 qes-callback rejected: body validation failed", {
            error: qesValidation.error,
          });
        } catch {}
        if (requestId != null) {
          logHttpResponse(slog, requestId, `/x509/qes-callback/${sessionId}`, 400, "Bad Request", res.getHeaders(), {
            error: qesValidation.error,
          });
        }
        return res.status(400).json({ error: "invalid_request", error_description: qesValidation.error });
      }
      const artifactValidation = await validateCs03CredentialResponses({
        qesByCredentialId: {
          [CS03_SIGNING_CREDENTIAL_ID]: req.body,
        },
        vpSession,
      });
      const artifactValidationSummary = summarizeCs03ValidationForLog(artifactValidation);
      if (!artifactValidation.ok) {
        vpSession.qes_oob_validation = artifactValidation;
        await storeVPSession(sessionId, vpSession);
        try {
          slog("[VERIFIER] CS-03 qes-callback rejected: artifact validation failed", artifactValidationSummary);
        } catch {}
        if (requestId != null) {
          logHttpResponse(slog, requestId, `/x509/qes-callback/${sessionId}`, 400, "Bad Request", res.getHeaders(), {
            error: "CS-03 artifact validation failed",
            validation: artifactValidationSummary,
          });
        }
        return res.status(400).json({
          error: "invalid_request",
          error_description: "CS-03 signed artifact validation failed",
          validation: artifactValidationSummary,
        });
      }
      vpSession.qes_oob_response = {
        [CS03_SIGNING_CREDENTIAL_ID]: req.body,
      };
      vpSession.qes_oob_validation = artifactValidation;
      await storeVPSession(sessionId, vpSession);
      const docCount = Array.isArray(req.body?.documentWithSignature)
        ? req.body.documentWithSignature.length
        : 0;
      const sigCount = Array.isArray(req.body?.signatureObject) ? req.body.signatureObject.length : 0;
      const firstLen =
        (req.body?.documentWithSignature?.[0]?.length ?? req.body?.signatureObject?.[0]?.length) || 0;
      try {
        slog("[VERIFIER] CS-03 qesResponse stored from responseURI callback", {
          documentWithSignatureCount: docCount,
          signatureObjectCount: sigCount,
          firstPayloadStringLength: firstLen,
          validation: artifactValidationSummary,
        });
      } catch {}
      if (requestId != null) {
        logHttpResponse(slog, requestId, `/x509/qes-callback/${sessionId}`, 200, "OK", res.getHeaders(), {
          stored: true,
          documentWithSignatureCount: docCount,
          signatureObjectCount: sigCount,
        });
      }
      res.sendStatus(200);
    } catch (e) {
      try {
        slog("[VERIFIER] CS-03 qes-callback error", { error: e.message, stack: e.stack?.split("\n")?.[0] });
      } catch {}
      if (requestId != null) {
        try {
          logHttpResponse(slog, requestId, `/x509/qes-callback/${sessionId}`, 500, "Error", res.getHeaders(), {
            error: e.message,
          });
        } catch {}
      }
      res.status(500).json({ error: e.message });
    }
  }
);

/**
 * Request URI endpoint (handles both POST and GET)
 */
x509Router
  .route("/x509VPrequest/:id")
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const responseMode = resolveVerifierResponseMode(req.body.response_mode, true);
      const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
      const clientId = resolveVerifierX509ClientId(req.query.client_id_scheme, { responseMode, jarAlg });
      const effectiveVerifierInfo = resolveVerifierInfoFromRequest(req, verifierInfo);
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;

      requestId = logHttpRequest(slog, "POST", `/x509VPrequest/${sessionId}`, req.headers, req.body);
      try { slog("[VERIFIER] [START] Processing POST x509 VP request", { clientId, hasWalletNonce: !!walletNonce, hasWalletMetadata: !!walletMetadata }); } catch {}

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId,
        verifierInfo: effectiveVerifierInfo,
        kid: null,
        walletNonce,
        walletMetadata,
      });

      if (result.error) {
        if (slog) {
          try { slog("[VERIFIER] [ERROR] VP request processing failed", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/x509VPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
        }
        // Mark session as failed
        try {
          const { getVPSession, storeVPSession } = await import("../../services/cacheServiceRedis.js");
          const vpSession = await getVPSession(sessionId);
          if (vpSession) {
            vpSession.status = "failed";
            vpSession.error = "processing_error";
            vpSession.error_description = result.error;
            await storeVPSession(sessionId, vpSession);
          }
        } catch (storageError) {
          if (slog) {
            try { slog("[VERIFIER] [WARN] Failed to update session status after x509 VP request processing failure", { error: storageError.message }); } catch {}
          }
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/x509VPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] VP request processed successfully (POST)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing POST x509 VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/x509VPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(error.message, "POST /x509VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const responseMode = resolveVerifierResponseMode(req.query.response_mode, true);
      const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
      const clientId = resolveVerifierX509ClientId(req.query.client_id_scheme, { responseMode, jarAlg });
      const effectiveVerifierInfo = resolveVerifierInfoFromRequest(req, verifierInfo);
      requestId = logHttpRequest(slog, "GET", `/x509VPrequest/${sessionId}`, req.headers, req.query);
      try { slog("[VERIFIER] [START] Processing GET x509 VP request", { clientId }); } catch {}
      
      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId,
        verifierInfo: effectiveVerifierInfo,
        kid: null,
      });

      if (result.error) {
        if (slog) {
          try { slog("[VERIFIER] [ERROR] VP request processing failed", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/x509VPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
        }
        // Mark session as failed
        try {
          const { getVPSession, storeVPSession } = await import("../../services/cacheServiceRedis.js");
          const vpSession = await getVPSession(sessionId);
          if (vpSession) {
            vpSession.status = "failed";
            vpSession.error = "processing_error";
            vpSession.error_description = result.error;
            await storeVPSession(sessionId, vpSession);
          }
        } catch (storageError) {
          if (slog) {
            try { slog("[VERIFIER] [WARN] Failed to update session status after x509 VP request processing failure", { error: storageError.message }); } catch {}
          }
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/x509VPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] VP request processed successfully (GET)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing GET x509 VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/x509VPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(error.message, "GET /x509VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  });

export default x509Router; 
