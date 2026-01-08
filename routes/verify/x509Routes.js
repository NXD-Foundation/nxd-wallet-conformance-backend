import express from "express";
import { v4 as uuidv4 } from "uuid";
import {
  CONFIG,
  DEFAULT_DCQL_QUERY,
  DEFAULT_TRANSACTION_DATA,
  loadConfigurationFiles,
  generateVPRequest,
  processVPRequest,
  createTransactionData,
  createErrorResponse,
} from "../../utils/routeUtils.js";
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
const { presentationDefinition, clientMetadata } = loadConfigurationFiles(
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
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequest", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation", { responseMode, jarAlg }); } catch {}

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition,
      clientId: CONFIG.CLIENT_ID,
      clientMetadata,
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
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestGet", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation (GET method)", { responseMode, jarAlg }); } catch {}

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition,
      clientId: CONFIG.CLIENT_ID,
      clientMetadata,
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
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestDCQL", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation with DCQL", { responseMode, jarAlg }); } catch {}

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition: null,
      clientId: CONFIG.CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: true,
      routePath: "/x509/x509VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestDCQL", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] VP request generation with DCQL", { success: true }); } catch {}
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
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestDCQLGET", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation with DCQL (GET method)", { responseMode, jarAlg }); } catch {}

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition: null,
      clientId: CONFIG.CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: false,
      routePath: "/x509/x509VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestDCQLGET", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] VP request generation with DCQL (GET method)", { success: true }); } catch {}
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
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const jarAlg = req.query.jar_alg || CONFIG.DEFAULT_JAR_ALG;
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestTransaction", req.headers, req.query);
    try { slog("[VERIFIER] [START] VP request generation with transaction data", { responseMode, jarAlg }); } catch {}

    const transactionDataObj = createTransactionData(presentationDefinition);
    const base64UrlEncodedTxData = Buffer.from(JSON.stringify(transactionDataObj))
      .toString("base64url");

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      jarAlg,
      presentationDefinition: null,
      clientId: CONFIG.CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      transactionData: base64UrlEncodedTxData,
      usePostMethod: true,
      routePath: "/x509/x509VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestTransaction", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] VP request generation with transaction data", { success: true }); } catch {}
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
 * Request URI endpoint (handles both POST and GET)
 */
x509Router
  .route("/x509VPrequest/:id")
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;

      requestId = logHttpRequest(slog, "POST", `/x509VPrequest/${sessionId}`, req.headers, req.body);
      try { slog("[VERIFIER] [START] Processing POST x509 VP request", { hasWalletNonce: !!walletNonce, hasWalletMetadata: !!walletMetadata }); } catch {}

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: CONFIG.CLIENT_ID,
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
      requestId = logHttpRequest(slog, "GET", `/x509VPrequest/${sessionId}`, req.headers, req.query);
      try { slog("[VERIFIER] [START] Processing GET x509 VP request"); } catch {}
      
      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: CONFIG.CLIENT_ID,
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