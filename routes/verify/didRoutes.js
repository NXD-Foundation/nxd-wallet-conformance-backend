import express from "express";
import { v4 as uuidv4 } from "uuid";
import {
  CONFIG,
  DEFAULT_DCQL_QUERY,
  DEFAULT_TRANSACTION_DATA,
  loadConfigurationFiles,
  generateDidIdentifiers,
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

const didRouter = express.Router();

// Middleware to set session context for console interception
didRouter.use((req, res, next) => {
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
const { presentationDefinition, clientMetadata, privateKey } = loadConfigurationFiles(
  "./data/presentation_definition_pid.json",
  "./data/verifier-config.json",
  "./didjwks/did_private_pkcs8.key"
);

/**
 * Generate VP request with presentation definition
 */
didRouter.get("/generateVPRequest", async (req, res) => {
  const sessionId = req.query.sessionId || uuidv4();
  const slog = makeSessionLogger(sessionId);
  let requestId = null;
  
  try {
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequest", req.headers, req.query);
    try { slog("[VERIFIER] [START] DID VP request generation", { responseMode, clientId: client_id, kid }); } catch {}

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId: client_id,
      privateKey,
      clientMetadata,
      kid,
      serverURL: CONFIG.SERVER_URL,
      usePostMethod: true,
      routePath: "/did/VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequest", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] DID VP request generation", { success: true, hasQR: !!result.qr }); } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error generating DID VP request", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/generateVPRequest", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(error.message, "generateVPRequest", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request for GET method
 */
didRouter.get("/generateVPRequestGET", async (req, res) => {
  const sessionId = req.query.sessionId || uuidv4();
  const slog = makeSessionLogger(sessionId);
  let requestId = null;
  
  try {
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestGET", req.headers, req.query);
    try { slog("[VERIFIER] [START] DID VP request generation (GET method)", { responseMode, clientId: client_id, kid }); } catch {}

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition:null,
      clientId: client_id,
      privateKey,
      clientMetadata,
      kid,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: false,
      routePath: "/did/VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestGET", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] DID VP request generation (GET method)", { success: true }); } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error generating DID VP request (GET method)", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/generateVPRequestGET", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(error.message, "generateVPRequestGET", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with DCQL query
 */
didRouter.get("/generateVPRequestDCQL", async (req, res) => {
  const sessionId = req.query.sessionId || uuidv4();
  const slog = makeSessionLogger(sessionId);
  let requestId = null;
  
  try {
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestDCQL", req.headers, req.query);
    try { slog("[VERIFIER] [START] DID VP request generation with DCQL", { responseMode, clientId: client_id, kid }); } catch {}

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition: null,
      clientId: client_id,
      privateKey,
      clientMetadata,
      kid,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: DEFAULT_DCQL_QUERY,
      usePostMethod: true,
      routePath: "/did/VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestDCQL", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] DID VP request generation with DCQL", { success: true }); } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error generating DID VP request with DCQL", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/generateVPRequestDCQL", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(error.message, "generateVPRequestDCQL", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Generate VP request with transaction data
 */
didRouter.get("/generateVPRequestTransaction", async (req, res) => {
  const sessionId = req.query.sessionId || uuidv4();
  const slog = makeSessionLogger(sessionId);
  let requestId = null;
  
  try {
    const responseMode = req.query.response_mode || CONFIG.DEFAULT_RESPONSE_MODE;
    const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
    
    requestId = logHttpRequest(slog, "GET", "/generateVPRequestTransaction", req.headers, req.query);
    try { slog("[VERIFIER] [START] DID VP request generation with transaction data", { responseMode, clientId: client_id, kid }); } catch {}

    const transactionDataObj = createTransactionData(presentationDefinition);
    const base64UrlEncodedTxData = Buffer.from(JSON.stringify(transactionDataObj))
      .toString("base64url");

    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId: client_id,
      privateKey,
      clientMetadata,
      kid,
      serverURL: CONFIG.SERVER_URL,
      transactionData: base64UrlEncodedTxData,
      usePostMethod: true,
      routePath: "/did/VPrequest",
    });

    logHttpResponse(slog, requestId, "/generateVPRequestTransaction", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] DID VP request generation with transaction data", { success: true }); } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error generating DID VP request with transaction data", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/generateVPRequestTransaction", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(error.message, "generateVPRequestTransaction", 500, sessionId);
    res.status(500).json(errorResponse);
  }
});

/**
 * Request URI endpoint (handles both POST and GET)
 */
didRouter
  .route("/VPrequest/:id")
  .post(async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;

      requestId = logHttpRequest(slog, "POST", `/VPrequest/${sessionId}`, req.headers, req.body);
      try { slog("[VERIFIER] [START] Processing POST DID VP request", { clientId: client_id, kid, hasWalletNonce: !!walletNonce, hasWalletMetadata: !!walletMetadata }); } catch {}

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: client_id,
        privateKey,
        kid,
        walletNonce,
        walletMetadata,
      });

      if (result.error) {
        if (slog) {
          try { slog("[VERIFIER] [ERROR] DID VP request processing failed", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/VPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
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
            try { slog("[VERIFIER] [WARN] Failed to update session status after DID VP request processing failure", { error: storageError.message }); } catch {}
          }
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/VPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] DID VP request processed successfully (POST)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing POST DID VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/VPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(error.message, "POST /VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
      
      requestId = logHttpRequest(slog, "GET", `/VPrequest/${sessionId}`, req.headers, req.query);
      try { slog("[VERIFIER] [START] Processing GET DID VP request", { clientId: client_id, kid }); } catch {}

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: client_id,
        privateKey,
        kid,
      });

      if (result.error) {
        if (slog) {
          try { slog("[VERIFIER] [ERROR] DID VP request processing failed (GET)", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/VPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/VPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] DID VP request processed successfully (GET)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing GET DID VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/VPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(error.message, "GET /VPrequest/:id", 500, sessionId);
      res.status(500).json(errorResponse);
    }
  });

export default didRouter; 