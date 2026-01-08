import express from "express";
import { v4 as uuidv4 } from "uuid";
import fs from "fs";
import {
  CONFIG,
  DEFAULT_DCQL_QUERY,
  DEFAULT_MDL_DCQL_QUERY,
  DEFAULT_TRANSACTION_DATA,
  loadConfigurationFiles,
  generateDidIdentifiers,
  generateDidJwkIdentifier,
  generateDidJwkIdentifiers,
  generateVPRequest,
  processVPRequest,
  createTransactionData,
  createErrorResponse,
  bindSessionLoggingContext,
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

const vpStandardRouter = express.Router();

// Middleware to set session context for console interception
vpStandardRouter.use((req, res, next) => {
  const sessionId = req.query.session_id || req.params.sessionId || req.params.id;
  if (sessionId) {
    setSessionContext(sessionId);
    res.on("finish", () => {
      clearSessionContext();
    });
  }
  next();
});

/**
 * Standardized VP Request Endpoint
 * 
 * Maps standardized parameters to existing verification logic:
 * - session_id: Session identifier
 * - client_id_scheme: x509 | did:web | did:jwk
 * - profile: dcql | tx | mdl
 * - credential_profile: pid | mdl
 * - request_uri_method: get | post
 * - response_mode: direct_post | direct_post.jwt
 * - tx_data: true | false
 */
vpStandardRouter.get("/vp/request", async (req, res) => {
  let sessionId;
  let requestId = null;
  
  try {
    // Extract standardized parameters
    sessionId = req.query.session_id || uuidv4();
    const slog = makeSessionLogger(sessionId);
    bindSessionLoggingContext(req, res, sessionId);

    const clientIdScheme = req.query.client_id_scheme || "x509";
    const profile = req.query.profile || "dcql";
    const credentialProfile = req.query.credential_profile || "pid";
    const requestUriMethod = req.query.request_uri_method || "post";
    const responseMode = req.query.response_mode || "direct_post";
    const txData = req.query.tx_data === "true";

    requestId = logHttpRequest(slog, "GET", "/vp/request", req.headers, req.query);
    try { slog("[VERIFIER] [START] Processing standardized VP request", { clientIdScheme, profile, credentialProfile, requestUriMethod, responseMode, txData }); } catch {}

    // Determine presentation definition based on credential_profile
    let presentationDefinitionPath;
    let presentationDefinition;
    let dcqlQuery = null;

    if (credentialProfile === "mdl") {
      // For mDL, use mDL-specific presentation definition or DCQL query
      if (profile === "mdl") {
        presentationDefinitionPath = "./data/presentation_definition_mdl.json";
        try {
          presentationDefinition = JSON.parse(
            fs.readFileSync(presentationDefinitionPath, "utf-8")
          );
        } catch (error) {
          // If file doesn't exist, use DCQL query for mDL
          dcqlQuery = DEFAULT_MDL_DCQL_QUERY;
        }
      } else {
        dcqlQuery = DEFAULT_MDL_DCQL_QUERY;
      }
    } else {
      // For PID, use PID presentation definition or DCQL query
      presentationDefinitionPath = "./data/presentation_definition_pid.json";
      try {
        presentationDefinition = JSON.parse(
          fs.readFileSync(presentationDefinitionPath, "utf-8")
        );
      } catch (error) {
        // If file doesn't exist, use default DCQL query
        dcqlQuery = DEFAULT_DCQL_QUERY;
      }
    }

    // Use DCQL query if profile is "dcql" or "tx"
    if (profile === "dcql" || profile === "tx") {
      presentationDefinition = null;
      if (!dcqlQuery) {
        dcqlQuery = credentialProfile === "mdl" ? DEFAULT_MDL_DCQL_QUERY : DEFAULT_DCQL_QUERY;
      }
    }

    // Load client metadata
    const clientMetadata = JSON.parse(
      fs.readFileSync("./data/verifier-config.json", "utf-8")
    );

    // Determine client ID, private key, and kid based on client_id_scheme
    let clientId;
    let privateKey = null;
    let kid = null;
    let routePath;

    if (clientIdScheme === "x509") {
      clientId = CONFIG.CLIENT_ID; // "x509_san_dns:dss.aegean.gr"
      routePath = "/vp/x509VPrequest";
    } else if (clientIdScheme === "did:web") {
      const didIdentifiers = generateDidIdentifiers(CONFIG.SERVER_URL);
      clientId = didIdentifiers.client_id;
      kid = didIdentifiers.kid;
      privateKey = fs.readFileSync("./didjwks/did_private_pkcs8.key", "utf8");
      routePath = "/vp/didVPrequest";
    } else if (clientIdScheme === "did:jwk") {
      const didJwkPrivateKey = fs.readFileSync("./didjwks/did_private_pkcs8.key", "utf8");
      const didJwkIdentifier = generateDidJwkIdentifier(didJwkPrivateKey);
      const didJwkIdentifiers = generateDidJwkIdentifiers(didJwkIdentifier);
      clientId = didJwkIdentifiers.client_id;
      kid = didJwkIdentifiers.kid;
      privateKey = didJwkPrivateKey;
      routePath = "/vp/didJwkVPrequest";
    } else {
      throw new Error(
        `Invalid client_id_scheme. Received: '${clientIdScheme}', expected: 'x509', 'did:web', or 'did:jwk'`
      );
    }

    // Prepare transaction data if tx_data is true
    let transactionData = null;
    if (txData) {
      const transactionDataObj = createTransactionData(
        presentationDefinition || dcqlQuery
      );
      transactionData = Buffer.from(JSON.stringify(transactionDataObj))
        .toString("base64url");
    }

    // Generate VP request
    const result = await generateVPRequest({
      sessionId,
      responseMode,
      presentationDefinition,
      clientId,
      privateKey,
      clientMetadata,
      kid,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery,
      transactionData,
      usePostMethod: requestUriMethod === "post",
      routePath,
    });

    logHttpResponse(slog, requestId, "/vp/request", 200, "OK", res.getHeaders(), result);
    try { slog("[VERIFIER] [COMPLETE] Standardized VP request generated successfully", { success: true, hasQR: !!result.qr, hasDeepLink: !!result.deepLink }); } catch {}
    res.json(result);
  } catch (error) {
    if (slog) {
      try { slog("[VERIFIER] [ERROR] Error in standardized VP request endpoint", { error: error.message }); } catch {}
      logHttpResponse(slog, requestId, "/vp/request", 500, "Internal Server Error", res.getHeaders(), { error: error.message });
    }
    const errorResponse = createErrorResponse(
      error.message,
      "vp/request",
      500,
      sessionId
    );
    res.status(500).json(errorResponse);
  }
});

/**
 * Request URI endpoint for x509 scheme (handles both POST and GET)
 */
vpStandardRouter
  .route("/vp/x509VPrequest/:id")
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } =
        req.body;

      requestId = logHttpRequest(slog, "POST", `/vp/x509VPrequest/${sessionId}`, req.headers, req.body);
      try { slog("[VERIFIER] [START] Processing POST x509 VP request", { hasWalletNonce: !!walletNonce, hasWalletMetadata: !!walletMetadata }); } catch {}

      const clientMetadata = JSON.parse(
        fs.readFileSync("./data/verifier-config.json", "utf-8")
      );

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
          try { slog("[VERIFIER] [ERROR] x509 VP request processing failed", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/vp/x509VPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/vp/x509VPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] x509 VP request processed successfully (POST)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing POST x509 VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/vp/x509VPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(
        error.message,
        "POST /vp/x509VPrequest/:id",
        500,
        sessionId
      );
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      requestId = logHttpRequest(slog, "GET", `/vp/x509VPrequest/${sessionId}`, req.headers, req.query);
      try { slog("[VERIFIER] [START] Processing GET x509 VP request"); } catch {}

      const clientMetadata = JSON.parse(
        fs.readFileSync("./data/verifier-config.json", "utf-8")
      );

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: CONFIG.CLIENT_ID,
        kid: null,
      });

      if (result.error) {
        if (slog) {
          try { slog("[VERIFIER] [ERROR] x509 VP request processing failed (GET)", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/vp/x509VPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/vp/x509VPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] x509 VP request processed successfully (GET)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing GET x509 VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/vp/x509VPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(
        error.message,
        "GET /vp/x509VPrequest/:id",
        500,
        sessionId
      );
      res.status(500).json(errorResponse);
    }
  });

/**
 * Request URI endpoint for did:web scheme (handles both POST and GET)
 */
vpStandardRouter
  .route("/vp/didVPrequest/:id")
  .post(async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } =
        req.body;

      requestId = logHttpRequest(slog, "POST", `/vp/didVPrequest/${sessionId}`, req.headers, req.body);
      try { slog("[VERIFIER] [START] Processing POST did:web VP request", { clientId: client_id, kid, hasWalletNonce: !!walletNonce, hasWalletMetadata: !!walletMetadata }); } catch {}

      const clientMetadata = JSON.parse(
        fs.readFileSync("./data/verifier-config.json", "utf-8")
      );
      const privateKey = fs.readFileSync(
        "./didjwks/did_private_pkcs8.key",
        "utf8"
      );

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
          try { slog("[VERIFIER] [ERROR] did:web VP request processing failed", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/vp/didVPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/vp/didVPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] did:web VP request processed successfully (POST)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing POST did:web VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/vp/didVPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(
        error.message,
        "POST /vp/didVPrequest/:id",
        500,
        sessionId
      );
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const { client_id, kid } = generateDidIdentifiers(CONFIG.SERVER_URL);

      requestId = logHttpRequest(slog, "GET", `/vp/didVPrequest/${sessionId}`, req.headers, req.query);
      try { slog("[VERIFIER] [START] Processing GET did:web VP request", { clientId: client_id, kid }); } catch {}

      const clientMetadata = JSON.parse(
        fs.readFileSync("./data/verifier-config.json", "utf-8")
      );
      const privateKey = fs.readFileSync(
        "./didjwks/did_private_pkcs8.key",
        "utf8"
      );

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
          try { slog("[VERIFIER] [ERROR] did:web VP request processing failed (GET)", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/vp/didVPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/vp/didVPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] did:web VP request processed successfully (GET)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing GET did:web VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/vp/didVPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(
        error.message,
        "GET /vp/didVPrequest/:id",
        500,
        sessionId
      );
      res.status(500).json(errorResponse);
    }
  });

/**
 * Request URI endpoint for did:jwk scheme (handles both POST and GET)
 */
vpStandardRouter
  .route("/vp/didJwkVPrequest/:id")
  .post(async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const didJwkPrivateKey = fs.readFileSync(
        "./didjwks/did_private_pkcs8.key",
        "utf8"
      );
      const didJwkIdentifier = generateDidJwkIdentifier(didJwkPrivateKey);
      const { client_id, kid } = generateDidJwkIdentifiers(didJwkIdentifier);
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } =
        req.body;

      requestId = logHttpRequest(slog, "POST", `/vp/didJwkVPrequest/${sessionId}`, req.headers, req.body);
      try { slog("[VERIFIER] [START] Processing POST did:jwk VP request", { clientId: client_id, kid, hasWalletNonce: !!walletNonce, hasWalletMetadata: !!walletMetadata }); } catch {}

      const clientMetadata = JSON.parse(
        fs.readFileSync("./data/verifier-config.json", "utf-8")
      );

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: client_id,
        privateKey: didJwkPrivateKey,
        kid,
        walletNonce,
        walletMetadata,
      });

      if (result.error) {
        if (slog) {
          try { slog("[VERIFIER] [ERROR] did:jwk VP request processing failed", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/vp/didJwkVPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/vp/didJwkVPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] did:jwk VP request processed successfully (POST)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing POST did:jwk VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/vp/didJwkVPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(
        error.message,
        "POST /vp/didJwkVPrequest/:id",
        500,
        sessionId
      );
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;
    
    try {
      const didJwkPrivateKey = fs.readFileSync(
        "./didjwks/did_private_pkcs8.key",
        "utf8"
      );
      const didJwkIdentifier = generateDidJwkIdentifier(didJwkPrivateKey);
      const { client_id, kid } = generateDidJwkIdentifiers(didJwkIdentifier);

      requestId = logHttpRequest(slog, "GET", `/vp/didJwkVPrequest/${sessionId}`, req.headers, req.query);
      try { slog("[VERIFIER] [START] Processing GET did:jwk VP request", { clientId: client_id, kid }); } catch {}

      const clientMetadata = JSON.parse(
        fs.readFileSync("./data/verifier-config.json", "utf-8")
      );

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: client_id,
        privateKey: didJwkPrivateKey,
        kid,
      });

      if (result.error) {
        if (slog) {
          try { slog("[VERIFIER] [ERROR] did:jwk VP request processing failed (GET)", { error: result.error, status: result.status }); } catch {}
          logHttpResponse(slog, requestId, `/vp/didJwkVPrequest/${sessionId}`, result.status, "Error", res.getHeaders(), { error: result.error });
        }
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(slog, requestId, `/vp/didJwkVPrequest/${sessionId}`, 200, "OK", res.getHeaders(), { jwtLength: result.jwt?.length });
      try { slog("[VERIFIER] [COMPLETE] did:jwk VP request processed successfully (GET)", { success: true, jwtLength: result.jwt?.length }); } catch {}
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      if (slog) {
        try { slog("[VERIFIER] [ERROR] Error processing GET did:jwk VP request", { error: error.message }); } catch {}
        logHttpResponse(slog, requestId, `/vp/didJwkVPrequest/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), { error: error.message });
      }
      const errorResponse = createErrorResponse(
        error.message,
        "GET /vp/didJwkVPrequest/:id",
        500,
        sessionId
      );
      res.status(500).json(errorResponse);
    }
  });

export default vpStandardRouter;


