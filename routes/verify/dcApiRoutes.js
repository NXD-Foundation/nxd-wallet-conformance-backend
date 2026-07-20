import express from "express";
import fs from "fs";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import {
  CONFIG,
  CS03_SIGNING_CREDENTIAL_ID,
  buildCs03QesRequestPayload,
  encodeCs03TransactionData,
  processCs03PresentationResponse,
  generateVPRequest,
} from "../../utils/routeUtils.js";
import {
  resolveCs07VerifierOrigin,
  normalizeCs07DigitalCredentialResponse,
  parseCs07AuthorizationResponse,
  Cs07DcApiResponseError,
} from "../../utils/cs07DcApi.js";
import { decryptJWE } from "../../utils/cryptoUtils.js";
import {
  Cs02VerifierResponseError,
} from "../../utils/cs02VerifierResponse.js";
import { validateCs03CredentialResponses } from "../../utils/cs03Validation.js";
import { makeSessionLogger, logHttpRequest, logHttpResponse } from "../../utils/sessionLogger.js";
import { getVPSession, storeVPSession } from "../../services/cacheServiceRedis.js";
import { loadCs07Config, resolveCs07Profile } from "../../utils/cs07Config.js";
import { validateCs07CredentialPresentations } from "../../utils/cs07ResponseValidation.js";
import { loadVerifierEncryptionKey } from "../../utils/verifierEncryptionKeys.js";

const dcApiRouter = express.Router();
// Load and validate once at startup. Profile mappings and DCQL are immutable
// for the lifetime of this verifier process.
const CS07_CONFIG = loadCs07Config();
const MAX_REQUEST_BODY_BYTES = 16 * 1024;
const MAX_RESPONSE_BODY_BYTES = 2 * 1024 * 1024;

function enforceBodyLimit(limit) {
  return (req, res, next) => {
    const length = Number(req.get("Content-Length"));
    if (Number.isFinite(length) && length > limit) {
      return res.status(413).json({ error: "request_too_large" });
    }
    return next();
  };
}

function computeSdHashFromPresentedToken(sdJwtToken) {
  if (typeof sdJwtToken !== "string") return null;
  const parts = sdJwtToken.split("~");
  if (parts.length > 1 && parts[parts.length - 1].includes(".")) parts.pop();
  let input = parts.join("~");
  if (!input.endsWith("~")) input += "~";
  return crypto.createHash("sha256").update(Buffer.from(input, "ascii")).digest("base64url");
}

function applyCors(res, origin) {
  res.set({
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "300",
    Vary: "Origin",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
}

function requestOrigin(req) {
  const origin = req.get("Origin");
  if (!origin) throw new Cs07DcApiResponseError("CS-07 requests require an Origin header", "invalid_request");
  return resolveCs07VerifierOrigin({ serverURL: origin, env: process.env });
}

dcApiRouter.options("/vp/dc-api/:resource(*)", (req, res) => {
  try {
    const origin = requestOrigin(req);
    if (!CS07_CONFIG.relying_parties[origin]) return res.status(403).end();
    applyCors(res, origin);
    return res.status(204).end();
  } catch {
    return res.status(403).end();
  }
});

// Pollable, deliberately sanitized session state for the browser adapter and
// test harness.  Never return request tokens, decrypted VP data, or secrets.
dcApiRouter.get("/vp/dc-api/session/:sessionId", async (req, res) => {
  let origin;
  try { origin = requestOrigin(req); } catch { return res.status(403).json({ error: "origin_not_allowed" }); }
  applyCors(res, origin);
  const session = await getVPSession(req.params.sessionId);
  if (!session || session.transport_profile !== "cs07-dc-api") {
    return res.status(404).json({ error: "session_not_found" });
  }
  if (origin !== session.verifier_origin) return res.status(403).json({ error: "origin_not_allowed" });
  return res.set("Cache-Control", "no-store").json({
    sessionId: req.params.sessionId,
    status: session.status || "pending",
    profile: session.profile_id || undefined,
    error: session.error || undefined,
    error_description: session.error_description || undefined,
    verified_credential_ids: session.verified_credential_ids || undefined,
    verification: session.verification || undefined,
  });
});

/** Create a CS-07 signed request descriptor for a browser verifier. */
dcApiRouter.post("/vp/dc-api/request", enforceBodyLimit(MAX_REQUEST_BODY_BYTES), async (req, res) => {
  const sessionId = uuidv4();
  const slog = makeSessionLogger(sessionId);
  const requestId = logHttpRequest(slog, "POST", "/vp/dc-api/request", req.headers, { sessionId });
  let verifierOrigin = null;

  try {
    verifierOrigin = requestOrigin(req);
    applyCors(res, verifierOrigin);
    const bodyKeys = Object.keys(req.body || {});
    if (bodyKeys.some((key) => !["profile"].includes(key))) {
      return res.status(400).json({ error: "invalid_request", error_description: "Only profile may be supplied" });
    }
    const profile = resolveCs07Profile(CS07_CONFIG, {
      profileId: req.body?.profile,
      origin: verifierOrigin,
    });
    const encryptionKey = loadVerifierEncryptionKey();
    const clientMetadata = JSON.parse(fs.readFileSync("./data/verifier-config.json", "utf8"));
    const cs03Signing = profile.workflow === "cs03-inline-signing";
    const qesRequest = cs03Signing
      ? buildCs03QesRequestPayload(CONFIG.SERVER_URL, sessionId, { oob: false })
      : null;
    const result = await generateVPRequest({
      sessionId,
      responseMode: "dc_api.jwt",
      jarAlg: "ES256",
      presentationDefinition: null,
      clientId: CONFIG.CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: profile.dcql_query,
      transactionData: cs03Signing
        ? encodeCs03TransactionData(qesRequest)
        : (req.body?.transactionData || null),
      cs03Signing,
      cs07DcApi: true,
      cs07VerifierOrigin: verifierOrigin,
      cs07ProfileId: profile.id,
      usePostMethod: false,
      routePath: "/vp/x509VPrequest",
    });

    const storedSession = await getVPSession(sessionId);
    if (!storedSession) throw new Error("CS-07 session persistence failed");
    storedSession.encryption_key_kid = encryptionKey.kid;
    storedSession.encryption_key_alg = encryptionKey.alg;
    await storeVPSession(sessionId, storedSession);
    const responseEndpoint = new URL(`/vp/dc-api/response/${sessionId}`, CONFIG.SERVER_URL).toString();
    const statusEndpoint = new URL(`/vp/dc-api/session/${sessionId}`, CONFIG.SERVER_URL).toString();
    const response = {
      ...result,
      expiresAt: storedSession?.expires_at,
      responseEndpoint,
      statusEndpoint,
    };
    logHttpResponse(slog, requestId, "/vp/dc-api/request", 200, "OK", res.getHeaders(), {
      sessionId,
      protocol: result.protocol,
    });
    return res.json(response);
  } catch (error) {
    if (verifierOrigin) applyCors(res, verifierOrigin);
    const message = error.message || "";
    const forbidden = /Origin header|Origin is not authorized/.test(message);
    const clientError = error instanceof Cs07DcApiResponseError ||
      /^(Unknown CS-07 profile|CS-07 configuration)/.test(message);
    const status = forbidden ? 403 : (clientError ? 400 : 500);
    logHttpResponse(slog, requestId, "/vp/dc-api/request", status, status === 400 ? "Bad Request" : "Internal Server Error", res.getHeaders(), {
      error: error.message,
    });
    return res.status(status).json({
      error: forbidden ? "origin_not_allowed" : (clientError ? "invalid_request" : "server_error"),
      error_description: error.message || "Unable to create CS-07 request",
    });
  }
});

/** Normalize and durably stage a browser-delivered DC API response. */
dcApiRouter.post("/vp/dc-api/response/:sessionId", enforceBodyLimit(MAX_RESPONSE_BODY_BYTES), async (req, res) => {
  const sessionId = req.params.sessionId;
  const slog = makeSessionLogger(sessionId);
  const requestId = logHttpRequest(slog, "POST", `/vp/dc-api/response/${sessionId}`, req.headers, {
    sessionId,
    protocol: req.body?.protocol,
    hasData: !!req.body?.data,
  });

  try {
    let origin;
    try { origin = requestOrigin(req); } catch { return res.status(403).json({ error: "origin_not_allowed" }); }
    applyCors(res, origin);
    const session = await getVPSession(sessionId);
    if (!session || session.transport_profile !== "cs07-dc-api") {
      return res.status(404).json({ error: "invalid_request", error_description: "CS-07 session not found" });
    }
    if (origin !== session.verifier_origin) return res.status(403).json({ error: "origin_not_allowed" });
    if (["success", "failed", "response_received"].includes(session.status)) {
      return res.status(409).json({
        error: "invalid_request",
        error_description: "Presentation session is already terminal or has a response",
      });
    }

    let normalized;
    try {
      normalized = normalizeCs07DigitalCredentialResponse(req.body);
    } catch (error) {
      if (error instanceof Cs07DcApiResponseError) {
        session.status = "failed";
        session.error = error.errorCode;
        session.error_description = error.message;
        await storeVPSession(sessionId, session);
        return res.status(400).json({ error: error.errorCode, error_description: error.message });
      }
      throw error;
    }

    if (normalized.walletError) {
      session.status = "failed";
      session.error = normalized.walletError.error;
      session.error_description = "Wallet returned a DC API protocol error";
      await storeVPSession(sessionId, session);
      return res.status(200).json({ status: "failed", error: normalized.walletError.error });
    }

    let decryptedResponse;
    try {
      const encryptionKey = loadVerifierEncryptionKey();
      decryptedResponse = await decryptJWE(normalized.encryptedResponse, encryptionKey.privateKeyPem, "dc_api.jwt");
    } catch (error) {
      session.status = "failed";
      session.error = "invalid_response";
      session.error_description = "Unable to decrypt DC API response";
      await storeVPSession(sessionId, session);
      return res.status(400).json({ error: "invalid_response", error_description: session.error_description });
    }

    let parsed;
    try {
      parsed = parseCs07AuthorizationResponse(decryptedResponse, session.dcql_query);
    } catch (error) {
      if (error instanceof Cs07DcApiResponseError) {
        session.status = "failed";
        session.error = error.errorCode;
        session.error_description = error.message;
        await storeVPSession(sessionId, session);
        return res.status(400).json({ error: error.errorCode, error_description: error.message });
      }
      throw error;
    }

    if (session.cs03_signing) {
      const cs03Result = processCs03PresentationResponse(parsed.vpToken, {
        expectedCredentialIds: session.cs03_expected_credential_ids || [CS03_SIGNING_CREDENTIAL_ID],
        oobRequested: false,
      });
      if (!cs03Result.ok) {
        session.status = "failed";
        session.error = cs03Result.error;
        session.error_description = cs03Result.error_description;
        await storeVPSession(sessionId, session);
        return res.status(400).json({ error: cs03Result.error, error_description: cs03Result.error_description });
      }
      const artifactValidation = await validateCs03CredentialResponses({
        qesByCredentialId: cs03Result.qes,
        vpSession: session,
      });
      if (!artifactValidation.ok) {
        session.status = "failed";
        session.error = "invalid_request";
        session.error_description = "CS-03 signed artifact validation failed";
        session.cs03_validation = artifactValidation;
        await storeVPSession(sessionId, session);
        return res.status(400).json({
          error: "invalid_request",
          error_description: session.error_description,
        });
      }
      session.status = "success";
      session.claims = cs03Result.claims;
      session.qes = cs03Result.qes;
      session.cs03_validation = artifactValidation;
      await storeVPSession(sessionId, session);
      return res.status(200).json({ status: "success", sessionId });
    }

    let validationResult;
    try {
      validationResult = await validateCs07CredentialPresentations({
        vpToken: parsed.vpToken,
        session,
        options: { computeSdHash: computeSdHashFromPresentedToken },
      });
    } catch (error) {
      if (error instanceof Cs02VerifierResponseError) {
        session.status = "failed";
        session.error = error.errorCode;
        session.error_description = error.message;
        await storeVPSession(sessionId, session);
        return res.status(400).json({ error: error.errorCode, error_description: error.message });
      }
      throw error;
    }

    session.status = "success";
    session.verified_credential_ids = validationResult.verifiedCredentialIds;
    session.verification = validationResult.verification;
    // Keep only a non-sensitive receipt. The decrypted VP token is not
    // persisted in Redis and can be retrieved only by the verifier process.
    session.dc_api_response = { parsed: true };
    await storeVPSession(sessionId, session);
    logHttpResponse(slog, requestId, `/vp/dc-api/response/${sessionId}`, 200, "OK", res.getHeaders(), {
      status: "success",
    });
    return res.status(200).json({
      status: "success",
      sessionId,
      verified_credential_ids: validationResult.verifiedCredentialIds,
    });
  } catch (error) {
    logHttpResponse(slog, requestId, `/vp/dc-api/response/${sessionId}`, 500, "Internal Server Error", res.getHeaders(), {
      error: error.message,
    });
    return res.status(500).json({
      error: "server_error",
      error_description: error.message || "Unable to process CS-07 response",
    });
  }
});

export default dcApiRouter;
