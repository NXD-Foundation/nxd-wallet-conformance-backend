import express from "express";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import {
  CONFIG,
  generateVPRequest,
  processVPRequest,
  createErrorResponse,
  bindSessionLoggingContext,
} from "../../utils/routeUtils.js";
import {
  TS12_DCQL_QUERY,
  TS12_PAYMENT_VCT,
  Ts12PaymentValidationError,
  buildTs12PaymentTransactionData,
  encodeTs12TransactionData,
  parseTs12PaymentRequestInput,
} from "../../utils/ts12PaymentUtils.js";
import {
  setSessionContext,
  clearSessionContext,
} from "../../services/cacheServiceRedis.js";
import { makeSessionLogger, logHttpRequest, logHttpResponse } from "../../utils/sessionLogger.js";
import { trustFrameworkSessionProps } from "../../utils/trustFrameworkPolicy.js";

const ts12PaymentRouter = express.Router();

ts12PaymentRouter.use((req, res, next) => {
  const sessionId = req.query.session_id || req.params.sessionId || req.params.id;
  if (sessionId) {
    setSessionContext(sessionId);
    res.on("finish", () => {
      clearSessionContext();
    });
  }
  next();
});

const clientMetadata = JSON.parse(
  fs.readFileSync("./data/verifier-config.json", "utf-8"),
);

/**
 * Generate a mock TS12 payment presentation request for EUDI Wallets.
 *
 * Query/body parameters:
 * - required: amount, currency, merchant/payee.name, payee_id/payee.id, transaction_id
 * - optional: session_id, response_mode (default direct_post), request_uri_method (get|post, default post)
 * - optional TS12 fields: execution_date, recurrence, pisp
 */
async function handleTs12PaymentRequest(req, res) {
  let sessionId;
  let requestId = null;
  let slog = null;

  try {
    sessionId = req.body?.session_id || req.query.session_id || uuidv4();
    slog = makeSessionLogger(sessionId);
    bindSessionLoggingContext(req, res, sessionId);

    const responseMode = req.body?.response_mode || req.query.response_mode || "direct_post";
    const requestUriMethod = req.body?.request_uri_method || req.query.request_uri_method || "post";
    const paymentInput = { ...req.query, ...req.body };
    const paymentPayload = parseTs12PaymentRequestInput(paymentInput);
    const transactionDataObj = buildTs12PaymentTransactionData(paymentPayload);
    const encodedTransactionData = encodeTs12TransactionData(transactionDataObj);

    requestId = logHttpRequest(slog, req.method, "/ts12/payment/request", req.headers, {
      ...paymentInput,
      sessionId,
      trustPolicy: trustFrameworkSessionProps(req.query).trustPolicy,
      responseMode,
      requestUriMethod,
    });

    const result = await generateVPRequest({
      sessionId,
      trustPolicy: trustFrameworkSessionProps(req.query).trustPolicy,
      responseMode,
      presentationDefinition: null,
      clientId: CONFIG.CLIENT_ID,
      clientMetadata,
      kid: null,
      serverURL: CONFIG.SERVER_URL,
      dcqlQuery: TS12_DCQL_QUERY,
      transactionData: encodedTransactionData,
      ts12Payment: true,
      ts12PaymentPayload: transactionDataObj.payload,
      ts12ExpectedVct: TS12_PAYMENT_VCT,
      usePostMethod: requestUriMethod !== "get",
      routePath: "/ts12/payment/x509VPrequest",
    });

    const response = {
      ...result,
      payment: transactionDataObj.payload,
      transactionDataType: transactionDataObj.type,
    };

    logHttpResponse(slog, requestId, "/ts12/payment/request", 200, "OK", res.getHeaders(), response);
    try {
      slog("[VERIFIER] [COMPLETE] TS12 payment request generated", {
        sessionId,
        transactionId: transactionDataObj.payload.transaction_id,
        amount: transactionDataObj.payload.amount,
        currency: transactionDataObj.payload.currency,
      });
    } catch {}
    res.json(response);
  } catch (error) {
    const statusCode = error instanceof Ts12PaymentValidationError ? 400 : 500;
    const statusText = statusCode === 400 ? "Bad Request" : "Internal Server Error";
    if (slog) {
      try {
        slog("[VERIFIER] [ERROR] TS12 payment request generation failed", { error: error.message });
      } catch {}
      logHttpResponse(
        slog,
        requestId,
        "/ts12/payment/request",
        statusCode,
        statusText,
        res.getHeaders(),
        { error: error.message },
      );
    }
    const errorResponse = createErrorResponse(
      error.message,
      "ts12/payment/request",
      statusCode,
      sessionId,
    );
    if (error instanceof Ts12PaymentValidationError) {
      errorResponse.errors = error.errors;
      errorResponse.code = "invalid_ts12_payment_payload";
    }
    res.status(statusCode).json(errorResponse);
  }
}

ts12PaymentRouter.post("/ts12/payment/request", handleTs12PaymentRequest);

ts12PaymentRouter.get("/ts12/payment/request", handleTs12PaymentRequest);

ts12PaymentRouter
  .route("/ts12/payment/x509VPrequest/:id")
  .post(express.urlencoded({ extended: true }), async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;

    try {
      const { wallet_nonce: walletNonce, wallet_metadata: walletMetadata } = req.body;

      requestId = logHttpRequest(
        slog,
        "POST",
        `/ts12/payment/x509VPrequest/${sessionId}`,
        req.headers,
        req.body,
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
        logHttpResponse(
          slog,
          requestId,
          `/ts12/payment/x509VPrequest/${sessionId}`,
          result.status,
          "Error",
          res.getHeaders(),
          { error: result.error },
        );
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(
        slog,
        requestId,
        `/ts12/payment/x509VPrequest/${sessionId}`,
        200,
        "OK",
        res.getHeaders(),
        { jwtLength: result.jwt?.length },
      );
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      logHttpResponse(
        slog,
        requestId,
        `/ts12/payment/x509VPrequest/${sessionId}`,
        500,
        "Internal Server Error",
        res.getHeaders(),
        { error: error.message },
      );
      const errorResponse = createErrorResponse(
        error.message,
        "POST /ts12/payment/x509VPrequest/:id",
        500,
        sessionId,
      );
      res.status(500).json(errorResponse);
    }
  })
  .get(async (req, res) => {
    const sessionId = req.params.id;
    const slog = makeSessionLogger(sessionId);
    let requestId = null;

    try {
      requestId = logHttpRequest(
        slog,
        "GET",
        `/ts12/payment/x509VPrequest/${sessionId}`,
        req.headers,
        req.query,
      );

      const result = await processVPRequest({
        sessionId,
        clientMetadata,
        serverURL: CONFIG.SERVER_URL,
        clientId: CONFIG.CLIENT_ID,
        kid: null,
      });

      if (result.error) {
        logHttpResponse(
          slog,
          requestId,
          `/ts12/payment/x509VPrequest/${sessionId}`,
          result.status,
          "Error",
          res.getHeaders(),
          { error: result.error },
        );
        return res.status(result.status).json({ error: result.error });
      }

      logHttpResponse(
        slog,
        requestId,
        `/ts12/payment/x509VPrequest/${sessionId}`,
        200,
        "OK",
        res.getHeaders(),
        { jwtLength: result.jwt?.length },
      );
      res.type(CONFIG.CONTENT_TYPE).send(result.jwt);
    } catch (error) {
      logHttpResponse(
        slog,
        requestId,
        `/ts12/payment/x509VPrequest/${sessionId}`,
        500,
        "Internal Server Error",
        res.getHeaders(),
        { error: error.message },
      );
      const errorResponse = createErrorResponse(
        error.message,
        "GET /ts12/payment/x509VPrequest/:id",
        500,
        sessionId,
      );
      res.status(500).json(errorResponse);
    }
  });

export default ts12PaymentRouter;
