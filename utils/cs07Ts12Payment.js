import { Cs07DcApiResponseError } from "./cs07DcApi.js";
import { extractKeyBindingJwtFromSdJwt } from "./sdJwtKeyBinding.js";
import { parseSdJwtClaims } from "./sdJwtClaims.js";
import {
  Ts12PaymentValidationError,
  assertSingleScaAttestationInDcql,
  buildTs12DcqlQuery,
  buildTs12PaymentTransactionData,
  encodeTs12TransactionData,
  getTs12AttestationTypeByVct,
  listScaVctsInDcql,
  parseTs12PaymentRequestInput,
  resolveTs12AttestationType,
} from "./ts12PaymentUtils.js";

export const CS07_BASE_REQUEST_KEYS = new Set(["profile", "sessionId"]);

export const CS07_TS12_PAYMENT_REQUEST_KEYS = new Set([
  ...CS07_BASE_REQUEST_KEYS,
  "amount",
  "value",
  "currency",
  "merchant",
  "payee_name",
  "payee_id",
  "payeeId",
  "payee",
  "transaction_id",
  "transactionId",
  "attestation_type",
  "vct",
  "pisp",
  "execution_date",
  "executionDate",
  "recurrence",
  "purpose",
  "amount_estimated",
  "amount_earmarked",
  "sct_inst",
]);

export function assertCs07DcApiRequestBodyKeys(body, workflow) {
  const allowed = workflow === "ts12-payment" ? CS07_TS12_PAYMENT_REQUEST_KEYS : CS07_BASE_REQUEST_KEYS;
  const unexpected = Object.keys(body || {}).find((key) => !allowed.has(key));
  if (!unexpected) return;
  throw new Cs07DcApiResponseError(
    workflow === "ts12-payment"
      ? `Unsupported CS-07 request field: ${unexpected}`
      : "Only profile and sessionId may be supplied",
    "invalid_request",
  );
}

export function buildCs07Ts12PaymentRequest(body = {}, profileDcql = null) {
  const dcqlQuery = profileDcql
    ? JSON.parse(JSON.stringify(profileDcql))
    : buildTs12DcqlQuery(
        resolveTs12AttestationType(body.attestation_type || body.vct || "sca-card-dpc").id,
      );
  assertSingleScaAttestationInDcql(dcqlQuery);
  const scaVcts = listScaVctsInDcql(dcqlQuery);
  if (scaVcts.length !== 1) {
    throw new Ts12PaymentValidationError(
      ["CS-07 payment profile DCQL must query exactly one SCA attestation"],
      "invalid_ts12_attestation_type",
    );
  }
  const attestationType = getTs12AttestationTypeByVct(scaVcts[0]);
  if (!attestationType) {
    throw new Ts12PaymentValidationError(
      ["CS-07 payment profile DCQL must query an in-scope SCA attestation"],
      "invalid_ts12_attestation_type",
    );
  }
  const paymentPayload = parseTs12PaymentRequestInput(body);
  const transactionDataObj = buildTs12PaymentTransactionData(
    paymentPayload,
    attestationType.credentialId,
  );
  return {
    dcqlQuery,
    attestationType,
    paymentPayload,
    transactionDataObj,
    encodedTransactionData: encodeTs12TransactionData(transactionDataObj),
  };
}

function decodeJwtPayload(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function collectPresentationTokens(vpToken) {
  if (!vpToken || typeof vpToken !== "object") return [];
  const tokens = [];
  for (const value of Object.values(vpToken)) {
    if (typeof value === "string") tokens.push(value);
    else if (Array.isArray(value)) {
      for (const entry of value) {
        if (typeof entry === "string") tokens.push(entry);
      }
    }
  }
  return tokens;
}

/** Pull KB-JWT payload and reconstructed claims from a CS-07 vp_token object. */
export function extractTs12PresentationArtifactsFromVpToken(vpToken) {
  const extractedClaims = [];
  let kbPayload = null;
  for (const token of collectPresentationTokens(vpToken)) {
    try {
      const parsed = parseSdJwtClaims(token);
      if (parsed?.claims) extractedClaims.push(parsed.claims);
    } catch {
      // CS-07 already validated the presentation; skip tokens that are not SD-JWT.
    }
    const kbJwt = extractKeyBindingJwtFromSdJwt(token);
    const payload = decodeJwtPayload(kbJwt);
    if (payload) kbPayload = payload;
  }
  return { kbPayload, extractedClaims };
}
