import ts12PaymentSchema from "../../data/ts12-urn-eudi-sca-payment-1-data-model.json" with { type: "json" };
import {
  computeTs12TransactionDataHash,
  TS12_PAYMENT_TRANSACTION_TYPE,
  TS12_PAYMENT_VCT,
  TS12_SCA_CATEGORY,
} from "../../utils/ts12PaymentUtils.js";

export const TS12_TRANSACTION_HASH_ALGORITHM = "sha-256";
export const DEFAULT_TS12_AMR = [
  { knowledge: "pin_6_or_more_digits" },
  { possession: "key_in_local_native_wscd" },
];

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasText(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isIsoDate(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value);
}

function isIsoDateTime(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function decodeTransactionDataEntry(entry) {
  return JSON.parse(Buffer.from(entry, "base64url").toString("utf8"));
}

function resolveStoredCredentialConfig(stored) {
  return stored?.metadata?.credentialConfiguration || null;
}

export function validateTs12PaymentPayloadSchema(payload, schemaId) {
  if (schemaId !== TS12_PAYMENT_VCT || ts12PaymentSchema.$id !== schemaId) {
    throw new Error(`Unsupported TS12 transaction_data schema '${schemaId}'`);
  }

  if (!isObject(payload)) {
    throw new Error("TS12 transaction_data payload must be an object");
  }
  if (!hasText(payload.transaction_id)) {
    throw new Error("TS12 transaction_data payload.transaction_id must be a non-empty string");
  }
  if (!isObject(payload.payee)) {
    throw new Error("TS12 transaction_data payload.payee must be an object");
  }
  if (!hasText(payload.payee.name)) {
    throw new Error("TS12 transaction_data payload.payee.name must be a non-empty string");
  }
  if (!hasText(payload.payee.id)) {
    throw new Error("TS12 transaction_data payload.payee.id must be a non-empty string");
  }
  if (!hasText(payload.currency) || !/^[A-Z]{3}$/.test(payload.currency)) {
    throw new Error("TS12 transaction_data payload.currency must be a 3-letter ISO4217 code");
  }
  if (typeof payload.amount !== "number" || !Number.isFinite(payload.amount)) {
    throw new Error("TS12 transaction_data payload.amount must be a finite number");
  }
  if (payload.date_time !== undefined && !isIsoDateTime(payload.date_time)) {
    throw new Error("TS12 transaction_data payload.date_time must be an ISO8601 date-time");
  }
  if (payload.execution_date !== undefined && !isIsoDate(payload.execution_date)) {
    throw new Error("TS12 transaction_data payload.execution_date must be an ISO8601 date");
  }
  if (payload.pisp !== undefined) {
    if (!isObject(payload.pisp)) {
      throw new Error("TS12 transaction_data payload.pisp must be an object");
    }
    if (!hasText(payload.pisp.legal_name)) {
      throw new Error("TS12 transaction_data payload.pisp.legal_name must be a non-empty string");
    }
    if (!hasText(payload.pisp.brand_name)) {
      throw new Error("TS12 transaction_data payload.pisp.brand_name must be a non-empty string");
    }
    if (!hasText(payload.pisp.domain_name)) {
      throw new Error("TS12 transaction_data payload.pisp.domain_name must be a non-empty string");
    }
  }
  if (payload.recurrence !== undefined) {
    if (!isObject(payload.recurrence)) {
      throw new Error("TS12 transaction_data payload.recurrence must be an object");
    }
    if (!hasText(payload.recurrence.frequency)) {
      throw new Error("TS12 transaction_data payload.recurrence.frequency must be a non-empty string");
    }
    if (payload.recurrence.start_date !== undefined && !isIsoDate(payload.recurrence.start_date)) {
      throw new Error("TS12 transaction_data payload.recurrence.start_date must be an ISO8601 date");
    }
    if (payload.recurrence.end_date !== undefined && !isIsoDate(payload.recurrence.end_date)) {
      throw new Error("TS12 transaction_data payload.recurrence.end_date must be an ISO8601 date");
    }
    if (payload.recurrence.number !== undefined && !Number.isInteger(payload.recurrence.number)) {
      throw new Error("TS12 transaction_data payload.recurrence.number must be an integer");
    }
  }
}

export function resolveTs12TransactionDataForCredential({
  transactionData = [],
  credentialQueryId,
  stored,
}) {
  if (!Array.isArray(transactionData) || transactionData.length === 0) {
    return null;
  }

  const matches = [];
  for (const entry of transactionData) {
    if (typeof entry !== "string") {
      continue;
    }
    const decoded = decodeTransactionDataEntry(entry);
    if (decoded?.type !== TS12_PAYMENT_TRANSACTION_TYPE) {
      continue;
    }
    if (
      !Array.isArray(decoded.credential_ids) ||
      decoded.credential_ids.length === 0 ||
      !decoded.credential_ids.includes(credentialQueryId)
    ) {
      continue;
    }
    matches.push({ entry, decoded });
  }

  if (matches.length === 0) {
    return null;
  }
  if (matches.length > 1) {
    throw new Error(`Multiple TS12 transaction_data entries matched DCQL credential id '${credentialQueryId}'`);
  }

  const match = matches[0];
  const credentialConfig = resolveStoredCredentialConfig(stored);
  if (!credentialConfig) {
    throw new Error("Wallet is missing stored credential metadata required for TS12");
  }
  if (credentialConfig.category !== TS12_SCA_CATEGORY) {
    throw new Error(
      `Stored credential is not advertised as TS12 SCA category '${TS12_SCA_CATEGORY}'`,
    );
  }
  const txTypeConfig = credentialConfig.transaction_data_types?.[match.decoded.type];
  if (!txTypeConfig) {
    throw new Error(
      `Stored credential metadata does not advertise transaction_data type '${match.decoded.type}'`,
    );
  }
  validateTs12PaymentPayloadSchema(match.decoded.payload, txTypeConfig.schema);

  return {
    encodedTransactionData: match.entry,
    decodedTransactionData: match.decoded,
    expectedVct: credentialConfig.vct || stored?.metadata?.configurationId || TS12_PAYMENT_VCT,
  };
}

export function buildTs12ProofClaims({
  encodedTransactionData,
  responseMode = "direct_post",
  amr = DEFAULT_TS12_AMR,
}) {
  if (!encodedTransactionData || typeof encodedTransactionData !== "string") {
    throw new Error("TS12 proof claims require encoded transaction_data");
  }

  return {
    response_mode: responseMode,
    amr,
    transaction_data_hashes: [computeTs12TransactionDataHash(encodedTransactionData)],
    transaction_data_hashes_alg: TS12_TRANSACTION_HASH_ALGORITHM,
  };
}
