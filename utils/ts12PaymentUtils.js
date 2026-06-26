import { createHash, randomUUID } from "crypto";

/** TS12 SCA payment credential type (SD-JWT vct). */
export const TS12_PAYMENT_VCT = "urn:eudi:sca:payment:1";

/** TS12 payment transaction_data.type value. */
export const TS12_PAYMENT_TRANSACTION_TYPE = "urn:eudi:sca:payment:1";

/** DCQL credential id for TS12 payment SCA attestation presentations. */
export const TS12_SCA_CREDENTIAL_ID = "ts12-payment-sca-01";

/** TS12 SCA attestation category per TS12 §3. */
export const TS12_SCA_CATEGORY = "urn:eu:europa:ec:eudi:sua:sca";

/** Credential configuration id in issuer-config.json. */
export const TS12_PAYMENT_CREDENTIAL_CONFIG_ID = "urn:eudi:sca:payment:1";

export class Ts12PaymentValidationError extends Error {
  constructor(errors) {
    super(errors.join("; "));
    this.name = "Ts12PaymentValidationError";
    this.errors = errors;
  }
}

/** DCQL query requesting the TS12 payment SCA attestation. */
export const TS12_DCQL_QUERY = {
  credentials: [
    {
      id: TS12_SCA_CREDENTIAL_ID,
      format: "dc+sd-jwt",
      meta: {
        vct_values: [TS12_PAYMENT_VCT],
      },
      claims: [
        { path: ["sub"] },
        { path: ["iban"] },
        { path: ["bic"] },
        { path: ["currency"] },
      ],
    },
  ],
};

/**
 * Build a mock TS12 payment payload object (decoded, before embedding in transaction_data).
 * @param {Object} [overrides]
 * @returns {Object}
 */
export function buildTs12PaymentPayload(overrides = {}) {
  const transactionId =
    overrides.transaction_id || overrides.transactionId || randomUUID();

  return {
    transaction_id: transactionId,
    date_time: overrides.date_time || new Date().toISOString(),
    payee: {
      name: overrides.payee?.name || overrides.merchant || "Demo Merchant",
      id: overrides.payee?.id || overrides.payee_id || "merchant-001",
      ...(overrides.payee?.logo ? { logo: overrides.payee.logo } : {}),
      ...(overrides.payee?.website ? { website: overrides.payee.website } : {}),
    },
    currency: overrides.currency || "EUR",
    amount:
      overrides.amount !== undefined && overrides.amount !== null
        ? Number(overrides.amount)
        : 42.5,
    ...(overrides.pisp ? { pisp: overrides.pisp } : {}),
    ...(overrides.execution_date ? { execution_date: overrides.execution_date } : {}),
    ...(overrides.recurrence ? { recurrence: overrides.recurrence } : {}),
  };
}

/**
 * Build decoded TS12 payment transaction_data object.
 * @param {Object} [paymentOverrides]
 * @param {string} [credentialId]
 * @returns {Object}
 */
export function buildTs12PaymentTransactionData(
  paymentOverrides = {},
  credentialId = TS12_SCA_CREDENTIAL_ID,
) {
  return {
    type: TS12_PAYMENT_TRANSACTION_TYPE,
    credential_ids: [credentialId],
    transaction_data_hashes_alg: ["sha-256"],
    payload: buildTs12PaymentPayload(paymentOverrides),
  };
}

/** Base64url-encode TS12 transaction_data for OpenID4VP transaction_data[]. */
export function encodeTs12TransactionData(transactionDataObj) {
  return Buffer.from(JSON.stringify(transactionDataObj)).toString("base64url");
}

/**
 * Compute TS12 / OID4VP dynamic-linking hash over the base64url-encoded transaction_data string.
 * @param {string} encodedTransactionData
 * @returns {string} base64url SHA-256 digest
 */
export function computeTs12TransactionDataHash(encodedTransactionData) {
  return createHash("sha256")
    .update(encodedTransactionData)
    .digest("base64url");
}

/**
 * Parse payment request overrides from query/body parameters.
 * @param {Record<string, unknown>} input
 * @returns {Object}
 */
export function parseTs12PaymentRequestInput(input = {}) {
  const amountRaw = input.amount ?? input.value;
  const amount =
    amountRaw !== undefined && amountRaw !== null && amountRaw !== ""
      ? Number(amountRaw)
      : undefined;

  const payload = buildTs12PaymentPayload({
    transaction_id: input.transaction_id || input.transactionId,
    merchant: input.merchant || input.payee_name,
    payee_id: input.payee_id || input.payeeId,
    payee: input.payee && typeof input.payee === "object" ? input.payee : undefined,
    pisp: input.pisp && typeof input.pisp === "object" ? input.pisp : undefined,
    execution_date: input.execution_date || input.executionDate,
    recurrence: input.recurrence && typeof input.recurrence === "object" ? input.recurrence : undefined,
    currency: input.currency,
    amount: Number.isFinite(amount) ? amount : undefined,
  });

  validateTs12PaymentPayloadOrThrow(payload, input);
  return payload;
}

function hasText(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isIsoDate(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value);
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object || {}, key);
}

export function validateTs12PaymentPayload(payload, originalInput = {}) {
  const errors = [];
  const hasOriginalInput = Object.keys(originalInput || {}).length > 0;
  const originalPayee = isObject(originalInput.payee) ? originalInput.payee : null;

  if (hasOwn(originalInput, "purpose")) {
    errors.push("purpose is not defined for TS12 payment confirmation payloads");
  }

  if (
    hasOriginalInput &&
    !hasText(originalInput.transaction_id) &&
    !hasText(originalInput.transactionId)
  ) {
    errors.push("transaction_id is required");
  } else if (!hasText(payload?.transaction_id)) {
    errors.push("transaction_id is required");
  }

  if (hasOriginalInput) {
    if (!hasText(originalInput.merchant) && !hasText(originalInput.payee_name) && !hasText(originalPayee?.name)) {
      errors.push("payee.name is required");
    }
    if (!hasText(originalInput.payee_id) && !hasText(originalInput.payeeId) && !hasText(originalPayee?.id)) {
      errors.push("payee.id is required");
    }
  } else if (!isObject(payload?.payee)) {
    errors.push("payee is required");
  } else {
    if (!hasText(payload.payee.name)) errors.push("payee.name is required");
    if (!hasText(payload.payee.id)) errors.push("payee.id is required");
  }

  if (hasOriginalInput && !hasText(originalInput.currency)) {
    errors.push("currency is required");
  } else if (!hasText(payload?.currency) || !/^[A-Z]{3}$/.test(payload.currency)) {
    errors.push("currency must be an ISO4217 alpha-3 code");
  }

  const originalAmount = originalInput.amount ?? originalInput.value;
  if (hasOriginalInput && (originalAmount === undefined || originalAmount === null || originalAmount === "")) {
    errors.push("amount is required");
  } else if (hasOriginalInput && !Number.isFinite(Number(originalAmount))) {
    errors.push("amount must be a finite number");
  } else if (typeof payload?.amount !== "number" || !Number.isFinite(payload.amount)) {
    errors.push("amount must be a finite number");
  }

  if (payload?.execution_date !== undefined) {
    if (!isIsoDate(payload.execution_date)) {
      errors.push("execution_date must be an ISO8601 date");
    } else {
      const today = new Date().toISOString().slice(0, 10);
      if (payload.execution_date < today) {
        errors.push("execution_date must not be in the past");
      }
    }
  }

  if (payload?.recurrence !== undefined) {
    if (!isObject(payload.recurrence)) {
      errors.push("recurrence must be an object");
    } else if (!hasText(payload.recurrence.frequency)) {
      errors.push("recurrence.frequency is required");
    }
    if (payload.execution_date !== undefined) {
      errors.push("execution_date must not be present when recurrence is present");
    }
  }

  return {
    ok: errors.length === 0,
    errors,
  };
}

export function validateTs12PaymentPayloadOrThrow(payload, originalInput = {}) {
  const result = validateTs12PaymentPayload(payload, originalInput);
  if (!result.ok) {
    throw new Ts12PaymentValidationError(result.errors);
  }
  return payload;
}
