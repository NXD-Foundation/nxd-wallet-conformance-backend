import { randomUUID } from "crypto";
import { computeTransactionDataHash } from "./transactionDataHash.js";

/** TS12 / CS-12 payment transaction_data.type and payload schema id. */
export const TS12_PAYMENT_TRANSACTION_TYPE = "urn:eudi:sca:payment:1";

/** TS12 SCA attestation category per TS12 §3 / CS-12 §7.3. */
export const TS12_SCA_CATEGORY = "urn:eu:europa:ec:eudi:sua:sca";

/** Base SCA VCT that in-scope types extend. */
export const TS12_SCA_BASE_EXTENDS = "https://webuildconsortium.eu/sca/1.0";

export const TS12_DEFAULT_ATTESTATION_TYPE = "sca-iban";

export const TS12_SCA_IBAN_VCT = "https://webuildconsortium.eu/sca/sca-iban/1.0";
export const TS12_SCA_USER_VCT = "https://webuildconsortium.eu/sca/sca-user/1.0";
export const TS12_SCA_CARD_DPC_VCT = "https://webuildconsortium.eu/sca/sca-card-dpc/1.0";

/**
 * CS-12 in-scope SCA attestation types. Keys are request `attestation_type` ids.
 * Issued `vct` values are the WE BUILD base VCTs so DCQL exact-match works in ITB+.
 */
export const TS12_SCA_ATTESTATION_TYPES = Object.freeze({
  "sca-iban": Object.freeze({
    id: "sca-iban",
    vct: TS12_SCA_IBAN_VCT,
    credentialId: "sca_iban",
    claims: Object.freeze([
      { path: ["masked_iban"] },
      { path: ["iban"] },
      { path: ["bic"] },
      { path: ["currency"] },
    ]),
    requiresAud: false,
  }),
  "sca-user": Object.freeze({
    id: "sca-user",
    vct: TS12_SCA_USER_VCT,
    credentialId: "sca_user",
    claims: Object.freeze([{ path: ["masked_psu_id"] }]),
    requiresAud: true,
  }),
  "sca-card-dpc": Object.freeze({
    id: "sca-card-dpc",
    vct: TS12_SCA_CARD_DPC_VCT,
    credentialId: "sca_card_dpc",
    claims: Object.freeze([
      { path: ["credential_id"] },
      { path: ["network"] },
      { path: ["card_id"] },
    ]),
    requiresAud: false,
  }),
});

export const TS12_SCA_BASE_VCTS = Object.freeze(
  Object.values(TS12_SCA_ATTESTATION_TYPES).map((entry) => entry.vct),
);

export const TS12_SCA_CREDENTIAL_ID =
  TS12_SCA_ATTESTATION_TYPES[TS12_DEFAULT_ATTESTATION_TYPE].credentialId;

export const TS12_PAYMENT_CREDENTIAL_CONFIG_ID = TS12_SCA_IBAN_VCT;

export class Ts12PaymentValidationError extends Error {
  constructor(errors, code = "invalid_ts12_payment_payload") {
    super(Array.isArray(errors) ? errors.join("; ") : String(errors));
    this.name = "Ts12PaymentValidationError";
    this.errors = Array.isArray(errors) ? errors : [String(errors)];
    this.code = code;
  }
}

export function getTs12AttestationTypeByVct(vct) {
  if (!vct || typeof vct !== "string") return null;
  return Object.values(TS12_SCA_ATTESTATION_TYPES).find((entry) => entry.vct === vct) || null;
}

export function isTs12ScaVct(vct) {
  return Boolean(getTs12AttestationTypeByVct(vct));
}

export function isTs12ScaCredentialType(credType) {
  return Boolean(
    TS12_SCA_ATTESTATION_TYPES[credType] ||
      getTs12AttestationTypeByVct(credType) ||
      credType === TS12_PAYMENT_TRANSACTION_TYPE,
  );
}

/** Persist the WUA expiry onto a credential request so SCA `exp` can be capped at issue time. */
export function applyScaWuaExpiryHint(requestBody, wuaExp) {
  if (requestBody && typeof wuaExp === "number" && Number.isFinite(wuaExp)) {
    requestBody._wuaExp = wuaExp;
  }
  return requestBody;
}

/**
 * Resolve a request attestation type from an id or a base VCT URL.
 * @param {unknown} raw
 * @param {string} [fallbackId]
 * @returns {typeof TS12_SCA_ATTESTATION_TYPES[string]}
 */
export function resolveTs12AttestationType(raw, fallbackId = TS12_DEFAULT_ATTESTATION_TYPE) {
  const value = typeof raw === "string" ? raw.trim() : "";
  if (!value) {
    return TS12_SCA_ATTESTATION_TYPES[fallbackId];
  }

  if (TS12_SCA_ATTESTATION_TYPES[value]) {
    return TS12_SCA_ATTESTATION_TYPES[value];
  }

  const byVct = getTs12AttestationTypeByVct(value);
  if (byVct) {
    return byVct;
  }

  throw new Ts12PaymentValidationError(
    [
      `attestation_type must be one of ${Object.keys(TS12_SCA_ATTESTATION_TYPES).join(", ")}`,
    ],
    "invalid_ts12_attestation_type",
  );
}

export function buildTs12DcqlQuery(attestationType = TS12_DEFAULT_ATTESTATION_TYPE) {
  const type = resolveTs12AttestationType(attestationType);
  return {
    credentials: [
      {
        id: type.credentialId,
        format: "dc+sd-jwt",
        meta: {
          vct_values: [type.vct],
        },
        claims: type.claims.map((claim) => ({ path: [...claim.path] })),
      },
    ],
  };
}

export const TS12_DCQL_QUERY = buildTs12DcqlQuery(TS12_DEFAULT_ATTESTATION_TYPE);

export function listScaVctsInDcql(dcqlQuery) {
  const credentials = Array.isArray(dcqlQuery?.credentials) ? dcqlQuery.credentials : [];
  const vcts = [];
  for (const credential of credentials) {
    const values = credential?.meta?.vct_values;
    if (!Array.isArray(values)) continue;
    const scaVcts = values.filter((value) => isTs12ScaVct(value));
    if (scaVcts.length > 0) {
      vcts.push(...scaVcts);
    }
  }
  return vcts;
}

export function assertSingleScaAttestationInDcql(dcqlQuery) {
  const vcts = listScaVctsInDcql(dcqlQuery);
  if (vcts.length > 1) {
    throw new Ts12PaymentValidationError(
      ["Authorization Request must query at most one of sca-iban, sca-user, or sca-card-dpc"],
      "combined_sca_presentation",
    );
  }
  return vcts;
}

export function capScaExpiryUnix(defaultExpUnix, wuaExpUnix) {
  if (typeof wuaExpUnix !== "number" || !Number.isFinite(wuaExpUnix)) {
    return defaultExpUnix;
  }
  return Math.min(defaultExpUnix, wuaExpUnix);
}

export function rpClientIdFromServerUrl(serverURL) {
  const candidate = typeof serverURL === "string" && serverURL.trim() ? serverURL.trim() : "http://localhost:3000";
  try {
    const href = candidate.includes("://") ? candidate : `https://${candidate}`;
    return `x509_san_dns:${new URL(href).hostname}`;
  } catch {
    return `x509_san_dns:${candidate}`;
  }
}

export function audienceIncludesRp(aud, rpIdentifier) {
  if (!rpIdentifier) return false;
  if (typeof aud === "string") {
    return aud === rpIdentifier;
  }
  if (Array.isArray(aud)) {
    return aud.includes(rpIdentifier);
  }
  return false;
}

export function parseTs12WalletMetadata(raw) {
  if (raw == null || raw === "") return null;
  if (typeof raw === "object") return raw;
  if (typeof raw !== "string") return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function isTs12EncryptionJwk(key) {
  return Boolean(key && typeof key === "object" && key.use === "enc");
}

export function selectTs12EncryptionJwk(walletMetadata) {
  const keys = walletMetadata?.jwks?.keys;
  if (!Array.isArray(keys)) return null;
  return keys.find((key) => isTs12EncryptionJwk(key)) || null;
}

export function hasTs12EncryptionJwk(walletMetadata) {
  return Boolean(selectTs12EncryptionJwk(walletMetadata));
}

export function isTs12PaymentRequestUri(requestUri) {
  if (typeof requestUri !== "string" || !requestUri.trim()) return false;
  try {
    return new URL(requestUri, "https://wallet.local").pathname.includes("/ts12/payment/");
  } catch {
    return requestUri.includes("/ts12/payment/");
  }
}

export function isCompactJwe(token) {
  return typeof token === "string" && token.split(".").length === 5;
}

export function decodeTs12TransactionDataEntry(entry) {
  if (typeof entry !== "string") return null;
  try {
    return JSON.parse(Buffer.from(entry, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export function requestDeclaresTs12PaymentTransaction(transactionData) {
  const entries = Array.isArray(transactionData) ? transactionData : [];
  return entries.some((entry) => decodeTs12TransactionDataEntry(entry)?.type === TS12_PAYMENT_TRANSACTION_TYPE);
}

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
    ...(overrides.purpose !== undefined ? { purpose: overrides.purpose } : {}),
    ...(overrides.amount_estimated !== undefined ? { amount_estimated: overrides.amount_estimated } : {}),
    ...(overrides.amount_earmarked !== undefined ? { amount_earmarked: overrides.amount_earmarked } : {}),
    ...(overrides.sct_inst !== undefined ? { sct_inst: overrides.sct_inst } : {}),
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
  return computeTransactionDataHash(encodedTransactionData);
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
    purpose: input.purpose,
    amount_estimated: parseOptionalBoolean(input.amount_estimated),
    amount_earmarked: parseOptionalBoolean(input.amount_earmarked),
    sct_inst: parseOptionalBoolean(input.sct_inst),
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

function parseOptionalBoolean(raw) {
  if (raw === undefined || raw === null || raw === "") return undefined;
  if (typeof raw === "boolean") return raw;
  if (raw === "true" || raw === "1") return true;
  if (raw === "false" || raw === "0") return false;
  return raw;
}

function optionalBooleanError(field, value, originalInput, errors) {
  const raw = hasOwn(originalInput, field) ? originalInput[field] : value;
  if (raw === undefined || raw === null || raw === "") return;
  if (typeof value !== "boolean") {
    errors.push(`${field} must be a boolean`);
  }
}

export function validateTs12PaymentPayload(payload, originalInput = {}) {
  const errors = [];
  const hasOriginalInput = Object.keys(originalInput || {}).length > 0;
  const originalPayee = isObject(originalInput.payee) ? originalInput.payee : null;

  if (payload?.purpose !== undefined && typeof payload.purpose !== "string") {
    errors.push("purpose must be a string");
  }
  optionalBooleanError("amount_estimated", payload?.amount_estimated, originalInput, errors);
  optionalBooleanError("amount_earmarked", payload?.amount_earmarked, originalInput, errors);
  optionalBooleanError("sct_inst", payload?.sct_inst, originalInput, errors);

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
