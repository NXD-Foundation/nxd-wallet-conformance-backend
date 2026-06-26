import { computeTs12TransactionDataHash, TS12_PAYMENT_VCT } from "./ts12PaymentUtils.js";

const TS12_AMR_VALUES = {
  knowledge: new Set([
    "pin_less_than_6_digits",
    "pin_6_or_more_digits",
    "passphrase_less_than_8_chars",
    "passphrase_8_to_11_chars",
    "passphrase_12_or_more_chars",
    "pattern",
    "other",
  ]),
  possession: new Set([
    "key_in_remote_wscd",
    "key_in_local_external_wscd",
    "key_in_local_internal_wscd",
    "key_in_local_native_wscd",
    "other",
  ]),
  inherence: new Set([
    "fingerprint_device",
    "fingerprint_external",
    "face_device",
    "face_external",
    "other",
  ]),
};

const PSD2_FACTOR_CATEGORIES = new Set(Object.keys(TS12_AMR_VALUES));

/**
 * Validate TS12 KB-JWT claims for a payment presentation response.
 * @param {Object} params
 * @param {import("jsonwebtoken").JwtPayload} params.kbPayload
 * @param {string} params.expectedResponseMode
 * @param {string} params.encodedTransactionData - base64url transaction_data entry from the authorization request
 * @param {Set<string>|string[]} [params.seenJti] - optional replay cache for jti values
 * @param {string} [params.expectedVct]
 * @returns {{ ok: true } | { ok: false, error: string, code: string }}
 */
export function validateTs12KeyBindingJwt({
  kbPayload,
  expectedResponseMode,
  encodedTransactionData,
  seenJti = null,
  expectedVct = TS12_PAYMENT_VCT,
}) {
  if (!kbPayload || typeof kbPayload !== "object") {
    return { ok: false, code: "missing_key_binding", error: "Key Binding JWT payload is missing" };
  }

  if (!kbPayload.jti || typeof kbPayload.jti !== "string") {
    return { ok: false, code: "missing_jti", error: "Key Binding JWT is missing required jti claim" };
  }

  if (seenJti && typeof seenJti.has === "function" && seenJti.has(kbPayload.jti)) {
    return { ok: false, code: "replayed_jti", error: "Key Binding JWT jti has already been used" };
  }

  if (!kbPayload.response_mode) {
    return {
      ok: false,
      code: "missing_response_mode",
      error: "Key Binding JWT is missing required response_mode claim",
    };
  }

  if (kbPayload.response_mode !== expectedResponseMode) {
    return {
      ok: false,
      code: "response_mode_mismatch",
      error: `Key Binding JWT response_mode mismatch. Received: '${kbPayload.response_mode}', expected: '${expectedResponseMode}'`,
    };
  }

  if (!Array.isArray(kbPayload.amr) || kbPayload.amr.length < 2) {
    return {
      ok: false,
      code: "insufficient_amr",
      error: "Key Binding JWT amr must contain at least two authentication factor categories",
    };
  }

  const categories = new Set();
  for (const entry of kbPayload.amr) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return { ok: false, code: "invalid_amr", error: "Key Binding JWT amr entries must be objects" };
    }

    const keys = Object.keys(entry);
    if (keys.length !== 1) {
      return {
        ok: false,
        code: "invalid_amr",
        error: "Key Binding JWT amr entries must contain exactly one TS12 factor category",
      };
    }

    const [key] = keys;
    if (!PSD2_FACTOR_CATEGORIES.has(key)) {
      return {
        ok: false,
        code: "invalid_amr_category",
        error: `Key Binding JWT amr contains unsupported TS12 factor category '${key}'`,
      };
    }

    if (!TS12_AMR_VALUES[key].has(entry[key])) {
      return {
        ok: false,
        code: "invalid_amr_value",
        error: `Key Binding JWT amr contains unsupported TS12 value '${entry[key]}' for category '${key}'`,
      };
    }

    categories.add(key);
  }

  if (categories.size < 2) {
    return {
      ok: false,
      code: "insufficient_amr_categories",
      error: "Key Binding JWT amr must represent at least two different PSD2 factor categories",
    };
  }

  const txHashes = kbPayload.transaction_data_hashes;
  if (!Array.isArray(txHashes) || txHashes.length === 0) {
    return {
      ok: false,
      code: "missing_transaction_data_hashes",
      error: "Key Binding JWT is missing transaction_data_hashes",
    };
  }

  if (!encodedTransactionData) {
    return {
      ok: false,
      code: "missing_session_transaction_data",
      error: "TS12 session is missing encoded transaction_data for hash verification",
    };
  }

  const expectedHash = computeTs12TransactionDataHash(encodedTransactionData);
  if (!txHashes.includes(expectedHash)) {
    return {
      ok: false,
      code: "transaction_data_hash_mismatch",
      error: "Key Binding JWT transaction_data_hashes do not match the authorization request",
    };
  }

  return { ok: true, expectedVct };
}

/**
 * Ensure the presented credential claims include the expected TS12 SCA payment vct.
 * @param {Array|Object} extractedClaims
 * @param {string} [expectedVct]
 * @returns {{ ok: true, credential: Object } | { ok: false, error: string, code: string }}
 */
export function validateTs12PresentedCredential(
  extractedClaims,
  expectedVct = TS12_PAYMENT_VCT,
) {
  const claimsArray = Array.isArray(extractedClaims)
    ? extractedClaims
    : extractedClaims
      ? [extractedClaims]
      : [];

  const credential = claimsArray.find((item) => item?.vct === expectedVct);
  if (!credential) {
    return {
      ok: false,
      code: "missing_sca_credential",
      error: `Presented credential with vct '${expectedVct}' was not found`,
    };
  }

  return { ok: true, credential };
}

/**
 * Run TS12 payment presentation validations for a direct_post response.
 * @param {Object} params
 * @returns {{ ok: true, jti: string, credential: Object } | { ok: false, error: string, code: string }}
 */
export function validateTs12PaymentPresentationResponse({
  kbPayload,
  extractedClaims,
  vpSession,
  seenJti = null,
}) {
  const encodedTransactionData = Array.isArray(vpSession?.transaction_data)
    ? vpSession.transaction_data[0]
    : vpSession?.ts12_encoded_transaction_data;

  const kbResult = validateTs12KeyBindingJwt({
    kbPayload,
    expectedResponseMode: vpSession?.response_mode || "direct_post",
    encodedTransactionData,
    seenJti,
    expectedVct: vpSession?.ts12_expected_vct || TS12_PAYMENT_VCT,
  });

  if (!kbResult.ok) {
    return kbResult;
  }

  const credResult = validateTs12PresentedCredential(
    extractedClaims,
    vpSession?.ts12_expected_vct || TS12_PAYMENT_VCT,
  );

  if (!credResult.ok) {
    return credResult;
  }

  return { ok: true, jti: kbPayload.jti, credential: credResult.credential };
}
