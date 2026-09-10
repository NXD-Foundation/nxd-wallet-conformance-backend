/**
 * WUA enforcement policy for CS-04 / CS-01 conformance credential configurations.
 * Enforcement is scoped to explicit credential IDs (not global).
 */

import {
  TS12_SCA_IBAN_VCT,
  TS12_SCA_USER_VCT,
  TS12_SCA_CARD_DPC_VCT,
} from "./ts12PaymentUtils.js";

export const WUA_REQUIRED_CREDENTIAL_ID = "VerifiablePIDSDJWTWUA";

export const WUA_REQUIRED_CREDENTIAL_IDS = new Set([
  WUA_REQUIRED_CREDENTIAL_ID,
  TS12_SCA_IBAN_VCT,
  TS12_SCA_USER_VCT,
  TS12_SCA_CARD_DPC_VCT,
]);

/** ISO 18045 AVA_VAN levels advertised for the WUA-required PID credential. */
export const WUA_REQUIRED_KEY_STORAGE_LEVELS = ["iso_18045_high"];
export const WUA_REQUIRED_USER_AUTH_LEVELS = ["iso_18045_high"];

/**
 * @param {string|null|undefined} credentialId
 * @returns {boolean}
 */
export function isWuaRequiredCredentialId(credentialId) {
  if (!credentialId || typeof credentialId !== "string") return false;
  return WUA_REQUIRED_CREDENTIAL_IDS.has(credentialId.trim());
}

function hasNonEmptyLevelList(value) {
  return Array.isArray(value) && value.length > 0;
}

/**
 * True when jwt.key_attestations_required advertises specific key_storage or
 * user_authentication levels. Empty `{}` is treated as no KA constraint.
 * @param {object|null|undefined} credConfig - credential_configurations_supported entry
 * @returns {boolean}
 */
export function credentialConfigRequiresKeyAttestation(credConfig) {
  const req = credConfig?.proof_types_supported?.jwt?.key_attestations_required;
  if (!req || typeof req !== "object") return false;
  return hasNonEmptyLevelList(req.key_storage) || hasNonEmptyLevelList(req.user_authentication);
}

/**
 * @param {object|null|undefined} credConfig
 * @returns {boolean}
 */
export function isWuaRequiredCredentialConfig(credConfig) {
  if (!credConfig) return false;
  const vct = credConfig.vct;
  if (isWuaRequiredCredentialId(vct)) return true;
  if (credentialConfigRequiresKeyAttestation(credConfig)) {
    return isWuaRequiredCredentialId(credConfig.scope);
  }
  return false;
}

/**
 * Parse authorization_details from PAR/token body (string or array).
 * @param {unknown} authorizationDetails
 * @returns {object[]|null}
 */
export function parseAuthorizationDetailsArray(authorizationDetails) {
  if (!authorizationDetails) return null;
  if (Array.isArray(authorizationDetails)) return authorizationDetails;
  if (typeof authorizationDetails === "string") {
    try {
      const parsed = JSON.parse(
        authorizationDetails.startsWith("%") ? decodeURIComponent(authorizationDetails) : authorizationDetails
      );
      return Array.isArray(parsed) ? parsed : parsed ? [parsed] : null;
    } catch {
      return null;
    }
  }
  if (typeof authorizationDetails === "object") return [authorizationDetails];
  return null;
}

/**
 * Extract credential configuration IDs from scope and authorization_details.
 * @param {{ scope?: string, authorization_details?: unknown }} params
 * @returns {string[]}
 */
export function extractRequestedCredentialConfigurationIds({ scope, authorization_details } = {}) {
  const ids = new Set();
  if (scope && typeof scope === "string") {
    for (const part of scope.split(/\s+/)) {
      const trimmed = part.trim();
      if (trimmed) ids.add(trimmed);
    }
  }
  const details = parseAuthorizationDetailsArray(authorization_details);
  if (details) {
    for (const item of details) {
      const id =
        item?.credential_configuration_id ||
        item?.credentialConfigurationId ||
        item?.types?.[0];
      if (id && typeof id === "string") ids.add(id);
    }
  }
  return [...ids];
}

/**
 * Whether the issuance request targets a WUA-required credential.
 * @param {{ scope?: string, authorization_details?: unknown, credential_configuration_id?: string }} params
 * @returns {boolean}
 */
export function issuanceRequestRequiresWua(params = {}) {
  if (isWuaRequiredCredentialId(params.credential_configuration_id)) return true;
  const ids = extractRequestedCredentialConfigurationIds(params);
  return ids.some((id) => isWuaRequiredCredentialId(id));
}

/**
 * @param {object|null|undefined} session
 * @returns {boolean}
 */
export function sessionRequiresWua(session) {
  if (!session) return false;
  if (session.requiresWua === true) return true;
  const ids = [
    session.credentialConfigurationId,
    session.credential_configuration_id,
    ...(session.requestedCredentialConfigurationIds || []),
    ...(session.credentials || []),
  ].filter(Boolean);
  return ids.some((id) => isWuaRequiredCredentialId(id));
}

/**
 * Compare ISO 18045 level lists: presented must meet or exceed required (same string or higher rank).
 * Simplified: exact match or includes required level string; higher rank not fully ordered yet.
 * @param {string[]} presented
 * @param {string[]} required
 * @returns {boolean}
 */
export function keyAttestationLevelsMeetRequirement(presented, required) {
  if (!Array.isArray(required) || required.length === 0) return true;
  if (!Array.isArray(presented) || presented.length === 0) return false;
  const presentedSet = new Set(presented.map(String));
  return required.every((r) => presentedSet.has(String(r)));
}

/**
 * @param {object} kaPayload - decoded KA JWT payload
 * @param {object} credConfig - credential configuration metadata
 * @returns {{ ok: boolean, error?: string }}
 */
export function validateKaLevelsAgainstMetadata(kaPayload, credConfig) {
  const required = credConfig?.proof_types_supported?.jwt?.key_attestations_required;
  if (!required || typeof required !== "object") {
    return { ok: true };
  }
  const reqKeyStorage = required.key_storage;
  const reqUserAuth = required.user_authentication;
  if (Array.isArray(reqKeyStorage) && reqKeyStorage.length > 0) {
    if (!keyAttestationLevelsMeetRequirement(kaPayload?.key_storage, reqKeyStorage)) {
      return {
        ok: false,
        error: `KA key_storage does not meet required levels [${reqKeyStorage.join(", ")}]`,
      };
    }
  }
  if (Array.isArray(reqUserAuth) && reqUserAuth.length > 0) {
    if (!keyAttestationLevelsMeetRequirement(kaPayload?.user_authentication, reqUserAuth)) {
      return {
        ok: false,
        error: `KA user_authentication does not meet required levels [${reqUserAuth.join(", ")}]`,
      };
    }
  }
  return { ok: true };
}
