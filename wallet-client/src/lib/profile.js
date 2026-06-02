/**
 * Wallet issuance profile selection for OpenID4VCI flows.
 *
 * - compatibility: generic OpenID4VCI testing (pre-authorized and authorization-code)
 * - webuild-cs01: WE BUILD CS-01 attestation conformance mode (authorization-code only)
 */

export const WALLET_PROFILES = Object.freeze({
  COMPATIBILITY: "compatibility",
  WEBUILD_CS01: "webuild-cs01",
});

const SUPPORTED_PROFILES = new Set(Object.values(WALLET_PROFILES));

export class Cs01ProfileError extends Error {
  constructor(message, errorCode = "unsupported_grant_type") {
    super(message);
    this.name = "Cs01ProfileError";
    this.errorCode = errorCode;
  }
}

export function normalizeWalletProfile(value) {
  if (value == null || value === "" || value === "default") {
    return WALLET_PROFILES.COMPATIBILITY;
  }
  if (value === "compatibility" || value === WALLET_PROFILES.COMPATIBILITY) {
    return WALLET_PROFILES.COMPATIBILITY;
  }
  if (value === "cs01" || value === WALLET_PROFILES.WEBUILD_CS01) {
    return WALLET_PROFILES.WEBUILD_CS01;
  }
  throw new Error(
    `Unknown WALLET_PROFILE '${value}'. Supported values: ${[...SUPPORTED_PROFILES].join(", ")}`,
  );
}

export function resolveWalletProfile(env = process.env) {
  return normalizeWalletProfile(env.WALLET_PROFILE);
}

export function isWebuildCs01Profile(profile) {
  return profile === WALLET_PROFILES.WEBUILD_CS01;
}

export function assertCs01AuthorizationCodeGrant(grants, { endpoint = "issuance" } = {}) {
  if (grants?.authorization_code) {
    return;
  }
  const found = Object.keys(grants || {});
  throw new Cs01ProfileError(
    `WE BUILD CS-01 profile requires authorization_code grant at ${endpoint}. Found: ${found.join(", ") || "none"}`,
  );
}

export function assertPreAuthorizedAllowed(profile, { endpoint = "issuance" } = {}) {
  if (!isWebuildCs01Profile(profile)) {
    return;
  }
  throw new Cs01ProfileError(
    `WE BUILD CS-01 profile does not support pre-authorized_code at ${endpoint}. Use authorization_code grant.`,
  );
}

export function selectVciGrantRoute(profile, grants) {
  if (isWebuildCs01Profile(profile)) {
    assertCs01AuthorizationCodeGrant(grants);
    return "authorization_code";
  }

  if (grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"]) {
    return "pre-authorized_code";
  }
  if (grants?.authorization_code) {
    return "authorization_code";
  }
  return null;
}

export class ParRequiredError extends Error {
  constructor(message) {
    super(message);
    this.name = "ParRequiredError";
    this.errorCode = "par_required";
  }
}

/** True when PAR must succeed (CS-01 profile or AS metadata flag). */
export function isParMandatory(profile, asRequiresPar = false) {
  return isWebuildCs01Profile(profile) || asRequiresPar === true;
}

export function assertParEndpointAvailable(profile, parEndpoint, { asRequiresPar = false } = {}) {
  if (!isParMandatory(profile, asRequiresPar)) {
    return;
  }
  if (parEndpoint) {
    return;
  }
  if (isWebuildCs01Profile(profile)) {
    throw new ParRequiredError(
      "WE BUILD CS-01 profile requires PAR but authorization server metadata has no pushed_authorization_request_endpoint",
    );
  }
  throw new ParRequiredError(
    "Authorization server metadata requires PAR but no pushed_authorization_request_endpoint was advertised",
  );
}

export function assertParResponse(profile, { ok, status, requestUri, asRequiresPar = false, responseBody = "" } = {}) {
  if (!isParMandatory(profile, asRequiresPar)) {
    return;
  }
  if (ok && requestUri) {
    return;
  }
  if (ok && !requestUri) {
    throw new ParRequiredError("PAR response is missing request_uri");
  }
  const suffix = responseBody ? `: ${responseBody}` : "";
  throw new ParRequiredError(`PAR request failed with status ${status}${suffix}`);
}

export function assertNoDirectAuthorizationFallback(profile, usedPar) {
  if (!isWebuildCs01Profile(profile)) {
    return;
  }
  if (usedPar) {
    return;
  }
  throw new ParRequiredError(
    "WE BUILD CS-01 profile requires PAR; direct front-channel authorization is not permitted",
  );
}
