/**
 * Wallet issuance profile selection for OpenID4VCI flows.
 *
 * - compatibility: generic OpenID4VCI testing (pre-authorized and authorization-code)
 * - webuild-cs01: WE BUILD CS-01 attestation conformance mode (authorization_code and
 *   pre-authorized_code; pre-auth may be disabled via CS01_DISABLE_PRE_AUTHORIZED)
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

/** True when CS-01 pre-authorized issuance is explicitly disabled (legacy CS-01 v1.0 semantics). */
export function isCs01PreAuthorizedDisabled(env = process.env) {
  const raw = env.CS01_DISABLE_PRE_AUTHORIZED;
  if (raw == null || raw === "") {
    return false;
  }
  const normalized = String(raw).trim().toLowerCase();
  return normalized === "true" || normalized === "1" || normalized === "yes";
}

/**
 * Summarize which grant types are enabled for the active wallet profile.
 * Used by /health and startup logging.
 */
export function describeCs01GrantPolicy(profile, env = process.env) {
  if (!isWebuildCs01Profile(profile)) {
    return {
      profile,
      authorizationCodeEnabled: true,
      preAuthorizedEnabled: true,
      preAuthorizedDisabledByEnv: false,
    };
  }

  const preAuthorizedDisabledByEnv = isCs01PreAuthorizedDisabled(env);
  return {
    profile,
    authorizationCodeEnabled: true,
    preAuthorizedEnabled: !preAuthorizedDisabledByEnv,
    preAuthorizedDisabledByEnv,
    preAuthorizedDisableEnvVar: "CS01_DISABLE_PRE_AUTHORIZED",
  };
}

const PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

export function describeSupportedVciGrants(profile, env = process.env) {
  if (isWebuildCs01Profile(profile) && isCs01PreAuthorizedDisabled(env)) {
    return ["authorization_code"];
  }
  return ["authorization_code", PRE_AUTHORIZED_GRANT];
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

export function assertPreAuthorizedAllowed(
  profile,
  { endpoint = "issuance", env = process.env } = {},
) {
  if (!isWebuildCs01Profile(profile)) {
    return;
  }
  if (!isCs01PreAuthorizedDisabled(env)) {
    return;
  }
  throw new Cs01ProfileError(
    `WE BUILD CS-01 profile has pre-authorized_code disabled at ${endpoint} (CS01_DISABLE_PRE_AUTHORIZED=true). Use authorization_code grant or unset the opt-out flag.`,
  );
}

export function selectVciGrantRoute(profile, grants, { env = process.env, endpoint = "issuance" } = {}) {
  if (grants?.authorization_code) {
    return "authorization_code";
  }
  if (grants?.[PRE_AUTHORIZED_GRANT]) {
    assertPreAuthorizedAllowed(profile, { endpoint, env });
    return "pre-authorized_code";
  }

  const found = Object.keys(grants || {}).join(", ") || "none";
  if (isWebuildCs01Profile(profile)) {
    const supported = describeSupportedVciGrants(profile, env).join(", ");
    throw new Cs01ProfileError(
      `WE BUILD CS-01 profile found no supported grant at ${endpoint}. Supported: ${supported}. Found: ${found}`,
    );
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
