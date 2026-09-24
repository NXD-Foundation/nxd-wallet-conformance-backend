import { isWebuildCs01Profile } from "./profile.js";

const PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

export class ScopeResolutionError extends Error {
  constructor(message, errorCode = "invalid_scope") {
    super(message);
    this.name = "ScopeResolutionError";
    this.errorCode = errorCode;
  }
}

export class CredentialSelectionError extends Error {
  constructor(message, errorCode = "invalid_credential_selection") {
    super(message);
    this.name = "CredentialSelectionError";
    this.errorCode = errorCode;
  }
}

export class AuthorizationDetailsSupportError extends Error {
  constructor(message, errorCode = "invalid_authorization_server") {
    super(message);
    this.name = "AuthorizationDetailsSupportError";
    this.errorCode = errorCode;
  }
}

/** Read credential_configuration_ids from a Credential Offer (VCI v1.0 + legacy credentials). */
export function extractOfferedConfigurationIds(offerConfig) {
  if (!offerConfig || typeof offerConfig !== "object") {
    return [];
  }
  const ids = Array.isArray(offerConfig.credential_configuration_ids)
    ? offerConfig.credential_configuration_ids
    : [];
  if (ids.length > 0) {
    return ids;
  }
  const legacy = offerConfig.credentials;
  if (Array.isArray(legacy)) {
    return legacy;
  }
  if (legacy && typeof legacy === "object") {
    return Object.keys(legacy);
  }
  return [];
}

export function extractOfferGrantScope(offerConfig) {
  const grant = offerConfig?.grants?.authorization_code;
  if (!grant || typeof grant.scope !== "string") {
    return null;
  }
  const scope = grant.scope.trim();
  return scope || null;
}

export function extractMetadataScope(issuerMeta, configurationId) {
  const config = issuerMeta?.credential_configurations_supported?.[configurationId];
  if (!config || typeof config.scope !== "string") {
    return null;
  }
  const scope = config.scope.trim();
  return scope || null;
}

/**
 * OAuth scope for a selected credential configuration (OpenID4VCI 1.0).
 * Prefer issuer metadata `credential_configurations_supported[id].scope`, then offer grant scope.
 * Returns null when no scope can be resolved (caller may fall back to authorization_details).
 */
export function resolveScopeForCredentialConfigurationOrNull({
  configurationId,
  issuerMeta = null,
  offer = null,
  offerConfig = null,
  grantType = null,
}) {
  const effectiveOffer = offerConfig ?? offer;
  if (!configurationId || typeof configurationId !== "string") {
    throw new ScopeResolutionError("scope_resolution: configurationId is required");
  }

  const config = issuerMeta?.credential_configurations_supported?.[configurationId];
  const metadataScope =
    typeof config?.scope === "string" && config.scope.trim() ? config.scope.trim() : null;
  if (metadataScope) {
    return metadataScope;
  }

  const grantScope = readScopeFromOfferGrant(effectiveOffer, grantType);
  if (grantScope) {
    const fromGrant = pickScopeTokenForConfiguration(grantScope, configurationId, issuerMeta);
    if (fromGrant) return fromGrant;
  }

  return null;
}

export function resolveScopeForCredentialConfiguration(args) {
  const scope = resolveScopeForCredentialConfigurationOrNull(args);
  if (scope) return scope;

  const configurationId = args?.configurationId ?? "(unknown)";
  throw new ScopeResolutionError(
    `issuer-defined scope required for credential configuration '${configurationId}'; none found in Credential Offer or issuer metadata`,
  );
}

export function resolveCredentialScope({
  profile,
  configurationId,
  issuerMeta,
  offerConfig = null,
  scopesSupported = null,
}) {
  if (!configurationId) {
    throw new ScopeResolutionError("credential configuration id is required for scope resolution");
  }

  const offerScope = extractOfferGrantScope(offerConfig);
  const metadataScope = extractMetadataScope(issuerMeta, configurationId);

  if (offerScope && metadataScope && offerScope !== metadataScope) {
    throw new ScopeResolutionError(
      `Conflicting scope mapping for '${configurationId}': offer scope '${offerScope}' does not match issuer metadata scope '${metadataScope}'`,
    );
  }

  let scope = offerScope || metadataScope;
  let source = offerScope ? (metadataScope ? "offer+metadata" : "offer") : metadataScope ? "metadata" : null;

  if (!scope) {
    if (isWebuildCs01Profile(profile)) {
      throw new ScopeResolutionError(
        `WE BUILD CS-01 profile requires an issuer-defined scope for credential configuration '${configurationId}'; none found in Credential Offer or issuer metadata`,
      );
    }

    if (Array.isArray(scopesSupported) && scopesSupported.includes(configurationId)) {
      scope = configurationId;
      source = "compatibility:configurationId-in-scopes_supported";
    } else {
      scope = configurationId;
      source = "compatibility:configurationId-fallback";
    }
  }

  return {
    configurationId,
    scope,
    source,
    offerScope,
    metadataScope,
  };
}

export function assertAuthorizationDetailsSupportForCredentialRequest({
  configurationId,
  issuerMeta = null,
  offer = null,
  offerConfig = null,
  grantType = null,
  authorizationServerMeta = null,
}) {
  const effectiveOffer = offerConfig ?? offer;
  const scope = resolveScopeForCredentialConfigurationOrNull({
    configurationId,
    issuerMeta,
    offer: effectiveOffer,
    grantType,
  });
  if (scope) {
    return { required: false, scope, reason: "issuer_scope_available" };
  }

  const supported =
    authorizationServerMeta?.authorization_details_types_supported;
  if (!Array.isArray(supported) || !supported.includes("openid_credential")) {
    const advertised = Array.isArray(supported) ? supported : null;
    throw new AuthorizationDetailsSupportError(
      `issuer_metadata_incomplete: credential configuration '${configurationId}' has no scope ` +
        `(issuer metadata / offer grant) and the Authorization Server does not advertise ` +
        `authorization_details_types_supported including 'openid_credential' ` +
        `(got ${advertised === null ? "missing/non-array" : JSON.stringify(advertised)}). ` +
        `Fix: add a scope on the credential configuration (and preferably list it in AS scopes_supported), ` +
        `or advertise authorization_details_types_supported: ["openid_credential"].`,
    );
  }
  return {
    required: true,
    scope: null,
    reason: "issuer_scope_missing",
    authorizationDetailsType: "openid_credential",
  };
}

export function readScopeFromOfferGrant(offer, grantType) {
  const grants = offer?.grants;
  if (!grants || typeof grants !== "object") return null;
  const grant =
    (grantType && grants[grantType]) ||
    grants.authorization_code ||
    grants[PRE_AUTHORIZED_GRANT];
  const scope = grant?.scope;
  return typeof scope === "string" && scope.trim() ? scope.trim() : null;
}

function pickScopeTokenForConfiguration(grantScope, configurationId, issuerMeta) {
  const tokens = grantScope.split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return null;
  if (tokens.length === 1) return tokens[0];

  const configs = issuerMeta?.credential_configurations_supported;
  const configScope = configs?.[configurationId]?.scope;
  if (typeof configScope === "string" && configScope.trim() && tokens.includes(configScope.trim())) {
    return configScope.trim();
  }
  if (tokens.includes(configurationId)) return configurationId;

  const knownCredentialScopes = new Set();
  if (configs && typeof configs === "object") {
    for (const cfg of Object.values(configs)) {
      if (typeof cfg?.scope === "string" && cfg.scope.trim()) {
        knownCredentialScopes.add(cfg.scope.trim());
      }
    }
  }
  const credentialTokens = tokens.filter(
    (t) => t !== "openid" && (knownCredentialScopes.has(t) || t === configurationId),
  );
  if (credentialTokens.length === 1) return credentialTokens[0];
  if (credentialTokens.length > 0) return credentialTokens[0];

  return tokens.find((t) => t !== "openid") || tokens[0];
}

function buildOpenIdCredentialAuthorizationDetails(configurationId, issuerMeta) {
  return [
    {
      type: "openid_credential",
      credential_configuration_id: configurationId,
      ...(issuerMeta?.credential_issuer ? { locations: [issuerMeta.credential_issuer] } : {}),
    },
  ];
}

export function resolvePreAuthorizedCredentialSelection({
  configurationId,
  issuerMeta,
  offerConfig = null,
}) {
  if (!configurationId) {
    throw new CredentialSelectionError(
      "credential configuration id is required for pre-authorized credential selection",
    );
  }

  const offeredConfigurationIds = extractOfferedConfigurationIds(offerConfig);
  if (offeredConfigurationIds.length > 0 && !offeredConfigurationIds.includes(configurationId)) {
    throw new CredentialSelectionError(
      `Selected credential configuration '${configurationId}' is not listed in offer credential_configuration_ids: ${offeredConfigurationIds.join(", ")}`,
    );
  }

  const metadataConfig = issuerMeta?.credential_configurations_supported?.[configurationId];
  if (!metadataConfig) {
    throw new CredentialSelectionError(
      `Selected credential configuration '${configurationId}' is not present in issuer metadata credential_configurations_supported`,
    );
  }

  const multiConfigurationOffer = offeredConfigurationIds.length > 1;
  const includeAuthorizationDetails = multiConfigurationOffer;
  const authorizationDetails = includeAuthorizationDetails
    ? buildOpenIdCredentialAuthorizationDetails(configurationId, issuerMeta)
    : null;

  let source = "metadata";
  if (offeredConfigurationIds.length > 1) {
    source = "offer:multi-configuration";
  } else if (offeredConfigurationIds.length === 1) {
    source = "offer:single-configuration";
  }

  return {
    configurationId,
    offeredConfigurationIds,
    includeAuthorizationDetails,
    authorizationDetails,
    source,
    metadataFormat: metadataConfig.format ?? null,
  };
}

export function resolveCredentialRequestTargets({ configurationId, tokenResponse }) {
  const details = tokenResponse?.authorization_details;
  if (details == null) {
    return [{ credential_configuration_id: configurationId }];
  }
  if (!Array.isArray(details)) {
    throw new CredentialSelectionError("Token Response authorization_details must be an array");
  }

  const matching = details.filter(
    (entry) =>
      entry?.type === "openid_credential" &&
      (!entry.credential_configuration_id || entry.credential_configuration_id === configurationId),
  );
  const identifiers = matching.flatMap((entry) => {
    if (entry.credential_identifiers == null) return [];
    if (
      !Array.isArray(entry.credential_identifiers) ||
      entry.credential_identifiers.length === 0 ||
      entry.credential_identifiers.some((id) => typeof id !== "string" || id.trim() === "")
    ) {
      throw new CredentialSelectionError(
        "Token Response credential_identifiers must be a non-empty string array",
      );
    }
    return entry.credential_identifiers;
  });

  if (identifiers.length > 0) {
    return identifiers.map((credential_identifier) => ({
      credential_configuration_id: configurationId,
      credential_identifier,
    }));
  }
  return [{ credential_configuration_id: configurationId }];
}
