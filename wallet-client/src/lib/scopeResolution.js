import { isWebuildCs01Profile } from "./profile.js";

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

// CS-01 requires scope from Credential Offer or issuer metadata (§7.2, §7.3, §7.7).
// OpenID4VCI v1.0 §5.1.2 MAY combine issuer and AS scopes but does not require
// rejecting a resolved scope absent from AS scopes_supported. Removed to avoid
// stricter-than-CS-01 enforcement.
// function assertScopeSupported(scope, scopesSupported, configurationId) {
//   if (!Array.isArray(scopesSupported) || scopesSupported.length === 0) {
//     return;
//   }
//   if (!scopesSupported.includes(scope)) {
//     throw new ScopeResolutionError(
//       `Resolved scope '${scope}' for credential configuration '${configurationId}' is not listed in authorization server scopes_supported`,
//     );
//   }
// }

/**
 * Resolve the OAuth scope for a selected credential configuration.
 *
 * Priority:
 * 1. Credential Offer authorization_code grant scope (when present)
 * 2. Issuer metadata credential_configurations_supported[configurationId].scope
 * 3. Compatibility-only fallback to configurationId when advertised in scopes_supported,
 *    then configurationId as legacy stand-in
 */
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

  // assertScopeSupported(scope, scopesSupported, configurationId);

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
  issuerMeta,
  offerConfig = null,
  authorizationServerMeta = null,
}) {
  if (!configurationId) {
    throw new AuthorizationDetailsSupportError(
      "credential configuration id is required to determine authorization_details support",
    );
  }

  const offerScope = extractOfferGrantScope(offerConfig);
  const metadataScope = extractMetadataScope(issuerMeta, configurationId);
  if (offerScope || metadataScope) {
    return {
      required: false,
      reason: "issuer_scope_available",
      offerScope,
      metadataScope,
    };
  }

  const supportedTypes = authorizationServerMeta?.authorization_details_types_supported;
  if (!Array.isArray(supportedTypes) || !supportedTypes.includes("openid_credential")) {
    throw new AuthorizationDetailsSupportError(
      `authorization_details support required for credential configuration '${configurationId}': issuer metadata does not define a scope, so AS metadata must advertise authorization_details_types_supported including 'openid_credential'`,
    );
  }

  return {
    required: true,
    reason: "issuer_scope_missing",
    offerScope: null,
    metadataScope: null,
    authorizationDetailsType: "openid_credential",
  };
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

/**
 * Resolve pre-authorized credential identification per OpenID4VCI v1.0.
 *
 * Pre-auth grants do not carry scope. Identification uses top-level
 * credential_configuration_ids and optional token-request authorization_details.
 */
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

/**
 * Resolve the credential selector required by VCI 1.0 §8.2 from a Token Response.
 * Returned credential identifiers take precedence over configuration IDs.
 */
export function resolveCredentialRequestTargets({ configurationId, tokenResponse }) {
  const details = tokenResponse?.authorization_details;
  if (details == null) {
    return [{ credential_configuration_id: configurationId }];
  }
  if (!Array.isArray(details)) {
    throw new CredentialSelectionError("Token Response authorization_details must be an array");
  }

  const matching = details.filter((entry) =>
    entry?.type === "openid_credential" &&
    (!entry.credential_configuration_id || entry.credential_configuration_id === configurationId),
  );
  const identifiers = matching.flatMap((entry) => {
    if (entry.credential_identifiers == null) return [];
    if (!Array.isArray(entry.credential_identifiers) || entry.credential_identifiers.length === 0 ||
        entry.credential_identifiers.some((id) => typeof id !== "string" || id.trim() === "")) {
      throw new CredentialSelectionError("Token Response credential_identifiers must be a non-empty string array");
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
