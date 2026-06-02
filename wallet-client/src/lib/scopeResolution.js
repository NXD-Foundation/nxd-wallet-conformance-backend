import { isWebuildCs01Profile } from "./profile.js";

export class ScopeResolutionError extends Error {
  constructor(message, errorCode = "invalid_scope") {
    super(message);
    this.name = "ScopeResolutionError";
    this.errorCode = errorCode;
  }
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

function assertScopeSupported(scope, scopesSupported, configurationId) {
  if (!Array.isArray(scopesSupported) || scopesSupported.length === 0) {
    return;
  }
  if (!scopesSupported.includes(scope)) {
    throw new ScopeResolutionError(
      `Resolved scope '${scope}' for credential configuration '${configurationId}' is not listed in authorization server scopes_supported`,
    );
  }
}

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

  assertScopeSupported(scope, scopesSupported, configurationId);

  return {
    configurationId,
    scope,
    source,
    offerScope,
    metadataScope,
  };
}
