const PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

export class ScopeResolutionError extends Error {
  constructor(message) {
    super(message);
    this.name = "ScopeResolutionError";
  }
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
  grantType = null,
}) {
  if (!configurationId || typeof configurationId !== "string") {
    throw new ScopeResolutionError("scope_resolution: configurationId is required");
  }

  const config = issuerMeta?.credential_configurations_supported?.[configurationId];
  const metadataScope =
    typeof config?.scope === "string" && config.scope.trim() ? config.scope.trim() : null;
  if (metadataScope) {
    return metadataScope;
  }

  const grantScope = readScopeFromOfferGrant(offer, grantType);
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

export function assertAuthorizationDetailsSupportForCredentialRequest({
  configurationId,
  issuerMeta = null,
  offer = null,
  grantType = null,
  authorizationServerMeta = null,
}) {
  const scope = resolveScopeForCredentialConfigurationOrNull({
    configurationId,
    issuerMeta,
    offer,
    grantType,
  });
  if (scope) return { required: false, scope };

  const supported = authorizationServerMeta?.authorization_details_types_supported;
  if (!Array.isArray(supported) || !supported.includes("openid_credential")) {
    const advertised = Array.isArray(supported) ? supported : null;
    throw new Error(
      `issuer_metadata_incomplete: credential configuration '${configurationId}' has no scope ` +
        `(issuer metadata / offer grant) and the Authorization Server does not advertise ` +
        `authorization_details_types_supported including 'openid_credential' ` +
        `(got ${advertised === null ? "missing/non-array" : JSON.stringify(advertised)}). ` +
        `Fix: add a scope on the credential configuration (and preferably list it in AS scopes_supported), ` +
        `or advertise authorization_details_types_supported: ["openid_credential"].`,
    );
  }
  return { required: true, scope: null };
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
