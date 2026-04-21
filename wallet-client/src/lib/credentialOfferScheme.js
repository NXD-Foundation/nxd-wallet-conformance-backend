/**
 * Map alternate credential-offer schemes to `openid-credential-offer://`
 * so URL parsing and query handling stay uniform (RFC001 / OIDC4VCI).
 */
export function normalizeCredentialOfferDeepLink(deepLink) {
  if (typeof deepLink !== "string") return deepLink;
  return deepLink
    .replace(/^haip(-vci)?:\/\//, "openid-credential-offer://")
    .replace(/^eu-eaa-offer:\/\//, "openid-credential-offer://");
}
