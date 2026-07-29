/**
 * OpenID4VP wallet invocation uses `openid4vp://present?…` (RFC 3986 authority).
 * Bare `openid4vp://` remains accepted for legacy links; `present` is the
 * recommended authority for same-device invocation (RFC002 / OpenID4VP 1.0).
 */
export const OPENID4VP_PRESENT_HOST = "present";

/** OAuth redirect_uri and invocation URI without query (e.g. authorization code return). */
export const OPENID4VP_PRESENT_URI = `openid4vp://${OPENID4VP_PRESENT_HOST}`;

/** Prefix for by-value VP deep links (`openid4vp://present?client_id=…`). */
export const OPENID4VP_PRESENT_QUERY_PREFIX = `${OPENID4VP_PRESENT_URI}?`;

export function isOpenId4VpDeepLink(value) {
  return typeof value === "string" && /^openid4vp:\/\//.test(value);
}

/**
 * Returns true when the URL uses the `present` authority.
 * Legacy bare `openid4vp://?…` links (empty authority) remain accepted by the wallet parser.
 */
export function isOpenId4VpPresentInvocation(url) {
  return url?.protocol === "openid4vp:" && url.hostname === OPENID4VP_PRESENT_HOST;
}
