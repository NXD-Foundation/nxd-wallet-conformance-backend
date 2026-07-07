/**
 * CS-02 §8.1 wallet invocation uses `openid4vp://present?…` (RFC 3986 authority).
 * Bare `openid4vp://` is valid under RFC 3986 but rejected by some URI libraries;
 * `present` is the normative CS-02 endpoint host.
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
 * Returns true when the URL uses the CS-02 `present` authority.
 * Legacy bare `openid4vp://?…` links (empty authority) remain accepted by the wallet parser.
 */
export function isOpenId4VpPresentInvocation(url) {
  return url?.protocol === "openid4vp:" && url.hostname === OPENID4VP_PRESENT_HOST;
}
