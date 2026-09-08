/**
 * CS-02 §6.1.2 / §8.1 wallet invocation is empty-authority `openid4vp://?…`.
 * `openid4vp://present?…` is a non-CS-02 compatibility form.
 */
export const OPENID4VP_PRESENT_HOST = "present";

/** Compatibility invocation URI with host `present` (not CS-02). */
export const OPENID4VP_PRESENT_URI = `openid4vp://${OPENID4VP_PRESENT_HOST}`;

/** Prefix for compatibility by-value VP deep links (`openid4vp://present?…`). */
export const OPENID4VP_PRESENT_QUERY_PREFIX = `${OPENID4VP_PRESENT_URI}?`;

/** CS-02 canonical invocation URI (empty RFC 3986 authority). */
export const OPENID4VP_CS02_URI = "openid4vp://";

/** Prefix for CS-02 by-value VP deep links (`openid4vp://?client_id=…`). */
export const OPENID4VP_CS02_QUERY_PREFIX = `${OPENID4VP_CS02_URI}?`;

export function isOpenId4VpDeepLink(value) {
  return typeof value === "string" && /^openid4vp:\/\//.test(value);
}

/**
 * Returns true when the URL uses the non-CS-02 `present` authority.
 */
export function isOpenId4VpPresentInvocation(url) {
  return url?.protocol === "openid4vp:" && url.hostname === OPENID4VP_PRESENT_HOST;
}

/**
 * Returns true when the URL uses CS-02 empty-authority `openid4vp://?…`.
 */
export function isOpenId4VpEmptyAuthorityInvocation(url) {
  return url?.protocol === "openid4vp:" && !url.hostname;
}
