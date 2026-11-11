/**
 * CS-02 §6.1.2 / §8.1 invocation schemes are `openid4vp:`, `eu-eaap:`,
 * and optionally `haip-vp:`. Generated links use an empty authority
 * (`openid4vp://?…`). The receiver ignores the host: it is not a verifier
 * identity, and the specs do not require rejecting other authorities.
 */
export const CS02_INVOCATION_PROTOCOLS = ["openid4vp:", "eu-eaap:", "haip-vp:"];

/** CS-02 canonical invocation URI (empty RFC 3986 authority). */
export const OPENID4VP_CS02_URI = "openid4vp://";

/** Prefix for CS-02 by-value VP deep links (`openid4vp://?client_id=…`). */
export const OPENID4VP_CS02_QUERY_PREFIX = `${OPENID4VP_CS02_URI}?`;

export function isCs02InvocationDeepLink(value) {
  if (typeof value !== "string") return false;
  try {
    return CS02_INVOCATION_PROTOCOLS.includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

export function isOpenId4VpDeepLink(value) {
  return isCs02InvocationDeepLink(value);
}

/**
 * Read invocation query parameters from a supported custom scheme.
 * The host and path do not select behavior.
 */
export function parseInvocationDeepLink(deepLink) {
  const url = new URL(deepLink);
  if (!CS02_INVOCATION_PROTOCOLS.includes(url.protocol)) {
    const error = new Error(`Unsupported request scheme: ${url.protocol}`);
    error.code = "unsupported_scheme";
    error.protocol = url.protocol;
    throw error;
  }
  return {
    url,
    requestUri: url.searchParams.get("request_uri"),
    clientId: url.searchParams.get("client_id"),
    method: url.searchParams.get("request_uri_method") || "get",
  };
}
