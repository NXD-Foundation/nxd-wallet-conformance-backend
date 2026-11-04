/**
 * Local canonical URI for generated OpenID4VP presentation links.
 * The receiver also accepts empty and arbitrary hostnames; `present` is a
 * local convention, not a hostname prescribed by RFC002 or OpenID4VP 1.0.
 */
export const OPENID4VP_PRESENT_HOST = "present";

/** Presentation invocation URI without query. */
export const OPENID4VP_PRESENT_URI = `openid4vp://${OPENID4VP_PRESENT_HOST}`;

/** Prefix for by-value VP deep links (`openid4vp://present?client_id=…`). */
export const OPENID4VP_PRESENT_QUERY_PREFIX = `${OPENID4VP_PRESENT_URI}?`;

/** Legacy presentation alias; OAuth callbacks are configured independently. */
export const OPENID4VP_CS02_URI = OPENID4VP_PRESENT_URI;

export function isOpenId4VpDeepLink(value) {
  return typeof value === "string" && /^openid4vp:\/\//.test(value);
}

/**
 * Returns true when the URL uses the `present` authority.
 * This identifies the local output convention, not the set of accepted links.
 */
export function isOpenId4VpPresentInvocation(url) {
  return url?.protocol === "openid4vp:" && url.hostname === OPENID4VP_PRESENT_HOST;
}

/** Parse invocation parameters independently of the custom URI hostname/path. */
export function parseOpenId4VpDeepLink(deepLink) {
  const url = new URL(deepLink);
  const supported = new Set(["openid4vp:", "mdoc-openid4vp:", "eu-eaap:"]);
  if (!supported.has(url.protocol)) {
    throw new Error(`Unsupported request scheme: ${url.protocol}`);
  }
  const requestUri = url.searchParams.get("request_uri");
  const clientId = url.searchParams.get("client_id");
  const method = url.searchParams.get("request_uri_method") || "get";
  return { requestUri, clientId, method };
}
