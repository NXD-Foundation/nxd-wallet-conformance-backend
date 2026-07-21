const PROTOCOL = "openid4vp-v1-signed";

export class DcApiClientError extends Error {
  constructor(message, code, cause = undefined) {
    super(message, { cause });
    this.name = "DcApiClientError";
    this.code = code;
  }
}

/** Join a path under verifierBaseUrl, preserving any reverse-proxy prefix. */
function endpoint(base, path) {
  const root = typeof base === "string" ? base : base.href;
  const normalizedBase = root.endsWith("/") ? root : `${root}/`;
  return new URL(String(path).replace(/^\//, ""), normalizedBase).toString();
}

function classifyBrowserError(error) {
  const name = error?.name || "";
  if (name === "NotAllowedError") return "permission_or_user_activation";
  if (name === "AbortError") return "cancelled";
  if (name === "SecurityError") return "security_context";
  return "api_failure";
}

export function createDcApiVerifierClient({
  verifierBaseUrl,
  fetchImpl = globalThis.fetch,
  navigatorImpl = globalThis.navigator,
  digitalCredential = globalThis.DigitalCredential,
  secureContext = globalThis.isSecureContext,
} = {}) {
  if (typeof verifierBaseUrl !== "string" || verifierBaseUrl.length === 0) {
    throw new DcApiClientError("verifierBaseUrl is required", "configuration");
  }
  const base = new URL(verifierBaseUrl);
  if (!fetchImpl) throw new DcApiClientError("fetch is unavailable", "configuration");
  let prepared;

  function isSupported() {
    if (!secureContext) return false;
    if (!navigatorImpl?.credentials?.get || !digitalCredential?.userAgentAllowsProtocol) return false;
    try { return digitalCredential.userAgentAllowsProtocol(PROTOCOL) === true; } catch { return false; }
  }

  async function jsonRequest(url, options) {
    let response;
    try {
      response = await fetchImpl(url, { cache: "no-store", ...options });
    } catch (error) {
      throw new DcApiClientError("Unable to reach verifier", "network", error);
    }
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new DcApiClientError(
        body.error_description || body.error || `Verifier request failed (${response.status})`,
        "verifier_rejected",
      );
    }
    return body;
  }

  async function prepare({ profile, sessionId, signal } = {}) {
    if (!isSupported()) throw new DcApiClientError("Digital Credentials API is unavailable", "unsupported");
    const descriptor = await jsonRequest(endpoint(base, "/vp/dc-api/request"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...(profile ? { profile } : {}),
        ...(sessionId ? { sessionId } : {}),
      }),
      signal,
    });
    if (descriptor?.request?.protocol !== PROTOCOL || typeof descriptor?.request?.data?.request !== "string") {
      throw new DcApiClientError("Verifier returned an invalid DC API request descriptor", "verifier_rejected");
    }
    prepared = { ...descriptor, used: false };
    return { ...prepared };
  }

  async function present(descriptor = prepared, { signal } = {}) {
    if (!descriptor || descriptor.used || !descriptor.sessionId) {
      throw new DcApiClientError("DC API request descriptor is missing or already used", "invalid_state");
    }
    if (!isSupported()) throw new DcApiClientError("Digital Credentials API is unavailable", "unsupported");
    if (descriptor.expiresAt != null && Number.isFinite(Number(descriptor.expiresAt)) &&
        Number(descriptor.expiresAt) * 1000 <= Date.now()) {
      throw new DcApiClientError("DC API request descriptor has expired", "expired");
    }
    descriptor.used = true;
    if (prepared?.sessionId === descriptor.sessionId) prepared.used = true;
    let credential;
    try {
      // This call must remain before any await to preserve transient activation.
      credential = await navigatorImpl.credentials.get({
        digital: { requests: [descriptor.request] },
        signal,
      });
    } catch (error) {
      throw new DcApiClientError(error?.message || "Digital Credentials API failed", classifyBrowserError(error), error);
    }
    if (!credential || credential.protocol !== PROTOCOL || !credential.data || typeof credential.data !== "object") {
      throw new DcApiClientError("DigitalCredential response has an invalid protocol or data member", "api_failure");
    }
    const responseEndpoint = descriptor.responseEndpoint || endpoint(base, `/vp/dc-api/response/${encodeURIComponent(descriptor.sessionId)}`);
    const result = await jsonRequest(responseEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ protocol: credential.protocol, data: credential.data }),
      signal,
    });
    if (typeof credential.data.error === "string") {
      throw new DcApiClientError(`Wallet returned ${credential.data.error}`, "wallet_protocol_error");
    }
    return result;
  }

  return { isSupported, prepare, present };
}

export { PROTOCOL as CS07_DC_API_PROTOCOL };
