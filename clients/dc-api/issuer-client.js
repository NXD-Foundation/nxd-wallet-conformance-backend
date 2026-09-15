const PROTOCOL = "openid4vci-v1";

export class DcApiIssuerClientError extends Error {
  constructor(message, code, cause) { super(message, { cause }); this.name = "DcApiIssuerClientError"; this.code = code; }
}

function classify(error) {
  if (error?.name === "NotAllowedError") return "permission_or_user_activation";
  if (error?.name === "AbortError") return "cancelled";
  if (error?.name === "SecurityError") return "security_context";
  return "api_failure";
}

export function createDcApiIssuerClient({ issuerBaseUrl, fetchImpl = globalThis.fetch, navigatorImpl = globalThis.navigator, digitalCredential = globalThis.DigitalCredential, secureContext = globalThis.isSecureContext } = {}) {
  if (!issuerBaseUrl || !fetchImpl) throw new DcApiIssuerClientError("issuerBaseUrl and fetch are required", "configuration");
  const base = new URL(issuerBaseUrl);
  const url = (path) => new URL(String(path).replace(/^\//, ""), `${base.origin}${base.pathname.endsWith("/") ? base.pathname : `${base.pathname}/`}`).toString();
  const isSupported = () => {
    if (!secureContext || !navigatorImpl?.credentials?.create || !digitalCredential?.userAgentAllowsProtocol) return false;
    try { return digitalCredential.userAgentAllowsProtocol(PROTOCOL) === true; } catch { return false; }
  };
  async function prepare({ scenario = "pid-pre-authorized", signal } = {}) {
    const response = await fetchImpl(url("/vci/dc-api/offer"), { method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenario }), signal });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new DcApiIssuerClientError(body.error_description || "Issuer rejected offer", "issuer_rejected");
    if (body?.digital?.requests?.[0]?.protocol !== PROTOCOL || !body.digital.requests[0].data || !body.sessionId) throw new DcApiIssuerClientError("Invalid issuer DC API descriptor", "issuer_rejected");
    return { ...body, used: false };
  }
  async function create(descriptor, { signal } = {}) {
    if (!descriptor || descriptor.used || descriptor.inFlight) throw new DcApiIssuerClientError("Descriptor is missing, busy, or already used", "invalid_state");
    if (!isSupported()) throw new DcApiIssuerClientError("Digital Credentials API is unavailable", "unsupported");
    if (Number(descriptor.expiresAt) * 1000 <= Date.now()) throw new DcApiIssuerClientError("Descriptor has expired", "expired");
    descriptor.inFlight = true;
    try {
      const result = await navigatorImpl.credentials.create({ digital: { requests: descriptor.digital.requests }, signal });
      if (!result || result.protocol !== PROTOCOL || !result.data || typeof result.data !== "object" || Array.isArray(result.data)) {
        throw new DcApiIssuerClientError("DigitalCredential response has an invalid protocol or data member", "api_failure");
      }
      descriptor.used = true;
      return result;
    } catch (error) {
      if (error instanceof DcApiIssuerClientError) throw error;
      throw new DcApiIssuerClientError(error?.message || "Digital Credentials API failed", classify(error), error);
    } finally { descriptor.inFlight = false; }
  }
  return { isSupported, prepare, create };
}

export { PROTOCOL as CS07_DC_API_ISSUANCE_PROTOCOL };
