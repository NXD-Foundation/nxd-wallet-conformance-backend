const PROTOCOL = "openid4vci-v1";
const descriptorState = new WeakMap();

export class DcApiIssuerClientError extends Error {
  constructor(message, code, cause) { super(message, { cause }); this.name = "DcApiIssuerClientError"; this.code = code; }
}

function classify(error) {
  if (error?.name === "NotAllowedError") return "permission_or_user_activation";
  if (error?.name === "AbortError") return "cancelled";
  if (error?.name === "SecurityError") return "security_context";
  if (error?.name === "NotSupportedError") return "unsupported";
  if (error?.name === "TypeError") return "invalid_request";
  return "api_failure";
}

export function createDcApiIssuerClient({ issuerBaseUrl, fetchImpl = globalThis.fetch, navigatorImpl = globalThis.navigator, digitalCredential = globalThis.DigitalCredential, secureContext = globalThis.isSecureContext } = {}) {
  if (!issuerBaseUrl || !fetchImpl) throw new DcApiIssuerClientError("issuerBaseUrl and fetch are required", "configuration");
  const base = new URL(issuerBaseUrl);
  const endpoint = (path) => new URL(String(path).replace(/^\//, ""), `${base.origin}${base.pathname.endsWith("/") ? base.pathname : `${base.pathname}/`}`);
  function getSupport() {
    if (!secureContext) return { state: "unsupported", reason: "secure_context_required" };
    if (!navigatorImpl?.credentials || typeof navigatorImpl.credentials.create !== "function") return { state: "unsupported", reason: "credentials_create_unavailable" };
    if (!digitalCredential || typeof digitalCredential.userAgentAllowsProtocol !== "function") return { state: "unknown", reason: "protocol_probe_unavailable" };
    try { return digitalCredential.userAgentAllowsProtocol(PROTOCOL) ? { state: "supported", reason: null } : { state: "unsupported", reason: "protocol_not_allowed" }; }
    catch { return { state: "unknown", reason: "protocol_probe_failed" }; }
  }
  const isSupported = () => getSupport().state === "supported";

  async function prepare(options = {}) {
    const { signal, ...request } = options;
    const response = await fetchImpl(endpoint("/vci/dc-api/offer"), {
      method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request), signal,
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new DcApiIssuerClientError(body.error_description || "Issuer rejected offer", "issuer_rejected");
    const offer = body?.credentialOffer;
    let offerIssuer;
    try { offerIssuer = new URL(offer?.credential_issuer); } catch {}
    const isLocalHttp = offerIssuer?.protocol === "http:" && ["localhost", "127.0.0.1"].includes(offerIssuer.hostname);
    if (!body?.sessionId || !Number.isFinite(Number(body.expiresAt)) || !offer || !Array.isArray(offer.credential_configuration_ids) || !offer.credential_configuration_ids.length || !offer.grants || !offerIssuer || offerIssuer.origin !== base.origin || (offerIssuer.protocol !== "https:" && !isLocalHttp) || body?.digital?.requests?.length !== 1 || body.digital.requests[0].protocol !== PROTOCOL || JSON.stringify(body.digital.requests[0].data) !== JSON.stringify(offer) || typeof body.statusEndpoint !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.statusToken || "")) {
      throw new DcApiIssuerClientError("Invalid issuer DC API descriptor", "issuer_rejected");
    }
    const statusUrl = endpoint(body.statusEndpoint);
    const expectedStatusUrl = endpoint(`/vci/dc-api/session/${encodeURIComponent(body.sessionId)}`);
    if (statusUrl.origin !== base.origin || statusUrl.pathname !== expectedStatusUrl.pathname || statusUrl.search || statusUrl.hash) throw new DcApiIssuerClientError("Status endpoint must be the session status route under the configured issuer base path", "issuer_rejected");
    const requests = structuredClone(body.digital.requests);
    const freezeDeep = (value) => {
      if (value && typeof value === "object" && !Object.isFrozen(value)) {
        Object.values(value).forEach(freezeDeep);
        Object.freeze(value);
      }
      return value;
    };
    const descriptor = freezeDeep({ sessionId: body.sessionId, expiresAt: Number(body.expiresAt), credentialOffer: structuredClone(offer), digital: { requests }, fallback: structuredClone(body.fallback), statusEndpoint: statusUrl.href, transactionCode: body.transactionCode });
    descriptorState.set(descriptor, { statusToken: body.statusToken, statusEndpoint: statusUrl.href, requests, inFlight: false, used: false });
    return descriptor;
  }

  async function create(descriptor, { signal } = {}) {
    const state = descriptorState.get(descriptor);
    if (!state || state.used || state.inFlight) throw new DcApiIssuerClientError("Descriptor is missing, busy, or already used", "invalid_state");
    if (descriptor.expiresAt * 1000 <= Date.now()) throw new DcApiIssuerClientError("Descriptor has expired", "expired");
    const support = getSupport();
    if (support.state === "unsupported") throw new DcApiIssuerClientError(`Digital Credentials API unavailable: ${support.reason}`, "unsupported");
    state.inFlight = true;
    // Call create immediately; doing async work before this point can lose user activation.
    try {
      const operation = navigatorImpl.credentials.create({ digital: { requests: state.requests }, signal });
      const result = await operation;
      if (!result || result.protocol !== PROTOCOL || !result.data || typeof result.data !== "object" || Array.isArray(result.data)) throw new DcApiIssuerClientError("DigitalCredential response has an invalid protocol or data member", "api_failure");
      state.used = true;
      return result;
    } catch (error) {
      if (error instanceof DcApiIssuerClientError) throw error;
      throw new DcApiIssuerClientError(error?.message || "Digital Credentials API failed", classify(error), error);
    } finally { state.inFlight = false; }
  }

  async function getStatus(descriptor, { signal } = {}) {
    const state = descriptorState.get(descriptor);
    if (!state) throw new DcApiIssuerClientError("Descriptor was not prepared by this client", "invalid_state");
    const response = await fetchImpl(state.statusEndpoint, { method: "GET", cache: "no-store", headers: { Authorization: `Bearer ${state.statusToken}` }, signal });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new DcApiIssuerClientError(body.error_description || body.error || "Unable to read issuer status", "status_unavailable");
    return body;
  }

  return { getSupport, isSupported, prepare, create, getStatus };
}

export { PROTOCOL as CS07_DC_API_ISSUANCE_PROTOCOL };
