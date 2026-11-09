export const PID = "urn:eu.europa.ec.eudi:pid:1";
export const MDOC = "urn:eu.europa.ec.eudi:pid:1:mso_mdoc";

const CLIENT_ID = /^x509_hash:[A-Za-z0-9_-]{43}$/;
const COUNTERPART_STOP = /registrar_dataset|WRPRC|verifier_info/i;
const UNSUPPORTED_SCHEME = /unsupported (request scheme|deeplink scheme|invocation)/i;

/**
 * CTS v1.1 trust-framework cases in pre-ship order.
 * SD-JWT presentations run while the VCI-001 PID is stored.
 * VP-007 runs while the VCI-005 mdoc is stored.
 * Later issuance of the same credential type comes after those presentations.
 */
export const CASES = [
  { id: "VCI-001", kind: "issue", path: "/offer-code-sd-jwt", credentialType: PID },
  { id: "VP-001", kind: "present", path: "/x509/generateVPRequestDCQL", credentialType: PID, scheme: "openid4vp", method: "post", requestPath: "/x509/x509VPrequest" },
  { id: "VP-002", kind: "present", path: "/x509/generateVPRequestDCQL", credentialType: PID, scheme: "openid4vp", method: "post", requestPath: "/x509/x509VPrequest", responseMode: "direct_post.jwt" },
  { id: "VP-003", kind: "present", path: "/x509/generateVPRequestDCQLGET", credentialType: PID, scheme: "openid4vp", method: "get", requestPath: "/x509/x509VPrequest", responseMode: "direct_post.jwt" },
  { id: "VP-011", kind: "present", path: "/x509/generateVPRequestDCQL", credentialType: PID, scheme: "openid4vp", method: "post", requestPath: "/x509/x509VPrequest", responseMode: "direct_post.jwt", invocationScheme: "openid4vp" },
  { id: "VP-012", kind: "present", path: "/x509/generateVPRequestDCQL", credentialType: PID, scheme: "eu-eaap", method: "post", requestPath: "/x509/x509VPrequest", responseMode: "direct_post.jwt", invocationScheme: "eu-eaap" },
  { id: "VP-013", kind: "present", path: "/x509/generateVPRequestDCQL", credentialType: PID, scheme: "haip-vp", method: "post", requestPath: "/x509/x509VPrequest", responseMode: "direct_post.jwt", invocationScheme: "haip-vp", optional: true },
  { id: "VCI-005", kind: "issue", path: "/offer-code-sd-jwt", credentialType: MDOC },
  { id: "VP-007", kind: "present", path: "/mdl/generateVPRequest", credentialType: MDOC, scheme: "openid4vp", method: "get", requestPath: "/mdl/VPrequest", responseMode: "direct_post.jwt" },
  { id: "VCI-006", kind: "issue", path: "/offer-no-code", credentialType: PID },
  { id: "VCI-007", kind: "issue", path: "/offer-tx-code", credentialType: PID, pin: true },
  { id: "VCI-008", kind: "issue", path: "/offer-no-code", credentialType: MDOC },
];

export function caseRequest(testCase, sessionId) {
  const params = new URLSearchParams();
  params.set("credentialType", testCase.credentialType);
  params.set("sessionId", sessionId);
  params.set("trustFramework", "true");
  if (testCase.kind === "issue") params.set("signatureType", "x509");
  if (testCase.responseMode) params.set("response_mode", testCase.responseMode);
  if (testCase.invocationScheme) params.set("invocation_scheme", testCase.invocationScheme);
  return params;
}

export function checkInvocationLink({ deepLink, sessionId, issuer, scheme, method, requestPath }) {
  let url;
  try {
    url = new URL(deepLink);
  } catch {
    return { ok: false, reason: "deepLink is not a URL" };
  }
  if (url.protocol !== `${scheme}:` || url.hostname !== "" || url.pathname !== "") {
    return { ok: false, reason: `expected ${scheme}://? and received ${deepLink}` };
  }
  const names = [...url.searchParams.keys()];
  const requestUri = url.searchParams.get("request_uri");
  const clientId = url.searchParams.get("client_id");
  const retrieval = url.searchParams.get("request_uri_method");
  const expectedUri = `${issuer.replace(/\/$/, "")}${requestPath}/${sessionId}`;
  if (requestUri !== expectedUri) {
    return { ok: false, reason: `request_uri ${requestUri || ""}` };
  }
  if (!CLIENT_ID.test(clientId || "")) {
    return { ok: false, reason: `client_id ${clientId || ""}` };
  }
  if (method === "post") {
    if (names.length !== 3 || retrieval !== "post") {
      return { ok: false, reason: "expected request_uri, client_id, and request_uri_method=post" };
    }
  } else if (retrieval != null && retrieval !== "get") {
    return { ok: false, reason: `request_uri_method ${retrieval}` };
  } else if (names.some((name) => !["request_uri", "client_id", "request_uri_method"].includes(name))) {
    return { ok: false, reason: `unexpected query ${names.join("&")}` };
  }
  return { ok: true };
}

export function walletSessionBody({ deepLink, sessionId, issuer, pin }) {
  const body = {
    deepLink,
    sessionId,
    trustFramework: true,
    issuer,
    verifier: issuer,
  };
  if (pin) body.pin = pin;
  return body;
}

export function judgeIssueStatus(body) {
  if (body?.status === "success") return { result: "pass" };
  return { result: "fail", detail: body?.reason || body?.status || "missing issue status" };
}

export function judgeVerificationStatus(body) {
  if (body?.status === "success" && body.claims != null) return { result: "pass" };
  if (body?.status === "success") return { result: "fail", detail: "verification succeeded without claims" };
  return { result: "fail", detail: body?.reason || body?.status || "missing verification status" };
}

export function classifyWalletFailure(testCase, text) {
  const detail = String(text || "wallet request failed");
  if (testCase.optional && UNSUPPORTED_SCHEME.test(detail)) {
    return { result: "skipped", detail };
  }
  if (COUNTERPART_STOP.test(detail)) {
    return { result: "counterpart-stop", detail };
  }
  return { result: "fail", detail };
}
