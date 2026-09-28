/**
 * Issuer-owned credential status references.
 * Callers cannot supply status or status_reference; only an explicit issuer
 * allocation is embedded, and it stays outside selective disclosure.
 */

export function discardCallerCredentialStatus(requestBody) {
  if (!requestBody || typeof requestBody !== "object") return requestBody;
  delete requestBody.status;
  delete requestBody.status_reference;
  delete requestBody.issuerStatusReference;
  return requestBody;
}

export function applyIssuerOwnedCredentialStatus(requestBody, { enabled = false, allocate } = {}) {
  discardCallerCredentialStatus(requestBody);
  if (enabled !== true) return null;
  if (typeof allocate !== "function") {
    throw new Error("issuer status allocation is required when revocation is enabled");
  }
  const status = allocate();
  requestBody.issuerStatusReference = status;
  return status;
}

export function disclosureFrameWithoutStatus(frame) {
  if (!frame || typeof frame !== "object" || Array.isArray(frame)) return frame;
  const copy = { ...frame };
  delete copy.status;
  if (copy.credentialSubject && typeof copy.credentialSubject === "object" && !Array.isArray(copy.credentialSubject)) {
    copy.credentialSubject = { ...copy.credentialSubject };
    delete copy.credentialSubject.status;
  }
  return copy;
}

export function embedIssuerOwnedStatus(sdPayload, requestBody) {
  if (!sdPayload || typeof sdPayload !== "object") return sdPayload;
  if (sdPayload.credentialSubject && typeof sdPayload.credentialSubject === "object") {
    sdPayload.credentialSubject = { ...sdPayload.credentialSubject };
    delete sdPayload.credentialSubject.status;
  }
  delete sdPayload.status;
  if (requestBody?.issuerStatusReference && typeof requestBody.issuerStatusReference === "object") {
    sdPayload.status = requestBody.issuerStatusReference;
  }
  return sdPayload;
}

export function storedDeferredCredential(sessionObject) {
  const credential = sessionObject?.issuedCredential;
  return typeof credential === "string" && credential.length > 0 ? credential : null;
}

/**
 * Sign a deferred credential on the first ready poll and return that same
 * token on every later poll.
 */
export async function issueDeferredCredentialOnce(sessionObject, issue) {
  const stored = storedDeferredCredential(sessionObject);
  if (stored) return { credential: stored, reused: true };
  const credential = await issue();
  if (typeof credential !== "string" || credential.length === 0) {
    throw new Error("deferred credential issuance did not return a credential");
  }
  sessionObject.issuedCredential = credential;
  return { credential, reused: false };
}
