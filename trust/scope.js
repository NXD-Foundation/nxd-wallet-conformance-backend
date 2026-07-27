import { TRUST_REASON_CODES, TrustListError } from "./errors.js";

/**
 * Normalizes evidence returned by a deployment-specific registrar adapter.
 * The trust framework has not published a common registrar response format;
 * the adapter is therefore responsible for signature/path validation before it
 * returns `verified: true`.
 */
export function evaluateRegistrarScope({ evidence = null, credentialContext = {}, operation = null } = {}) {
  if (!evidence) return { status: "unverified" };
  if (evidence.verified !== true) return { trusted: false, reason: "registrar-evidence-unverified" };
  const credentialType = credentialContext.vct || credentialContext.doctype || null;
  if (credentialType && Array.isArray(evidence.credentialTypes) && !evidence.credentialTypes.includes(credentialType)) {
    return { trusted: false, reason: "credential-type-not-registered", credentialType };
  }
  if (operation && Array.isArray(evidence.operations) && !evidence.operations.includes(operation)) {
    return { trusted: false, reason: "operation-not-registered", operation };
  }
  return { status: "verified", registrar: evidence.registrar || null };
}
