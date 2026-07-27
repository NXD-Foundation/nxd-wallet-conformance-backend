import { certificateFingerprint } from "./crypto.js";
import { listTypeProfile } from "./profile.js";
import { TRUST_REASON_CODES } from "./errors.js";

function identityMatches(entity, presentedIdentity) {
  if (!presentedIdentity) return true;
  const values = [presentedIdentity.entityId, presentedIdentity.issuer, presentedIdentity.name].filter(Boolean);
  if (values.includes(entity.id) || values.includes(entity.name)) return true;
  if (presentedIdentity.certificateFingerprint) {
    return entity.services?.some((service) =>
      service.certificates?.includes(presentedIdentity.certificateFingerprint),
    ) || false;
  }
  return false;
}

function result(snapshot, trusted, reasonCode, extra = {}) {
  return {
    trusted,
    state: trusted ? "trusted" : reasonCode === TRUST_REASON_CODES.TRUST_EVALUATION_INDETERMINATE ? "indeterminate" : "not_trusted",
    reasonCode,
    evidence: {
      profileId: snapshot.profileId,
      lotl: { url: snapshot.lotl.source.url, format: snapshot.lotl.format, sequence: snapshot.lotl.scheme.sequence, signerFingerprint: snapshot.lotl.signer.fingerprint },
      ...extra,
    },
  };
}

export function evaluateTrust({ snapshot, role, operation = null, presentedIdentity = {}, credentialContext = {}, evaluationTime = new Date(), acceptedStatuses = snapshot.profile.acceptedStatuses }) {
  listTypeProfile(snapshot.profile, role);
  const list = snapshot.lists[role];
  if (!list) return result(snapshot, false, TRUST_REASON_CODES.POINTER_NOT_FOUND, { role, operation, credentialContext });
  const fingerprint = presentedIdentity.certificatePem ? certificateFingerprint(presentedIdentity.certificatePem) : presentedIdentity.certificateFingerprint;
  const entity = list.entities.find((candidate) => identityMatches(candidate, presentedIdentity));
  if (!entity) return result(snapshot, false, TRUST_REASON_CODES.ENTITY_NOT_LISTED, { role, operation, credentialContext });
  const service = entity.services.find((candidate) => {
    if (credentialContext.serviceType && candidate.type !== credentialContext.serviceType) return false;
    if (fingerprint && !candidate.certificates.some((cert) => cert === fingerprint || cert === presentedIdentity.certificateFingerprint)) return false;
    return true;
  });
  if (!service) return result(snapshot, false, fingerprint ? TRUST_REASON_CODES.ANCHOR_MISMATCH : TRUST_REASON_CODES.IDENTITY_MISMATCH, { role, entity: entity.id, operation, credentialContext });
  if (service.status && !acceptedStatuses.includes(service.status)) {
    return result(snapshot, false, TRUST_REASON_CODES.ENTITY_STATUS_INVALID, { role, entity: entity.id, service: service.type, status: service.status, operation, credentialContext });
  }
  return result(snapshot, true, "TRUSTED", { role, entity: entity.id, service: service.type, status: service.status || "implicitly-valid", operation, credentialContext, evaluationTime: new Date(evaluationTime).toISOString() });
}
