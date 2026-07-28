import { certificateFingerprint, validateCertificatePath } from "./crypto.js";
import { listTypeProfile } from "./profile.js";
import { TRUST_REASON_CODES } from "./errors.js";

function identityMatches(entity, presentedIdentity) {
  if (!presentedIdentity) return true;
  const values = [presentedIdentity.entityId, presentedIdentity.issuer, presentedIdentity.name].filter(Boolean);
  if (values.includes(entity.id) || values.includes(entity.name)) return true;
  if (presentedIdentity.certificateFingerprint) {
    const chainFingerprints = (presentedIdentity.certificateChain || []).map((certificatePem) => certificateFingerprint(certificatePem));
    return entity.services?.some((service) =>
      service.certificates?.includes(presentedIdentity.certificateFingerprint)
      || service.certificates?.some((fingerprint) => chainFingerprints.includes(fingerprint)),
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
      lotl: { url: snapshot.lotl.source.url, format: snapshot.lotl.format, sequence: snapshot.lotl.scheme.sequence, signerFingerprint: snapshot.lotl.signer.fingerprint, bootstrapMode: snapshot.lotl.signer.bootstrapMode || "pinned" },
      ...extra,
    },
  };
}

function listCandidates(snapshot, role) {
  const configured = snapshot.lists?.[role];
  return Array.isArray(configured) ? configured : configured ? [configured] : [];
}

function listEvidence(list) {
  return {
    url: list?.source?.url || null,
    format: list?.format || null,
    sequence: list?.scheme?.sequence || null,
    signerFingerprint: list?.signer?.fingerprint || null,
  };
}

export function evaluateTrust({ snapshot, role, operation = null, presentedIdentity = {}, credentialContext = {}, evaluationTime = new Date(), acceptedStatuses = snapshot.profile.acceptedStatuses }) {
  listTypeProfile(snapshot.profile, role);
  const lists = listCandidates(snapshot, role);
  const pointerFailures = snapshot.listFailures?.[role] || [];
  if (!lists.length) {
    return result(snapshot, false, pointerFailures.length ? TRUST_REASON_CODES.TRUST_EVALUATION_INDETERMINATE : TRUST_REASON_CODES.POINTER_NOT_FOUND, { role, operation, credentialContext, pointerFailures });
  }
  const fingerprint = presentedIdentity.certificatePem ? certificateFingerprint(presentedIdentity.certificatePem) : presentedIdentity.certificateFingerprint;
  const negatives = [];
  for (const list of lists) {
    const entity = list.entities.find((candidate) => identityMatches(candidate, presentedIdentity));
    if (!entity) {
      negatives.push(result(snapshot, false, TRUST_REASON_CODES.ENTITY_NOT_LISTED, { role, operation, credentialContext, list: listEvidence(list) }));
      continue;
    }
    const service = entity.services.find((candidate) => {
      if (credentialContext.serviceType && candidate.type !== credentialContext.serviceType) return false;
      const chainFingerprints = (presentedIdentity.certificateChain || []).map((certificatePem) => certificateFingerprint(certificatePem));
      if (fingerprint && !candidate.certificates.some((cert) => cert === fingerprint || cert === presentedIdentity.certificateFingerprint || chainFingerprints.includes(cert))) return false;
      return true;
    });
    if (!service) {
      negatives.push(result(snapshot, false, fingerprint ? TRUST_REASON_CODES.ANCHOR_MISMATCH : TRUST_REASON_CODES.IDENTITY_MISMATCH, { role, entity: entity.id, operation, credentialContext, list: listEvidence(list) }));
      continue;
    }
    if (service.status && !acceptedStatuses.includes(service.status)) {
      negatives.push(result(snapshot, false, TRUST_REASON_CODES.ENTITY_STATUS_INVALID, { role, entity: entity.id, service: service.type, status: service.status, operation, credentialContext, list: listEvidence(list) }));
      continue;
    }
    let certificatePath = null;
    try {
      if (presentedIdentity.certificateChain?.length && service.certificatePems?.length) {
        certificatePath = validateCertificatePath({ certificateChain: presentedIdentity.certificateChain, anchorCertificates: service.certificatePems, evaluationTime });
      }
    } catch (error) {
      negatives.push(result(snapshot, false, error.reasonCode || TRUST_REASON_CODES.CERTIFICATE_PATH_INVALID, { role, entity: entity.id, service: service.type, operation, credentialContext, list: listEvidence(list) }));
      continue;
    }
    const scope = credentialContext.scopeEvidence;
    if (scope?.trusted === false) {
      negatives.push(result(snapshot, false, TRUST_REASON_CODES.CREDENTIAL_SCOPE_INVALID, { role, entity: entity.id, service: service.type, operation, credentialContext, scope, list: listEvidence(list) }));
      continue;
    }
    return result(snapshot, true, "TRUSTED", { role, entity: entity.id, service: service.type, status: service.status || "implicitly-valid", operation, credentialContext, certificatePath, scope: scope || { status: "unverified" }, evaluationTime: new Date(evaluationTime).toISOString(), list: listEvidence(list), pointerFailures });
  }
  const selected = negatives.find((candidate) => candidate.reasonCode !== TRUST_REASON_CODES.ENTITY_NOT_LISTED) || negatives[0];
  return { ...selected, evidence: { ...selected.evidence, pointerFailures, evaluatedLists: lists.map(listEvidence) } };
}
