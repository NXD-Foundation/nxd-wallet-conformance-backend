import { evaluateTrust } from "./evaluate.js";
import { listTypeProfile } from "./profile.js";
import { TRUST_REASON_CODES, TrustListError } from "./errors.js";

const ROLES = new Set([
  "pid-provider", "wallet-provider", "wrpac-provider", "wrprc-provider",
  "pub-eaa-provider", "eaa-provider", "qeaa-provider", "ebwoid-provider",
]);

function isObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

export function validateResolutionRequest(request, profile) {
  if (!isObject(request)) throw new TrustListError("Trust resolution request must be an object", TRUST_REASON_CODES.INVALID_REQUEST);
  if (request.framework !== profile.id) throw new TrustListError("Unsupported trust framework profile", TRUST_REASON_CODES.UNSUPPORTED_FRAMEWORK, { requested: request.framework, expected: profile.id });
  if (!ROLES.has(request.role) || !profile.listTypes[request.role]) throw new TrustListError("Unsupported trust resolution role", TRUST_REASON_CODES.UNSUPPORTED_ROLE, { role: request.role });
  if (typeof request.operation !== "string" || !request.operation) throw new TrustListError("Trust resolution operation is required", TRUST_REASON_CODES.INVALID_REQUEST);
  if (!isObject(request.presentedIdentity)) throw new TrustListError("presentedIdentity must be an object", TRUST_REASON_CODES.INVALID_REQUEST);
  if (!Object.values(request.presentedIdentity).some(Boolean)) throw new TrustListError("presentedIdentity must contain an identifier or certificate", TRUST_REASON_CODES.INVALID_REQUEST);
  if (request.credentialContext != null && !isObject(request.credentialContext)) throw new TrustListError("credentialContext must be an object", TRUST_REASON_CODES.INVALID_REQUEST);
  if (request.policy != null && !isObject(request.policy)) throw new TrustListError("policy must be an object", TRUST_REASON_CODES.INVALID_REQUEST);
  return request;
}

function normalizePolicy(request, profile) {
  const policy = request.policy || {};
  const acceptedStatuses = policy.acceptedStatuses || profile.acceptedStatuses;
  if (!Array.isArray(acceptedStatuses) || acceptedStatuses.some((status) => typeof status !== "string")) {
    throw new TrustListError("policy.acceptedStatuses must be an array of strings", TRUST_REASON_CODES.INVALID_REQUEST);
  }
  return {
    acceptedStatuses,
    requireRevocation: policy.requireRevocation === true,
    allowStaleSnapshot: policy.allowStaleSnapshot === true,
  };
}

function outputError(snapshot, request, error) {
  const safeRequest = request || {};
  return {
    trusted: false,
    state: error.reasonCode === TRUST_REASON_CODES.TRUST_EVALUATION_INDETERMINATE || error.reasonCode === TRUST_REASON_CODES.REVOCATION_UNKNOWN ? "indeterminate" : "not_trusted",
    reasonCode: error.reasonCode || TRUST_REASON_CODES.TRUST_EVALUATION_INDETERMINATE,
    evidence: {
      profileId: snapshot?.profileId || safeRequest.framework,
      role: safeRequest.role,
      operation: safeRequest.operation,
      credentialContext: safeRequest.credentialContext || {},
      details: error.details || {},
    },
  };
}

function assertSnapshotFresh(snapshot, evaluationTime, allowStaleSnapshot) {
  if (allowStaleSnapshot) return;
  const now = new Date(evaluationTime).getTime();
  const documents = [snapshot.lotl, ...Object.values(snapshot.lists || {})];
  const stale = documents.find((document) => document?.scheme?.nextUpdate && now > Date.parse(document.scheme.nextUpdate));
  if (stale) throw new TrustListError("Authenticated trust snapshot is stale", TRUST_REASON_CODES.LIST_STALE, { nextUpdate: stale.scheme.nextUpdate });
}

export function createTrustResolver({ profile, snapshot = null, snapshotProvider = null, clock = () => new Date() } = {}) {
  if (!profile) throw new TypeError("Trust resolver requires a profile");
  if (!snapshot && typeof snapshotProvider !== "function") throw new TypeError("Trust resolver requires a snapshot or snapshotProvider");

  return {
    async resolve(request) {
      try {
        validateResolutionRequest(request, profile);
        const policy = normalizePolicy(request, profile);
        listTypeProfile(profile, request.role);
        const currentSnapshot = snapshotProvider
          ? await snapshotProvider({ profile, request })
          : snapshot;
        if (!currentSnapshot) throw new TrustListError("No authenticated trust snapshot is available", TRUST_REASON_CODES.TRUST_EVALUATION_INDETERMINATE);
        const evaluationTime = request.evaluationTime ? new Date(request.evaluationTime) : clock();
        if (!Number.isFinite(evaluationTime.getTime())) throw new TrustListError("evaluationTime must be a valid date", TRUST_REASON_CODES.INVALID_REQUEST);
        assertSnapshotFresh(currentSnapshot, evaluationTime, policy.allowStaleSnapshot);
        const list = currentSnapshot.lists?.[request.role];
        if (policy.requireRevocation && !list?.revocation) {
          return outputError(currentSnapshot, request, new TrustListError("Required revocation evidence is unavailable", TRUST_REASON_CODES.REVOCATION_UNKNOWN));
        }
        const result = evaluateTrust({
          snapshot: currentSnapshot,
          role: request.role,
          operation: request.operation,
          presentedIdentity: request.presentedIdentity,
          credentialContext: request.credentialContext || {},
          evaluationTime,
          acceptedStatuses: policy.acceptedStatuses,
        });
        return {
          ...result,
          reasonCode: result.trusted ? TRUST_REASON_CODES.TRUSTED : result.reasonCode,
          evidence: { ...result.evidence, policy, framework: request.framework },
        };
      } catch (error) {
        if (error instanceof TrustListError) return outputError(snapshot, request, error);
        return outputError(snapshot, request, new TrustListError(error.message, TRUST_REASON_CODES.TRUST_EVALUATION_INDETERMINATE));
      }
    },
  };
}
