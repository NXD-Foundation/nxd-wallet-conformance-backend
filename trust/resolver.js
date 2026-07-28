import { evaluateTrust } from "./evaluate.js";
import { listTypeProfile } from "./profile.js";
import { TRUST_REASON_CODES, TrustListError } from "./errors.js";
import { checkCertificateRevocation } from "./revocation.js";
import { evaluateRegistrarScope } from "./scope.js";

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
  const stale = snapshot.lotl?.scheme?.nextUpdate && now > Date.parse(snapshot.lotl.scheme.nextUpdate)
    ? snapshot.lotl
    : null;
  if (stale) throw new TrustListError("Authenticated trust snapshot is stale", TRUST_REASON_CODES.LIST_STALE, { nextUpdate: stale.scheme.nextUpdate });
}

function freshSnapshotForRole(snapshot, role, evaluationTime, allowStaleSnapshot) {
  if (allowStaleSnapshot) return snapshot;
  const configured = snapshot.lists?.[role];
  const lists = Array.isArray(configured) ? configured : configured ? [configured] : [];
  const now = evaluationTime.getTime();
  const stale = lists.filter((list) => list?.scheme?.nextUpdate && now > Date.parse(list.scheme.nextUpdate));
  if (!stale.length) return snapshot;
  const fresh = lists.filter((list) => !stale.includes(list));
  if (!fresh.length) {
    throw new TrustListError("No authenticated referenced trust list is fresh", TRUST_REASON_CODES.LIST_STALE, {
      nextUpdate: stale[0].scheme.nextUpdate,
      url: stale[0].source?.url || null,
    });
  }
  return {
    ...snapshot,
    lists: { ...snapshot.lists, [role]: fresh },
    listFailures: {
      ...(snapshot.listFailures || {}),
      [role]: [
        ...(snapshot.listFailures?.[role] || []),
        ...stale.map((list) => ({
          url: list.source?.url || null,
          reasonCode: TRUST_REASON_CODES.LIST_STALE,
          message: "Referenced trust list is stale",
          nextUpdate: list.scheme.nextUpdate,
        })),
      ],
    },
  };
}

export function createTrustResolver({ profile, snapshot = null, snapshotProvider = null, scopeProvider = null, clock = () => new Date() } = {}) {
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
        const evaluationSnapshot = freshSnapshotForRole(currentSnapshot, request.role, evaluationTime, policy.allowStaleSnapshot);
        const configuredLists = evaluationSnapshot.lists?.[request.role];
        const lists = Array.isArray(configuredLists) ? configuredLists : configuredLists ? [configuredLists] : [];
        const suppliedScope = request.credentialContext?.scopeEvidence
          || (scopeProvider ? await scopeProvider({ profile, snapshot: evaluationSnapshot, request }) : null);
        const credentialContext = {
          ...(request.credentialContext || {}),
          scopeEvidence: evaluateRegistrarScope({ evidence: suppliedScope, credentialContext: request.credentialContext, operation: request.operation }),
        };
        const result = evaluateTrust({
          snapshot: evaluationSnapshot,
          role: request.role,
          operation: request.operation,
          presentedIdentity: request.presentedIdentity,
          credentialContext,
          evaluationTime,
          acceptedStatuses: policy.acceptedStatuses,
        });
        if (result.trusted && policy.requireRevocation) {
          const selectedUrl = result.evidence.list?.url;
          const selectedList = lists.find((list) => list?.source?.url === selectedUrl);
          if (!selectedList?.revocation) {
            return outputError(evaluationSnapshot, request, new TrustListError(
              "Required revocation evidence is unavailable for the LoTE that authorized this identity",
              TRUST_REASON_CODES.REVOCATION_UNKNOWN,
              { url: selectedUrl || null },
            ));
          }
        }
        if (result.trusted && request.presentedIdentity.certificateChain?.length) {
          const chain = request.presentedIdentity.certificateChain;
          const issuerPem = chain[1] || null;
          const revocation = await checkCertificateRevocation({
            certificatePem: chain[0], issuerPem, evaluationTime,
            network: { timeoutMs: profile.network.timeoutMs, maxBytes: profile.network.maxBytes, allowInsecureHttp: profile.network.allowInsecureHttp === true },
          });
          result.evidence.revocation = revocation;
        }
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
