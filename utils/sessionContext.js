const SESSION_CONTEXT_VERSION = 1;

function asObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function appendDecisionIfMissing(decisions, decision) {
  if (!decision) return decisions;
  const serialized = JSON.stringify(decision);
  return decisions.some((entry) => JSON.stringify(entry) === serialized)
    ? decisions
    : [...decisions, clone(decision)];
}

function buildContext(input = {}) {
  const source = asObject(input);
  const existing = asObject(source.sessionContext);
  const request = asObject(existing.request);
  const trust = asObject(existing.trust);
  const lifecycle = asObject(existing.lifecycle);
  const now = source.updatedAt || new Date().toISOString();

  return {
    version: SESSION_CONTEXT_VERSION,
    id: source.id ?? existing.id ?? null,
    domain: source.domain ?? existing.domain ?? "verification",
    flow: source.flow ?? existing.flow ?? null,
    lifecycle: {
      status: source.status ?? lifecycle.status ?? "pending",
      createdAt: source.createdAt ?? lifecycle.createdAt ?? now,
      updatedAt: now,
    },
    request: {
      nonce: source.nonce ?? request.nonce ?? null,
      clientId: source.clientId ?? request.clientId ?? null,
      audience: source.audience ?? request.audience ?? null,
      transactionData: source.transactionData ?? request.transactionData ?? null,
    },
    trust: {
      enabled: source.trustEnabled ?? trust.enabled ?? false,
      policy: clone(source.trustPolicy ?? trust.policy ?? null),
      decisions: clone(source.trustDecisions ?? trust.decisions ?? (source.trustDecision ? [source.trustDecision] : [])),
    },
    correlation: {
      sessionId: source.id ?? existing.correlation?.sessionId ?? null,
      domain: source.domain ?? existing.correlation?.domain ?? "verification",
      flow: source.flow ?? existing.correlation?.flow ?? null,
      operationId: source.operationId ?? existing.correlation?.operationId ?? null,
    },
    extensions: clone(source.extensions ?? existing.extensions ?? {}),
  };
}

class SessionContextBuilder {
  constructor(context) {
    this.context = Object.freeze(context);
    Object.freeze(this);
  }

  with(values) {
    return new SessionContextBuilder(buildContext({ ...this.context, ...values, sessionContext: this.context }));
  }

  withNonce(nonce) { return this.with({ nonce }); }
  withClientId(clientId) { return this.with({ clientId }); }
  withAudience(audience) { return this.with({ audience }); }
  withTransactionData(transactionData) { return this.with({ transactionData }); }
  withTrustFrameworkEnabled(enabled = true) { return this.with({ trustEnabled: enabled }); }
  withTrustPolicy(trustPolicy) { return this.with({ trustPolicy, trustEnabled: !!trustPolicy }); }
  withTrustDecision(decision) {
    const clonedDecision = clone(decision);
    return this.with({
      trustDecision: clonedDecision,
      trustDecisions: [...this.context.trust.decisions, clonedDecision],
    });
  }
  withStatus(status) { return this.with({ status }); }
  withExtension(name, value) {
    return this.with({ extensions: { ...this.context.extensions, [name]: clone(value) } });
  }
  withVpSession(session) { return this.with({ extensions: { ...this.context.extensions, vpSession: clone(session) } }); }
  withIssuanceSession(session) { return this.with({ extensions: { ...this.context.extensions, issuanceSession: clone(session) } }); }
  withWalletSession(session) { return this.with({ extensions: { ...this.context.extensions, walletSession: clone(session) } }); }
  toJSON() { return clone(this.context); }
  toSession(legacySession = {}) {
    const context = this.toJSON();
    const latestDecision = context.trust.decisions.at(-1) || null;
    return {
      ...legacySession,
      ...(context.trust.policy ? { trustPolicy: context.trust.policy } : {}),
      ...(latestDecision ? { trustDecision: latestDecision } : {}),
      sessionContext: context,
    };
  }
}

export function createSessionContext(input = {}) {
  return new SessionContextBuilder(buildContext(input));
}

export function createVerificationContext(input = {}) {
  return createSessionContext({ ...input, domain: "verification" });
}

export function createIssuanceContext(input = {}) {
  return createSessionContext({ ...input, domain: "issuance" });
}

export function createWalletContext(input = {}) {
  return createSessionContext({ ...input, domain: "wallet" });
}

export function sessionContextFor(session = {}) {
  const context = session?.sessionContext;
  if (context?.version === SESSION_CONTEXT_VERSION) return context;
  return null;
}

export function sessionTrustPolicy(session = {}) {
  return sessionContextFor(session)?.trust?.policy ?? session?.trustPolicy ?? null;
}

export function withCanonicalSessionContext(sessionId, session, domain, flow = null) {
  const existing = sessionContextFor(session);
  const request = existing?.request || {};
  const trustPolicy = existing?.trust?.policy ?? session?.trustPolicy ?? null;
  const existingDecisions = existing?.trust?.decisions || [];
  const sessionDecisions = Array.isArray(session?.trustDecisions) ? session.trustDecisions : [];
  const decisions = sessionDecisions.reduce(appendDecisionIfMissing, existingDecisions);
  const decisionsWithCurrent = appendDecisionIfMissing(decisions, session?.trustDecision);
  return createSessionContext({
    sessionContext: existing,
    id: sessionId,
    domain,
    flow: flow ?? existing?.flow ?? session?.flowType ?? null,
    status: session?.status ?? existing?.lifecycle?.status,
    nonce: request.nonce ?? session?.nonce,
    clientId: request.clientId ?? session?.client_id,
    audience: request.audience ?? session?.expected_audience ?? session?.client_id,
    transactionData: request.transactionData ?? session?.transaction_data,
    trustPolicy,
    trustEnabled: !!trustPolicy,
    trustDecisions: decisionsWithCurrent,
  }).toSession(session);
}
