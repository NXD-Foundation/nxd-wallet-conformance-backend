import { expect } from "chai";
import {
  createIssuanceContext,
  createVerificationContext,
  createWalletContext,
  withCanonicalSessionContext,
  sessionTrustPolicy,
} from "../utils/sessionContext.js";
import {
  getSessionLogContext,
  runWithSessionLogContext,
} from "../utils/sessionLogContext.js";

describe("session context", () => {
  it("builds immutable verification context and preserves legacy session fields", () => {
    const base = createVerificationContext({ id: "vp-1", flow: "dc-api" });
    const enriched = base
      .withNonce("nonce-1")
      .withClientId("client-1")
      .withAudience("aud-1")
      .withTransactionData(["tx-1"])
      .withTrustPolicy({ mode: "webuild", profile: "webuild-wp4-pilot" })
      .withTrustDecision({ trusted: true });

    expect(base.toJSON().request.nonce).to.equal(null);
    expect(enriched.toJSON()).to.deep.include({ id: "vp-1", domain: "verification", flow: "dc-api" });
    expect(enriched.toJSON().request).to.deep.equal({ nonce: "nonce-1", clientId: "client-1", audience: "aud-1", transactionData: ["tx-1"] });
    expect(enriched.toJSON().trust.decisions).to.deep.equal([{ trusted: true }]);

    const session = enriched.toSession({ nonce: "legacy-nonce", response_mode: "direct_post" });
    expect(session.nonce).to.equal("legacy-nonce");
    expect(session.trustDecision).to.deep.equal({ trusted: true });
    expect(session.trustPolicy).to.deep.equal({ mode: "webuild", profile: "webuild-wp4-pilot" });
    expect(session.sessionContext.correlation.sessionId).to.equal("vp-1");
    expect(sessionTrustPolicy(session)).to.deep.equal({ mode: "webuild", profile: "webuild-wp4-pilot" });
  });

  it("creates domain-specific contexts", () => {
    expect(createIssuanceContext({ id: "issue-1" }).toJSON().domain).to.equal("issuance");
    expect(createWalletContext({ id: "wallet-1" }).toJSON().domain).to.equal("wallet");
  });

  it("carries legacy trust decisions into the canonical context on updates", () => {
    const decision = {
      trusted: false,
      state: "not_trusted",
      reasonCode: "ANCHOR_MISMATCH",
      evaluatedAt: "2026-07-27T00:00:00.000Z",
    };
    const updated = withCanonicalSessionContext(
      "vp-trust-1",
      {
        status: "pending",
        trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
        trustDecision: decision,
      },
      "verification",
    );
    expect(updated.sessionContext.trust.decisions).to.deep.equal([decision]);
  });

  it("preserves wallet context state across status updates", () => {
    const pending = createWalletContext({
      id: "wallet-1",
      flow: "issuance",
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    }).withTrustDecision({ trusted: true, state: "trusted" }).toSession({ status: "pending" });
    const completed = createWalletContext({
      sessionContext: pending.sessionContext,
      id: "wallet-1",
      flow: "issuance",
      status: "ok",
      trustPolicy: pending.trustPolicy,
    }).toSession({ status: "ok" });

    expect(completed.sessionContext.lifecycle.status).to.equal("ok");
    expect(completed.sessionContext.trust.decisions).to.deep.equal([{ trusted: true, state: "trusted" }]);
    expect(completed.sessionContext.trust.policy).to.deep.equal(pending.trustPolicy);
  });

  it("isolates concurrent async log contexts", async () => {
    const seen = await Promise.all(["one", "two"].map((sessionId, index) =>
      runWithSessionLogContext({ sessionId, domain: "verification" }, async () => {
        await new Promise((resolve) => setTimeout(resolve, 10 - index * 5));
        return getSessionLogContext();
      }),
    ));
    expect(seen).to.deep.equal([
      { sessionId: "one", domain: "verification", flow: null, operationId: null },
      { sessionId: "two", domain: "verification", flow: null, operationId: null },
    ]);
  });
});
