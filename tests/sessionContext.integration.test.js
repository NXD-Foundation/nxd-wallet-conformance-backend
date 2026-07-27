import { expect } from "chai";
import { v4 as uuidv4 } from "uuid";
import {
  client,
  clearSessionLogs,
  getSessionLogs,
  getVPSession,
  storeSessionLog,
  storeVPSession,
} from "../services/cacheServiceRedis.js";
import { makeSessionLogger } from "../utils/sessionLogger.js";
import { runWithSessionLogContext } from "../utils/sessionLogContext.js";

describe("session context Redis integration", () => {
  before(function () {
    if (!client.isReady) this.skip();
  });

  it("persists a canonical VP context without changing flat-field compatibility", async () => {
    const sessionId = `session-context-${uuidv4()}`;
    await storeVPSession(sessionId, {
      status: "pending",
      nonce: "nonce-1",
      client_id: "client-1",
      expected_audience: "aud-1",
      transaction_data: ["tx-1"],
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    });

    const stored = await getVPSession(sessionId);
    expect(stored.nonce).to.equal("nonce-1");
    expect(stored.sessionContext).to.deep.include({
      version: 1,
      id: sessionId,
      domain: "verification",
    });
    expect(stored.sessionContext.request).to.deep.equal({
      nonce: "nonce-1",
      clientId: "client-1",
      audience: "aud-1",
      transactionData: ["tx-1"],
    });
  });

  it("keeps issuer log retrieval compatible with correlated metadata", async () => {
    const sessionId = `session-log-${uuidv4()}`;
    await storeSessionLog(sessionId, "info", "context test", {
      domain: "verification",
      flow: "dc-api",
    });
    const logs = await getSessionLogs(sessionId);
    expect(logs).to.have.length(1);
    expect(logs[0]).to.include({ level: "info", message: "context test" });
    expect(logs[0].metadata).to.deep.include({ domain: "verification", flow: "dc-api" });
    expect(await clearSessionLogs(sessionId)).to.equal(true);
  });

  it("keeps concurrent issuance and verification logs on their own sessions", async () => {
    const issuanceId = `concurrent-issuance-${uuidv4()}`;
    const verificationId = `concurrent-verification-${uuidv4()}`;
    await Promise.all([
      runWithSessionLogContext({ sessionId: issuanceId, domain: "issuance" }, async () => {
        makeSessionLogger(issuanceId)("issuance event");
        await new Promise((resolve) => setTimeout(resolve, 10));
      }),
      runWithSessionLogContext({ sessionId: verificationId, domain: "verification" }, async () => {
        makeSessionLogger(verificationId)("verification event");
        await new Promise((resolve) => setTimeout(resolve, 5));
      }),
    ]);
    await new Promise((resolve) => setTimeout(resolve, 20));

    const issuanceLogs = await getSessionLogs(issuanceId);
    const verificationLogs = await getSessionLogs(verificationId);
    expect(issuanceLogs.some((entry) => entry.message === "issuance event" && entry.metadata.domain === "issuance")).to.equal(true);
    expect(verificationLogs.some((entry) => entry.message === "verification event" && entry.metadata.domain === "verification")).to.equal(true);
    expect(issuanceLogs.some((entry) => entry.message === "verification event")).to.equal(false);
    expect(verificationLogs.some((entry) => entry.message === "issuance event")).to.equal(false);
    await clearSessionLogs(issuanceId);
    await clearSessionLogs(verificationId);
  });
});
