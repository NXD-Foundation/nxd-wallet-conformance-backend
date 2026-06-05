import { expect } from "chai";
import {
  resolveDeferredPollIntervalMs,
  isTerminalDeferredPollError,
  pollDeferredCredentialIssuance,
} from "../src/lib/deferredIssuance.js";

describe("wallet-client deferredIssuance (Phase 5)", () => {
  it("prefers issuer interval seconds over default poll interval", () => {
    expect(resolveDeferredPollIntervalMs(3, 2000)).to.equal(3000);
    expect(resolveDeferredPollIntervalMs(undefined, 1500)).to.equal(1500);
    expect(resolveDeferredPollIntervalMs(undefined, undefined)).to.equal(2000);
  });

  it("detects terminal deferred poll errors", () => {
    expect(isTerminalDeferredPollError(401, {})).to.equal(true);
    expect(isTerminalDeferredPollError(400, { error: "invalid_transaction_id" })).to.equal(true);
    expect(isTerminalDeferredPollError(400, { error: "credential_request_denied" })).to.equal(true);
    expect(isTerminalDeferredPollError(400, { error: "invalid_request" })).to.equal(false);
    expect(isTerminalDeferredPollError(500, { error: "server_error" })).to.equal(false);
  });

  it("polls 202 responses until a 200 credential is returned", async () => {
    const calls = [];
    const defBody = await pollDeferredCredentialIssuance({
      transactionId: "tx-123",
      issuerIntervalSeconds: 0.001,
      pollTimeoutMs: 5000,
      pollIntervalMs: 1,
      deferredEndpoint: "https://issuer.example/credential_deferred",
      buildPollRequest: async () => ({ body: { transaction_id: "tx-123" }, headers: {} }),
      httpPostJson: async () => {
        calls.push(calls.length);
        if (calls.length < 2) {
          return { status: 202, text: async () => JSON.stringify({ transaction_id: "tx-123", interval: 0.001 }) };
        }
        return { status: 200, text: async () => JSON.stringify({ credential: "vc.jwt" }) };
      },
      logSessionId: "sess-1",
      sleep: async () => {},
    });

    expect(defBody).to.deep.equal({ credential: "vc.jwt" });
    expect(calls.length).to.equal(2);
  });

  it("stops polling on credential_request_denied", async () => {
    let calls = 0;
    let thrown = null;
    try {
      await pollDeferredCredentialIssuance({
        transactionId: "tx-denied",
        issuerIntervalSeconds: 0.001,
        pollTimeoutMs: 5000,
        pollIntervalMs: 1,
        deferredEndpoint: "https://issuer.example/credential_deferred",
        buildPollRequest: async () => ({ body: { transaction_id: "tx-denied" }, headers: {} }),
        httpPostJson: async () => {
          calls += 1;
          return {
            status: 400,
            text: async () => JSON.stringify({ error: "credential_request_denied" }),
          };
        },
        logSessionId: "sess-2",
        sleep: async () => {},
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).to.be.an("error");
    expect(String(thrown.message)).to.match(/credential_request_denied/);
    expect(calls).to.equal(1);
  });
});
