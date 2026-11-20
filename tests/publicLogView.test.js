import { strict as assert } from "node:assert";
import { toPublicLogs } from "../utils/publicLogView.js";

describe("public log view", () => {
  it("summarizes an error stack while retaining its complete diagnostic", () => {
    const message = "DpopRequiredError: token response is not DPoP-bound\n    at assertDpopBoundTokenReceived (dpopBinding.js:42)";
    const data = { errorCode: "dpop_required", stack: message };
    const [log] = toPublicLogs([{ level: "error", message, step: 55, data }]);
    assert.equal(log.message, "DpopRequiredError: token response is not DPoP-bound");
    assert.equal(log.detail, message);
    assert.equal(log.data, data);
    assert.equal(log.step, 55);
  });

  it("retains complete HTTP and credential diagnostics in endpoint responses", () => {
    const metadata = {
      headers: { authorization: "Bearer full-access-token" },
      body: { credential: "full-credential", vp_token: "full-vp-response" },
      url: "https://issuer.example/token?code=full-code",
    };
    const [log] = toPublicLogs([{ level: "info", message: "[HTTP] [REQUEST] POST token", metadata }]);
    assert.equal(log.metadata, metadata);
    assert.equal(log.message, "[HTTP] [REQUEST] POST token");
    assert.equal(log.detail, undefined);
  });

  it("bounds the summary without losing a long original message", () => {
    const message = `credential response ${"x".repeat(400)}`;
    const [log] = toPublicLogs([{ level: "info", message }]);
    assert.ok(log.message.length <= 240);
    assert.equal(log.detail, message);
  });
});
