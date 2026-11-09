import { assertTs12ScaPresentationConstraints } from "../src/lib/ts12Presentation.js";
import { strict as assert } from "assert";
import {
  makeSessionLogger,
  registerLogSinks,
  runWithLogContext,
} from "../src/lib/logger.js";

describe("wallet logger", () => {
  let sessionEntries;
  let globalEntries;

  beforeEach(() => {
    sessionEntries = [];
    globalEntries = [];
    registerLogSinks({
      appendSessionLog: async (sessionId, entry) => {
        sessionEntries.push({ sessionId, entry });
      },
      appendGlobalLog: async (entry) => {
        globalEntries.push(entry);
      },
    });
  });

  it("records the skipped SCA-User audience binding check on the owning wallet session", async () => {
    assertTs12ScaPresentationConstraints({
      dcqlQuery: { credentials: [] },
      stored: { metadata: { configurationId: "https://webuildconsortium.eu/sca/sca-user/1.0" } },
      clientId: "x509_hash:request-certificate",
      log: makeSessionLogger("sca-wallet-session"),
    });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(sessionEntries.length, 1);
    assert.equal(sessionEntries[0].sessionId, "sca-wallet-session");
    assert.equal(sessionEntries[0].entry.data.code, "sca_user_audience_binding_unresolved");
    assert.equal(sessionEntries[0].entry.data.audienceBindingValidated, false);
    assert.equal(sessionEntries[0].entry.data.decision, "continue");
  });

  it("captures plain console output in global logs", async () => {
    console.log("[test] global message");
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(globalEntries.length, 1);
    assert.equal(globalEntries[0].level, "info");
    assert.match(globalEntries[0].message, /\[test\] global message/);
    assert.equal(sessionEntries.length, 0);
  });

  it("captures console output in both global and session logs when context is active", async () => {
    await runWithLogContext("session-1", async () => {
      console.error("[test] failure", new Error("boom"));
      console.log("[test] structured", { ok: true });
    });
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(sessionEntries.length, 2);
    assert.equal(globalEntries.length, 2);
    assert.equal(sessionEntries[0].sessionId, "session-1");
    assert.equal(sessionEntries[0].entry.level, "error");
    assert.equal(sessionEntries[0].entry.domain, "wallet");
    assert.match(sessionEntries[0].entry.message, /\[test\] failure/);
    assert.equal(sessionEntries[0].entry.step, 0);
    assert.equal(sessionEntries[1].entry.level, "info");
    assert.equal(sessionEntries[1].entry.step, 1);
    assert.deepEqual(sessionEntries[1].entry.data, { ok: true });
  });
});
