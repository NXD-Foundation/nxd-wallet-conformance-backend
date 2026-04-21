import { expect } from "chai";
import {
  getNextPollDelayMs,
  resolveDeferredPollResult,
  formatDeferredTerminalError,
} from "../src/lib/deferredIssuancePoll.js";

describe("deferredIssuancePoll", () => {
  describe("getNextPollDelayMs", () => {
    it("uses the larger of issuer interval (seconds) and client default (ms)", () => {
      expect(getNextPollDelayMs(5, 2000)).to.equal(5000);
      expect(getNextPollDelayMs(1, 3000)).to.equal(3000);
    });

    it("falls back to client interval when issuer interval is absent", () => {
      expect(getNextPollDelayMs(undefined, 2500)).to.equal(2500);
    });

    it("defaults client interval to 2000ms when missing or zero", () => {
      expect(getNextPollDelayMs(undefined, 0)).to.equal(2000);
    });
  });

  describe("resolveDeferredPollResult", () => {
    it("returns success for HTTP 200 JSON body", async () => {
      const out = await resolveDeferredPollResult({
        status: 200,
        ok: true,
        contentType: "application/json",
        responseText: JSON.stringify({ credentials: [{ credential: "x" }] }),
        decryptionPrivateKey: null,
      });
      expect(out.kind).to.equal("success");
      expect(out.body.credentials).to.have.length(1);
    });

    it("returns pending for issuance_pending 400", async () => {
      const out = await resolveDeferredPollResult({
        status: 400,
        ok: false,
        contentType: "application/json",
        responseText: JSON.stringify({
          error: "issuance_pending",
          interval: 3,
        }),
        decryptionPrivateKey: null,
      });
      expect(out.kind).to.equal("pending");
      expect(out.interval).to.equal(3);
    });

    it("returns terminal for invalid_transaction_id", async () => {
      const out = await resolveDeferredPollResult({
        status: 400,
        ok: false,
        contentType: "application/json",
        responseText: JSON.stringify({
          error: "invalid_transaction_id",
          error_description: "bad",
        }),
        decryptionPrivateKey: null,
      });
      expect(out.kind).to.equal("terminal");
      expect(out.errorBody.error).to.equal("invalid_transaction_id");
    });

    it("returns terminal for expired_transaction_id", async () => {
      const out = await resolveDeferredPollResult({
        status: 400,
        ok: false,
        contentType: "application/json",
        responseText: JSON.stringify({ error: "expired_transaction_id" }),
        decryptionPrivateKey: null,
      });
      expect(out.kind).to.equal("terminal");
    });

    it("returns terminal for other 4xx errors", async () => {
      const out = await resolveDeferredPollResult({
        status: 400,
        ok: false,
        contentType: "application/json",
        responseText: JSON.stringify({ error: "invalid_grant" }),
        decryptionPrivateKey: null,
      });
      expect(out.kind).to.equal("terminal");
    });

    it("returns terminal for 5xx", async () => {
      const out = await resolveDeferredPollResult({
        status: 503,
        ok: false,
        contentType: "application/json",
        responseText: JSON.stringify({ error: "server_error" }),
        decryptionPrivateKey: null,
      });
      expect(out.kind).to.equal("terminal");
    });
  });

  describe("formatDeferredTerminalError", () => {
    it("includes status and description", () => {
      const msg = formatDeferredTerminalError({
        status: 400,
        errorBody: { error: "expired_transaction_id", error_description: "done" },
      });
      expect(msg).to.include("400");
      expect(msg).to.include("done");
    });
  });
});
