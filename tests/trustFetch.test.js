import { expect } from "chai";
import { fetchDocument } from "../trust/fetch.js";

describe("Phase 1 trust-list fetch policy", () => {
  it("rejects HTTP unless explicitly enabled for local fixtures", async () => {
    try {
      await fetchDocument("http://example.test/list.json", { fetchImpl: async () => ({ ok: true }) });
      expect.fail("expected HTTP rejection");
    } catch (error) {
      expect(error.reasonCode).to.equal("REFERENCED_LIST_UNAVAILABLE");
      expect(error.message).to.match(/HTTP\(S\)/);
    }
  });

  it("enforces the response size limit", async () => {
    try {
      await fetchDocument("http://example.test/list.json", {
        allowInsecureHttp: true,
        maxBytes: 2,
        fetchImpl: async () => ({ ok: true, headers: { get: () => "application/json" }, arrayBuffer: async () => Buffer.from("123") }),
      });
      expect.fail("expected size rejection");
    } catch (error) {
      expect(error.message).to.match(/size limit/i);
    }
  });
});
