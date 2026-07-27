import { expect } from "chai";
import { fetchDocument } from "../trust/fetch.js";

describe("Phase 1 trust-list fetch policy", () => {
  it("rejects HTTP unless explicitly enabled for local fixtures", async () => {
    try {
      await fetchDocument("http://example.test/list.json", { fetchImpl: async () => ({ ok: true }), resolveHostname: async () => [] });
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
        resolveHostname: async () => [],
        maxBytes: 2,
        fetchImpl: async () => ({ ok: true, headers: { get: () => "application/json" }, arrayBuffer: async () => Buffer.from("123") }),
      });
      expect.fail("expected size rejection");
    } catch (error) {
      expect(error.message).to.match(/size limit/i);
    }
  });

  it("rejects a URL resolving to a private address", async () => {
    try {
      await fetchDocument("https://trust.example/list.json", { fetchImpl: async () => ({ ok: true }), resolveHostname: async () => [{ address: "127.0.0.1" }] });
      expect.fail("expected private-address rejection");
    } catch (error) {
      expect(error.reasonCode).to.equal("REFERENCED_LIST_UNAVAILABLE");
      expect(error.message).to.match(/private|reserved/i);
    }
  });

  it("rejects the complete IPv6 link-local range", async () => {
    for (const address of ["fe80::1", "fe81::1", "fe9f::1", "feaf::1", "febf::1"]) {
      try {
        await fetchDocument("https://trust.example/list.json", { fetchImpl: async () => ({ ok: true }), resolveHostname: async () => [{ address }] });
        expect.fail(`expected ${address} rejection`);
      } catch (error) {
        expect(error.reasonCode).to.equal("REFERENCED_LIST_UNAVAILABLE");
      }
    }
  });

  it("rejects IPv4-mapped IPv6 private addresses", async () => {
    for (const address of ["::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:7f00:1"]) {
      try {
        await fetchDocument("https://trust.example/list.json", { fetchImpl: async () => ({ ok: true }), resolveHostname: async () => [{ address }] });
        expect.fail(`expected ${address} rejection`);
      } catch (error) {
        expect(error.reasonCode).to.equal("REFERENCED_LIST_UNAVAILABLE");
      }
    }
  });
});
