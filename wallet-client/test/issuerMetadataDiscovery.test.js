import { expect } from "chai";

// Prevent importing the Express app from starting its listener in this unit test.
process.env.NODE_ENV = "test";
const { discoverIssuerMetadata, isDirectWalletTrustEnabled } = await import("../src/server.js");

describe("wallet issuer metadata discovery", () => {
  it("does not enable direct-route trust setup for string false", () => {
    expect(isDirectWalletTrustEnabled("false")).to.equal(false);
    expect(isDirectWalletTrustEnabled(false)).to.equal(false);
    expect(isDirectWalletTrustEnabled("true")).to.equal(true);
  });

  it("retries JSON metadata when signed metadata is unavailable", async () => {
    const accepts = [];
    const metadata = {
      credential_issuer: "https://issuer.example",
      credential_endpoint: "https://issuer.example/credential",
    };
    const result = await discoverIssuerMetadata("https://issuer.example", null, async (_url, options) => {
      accepts.push(options.headers.Accept);
      if (options.headers.Accept.includes("application/jwt")) {
        return { ok: false, status: 503, headers: { get: () => "application/problem+json" } };
      }
      return {
        ok: true,
        status: 200,
        headers: { get: () => "application/json" },
        json: async () => metadata,
      };
    });
    expect(accepts).to.deep.equal(["application/jwt, application/json", "application/json"]);
    expect(result).to.deep.equal(metadata);
  });
});
