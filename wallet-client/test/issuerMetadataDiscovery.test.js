import { expect } from "chai";

process.env.NODE_ENV = "test";
const { discoverIssuerMetadata } = await import("../src/server.js");

describe("wallet issuer metadata discovery", () => {
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
        text: async () => JSON.stringify(metadata),
      };
    });
    expect(accepts).to.deep.equal(["application/jwt, application/json", "application/json"]);
    expect(result.credential_issuer).to.equal("https://issuer.example");
    expect(result.credential_endpoint).to.equal("https://issuer.example/credential");
  });
});
