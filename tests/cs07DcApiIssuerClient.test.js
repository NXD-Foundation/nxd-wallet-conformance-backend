import { strict as assert } from "node:assert";
import { createDcApiIssuerClient } from "../clients/dc-api/issuer-client.js";

function response(body, ok = true, status = 200) {
  return { ok, status, json: async () => body };
}

describe("CS-07 DC API issuer client", () => {
  it("prepares an openid4vci-v1 descriptor and invokes create", async () => {
    const calls = [];
    const navigatorImpl = { credentials: { create: async options => { calls.push(options); return { protocol: "openid4vci-v1", data: { accepted: true } }; } } };
    const digitalCredential = { userAgentAllowsProtocol: protocol => protocol === "openid4vci-v1" };
    const client = createDcApiIssuerClient({ issuerBaseUrl: "https://issuer.example", secureContext: true, navigatorImpl, digitalCredential, fetchImpl: async (_url, options) => { calls.push(options); return response({ sessionId: "s1", expiresAt: Math.floor(Date.now() / 1000) + 60, digital: { requests: [{ protocol: "openid4vci-v1", data: { credential_issuer: "https://issuer.example" } }] }, fallback: {} }); } });
    const descriptor = await client.prepare({ scenario: "pid-pre-authorized" });
    assert.equal(client.isSupported(), true);
    const result = await client.create(descriptor);
    assert.deepEqual(result.data, { accepted: true });
    assert.equal(calls.at(-1).digital.requests[0].protocol, "openid4vci-v1");
  });

  it("validates browser responses and permits retry after cancellation", async () => {
    const client = createDcApiIssuerClient({ issuerBaseUrl: "https://issuer.example", secureContext: true, digitalCredential: { userAgentAllowsProtocol: () => true }, navigatorImpl: { credentials: { create: async () => { const e = new Error("cancelled"); e.name = "AbortError"; throw e; } } }, fetchImpl: async () => response({ sessionId: "s1", expiresAt: Math.floor(Date.now() / 1000) + 60, digital: { requests: [{ protocol: "openid4vci-v1", data: {} }] } }) });
    const descriptor = await client.prepare();
    await assert.rejects(() => client.create(descriptor), error => error.code === "cancelled");
    await assert.rejects(() => client.create(descriptor), error => error.code === "cancelled");
  });

  it("rejects malformed DigitalCredential responses", async () => {
    const client = createDcApiIssuerClient({ issuerBaseUrl: "https://issuer.example", secureContext: true, digitalCredential: { userAgentAllowsProtocol: () => true }, navigatorImpl: { credentials: { create: async () => ({ protocol: "wrong", data: {} }) } }, fetchImpl: async () => response({ sessionId: "s1", expiresAt: Math.floor(Date.now() / 1000) + 60, digital: { requests: [{ protocol: "openid4vci-v1", data: {} }] } }) });
    const descriptor = await client.prepare();
    await assert.rejects(() => client.create(descriptor), error => error.code === "api_failure");
  });
});
