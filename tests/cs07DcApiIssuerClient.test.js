import { strict as assert } from "node:assert";
import { createDcApiIssuerClient } from "../clients/dc-api/issuer-client.js";

function response(body, ok = true, status = 200) {
  return { ok, status, json: async () => body };
}
function makeDescriptor(sessionId = "s1") {
  const offer = { credential_issuer: "https://issuer.example", credential_configuration_ids: ["pid"], grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": sessionId } } };
  return { sessionId, expiresAt: Math.floor(Date.now() / 1000) + 60, credentialOffer: offer, digital: { requests: [{ protocol: "openid4vci-v1", data: offer }] }, statusEndpoint: `/vci/dc-api/session/${sessionId}`, statusToken: "A".repeat(43), fallback: { deepLink: "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer", qr: "data:image/png;base64,AA==" } };
}

describe("CS-07 DC API issuer client", () => {
  it("prepares an openid4vci-v1 descriptor and invokes create", async () => {
    const calls = [];
    const navigatorImpl = { credentials: { create: async options => { calls.push(options); return { protocol: "openid4vci-v1", data: { accepted: true } }; } } };
    const digitalCredential = { userAgentAllowsProtocol: protocol => protocol === "openid4vci-v1" };
    const client = createDcApiIssuerClient({ issuerBaseUrl: "https://issuer.example", secureContext: true, navigatorImpl, digitalCredential, fetchImpl: async (_url, options) => { calls.push(options); return response(makeDescriptor()); } });
    const descriptor = await client.prepare({ scenario: "pid-pre-authorized" });
    assert.equal(client.isSupported(), true);
    const result = await client.create(descriptor);
    assert.deepEqual(result.data, { accepted: true });
    assert.equal(calls.at(-1).digital.requests[0].protocol, "openid4vci-v1");
  });

  it("validates browser responses and permits retry after cancellation", async () => {
    const client = createDcApiIssuerClient({ issuerBaseUrl: "https://issuer.example", secureContext: true, digitalCredential: { userAgentAllowsProtocol: () => true }, navigatorImpl: { credentials: { create: async () => { const e = new Error("cancelled"); e.name = "AbortError"; throw e; } } }, fetchImpl: async () => response(makeDescriptor()) });
    const descriptor = await client.prepare();
    await assert.rejects(() => client.create(descriptor), error => error.code === "cancelled");
    await assert.rejects(() => client.create(descriptor), error => error.code === "cancelled");
  });

  it("rejects malformed DigitalCredential responses", async () => {
    const client = createDcApiIssuerClient({ issuerBaseUrl: "https://issuer.example", secureContext: true, digitalCredential: { userAgentAllowsProtocol: () => true }, navigatorImpl: { credentials: { create: async () => ({ protocol: "wrong", data: {} }) } }, fetchImpl: async () => response(makeDescriptor()) });
    const descriptor = await client.prepare();
    await assert.rejects(() => client.create(descriptor), error => error.code === "api_failure");
  });

  it("reports unknown support when the protocol probe is unavailable and keeps status capability private", async () => {
    const calls = [];
    const client = createDcApiIssuerClient({ issuerBaseUrl: "https://issuer.example", secureContext: true, digitalCredential: undefined, navigatorImpl: { credentials: { create: async () => ({ protocol: "openid4vci-v1", data: {} }) } }, fetchImpl: async (url, options) => { calls.push({ url: String(url), options }); return response(calls.length === 1 ? makeDescriptor() : { status: "pending" }); } });
    assert.equal(client.getSupport().state, "unknown");
    const prepared = await client.prepare({ credentials: [{ credential_configuration_id: "pid", payload: { name: "Ada" } }] });
    assert.equal(Object.hasOwn(prepared, "statusToken"), false);
    assert.equal((await client.getStatus(prepared)).status, "pending");
    assert.equal(calls[1].options.headers.Authorization, `Bearer ${"A".repeat(43)}`);
    assert.equal((await client.create(prepared)).protocol, "openid4vci-v1");
  });

  it("rejects a status path outside the session route under the issuer base path", async () => {
    const descriptor = makeDescriptor();
    descriptor.statusEndpoint = "/attacker";
    const client = createDcApiIssuerClient({ issuerBaseUrl: "https://issuer.example/tenant/", secureContext: true, digitalCredential: undefined, navigatorImpl: { credentials: { create: async () => ({}) } }, fetchImpl: async () => response(descriptor) });
    await assert.rejects(() => client.prepare(), error => error.code === "issuer_rejected");
  });
});
