import { strict as assert } from "node:assert";
import { resolveCredentialSelection, issuanceTtlSeconds, SCENARIOS, PROTOCOL, createOfferHandler } from "../routes/issue/dcApiIssuanceRoutes.js";

describe("CS-07 DC API issuance route contract", () => {
  it("exposes only the supported scenarios and protocol", () => {
    assert.deepEqual(Object.keys(SCENARIOS), ["pid-pre-authorized", "pid-pre-authorized-tx-code", "pid-authorization-code"]);
    assert.equal(PROTOCOL, "openid4vci-v1");
  });
  it("accepts a configured credential and rejects an incompatible format", () => {
    const selection = resolveCredentialSelection({ credentialType: "VerifiablePortableDocumentA2SDJWT", credentialFormat: "sd-jwt" });
    assert.equal(selection.credentialType, "VerifiablePortableDocumentA2SDJWT");
    assert.throws(() => resolveCredentialSelection({ credentialType: "VerifiablePortableDocumentA2SDJWT", credentialFormat: "mso_mdoc" }), /incompatible/);
    assert.throws(() => resolveCredentialSelection({ credentialType: "does-not-exist" }), /Unsupported/);
  });
  it("uses the configured flow TTL", () => {
    const previous = process.env.VCI_PRE_AUTH_TIMEOUT;
    process.env.VCI_PRE_AUTH_TIMEOUT = "91";
    assert.equal(issuanceTtlSeconds("pre_authorized_code"), 91);
    if (previous === undefined) delete process.env.VCI_PRE_AUTH_TIMEOUT; else process.env.VCI_PRE_AUTH_TIMEOUT = previous;
  });
  it("executes the offer handler and returns the DC API envelope", async () => {
    const state = { statusCode: 200, headers: {}, body: null };
    const res = {
      set(name, value) { if (typeof name === "string") this.headers[name] = value; else Object.assign(this.headers, name); return this; },
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
    };
    Object.assign(res, state);
    await createOfferHandler({ body: { scenario: "pid-pre-authorized" } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.digital.requests[0].protocol, PROTOCOL);
    assert.ok(res.body.fallback.deepLink);
  });
});
