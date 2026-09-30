import { strict as assert } from "node:assert";
import * as jose from "jose";
import { createCallerSdJwtPayload, resolveConfiguredCallerSdJwtPayload } from "../utils/credPayloadUtil.js";
import { handleCredentialGenerationBasedOnFormat } from "../utils/credGenerationUtils.js";

describe("caller supplied SD-JWT claims", () => {
  it("uses only the supplied claims and makes each top-level claim selectively disclosable", () => {
    const input = { booking_reference: "REF-1", booking: { hotel: "Example" } };
    const payload = createCallerSdJwtPayload(input);
    assert.deepEqual(payload.claims, input);
    assert.deepEqual(payload.disclosureFrame, { _sd: ["booking_reference", "booking"] });
    payload.claims.booking_reference = "changed";
    assert.equal(input.booking_reference, "REF-1");
  });

  it("rejects empty, array, and primitive payloads", () => {
    for (const value of [{}, [], "claim", null]) assert.throws(() => createCallerSdJwtPayload(value));
  });

  it("resolves a multi-credential LoyaltyCard payload before its fixture builder is needed", () => {
    const session = { credentialPayloads: { LoyaltyCard: { "customer.first_name": "Ada", "loyalty_card.id": "L-1" } } };
    const payload = resolveConfiguredCallerSdJwtPayload(session, "LoyaltyCard", "dc+sd-jwt");
    assert.deepEqual(payload.claims, session.credentialPayloads.LoyaltyCard);
    assert.deepEqual(payload.disclosureFrame, { _sd: ["customer.first_name", "loyalty_card.id"] });
    assert.equal(resolveConfiguredCallerSdJwtPayload(session, "VerifiablePortableDocumentA2SDJWT", "dc+sd-jwt"), null);
  });

  it("issues a multi-credential LoyaltyCard without dereferencing the single-credential fixture payload", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const jwk = await jose.exportJWK(publicKey);
    const proof = await new jose.SignJWT({ iss: "holder", aud: "http://localhost:3000", nonce: "test" })
      .setProtectedHeader({ alg: "ES256", typ: "openid4vci-proof+jwt", jwk })
      .sign(privateKey);
    const credential = await handleCredentialGenerationBasedOnFormat({
      vct: "LoyaltyCard",
      proofs: { jwt: [proof] },
    }, {
      signatureType: "kid-jwk",
      isHaip: false,
      credentialPayloads: { LoyaltyCard: { "customer.first_name": "Ada", "loyalty_card.id": "L-1" } },
    }, "http://localhost:3000", "dc+sd-jwt");
    assert.equal(typeof credential, "string");
    assert.ok(credential.startsWith("ey"));
  });
});
