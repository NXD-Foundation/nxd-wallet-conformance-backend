import { expect } from "chai";
import { generateKeyPair, exportJWK, compactDecrypt } from "jose";
import { pollDeferredCredential } from "../src/lib/issuance.js";
import { pollDeferredCredentialIssuance } from "../src/lib/deferredIssuance.js";
import { prepareCredentialResponseEncryption, parseCredentialResponsePayload } from "../src/lib/credentialResponseEncryption.js";
import { encryptCredentialResponseToJwe } from "../../utils/credentialResponseEncryption.js";
const response = (status, body, type = "application/json") => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": type } });
describe("OID4VCI deferred polling", () => {
  for (const encrypted of [false, true]) {
    it(`polls 202 to completion with ${encrypted ? "encrypted" : "plain"} messages`, async () => {
      const { publicKey, privateKey } = await generateKeyPair("ECDH-ES", { crv: "P-256" });
      const jwk = await exportJWK(publicKey); jwk.alg = "ECDH-ES";
      const issuerMeta = { credential_request_encryption: { jwks: { keys: [jwk] }, enc_values_supported: ["A256GCM"] }, credential_response_encryption: { alg_values_supported: ["ECDH-ES"], enc_values_supported: ["A256GCM"] } };
      const ctx = encrypted ? await prepareCredentialResponseEncryption(issuerMeta) : null;
      let calls = 0;
      const send = async (_url, body) => {
        calls++;
        const request = encrypted ? JSON.parse(new TextDecoder().decode((await compactDecrypt(body, privateKey)).plaintext)) : body;
        expect(request.transaction_id).to.equal("tx");
        const payload = calls === 1 ? { transaction_id: "tx", interval: 0 } : { credentials: [{ credential: "issued" }] };
        return encrypted ? response(calls === 1 ? 202 : 200, await encryptCredentialResponseToJwe(payload, request.credential_response_encryption, issuerMeta), "application/jwt") : response(calls === 1 ? 202 : 200, payload);
      };
      const result = await pollDeferredCredential({ deferredEndpoint: "https://issuer.example/deferred", transactionId: "tx", initialInterval: 0, pollIntervalMs: 1, pollTimeoutMs: 1000, accessToken: "token", tokenBody: {}, isDpopBoundAccessToken: () => false, computeAthForDpop: () => null, createDPoP: () => {}, postJson: send, issuerMeta, credentialResponseEncryption: ctx?.credential_response_encryption, parseCredentialResponsePayload: (text, type) => parseCredentialResponsePayload(text, type, ctx?.privateKey) });
      expect(calls).to.equal(2); expect(result.credentials[0].credential).to.equal("issued");
    });
  }
  it("authorization-code poller accepts encrypted pending and success responses", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ECDH-ES", { crv: "P-256" });
    const jwk = await exportJWK(publicKey); jwk.alg = "ECDH-ES";
    const issuerMeta = { credential_request_encryption: { jwks: { keys: [jwk] }, enc_values_supported: ["A128GCM"] }, credential_response_encryption: { alg_values_supported: ["ECDH-ES"], enc_values_supported: ["A128GCM"] } };
    const encryptionContext = await prepareCredentialResponseEncryption(issuerMeta);
    let calls = 0;
    const result = await pollDeferredCredentialIssuance({ transactionId: "tx", deferredEndpoint: "https://issuer.example/deferred", pollTimeoutMs: 1000, sleep: async () => {}, issuerMeta, encryptionContext, buildPollRequest: async () => ({ body: { transaction_id: "tx" }, headers: {} }), httpPostJson: async (_url, body) => {
      const req = JSON.parse(new TextDecoder().decode((await compactDecrypt(body, privateKey)).plaintext));
      calls++;
      const payload = calls === 1 ? { transaction_id: "tx", interval: 1 } : { credentials: [{ credential: "issued" }] };
      return response(calls === 1 ? 202 : 200, await encryptCredentialResponseToJwe(payload, req.credential_response_encryption, issuerMeta), "application/jwt");
    } });
    expect(calls).to.equal(2); expect(result.credentials[0].credential).to.equal("issued");
  });
  it("rejects a changed transaction id in a pending response", async () => {
    try {
      await pollDeferredCredentialIssuance({ transactionId: "tx", deferredEndpoint: "https://issuer.example/deferred", pollTimeoutMs: 100, sleep: async () => {}, buildPollRequest: async () => ({ body: { transaction_id: "tx" }, headers: {} }), httpPostJson: async () => response(202, { transaction_id: "other", interval: 0 }) });
      throw new Error("expected failure");
    } catch (error) { expect(error.message).to.equal("Invalid deferred transaction_id"); }
  });
});
