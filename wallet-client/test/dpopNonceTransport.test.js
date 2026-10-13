import { expect } from "chai";
import { Response } from "node-fetch";
import { decodeJwt, importJWK, jwtVerify } from "jose";
import { createDPoP, ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { createDpopNonceState, requestWithDpopNonce, isDpopNonceChallenge } from "../src/lib/dpopNonce.js";
import { redactHttpLog } from "../src/lib/httpLogRedaction.js";
const url = "https://issuer.example/credential";
const challenge = (nonce = "rs-nonce") => new Response(null, { status: 401, headers: {
  "WWW-Authenticate": 'Bearer realm="a,b", DPoP realm="issuer", error="use_dpop_nonce"',
  ...(nonce ? { "DPoP-Nonce": nonce } : {}),
} });
const json = (body, headers = {}, status = 200) => new Response(JSON.stringify(body), { status, headers });
async function rejects(fn, text) {
  try { await fn(); } catch (error) { expect(error.message).to.include(text); return; }
  expect.fail("Expected request to fail");
}

describe("portable DPoP nonce transport", () => {
  let keys;
  beforeEach(async () => { keys = await ensureOrCreateEcKeyPair(null, "ES256"); });

  it("parses multiple schemes and quoted commas without confusing Bearer errors", () => {
    expect(isDpopNonceChallenge('Bearer error="use_dpop_nonce", DPoP realm="x"')).to.equal(false);
    expect(isDpopNonceChallenge('Basic realm="x,y", dPoP realm="x", error = "use_dpop_nonce"')).to.equal(true);
    expect(isDpopNonceChallenge(null)).to.equal(false);
  });

  it("signs nonce-bearing proofs, preserving paths and excluding query and fragment", async () => {
    const jwt = await createDPoP({ ...keys, htu: `${url}/?x=1#fragment`, nonce: "nonce" });
    const { payload } = await jwtVerify(jwt, await importJWK(keys.publicJwk, "ES256"));
    expect(payload.nonce).to.equal("nonce"); expect(payload.htu).to.equal(`${url}/`);
  });

  it("separates same-origin AS/resource nonces, sessions and binding keys, including handoff", async () => {
    const state = createDpopNonceState();
    await requestWithDpopNonce({ url, namespace: "as", state, ...keys,
      send: async () => json({}, { "DPoP-Nonce": "as-nonce" }) });
    await requestWithDpopNonce({ url, state, ...keys, send: async (proof) => {
      expect(decodeJwt(proof)).not.to.have.property("nonce"); return json({}, { "DPoP-Nonce": "rs-nonce" });
    } });
    const otherKeys = await ensureOrCreateEcKeyPair(null, "ES256");
    for (const [otherState, keyPair] of [[createDpopNonceState(), keys], [state, otherKeys]]) {
      await requestWithDpopNonce({ url, state: otherState, ...keyPair, send: async (proof) => {
        expect(decodeJwt(proof)).not.to.have.property("nonce"); return json({});
      } });
    }
    const restored = { dpopBinding: { nonceState: JSON.parse(JSON.stringify(state)) } };
    await requestWithDpopNonce({ url, namespace: "as", state: restored.dpopBinding.nonceState, ...keys,
      send: async (proof) => { expect(decodeJwt(proof).nonce).to.equal("as-nonce"); return json({}); } });
  });

  it("uses successful response rotation for subsequent requests", async () => {
    const state = createDpopNonceState();
    for (const [expected, next] of [[undefined, "first"], ["first", "second"], ["second", "third"]]) {
      await requestWithDpopNonce({ url, state, ...keys, send: async (proof) => {
        expect(decodeJwt(proof).nonce).to.equal(expected); return json({}, { "DPoP-Nonce": next });
      } });
    }
  });

  it("bounds persistent challenges to three sends", async () => {
    let sends = 0;
    await rejects(() => requestWithDpopNonce({ url, ...keys,
      send: async () => { sends++; return challenge(); } }), "nonce retries exhausted");
    expect(sends).to.equal(3);
  });

  it("fails for missing nonce/binding and preserves unrelated 401 bodies", async () => {
    await rejects(() => requestWithDpopNonce({ url, ...keys, send: async () => challenge(null) }), "missing a valid DPoP-Nonce");
    await rejects(() => requestWithDpopNonce({ url, send: async () => challenge() }), "without a DPoP binding");
    await rejects(() => requestWithDpopNonce({ url, enabled: true, send: async () => json({}) }), "key material is missing");
    let sends = 0;
    const response = await requestWithDpopNonce({ url, ...keys, send: async () => {
      sends++; return json({ error: "invalid_token" }, {}, 401);
    } });
    expect(sends).to.equal(1); expect(await response.json()).to.deep.equal({ error: "invalid_token" });
  });

  it("rejects malformed nonce headers instead of replaying", async () => {
    for (const nonce of ["with spaces", "nonascii-é"]) {
      await rejects(() => requestWithDpopNonce({ url, ...keys, send: async () => challenge(nonce) }), "missing a valid DPoP-Nonce");
    }
    const duplicate = challenge(); duplicate.headers.append("DPoP-Nonce", "second");
    await rejects(() => requestWithDpopNonce({ url, ...keys, send: async () => duplicate }), "missing a valid DPoP-Nonce");
  });

  it("redacts HTTP secrets without mutating protocol responses", () => {
    const data = { headers: { "DPoP-Nonce": "nonce", Authorization: "DPoP token" },
      body: { access_token: "token", c_nonce: "credential-nonce", nested: [{ proofs: { jwt: ["secret"] } }], error: "use_dpop_nonce" } };
    const redacted = redactHttpLog(data);
    expect(redacted.headers["DPoP-Nonce"]).to.equal("<redacted>");
    expect(redacted.body.access_token).to.equal("<redacted>"); expect(redacted.body.nested[0].proofs).to.equal("<redacted>");
    expect(redacted.body.error).to.equal("use_dpop_nonce"); expect(data.body.access_token).to.equal("token");
  });

});
