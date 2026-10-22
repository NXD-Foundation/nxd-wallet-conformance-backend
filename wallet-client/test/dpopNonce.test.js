import { X509Certificate } from "node:crypto";
import { redactHttpLog } from "../src/lib/httpLogRedaction.js";
import { encryptCredentialResponseToJwe } from "../../utils/credentialResponseEncryption.js";
import { prepareCredentialResponseEncryption, parseCredentialResponsePayload } from "../src/lib/credentialResponseEncryption.js";
import { expect } from "chai";
import { Response } from "node-fetch";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { createDPoP, ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { createDpopNonceState, requestWithDpopNonce, isDpopNonceChallenge } from "../src/lib/dpopNonce.js";
import { postCredentialRequest, fetchCredentialNonce, exchangeToken, pollDeferredCredential } from "../src/lib/issuance.js";
import { pollDeferredCredentialIssuance } from "../src/lib/deferredIssuance.js";
import { isDpopBoundAccessToken, computeAthForDpop } from "../utils/tokenUtils.js";
import { createAuthCodeIssuanceHost } from "../src/lib/authCodeIssuanceHost.js";
import { postCredentialAcceptedNotification } from "../src/lib/credentialNotification.js";
import { cs01IssuerMetadata, cs01AuthorizationServerMetadata } from "./fixtures/cs01Fixtures.js";
import { WALLET_PROFILES } from "../src/lib/profile.js";
import { createAttestationChallengeState } from "../src/lib/attestationChallenge.js";
import { serializePendingContext, deserializePendingContext } from "../src/lib/authorizationCodeIssuance.js";

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

describe("DPoP nonce negotiation", () => {
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

  for (const proofMode of ["jwt", "attestation"]) {
    it(`recovers from an empty-body 401 without changing ${proofMode} credential material`, async () => {
      const attempts = [];
      const result = await postCredentialRequest({
        credentialEndpoint: url, credentialRequest: { proofs: { [proofMode]: ["unchanged-proof"] } },
        accessToken: "access-token", tokenBody: { token_type: "DPoP" },
        dpopPrivateJwk: keys.privateJwk, dpopPublicJwk: keys.publicJwk,
        isDpopBoundAccessToken, computeAthForDpop, createDPoP,
        fetchImpl: async (_url, opts) => {
          attempts.push(opts); return attempts.length === 1 ? challenge() : json({ credential: "issued" });
        }, parseCredentialResponsePayload: async (text) => JSON.parse(text),
      });
      expect(result.body.credential).to.equal("issued"); expect(attempts).to.have.length(2);
      expect(attempts[0].body).to.equal(attempts[1].body);
      const proofs = attempts.map((x) => decodeJwt(x.headers.DPoP));
      expect(proofs[0]).not.to.have.property("nonce"); expect(proofs[1].nonce).to.equal("rs-nonce");
      expect(proofs[0].jti).not.to.equal(proofs[1].jti);
      for (const attempt of attempts) {
        await jwtVerify(attempt.headers.DPoP, await importJWK(keys.publicJwk, "ES256"));
        expect(attempt.headers.authorization).to.equal("DPoP access-token");
        expect(decodeJwt(attempt.headers.DPoP).ath).to.equal(computeAthForDpop("access-token"));
        expect(decodeProtectedHeader(attempt.headers.DPoP).jwk).to.deep.equal(keys.publicJwk);
      }
    });
  }

  it("gets fresh c_nonce and carries the independent resource nonce across endpoint hosts", async () => {
    const state = createDpopNonceState();
    const nonce = await fetchCredentialNonce({
      tokenBody: { c_nonce: "legacy" }, nonceEndpoint: "https://nonce.example/nonce",
      dpopNonceState: state, dpopPrivateJwk: keys.privateJwk, dpopPublicJwk: keys.publicJwk,
      resourceServer: "https://issuer.example", accessToken: "secret",
      postJson: async (_url, _body, proof, headers) => {
        expect(headers).not.to.have.property("Authorization"); expect(decodeJwt(proof)).not.to.have.property("ath");
        return json({ c_nonce: "credential-nonce" }, { "DPoP-Nonce": "resource-nonce" });
      },
    });
    expect(nonce.c_nonce).to.equal("credential-nonce");
    await requestWithDpopNonce({ url, state, ...keys, send: async (proof) => {
      expect(decodeJwt(proof).nonce).to.equal("resource-nonce"); return json({});
    } });
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
    const restored = deserializePendingContext(JSON.parse(JSON.stringify(serializePendingContext({ dpopBinding: { ...keys, nonceState: state } }))));
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

  for (const grantType of ["authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"]) {
    it(`composes nonce, attestation and rotation retries for ${grantType}`, async () => {
      const proofs = [], params = [], wiaKeys = [];
      let sends = 0, rotations = 0;
      const result = await exchangeToken({
        tokenEndpoint: "https://issuer.example/token", tokenPayload: { grant_type: grantType, code: "code", client_id: "wallet" },
        authorizationServerIssuer: "https://issuer.example", ensureOrCreateEcKeyPair: async () => keys, createDPoP,
        resolveWiaForParOrToken: async (opts) => { wiaKeys.push(opts.cnfKeyPair.publicJwk); return { wiaHeaders: {} }; },
        challengeState: createAttestationChallengeState(),
        shouldRetryTokenExchangeAfterRotatingWalletProviderKey: (_status, error) => error.error === "invalid_client",
        rotateWalletProviderKeyPair: async () => { rotations++; return true; },
        postForm: async (_url, payload, proof) => {
          proofs.push(decodeJwt(proof)); params.push(payload); sends++;
          if (sends === 1) return json({ error: "use_dpop_nonce" }, { "DPoP-Nonce": "as-nonce" }, 400);
          if (sends === 2) return json({ error: "use_attestation_challenge" }, { "OAuth-Client-Attestation-Challenge": "attestation" }, 400);
          if (sends === 3) return json({ error: "invalid_client" }, {}, 400);
          return json({ access_token: "token", token_type: "DPoP" });
        },
      });
      expect(sends).to.equal(4); expect(rotations).to.equal(1); expect(result.tokenBody.access_token).to.equal("token");
      expect(proofs.slice(1).map((p) => p.nonce)).to.deep.equal(["as-nonce", "as-nonce", "as-nonce"]);
      expect(new Set(proofs.map((p) => p.jti)).size).to.equal(4);
      expect(params.every((p) => JSON.stringify(p) === JSON.stringify(params[0]))).to.equal(true);
      expect(wiaKeys.every((key) => JSON.stringify(key) === JSON.stringify(keys.publicJwk))).to.equal(true);
    });
  }

  it("retries legacy deferred nonce challenges immediately with the original transaction", async () => {
    let sends = 0;
    const result = await pollDeferredCredential({
      deferredEndpoint: url, transactionId: "tx", initialInterval: 0, pollIntervalMs: 1, pollTimeoutMs: 1000,
      accessToken: "token", tokenBody: { token_type: "DPoP" }, dpopPrivateJwk: keys.privateJwk, dpopPublicJwk: keys.publicJwk,
      isDpopBoundAccessToken, computeAthForDpop, createDPoP,
      postJson: async (_url, body, proof) => {
        expect(body.transaction_id).to.equal("tx"); sends++;
        if (sends === 1) return challenge();
        expect(decodeJwt(proof).nonce).to.equal("rs-nonce"); return json({ credential: "issued" });
      }, parseCredentialResponsePayload: async (text) => JSON.parse(text),
    });
    expect(sends).to.equal(2); expect(result.credential).to.equal("issued");
  });

  it("uses the same nonce transport for authorization-code deferred polling", async () => {
    let sends = 0, sleeps = 0;
    const result = await pollDeferredCredentialIssuance({ deferredEndpoint: url, transactionId: "tx", pollTimeoutMs: 1000,
      buildPollRequest: async () => ({ body: { transaction_id: "tx" }, headers: { DPoP: "initial", Authorization: "DPoP token" },
        dpopBinding: { ...keys, nonceState: createDpopNonceState() }, accessToken: "token" }),
      sleep: async () => { sleeps++; }, httpPostJson: async (_url, body, _session, headers) => {
        sends++; expect(body.transaction_id).to.equal("tx");
        if (sends === 1) return challenge();
        expect(decodeJwt(headers.DPoP).nonce).to.equal("rs-nonce"); return json({ credential: "issued" });
      },
    });
    expect(result.credential).to.equal("issued"); expect(sends).to.equal(2); expect(sleeps).to.equal(1);
  });
  it("integrates PAR/token, Nonce Endpoint and credential retries through blocking authorization", async () => {
    const callback = "https://wallet.example/oauth/callback";
    let parParams, parSends = 0, tokenSends = 0;
    const credentialRequests = [], keyHeaders = [], stored = [];
    const host = createAuthCodeIssuanceHost({
      discoverAuthorizationServerMetadata: async () => cs01AuthorizationServerMetadata,
      httpPostForm: async (endpoint, params, _session, proof, headers) => {
        keyHeaders.push(decodeProtectedHeader(proof).jwk);
        expect(decodeJwt(headers["OAuth-Client-Attestation"]).cnf.jwk).to.deep.equal(decodeProtectedHeader(proof).jwk);
        expect(params.redirect_uri).to.equal(callback);
        if (endpoint.endsWith("/par")) {
          parParams = params; parSends++;
          if (parSends === 1) return json({ error: "use_dpop_nonce" }, { "DPoP-Nonce": "par-nonce" }, 400);
          expect(decodeJwt(proof).nonce).to.equal("par-nonce");
          return json({ request_uri: "urn:par:request", expires_in: 300 }, {}, 201);
        }
        tokenSends++;
        expect(decodeJwt(proof).nonce).to.equal(tokenSends === 1 ? "par-nonce" : "token-nonce");
        if (tokenSends === 1) return json({ error: "use_dpop_nonce" }, { "DPoP-Nonce": "token-nonce" }, 400);
        return json({ access_token: "token", token_type: "DPoP", c_nonce: "legacy" });
      },
      httpPostJson: async (endpoint, _body, _session, headers) => {
        expect(endpoint).to.equal(cs01IssuerMetadata.nonce_endpoint);
        expect(decodeJwt(headers.DPoP)).not.to.have.property("nonce");
        return json({ c_nonce: "credential-nonce" }, { "DPoP-Nonce": "initial-resource-nonce" });
      },
      fetchImpl: async (endpoint, opts) => {
        if (endpoint.includes("/authorize")) return new Response(null, { status: 302,
          headers: { Location: `${callback}?code=code&state=${parParams.state}` } });
        credentialRequests.push(opts);
        expect(decodeJwt(opts.headers.DPoP).nonce).to.equal(credentialRequests.length === 1 ? "initial-resource-nonce" : "rs-nonce");
        const body = JSON.parse(opts.body);
        expect(decodeJwt(body.proofs.jwt[0]).nonce).to.equal("credential-nonce");
        const kaJwt = decodeProtectedHeader(body.proofs.jwt[0]).key_attestation;
        const kaHeader = decodeProtectedHeader(kaJwt);
        const certificate = new X509Certificate(Buffer.from(kaHeader.x5c[0], "base64"));
        await jwtVerify(kaJwt, certificate.publicKey);
        expect(decodeJwt(kaJwt).nonce).to.equal("credential-nonce");
        return credentialRequests.length === 1 ? challenge() : json({ credential: "issued" });
      }, validateAndStoreCredential: async (value) => stored.push(value), sleep: async () => {},
    });
    const result = await host.getAuthCodeIssuance().runAuthorizationCodeIssuance({
      profile: WALLET_PROFILES.WEBUILD_CS01, walletClientId: "wallet", apiBase: cs01IssuerMetadata.credential_issuer,
      issuerMeta: { ...cs01IssuerMetadata }, configurationId: "VerifiableIdCard", redirectUri: callback,
    });
    expect(result.credential).to.equal("issued"); expect(parSends).to.equal(2); expect(tokenSends).to.equal(2);
    expect(credentialRequests[0].body).to.equal(credentialRequests[1].body);
    expect(keyHeaders.every((key) => JSON.stringify(key) === JSON.stringify(keyHeaders[0]))).to.equal(true);
    expect(stored).to.have.length(1);
  });

  it("retries notification nonce challenges and refreshes DPoP on a subsequent 5xx retry", async () => {
    const proofs = [];
    await postCredentialAcceptedNotification({ notificationEndpoint: url, notificationId: "id", accessToken: "token",
      tokenBody: { token_type: "DPoP" }, dpopPrivateJwk: keys.privateJwk, dpopPublicJwk: keys.publicJwk,
      fetchImpl: async (_endpoint, opts) => {
        proofs.push(decodeJwt(opts.headers.DPoP));
        if (proofs.length === 1) return challenge();
        expect(proofs.at(-1).nonce).to.equal("rs-nonce");
        return proofs.length === 2 ? json({}, {}, 503) : json({});
      },
    });
    expect(proofs).to.have.length(3); expect(new Set(proofs.map((p) => p.jti)).size).to.equal(3);
  });

  it("retains encrypted credential response handling after a nonce retry", async () => {
    const metadata = { credential_response_encryption: {
      alg_values_supported: ["ECDH-ES"], enc_values_supported: ["A128GCM"],
    } };
    const encryption = await prepareCredentialResponseEncryption(metadata);
    const credential = { credentials: [{ credential: "encrypted-issued" }] };
    const jwe = await encryptCredentialResponseToJwe(credential, encryption.credential_response_encryption, metadata);
    let sends = 0;
    const result = await postCredentialRequest({ credentialEndpoint: url,
      credentialRequest: { proofs: { jwt: ["proof"] }, credential_response_encryption: encryption.credential_response_encryption },
      accessToken: "token", tokenBody: { token_type: "DPoP" }, dpopPrivateJwk: keys.privateJwk, dpopPublicJwk: keys.publicJwk,
      isDpopBoundAccessToken, computeAthForDpop, createDPoP,
      fetchImpl: async () => ++sends === 1 ? challenge() : new Response(jwe, { headers: { "Content-Type": "application/jwt" } }),
      parseCredentialResponsePayload: (text, type) => parseCredentialResponsePayload(text, type, encryption.privateKey),
    });
    expect(sends).to.equal(2); expect(result.body).to.deep.equal(credential);
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
