import { cs01IssuerMetadata, cs01AuthorizationServerMetadata } from "./fixtures/cs01Fixtures.js";
import { expect } from "chai";
import { Response } from "node-fetch";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, CompactEncrypt, compactDecrypt } from "jose";
import { createDpopNonceState } from "../src/lib/dpopNonce.js";
import { postFormWithAttestationNonceRetry, requestWithResourceDpop, requestCredentialNonce } from "../src/lib/dpopIssuanceTransport.js";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { createWalletUnitAttestationClientAuth } from "../src/lib/walletUnitAttestation.js";
import { createAttestationChallengeState } from "../src/lib/attestationChallenge.js";
import { serializePendingContext, deserializePendingContext, createAuthorizationCodeIssuance } from "../src/lib/authorizationCodeIssuance.js";
import { pollDeferredCredentialIssuance } from "../src/lib/deferredIssuance.js";
import { assertPreAuthorizedAllowed } from "../src/lib/profile.js";
const cs01 = "webuild-cs01";
const json = (body, headers = {}, status = 200) => new Response(JSON.stringify(body), { headers, status });
const rsChallenge = () => new Response(null, { status: 401, headers: { "WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "resource" } });

describe("WE BUILD issuance nonce integration", () => {
  it("retains separate WIA and DPoP keys across PAR, handoff and token nonce/attestation retries", async () => {
    const state = createDpopNonceState(); state.authorizationServer = "https://issuer.example";
    const challengeState = createAttestationChallengeState();
    const proofJtis = [], popJtis = [], wias = [];
    const build = (url) => async (session) => createWalletUnitAttestationClientAuth({
      profile: cs01, clientId: "wallet-client", endpointAudience: url,
      authorizationServerIssuer: "https://issuer.example", challenge: challengeState.consume(), ...session,
    });
    let parSends = 0;
    const par = await postFormWithAttestationNonceRetry({ url: "https://issuer.example/par", params: { response_type: "code" },
      nonceState: state, challengeState, buildAttestation: build("https://issuer.example/par"),
      postForm: async (_url, _body, proof, headers) => {
        wias.push(headers["OAuth-Client-Attestation"]); proofJtis.push(decodeJwt(proof).jti);
        popJtis.push(decodeJwt(headers["OAuth-Client-Attestation-PoP"]).jti);
        return ++parSends === 1 ? json({ error: "use_dpop_nonce" }, { "DPoP-Nonce": "par-nonce" }, 400) : json({ request_uri: "urn:par:1" });
      },
    });
    const pending = deserializePendingContext(JSON.parse(JSON.stringify(serializePendingContext({ sessionClientAttestation: par.sessionClientAttestation }))));
    const session = pending.sessionClientAttestation;
    let tokenSends = 0;
    await postFormWithAttestationNonceRetry({ url: "https://issuer.example/token", params: { grant_type: "authorization_code", code: "code", code_verifier: "verifier" },
      cnfKeyPair: session.cnfKeyPair, dpopKeyPair: session.dpopKeyPair, reuseAttestationJwt: session.attestationJwt, nonceState: session.nonceState,
      challengeState, buildAttestation: build("https://issuer.example/token"),
      postForm: async (_url, body, proof, headers) => {
        expect(body.code).to.equal("code"); expect(body.code_verifier).to.equal("verifier");
        wias.push(headers["OAuth-Client-Attestation"]); proofJtis.push(decodeJwt(proof).jti);
        popJtis.push(decodeJwt(headers["OAuth-Client-Attestation-PoP"]).jti);
        const publicJwk = decodeJwt(wias.at(-1)).cnf.jwk;
        expect(decodeProtectedHeader(proof).jwk).to.deep.equal(session.dpopKeyPair.publicJwk);
        expect(decodeProtectedHeader(proof).jwk).not.to.deep.equal(publicJwk);
        await jwtVerify(proof, await importJWK(session.dpopKeyPair.publicJwk, "ES256"));
        await jwtVerify(headers["OAuth-Client-Attestation-PoP"], await importJWK(publicJwk, "ES256"));
        tokenSends++;
        if (tokenSends === 1) { expect(decodeJwt(proof).nonce).to.equal("par-nonce"); return json({ error: "use_dpop_nonce" }, { "DPoP-Nonce": "token-nonce" }, 400); }
        if (tokenSends === 2) return json({ error: "use_attestation_challenge" }, { "OAuth-Client-Attestation-Challenge": "attestation" }, 400);
        expect(decodeJwt(proof).nonce).to.equal("token-nonce");
        expect(decodeJwt(headers["OAuth-Client-Attestation-PoP"]).challenge).to.equal("attestation");
        return json({ access_token: "token", token_type: "DPoP" });
      },
    });
    expect(new Set(wias).size).to.equal(1); expect(new Set(proofJtis).size).to.equal(5); expect(new Set(popJtis).size).to.equal(5);
  });

  it("uses the same recovery for permitted pre-authorized grants without changing grant fields", async () => {
    assertPreAuthorizedAllowed(cs01, { env: { CS01_DISABLE_PRE_AUTHORIZED: "false" } });
    const binding = await ensureOrCreateEcKeyPair(null);
    const params = { grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": "code", tx_code: "1234" };
    let sends = 0;
    await postFormWithAttestationNonceRetry({ url: "https://issuer.example/token", params, cnfKeyPair: binding,
      buildAttestation: async () => ({ headers: { "OAuth-Client-Attestation": "wia" } }),
      postForm: async (_url, body, proof) => { expect(body).to.deep.equal(params); return ++sends === 1 ? json({ error: "use_dpop_nonce" }, { "DPoP-Nonce": "as" }, 400) : json({ access_token: "token" }); },
    });
    expect(sends).to.equal(2);
  });

  it("captures independent c_nonce/resource nonce and preserves multiple credential bodies", async () => {
    const binding = { ...await ensureOrCreateEcKeyPair(null), nonceState: createDpopNonceState() };
    binding.nonceState.resourceServer = "https://issuer.example";
    const nonce = await requestCredentialNonce({ url: "https://nonce.example/nonce", binding, send: async (proof) => {
      expect(decodeJwt(proof)).not.to.have.property("ath");
      return json({ c_nonce: "credential" }, { "DPoP-Nonce": "initial" });
    } });
    expect((await nonce.json()).c_nonce).to.equal("credential");
    for (const target of ["first", "second"]) {
      const body = JSON.stringify({ credential_identifier: target, proofs: { jwt: ["unchanged-credential-proof"] } });
      let sends = 0;
      const response = await requestWithResourceDpop({ url: "https://issuer.example/credential", binding, profile: cs01,
        tokenBody: { token_type: "DPoP" }, accessToken: "token", send: async (proof) => {
          sends++; expect(JSON.parse(body).credential_identifier).to.equal(target);
          if (sends === 1) return rsChallenge();
          expect(decodeJwt(proof).nonce).to.equal("resource"); return json({ credential: target });
        },
      });
      expect((await response.json()).credential).to.equal(target); expect(sends).to.equal(2);
    }
  });

  it("keeps compatibility Bearer requests and rejects CS01 bearer tokens", async () => {
    const binding = {};
    let sends = 0;
    await requestWithResourceDpop({ url: "https://issuer.example/credential", binding, profile: "compatibility", accessToken: "token", tokenBody: { token_type: "Bearer" },
      send: async (proof) => { sends++; expect(proof).to.equal(null); return json({}); } });
    try { await requestWithResourceDpop({ url: "https://issuer.example/credential", binding, profile: cs01, accessToken: "token", tokenBody: { token_type: "Bearer" }, send: async () => json({}) }); expect.fail("expected rejection"); }
    catch (error) { expect(error.message).to.include("not DPoP-bound"); }
    expect(sends).to.equal(1);
  });

  it("recovers during deferred polling without changing its interval or transaction", async () => {
    const binding = { ...await ensureOrCreateEcKeyPair(null), nonceState: createDpopNonceState() };
    let sleeps = 0, sends = 0;
    const result = await pollDeferredCredentialIssuance({ deferredEndpoint: "https://issuer.example/deferred", transactionId: "tx", pollTimeoutMs: 1000,
      buildPollRequest: async () => ({ body: { transaction_id: "tx" }, headers: { Authorization: "DPoP token" }, profile: cs01, dpopBinding: binding, tokenBody: { token_type: "DPoP" }, accessToken: "token" }),
      sleep: async () => { sleeps++; }, httpPostJson: async (_url, body, _session, headers) => {
        expect(body.transaction_id).to.equal("tx"); sends++;
        if (sends === 1) return rsChallenge(); expect(decodeJwt(headers.DPoP).nonce).to.equal("resource"); return json({ credential: "issued" });
      },
    });
    expect(result.credential).to.equal("issued"); expect(sleeps).to.equal(1); expect(sends).to.equal(2);
  });

  it("retains encrypted credential response parsing following a nonce retry", async () => {
    const binding = await ensureOrCreateEcKeyPair(null);
    const encryptionKey = new Uint8Array(16).fill(7);
    const payload = { credentials: [{ credential: "issued" }] };
    const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
      .setProtectedHeader({ alg: "dir", enc: "A128GCM" }).encrypt(encryptionKey);
    let sends = 0;
    const response = await requestWithResourceDpop({ url: "https://issuer.example/credential", binding, profile: cs01, tokenBody: { token_type: "DPoP" }, accessToken: "token",
      send: async () => ++sends === 1 ? rsChallenge() : new Response(jwe, { headers: { "content-type": "application/jwt" } }),
    });
    const decrypted = await compactDecrypt(await response.text(), encryptionKey);
    expect(JSON.parse(new TextDecoder().decode(decrypted.plaintext))).to.deep.equal(payload);
  });
  it("runs the existing authorization-code service through PAR, token and credential challenges", async () => {
    let params, parSends = 0, tokenSends = 0;
    const requests = [], wias = [], stored = [];
    const callback = "openid4vp://"; // Preserve the WE BUILD callback policy.
    const flow = createAuthorizationCodeIssuance({
      discoverAuthorizationServerMetadata: async () => cs01AuthorizationServerMetadata,
      httpPostFormWithAttestationChallengeRetry: async (options) => postFormWithAttestationNonceRetry({
        ...options,
        buildAttestation: (session) => createWalletUnitAttestationClientAuth({
          ...options, ...session, challenge: options.challengeState.consume(),
        }),
        postForm: async (url, body, proof, headers) => {
          expect(body.redirect_uri).to.equal(callback); wias.push(headers["OAuth-Client-Attestation"]);
          if (url.endsWith("/par")) {
            params = body;
            return ++parSends === 1 ? json({ error: "use_dpop_nonce" }, { "DPoP-Nonce": "par" }, 400)
              : json({ request_uri: "urn:par:1", expires_in: 300 }, {}, 201);
          }
          tokenSends++;
          expect(decodeJwt(proof).nonce).to.equal(tokenSends === 1 ? "par" : "token");
          return tokenSends === 1 ? json({ error: "use_dpop_nonce" }, { "DPoP-Nonce": "token" }, 400)
            : json({ access_token: "token", token_type: "DPoP" });
        },
      }),
      httpPostJson: async (_url, _body, _session, headers) => {
        expect(decodeJwt(headers.DPoP)).not.to.have.property("nonce");
        return json({ c_nonce: "credential-nonce" }, { "DPoP-Nonce": "initial" });
      },
      fetchImpl: async (url, options) => {
        if (url.includes("/authorize")) return new Response(null, { status: 302, headers: {
          location: `${callback}?code=code&state=${params.state}`,
        } });
        requests.push(options);
        expect(decodeJwt(JSON.parse(options.body).proofs.jwt[0]).nonce).to.equal("credential-nonce");
        expect(decodeJwt(options.headers.DPoP).nonce).to.equal(requests.length === 1 ? "initial" : "resource");
        return requests.length === 1 ? rsChallenge() : json({ credential: "issued" });
      },
      validateAndStoreCredential: async (value) => stored.push(value),
      wrapIssuanceResult: (credential) => credential, sleep: async () => {},
      issueCredentialTargets: async () => { throw new Error("unexpected multi-target dispatch"); },
    });
    const result = await flow.runAuthorizationCodeIssuance({ profile: cs01, walletClientId: "wallet-client",
      apiBase: cs01IssuerMetadata.credential_issuer, issuerMeta: { ...cs01IssuerMetadata },
      configurationId: "VerifiableIdCard", redirectUri: callback,
    });
    expect(result.credential).to.equal("issued"); expect(parSends).to.equal(2); expect(tokenSends).to.equal(2);
    expect(new Set(wias).size).to.equal(1); expect(requests[0].body).to.equal(requests[1].body); expect(stored).to.have.length(1);
  });

  it("retains refresh binding when an authorization-code token returns multiple credential identifiers", async () => {
    let params, storageMetadata, binding;
    const flow = createAuthorizationCodeIssuance({
      discoverAuthorizationServerMetadata: async () => cs01AuthorizationServerMetadata,
      httpPostFormWithAttestationChallengeRetry: options => postFormWithAttestationNonceRetry({
        ...options,
        buildAttestation: session => createWalletUnitAttestationClientAuth({ ...options, ...session }),
        postForm: async (url, body) => {
          if (url.endsWith('/par')) { params = body; return json({ request_uri: 'urn:par:multi', expires_in: 300 }); }
          return json({ access_token: 'opaque', token_type: 'DPoP', refresh_token: 'retained-refresh', c_nonce: 'cn',
            authorization_details: [{ type: 'openid_credential', credential_configuration_id: 'VerifiableIdCard',
              credential_identifiers: ['first', 'second'] }] });
        },
      }),
      fetchImpl: async () => new Response(null, { status: 302, headers: { location: `openid4vp://?code=code&state=${params.state}` } }),
      issueCredentialTargets: async options => {
        storageMetadata = options.metadata;
        binding = options.dpopBinding;
        return { credentials: [{ credential: 'first' }, { credential: 'second' }], proofBindings: [{}] };
      },
      httpPostJson: async () => json({}), validateAndStoreCredential: async () => {},
      wrapIssuanceResult: credential => credential, sleep: async () => {},
    });
    const result = await flow.runAuthorizationCodeIssuance({ profile: cs01, walletClientId: 'wallet-client',
      apiBase: cs01IssuerMetadata.credential_issuer, issuerMeta: { ...cs01IssuerMetadata },
      configurationId: 'VerifiableIdCard', redirectUri: 'openid4vp://' });
    expect(result.credentials).to.have.length(2);
    expect(storageMetadata.reissuanceBinding.refreshToken).to.equal('retained-refresh');
    expect(storageMetadata.reissuanceBinding.publicJwk).to.deep.equal(binding.publicJwk);
    expect(storageMetadata.refreshToken.present).to.equal(true);
  });

});
