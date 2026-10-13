import { expect } from "chai";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import request from "supertest";
import sinon from "sinon";
import { walletRedisClient } from "../src/lib/cache.js";
import { decodeJwt, decodeProtectedHeader, calculateJwkThumbprint, SignJWT, importJWK } from "jose";
import { Response } from "node-fetch";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { postFormWithAttestationNonceRetry } from "../src/lib/dpopIssuanceTransport.js";
import {
  buildReissuanceBinding,
  diffCredentialAttributes,
  runRefreshTokenReissuance,
  requestWithReissuanceBackoff,
} from "../src/lib/reissuance.js";

const cs01 = "webuild-cs01";
const json = (body, headers = {}, status = 200) => new Response(JSON.stringify(body), { headers, status });

describe("CS-01 refresh re-issuance", () => {
  it("buildReissuanceBinding requires CS-01 profile and refresh token", async () => {
    const keys = await ensureOrCreateEcKeyPair(null);
    expect(
      buildReissuanceBinding({
        profile: cs01,
        refreshToken: "rt-1",
        dpopBinding: keys,
        walletClientId: "wallet-client",
        apiBase: "https://issuer.example",
        issuerMeta: { credential_issuer: "https://issuer.example" },
        tokenEndpoint: "https://issuer.example/token",
        authorizationServerIssuer: "https://issuer.example",
      }),
    ).to.have.property("refreshToken", "rt-1");
    expect(
      buildReissuanceBinding({
        profile: "compatibility",
        refreshToken: "rt-1",
        dpopBinding: keys,
        walletClientId: "wallet-client",
        apiBase: "https://issuer.example",
        issuerMeta: {},
        tokenEndpoint: "https://issuer.example/token",
        authorizationServerIssuer: "https://issuer.example",
      }),
    ).to.equal(null);
  });

  it("diffCredentialAttributes reports payload changes between SD-JWTs", () => {
    const prev = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJnaXZlbl9uYW1lIjoiam9obiIsImZhbWlseV9uYW1lIjoic21pdGgifQ.sig~";
    const next = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJnaXZlbl9uYW1lIjoiam9obiIsImZhbWlseV9uYW1lIjoic210aCJ9.sig~";
    const diff = diffCredentialAttributes(prev, next);
    expect(diff.comparable).to.equal(true);
    expect(diff.changes.some((c) => c.key === "family_name")).to.equal(true);
  });

  it("maps invalid_grant refresh failures to reauthorization_required", async () => {
    const keys = await ensureOrCreateEcKeyPair(null);
    const binding = buildReissuanceBinding({
      profile: cs01,
      refreshToken: "rt-expired",
      dpopBinding: keys,
      walletClientId: "wallet-client",
      apiBase: "https://issuer.example",
      issuerMeta: { credential_issuer: "https://issuer.example", credential_endpoint: "https://issuer.example/credential" },
      tokenEndpoint: "https://issuer.example/token",
      authorizationServerIssuer: "https://issuer.example",
    });
    try {
      await runRefreshTokenReissuance({
        profile: cs01,
        binding,
        configurationId: "VerifiableIdCard",
        httpPostFormWithAttestationNonceRetry: async () =>
          json({ error: "invalid_grant", error_description: "expired" }, {}, 400),
        httpPostJson: async () => json({}),
        fetchImpl: async () => json({}),
        validateAndStoreCredential: async () => {},
      });
      expect.fail("expected reauthorization_required");
    } catch (error) {
      expect(error.errorCode).to.equal("reauthorization_required");
    }
  });

  it("retries refresh with the same refresh_token after use_dpop_nonce", async () => {
    const keys = await ensureOrCreateEcKeyPair(null);
    const binding = buildReissuanceBinding({
      profile: cs01,
      refreshToken: "rt-1",
      dpopBinding: keys,
      walletClientId: "wallet-client",
      apiBase: "https://issuer.example",
      issuerMeta: {
        credential_issuer: "https://issuer.example",
        credential_endpoint: "https://issuer.example/credential",
        nonce_endpoint: "https://issuer.example/nonce",
      },
      tokenEndpoint: "https://issuer.example/token",
      authorizationServerIssuer: "https://issuer.example",
    });
    const refreshBodies = [];
    let tokenSends = 0;
    const sdJwt =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJnaXZlbl9uYW1lIjoiam9obiJ9.sig~";
    await runRefreshTokenReissuance({
      profile: cs01,
      binding,
      configurationId: "VerifiableIdCard",
      httpPostFormWithAttestationNonceRetry: (opts) =>
        postFormWithAttestationNonceRetry({
          ...opts,
          log: () => {},
          buildAttestation: async () => ({ headers: {} }),
          postForm: async (_url, params) => {
            refreshBodies.push(params.refresh_token);
            tokenSends++;
            if (tokenSends === 1) {
              return json({ error: "use_dpop_nonce" }, { "DPoP-Nonce": "as-nonce" }, 400);
            }
            return json({
              access_token: "access",
              token_type: "DPoP",
              refresh_token: "rt-2",
              c_nonce: "cn",
            });
          },
        }),
      httpPostJson: async () => json({ c_nonce: "cn" }),
      fetchImpl: async () => json({ credential: sdJwt }),
      validateAndStoreCredential: async () => {},
    });
    expect(refreshBodies).to.deep.equal(["rt-1", "rt-1"]);
    expect(tokenSends).to.equal(2);
  });
  const fixture = async () => {
    const keys = await ensureOrCreateEcKeyPair(null);
    const binding = buildReissuanceBinding({ profile: cs01, refreshToken: "old", dpopBinding: keys,
      walletClientId: "wallet-client", apiBase: "https://issuer.example",
      issuerMeta: { credential_issuer: "https://issuer.example", credential_endpoint: "https://issuer.example/credential" },
      tokenEndpoint: "https://issuer.example/token", authorizationServerIssuer: "https://issuer.example",
      configurationId: "VerifiableIdCard", trustSessionId: "original-session" });
    const subjectKey = { ...await ensureOrCreateEcKeyPair(null), proofAlg: "ES256", keyRole: "wallet-unit-subject-key", subjectDidJwk: "did:jwk:subject" };
    return { binding, options: { profile: cs01, binding, configurationId: "VerifiableIdCard",
      httpPostFormWithAttestationNonceRetry: async () => json({ access_token: "opaque", token_type: "DPoP", refresh_token: "new", c_nonce: "cn" }),
      buildCredentialProofRequest: async () => ({ credentialRequest: { credential_configuration_id: "VerifiableIdCard" }, subjectKey }),
      fetchImpl: async () => json({ credential: "e30.eyJuYW1lIjoiTmV3In0.sig~" }),
      validateAndStoreCredential: async () => {}, retryOptions: { sleep: async () => {} },
    } };
  };


  it("uses credential_identifier advertised by the refresh response instead of configuration_id", async () => {
    const { options } = await fixture();
    options.httpPostFormWithAttestationNonceRetry = async () => json({ access_token: 'opaque', token_type: 'DPoP',
      refresh_token: 'new', c_nonce: 'nonce', authorization_details: [{ type: 'openid_credential',
        credential_configuration_id: 'VerifiableIdCard', credential_identifiers: ['replacement-identifier'] }] });
    const { buildCredentialProofRequest } = await import('../src/lib/credentialProofBinding.js');
    options.buildCredentialProofRequest = buildCredentialProofRequest;
    let body;
    options.fetchImpl = async (_url, request) => { body = JSON.parse(request.body); return json({ credential: 'e30.e30.sig~' }); };
    await runRefreshTokenReissuance(options);
    expect(body.credential_identifier).to.equal('replacement-identifier');
    expect(body).not.to.have.property('credential_configuration_id');
  });
  it("detects changes in selectively disclosed attributes in credential envelopes", () => {
    const token = (name) => {
      const disclosure = Buffer.from(JSON.stringify(["salt", "name", name])).toString("base64url");
      const hash = createHash("sha256").update(disclosure).digest("base64url");
      const payload = Buffer.from(JSON.stringify({ _sd_alg: "sha-256", _sd: [hash] })).toString("base64url");
      return `e30.${payload}.sig~${disclosure}~`;
    };
    const result = diffCredentialAttributes({ credentials: [{ credential: token("Old") }] }, { credential: token("New") });
    expect(result).to.deep.equal({ comparable: true, changes: [{ key: "name", previous: "Old", next: "New" }] });
  });

  it("persists the rotated token before a credential failure and preserves the old credential", async () => {
    const { binding, options } = await fixture();
    const oldCredential = { credential: "old-credential", metadata: { reissuanceBinding: binding } };
    let wallet = structuredClone(oldCredential);
    options.persistReissuanceBinding = async next => { wallet.metadata.reissuanceBinding = structuredClone(next); };
    options.fetchImpl = async () => { throw new Error("temporary network failure"); };
    try { await runRefreshTokenReissuance(options); expect.fail("expected failure"); }
    catch (error) { expect(error.message).to.equal("temporary network failure"); }
    expect(wallet.credential).to.equal("old-credential");
    expect(wallet.metadata.reissuanceBinding.refreshToken).to.equal("new");
  });

  it("passes the trust session into validation and returns no private refresh binding", async () => {
    const { options } = await fixture();
    options.logSessionId = "trusted-session";
    let validationSession;
    options.validateAndStoreCredential = async (_payload, session) => { validationSession = session; };
    const result = await runRefreshTokenReissuance(options);
    expect(validationSession).to.equal("trusted-session");
    expect(result.issuanceContext).not.to.have.property("reissuanceBinding");
  });

  it("retries temporary refusal with bounded back-off and keeps invalid_grant terminal", async () => {
    const delays = [];
    let calls = 0;
    const refusal = await requestWithReissuanceBackoff(async () => { calls++; return json({ error: "temporarily_unavailable" }, {}, 503); },
      { pollIntervalMs: 10, pollTimeoutMs: 1000, sleep: async ms => { delays.push(ms); } });
    expect(refusal.status).to.equal(503);
    expect(calls).to.equal(3);
    expect(delays).to.deep.equal([10, 20]);
    calls = 0;
    await requestWithReissuanceBackoff(async () => { calls++; return json({ error: "invalid_grant" }, {}, 400); }, { sleep: async () => { throw new Error("must not retry"); } });
    expect(calls).to.equal(1);
  });

  it("recovers from a credential refusal without repeating the refresh grant", async () => {
    const { options } = await fixture();
    let grants = 0, requests = 0;
    const proofNonces = [];
    options.binding.issuerMeta.nonce_endpoint = "https://issuer.example/nonce";
    options.httpPostJson = async () => json({ c_nonce: "replacement-nonce" });
    const buildProof = options.buildCredentialProofRequest;
    options.buildCredentialProofRequest = async args => { proofNonces.push(args.cNonce); return buildProof(args); };
    options.httpPostFormWithAttestationNonceRetry = async () => { grants++; return json({ access_token: "opaque", token_type: "DPoP", refresh_token: "new", c_nonce: "cn" }); };
    options.fetchImpl = async () => ++requests === 1 ? json({ error: "credential_request_denied" }, {}, 400) : json({ credential: "e30.e30.sig~" });
    await runRefreshTokenReissuance(options);
    expect(grants).to.equal(1);
    expect(requests).to.equal(2);
    expect(proofNonces).to.deep.equal(["cn", "replacement-nonce"]);
  });

  it("pre-authorized issuance retains refresh binding for every returned credential identifier", async () => {
    const previousProfile = process.env.WALLET_PROFILE;
    process.env.WALLET_PROFILE = cs01;
    const sandbox = sinon.createSandbox();
    const keys = await ensureOrCreateEcKeyPair(null);
    const signingKey = await importJWK(keys.privateJwk, 'ES256');
    let endpoint, metadata;
    const requested = [], writes = [];
    const issuer = createServer(async (req, res) => {
      res.setHeader('content-type', 'application/json');
      if (req.url.includes('.well-known')) return res.end(JSON.stringify(metadata));
      if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [{ ...keys.publicJwk, kid: 'issuer-key' }] }));
      let raw = '';
      for await (const chunk of req) raw += chunk;
      if (req.url === '/token') return res.end(JSON.stringify({ access_token: 'opaque', token_type: 'DPoP', refresh_token: 'retained-refresh', c_nonce: 'fresh', authorization_details: [{ type: 'openid_credential', credential_configuration_id: 'VerifiableIdCard', credential_identifiers: ['first', 'second'] }] }));
      const body = JSON.parse(raw);
      requested.push(body.credential_identifier);
      const credential = await new SignJWT({ iss: endpoint, vct: 'urn:test:credential', name: body.credential_identifier }).setProtectedHeader({ alg: 'ES256', kid: 'issuer-key' }).setIssuedAt().setExpirationTime('1h').sign(signingKey);
      res.end(JSON.stringify({ credentials: [{ credential: credential + '~' }] }));
    });
    await new Promise(resolve => issuer.listen(0, '127.0.0.1', resolve));
    try {
      endpoint = `http://127.0.0.1:${issuer.address().port}`;
      metadata = { issuer: endpoint, credential_issuer: endpoint, token_endpoint: `${endpoint}/token`, credential_endpoint: `${endpoint}/credential`, jwks_uri: `${endpoint}/jwks`, credential_configurations_supported: { VerifiableIdCard: { format: 'dc+sd-jwt', vct: 'urn:test:credential', proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } } } } };
      sandbox.stub(walletRedisClient, 'get').resolves(null);
      sandbox.stub(walletRedisClient, 'setEx').callsFake(async (key, _ttl, value) => { if (key.startsWith('wallet:credentials:')) writes.push(JSON.parse(value)); return 'OK'; });
      const { app } = await import('../src/server.js?cs01-reissue-regression');
      const offer = { credential_issuer: endpoint, credential_configuration_ids: ['VerifiableIdCard'], grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'code' } } };
      const response = await request(app).post('/issue').send({ issuer: endpoint, credential: 'VerifiableIdCard', offer: `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}` });
      expect(response.status, JSON.stringify(response.body)).to.equal(200);
      expect(requested).to.deep.equal(['first', 'second']);
      expect(writes).to.have.length(2);
      for (const saved of writes) {
        expect(saved.metadata.reissuanceBinding.refreshToken).to.equal('retained-refresh');
        expect(saved.metadata.reissuanceBinding.publicJwk).to.have.property('kty', 'EC');
      }
    } finally {
      sandbox.restore();
      await new Promise(resolve => issuer.close(resolve));
      if (previousProfile === undefined) delete process.env.WALLET_PROFILE; else process.env.WALLET_PROFILE = previousProfile;
    }
  });

  it("the actual /reissue API sends a refresh request and maps invalid_grant", async () => {
    const previousProfile = process.env.WALLET_PROFILE;
    process.env.WALLET_PROFILE = cs01;
    const sandbox = sinon.createSandbox();
    const bodies = [];
    const issuer = createServer(async (req, res) => {
      let body = "";
      for await (const chunk of req) body += chunk;
      bodies.push({ params: Object.fromEntries(new URLSearchParams(body)), headers: req.headers });
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
    });
    await new Promise(resolve => issuer.listen(0, "127.0.0.1", resolve));
    try {
      const { binding } = await fixture();
      binding.tokenEndpoint = `http://127.0.0.1:${issuer.address().port}/token`;
      binding.trustPolicy = { mode: "webuild", profile: "webuild-wp4-pilot" };
      const saved = { credential: "old", metadata: { reissuanceBinding: binding } };
      const savedSessions = [];
      sandbox.stub(walletRedisClient, "setEx").callsFake(async (key, _ttl, value) => { savedSessions.push({ key, session: JSON.parse(value) }); return "OK"; });
      sandbox.stub(walletRedisClient, "get").callsFake(async key => key.startsWith("wallet:credentials:") ? JSON.stringify(saved) : null);
      const { app } = await import("../src/server.js?cs01-reissue-regression");
      const response = await request(app).post("/reissue").send({ configurationId: "VerifiableIdCard" });
      expect(response.status, JSON.stringify(response.body)).to.equal(400);
      expect(response.body.error).to.equal("reauthorization_required");
      expect(bodies).to.have.length(1);
      expect(savedSessions.find(s => s.key === "wallet:test-session:original-session").session.trustPolicy).to.deep.equal(binding.trustPolicy);
      expect(bodies[0].params).to.include({ grant_type: "refresh_token", refresh_token: "old" });
      expect(bodies[0].params).not.to.have.property("dpop_jkt");
      const wia = decodeJwt(bodies[0].headers["oauth-client-attestation"]);
      const proofKey = decodeProtectedHeader(bodies[0].headers.dpop).jwk;
      expect(await calculateJwkThumbprint(wia.cnf.jwk)).to.equal(await calculateJwkThumbprint(binding.publicJwk));
      expect(await calculateJwkThumbprint(proofKey)).to.equal(await calculateJwkThumbprint(binding.publicJwk));
    } finally {
      sandbox.restore();
      await new Promise(resolve => issuer.close(resolve));
      if (previousProfile === undefined) delete process.env.WALLET_PROFILE; else process.env.WALLET_PROFILE = previousProfile;
    }
  });

  it("the actual /reissue API validates and replaces the stored credential and reports changed claims", async () => {
    const previousProfile = process.env.WALLET_PROFILE;
    process.env.WALLET_PROFILE = cs01;
    const sandbox = sinon.createSandbox();
    const keys = await ensureOrCreateEcKeyPair(null);
    const signingKey = await importJWK(keys.privateJwk, "ES256");
    let stored, replacement, endpoint;
    const signCredential = name => new SignJWT({ iss: endpoint, vct: "urn:test:credential", name })
      .setProtectedHeader({ alg: "ES256", kid: "issuer-key" }).setIssuedAt().setExpirationTime("1h").sign(signingKey).then(jwt => jwt + "~");
    const issuer = createServer(async (req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/jwks") return res.end(JSON.stringify({ keys: [{ ...keys.publicJwk, kid: "issuer-key" }] }));
      let body = "";
      for await (const chunk of req) body += chunk;
      if (req.url === "/token") {
        res.end(JSON.stringify({ access_token: "opaque", token_type: "DPoP", refresh_token: "new", c_nonce: "fresh-credential-nonce" }));
      } else {
        const proof = decodeJwt(JSON.parse(body).proofs.jwt[0]);
        expect(proof.nonce).to.equal("fresh-credential-nonce");
        replacement = { credentials: [{ credential: await signCredential("New") }] };
        res.end(JSON.stringify(replacement));
      }
    });
    await new Promise(resolve => issuer.listen(0, "127.0.0.1", resolve));
    try {
      endpoint = `http://127.0.0.1:${issuer.address().port}`;
      const { binding } = await fixture();
      binding.apiBase = endpoint;
      binding.tokenEndpoint = `${endpoint}/token`;
      binding.issuerMeta = { credential_issuer: endpoint, credential_endpoint: `${endpoint}/credential`, jwks_uri: `${endpoint}/jwks`,
        credential_configurations_supported: { VerifiableIdCard: { format: "dc+sd-jwt", vct: "urn:test:credential" } } };
      const originalToken = await signCredential("Old");
      stored = { credential: { credential: originalToken }, metadata: { reissuanceBinding: binding } };
      const writes = [];
      sandbox.stub(walletRedisClient, "get").callsFake(async key => key.startsWith("wallet:credentials:") ? JSON.stringify(stored) : null);
      sandbox.stub(walletRedisClient, "setEx").callsFake(async (key, _ttl, value) => {
        if (key.startsWith("wallet:credentials:")) { stored = JSON.parse(value); writes.push(structuredClone(stored)); }
        return "OK";
      });
      const { app } = await import("../src/server.js?cs01-reissue-regression");
      const response = await request(app).post("/reissue").send({ configurationId: "VerifiableIdCard" });
      expect(response.status, JSON.stringify(response.body)).to.equal(200);
      expect(writes).to.have.length(2);
      expect(writes[0].credential.credential).to.equal(originalToken);
      expect(writes[0].metadata.reissuanceBinding.refreshToken).to.equal("new");
      expect(stored.credential).to.deep.equal(replacement);
      expect(JSON.stringify(stored)).not.to.include(originalToken);
      expect(response.body.result.issuanceContext.attributeDiff.changes).to.deep.equal([{ key: "name", previous: "Old", next: "New" }]);
      expect(response.body.result.issuanceContext).not.to.have.property("reissuanceBinding");
    } finally {
      sandbox.restore();
      await new Promise(resolve => issuer.close(resolve));
      if (previousProfile === undefined) delete process.env.WALLET_PROFILE; else process.env.WALLET_PROFILE = previousProfile;
    }
  });

});
