import { expect } from "chai";
import { SignJWT, importPKCS8 } from "jose";
import { encodeRegistrationCertificate } from "../../utils/wrprc.js";
import {
  credentialMatchesRequest,
  credentialTypeFromJwtVcPayload,
  enforceIssuedCredentialTrust,
  enforceVerifierPresentationTrust,
  resolveIssuerRole,
  assertVerifierCertificateBinding,
  assertVerifierAttestationBinding,
  authorizeVerifierRegistrationScope,
  registrationCredentials,
  parseVerifierInfo,
  setWalletTrustSessionStorageForTests,
} from "../src/lib/trustFramework.js";
import {
  clearTrustResolverForTests,
  setTrustResolverForTests,
} from "../../utils/trustFrameworkPolicy.js";
import fs from "node:fs/promises";
import sinon from "sinon";
import forge from "node-forge";
import { computeX509HashClientIdFromLeafCertBase64 } from "../../utils/cs02ClientIdBinding.js";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TRUST_FIXTURE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../tests/fixtures/trust/webuild-wp4/keys");

describe("wallet WE BUILD trust framework helpers", () => {
  afterEach(() => {
    clearTrustResolverForTests();
    setWalletTrustSessionStorageForTests(null);
  });
  it("maps only explicitly approved credential types to provider roles", async () => {
    expect(await resolveIssuerRole({ vct: "urn:eu.europa.ec.eudi:pid:1" })).to.equal("pid-provider");
    expect(await resolveIssuerRole({ doctype: "eu.europa.ec.av.1" })).to.equal("pub-eaa-provider");
    expect(await resolveIssuerRole({ vct: "urn:example:unknown" })).to.equal(null);
  });

  it("extracts conventional JWT VC type for trust scope evaluation", () => {
    expect(credentialTypeFromJwtVcPayload({
      vc: { type: ["VerifiableCredential", "UniversityCredential"] },
    })).to.equal("UniversityCredential");
    expect(credentialTypeFromJwtVcPayload({ credential_type: "PortableDocument" })).to.equal("PortableDocument");
  });

  it("requires the RP registration record to cover format, type, and every requested claim", () => {
    const registered = {
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eu.europa.ec.eudi:pid:1"] },
      claims: [{ path: ["family_name"] }, { path: ["given_name"] }],
    };
    expect(credentialMatchesRequest(registered, {
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eu.europa.ec.eudi:pid:1"] },
      claims: [{ path: ["family_name"] }],
    })).to.equal(true);
    expect(credentialMatchesRequest(registered, {
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eu.europa.ec.eudi:pid:1"] },
      claims: [{ path: ["birth_date"] }],
    })).to.equal(false);
    expect(credentialMatchesRequest(registered, {
      format: "dc+sd-jwt",
      meta: {},
      claims: [{ path: ["family_name"] }],
    })).to.equal(false);
  });

  it("normalizes JSON-encoded TS5 registration claim paths", () => {
    expect(credentialMatchesRequest({
      format: "dc+sd-jwt",
      meta: "{\"vct_values\":[\"urn:eu.europa.ec.eudi:pid:1\"]}",
      claims: [{ path: "[\"family_name\"]" }],
    }, {
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eu.europa.ec.eudi:pid:1"] },
      claims: [{ path: ["family_name"] }],
    })).to.equal(true);
  });

  it("reads TS5 credential authorization from a single unambiguous intended-use record", () => {
    const registered = registrationCredentials({
      intendedUse: [{
        credentials: [{
          format: "dc+sd-jwt",
          meta: { vct_values: ["urn:eu.europa.ec.eudi:pid:1"] },
          claims: [{ path: ["family_name"] }],
        }],
      }],
    });
    expect(registered).to.have.length(1);
    expect(credentialMatchesRequest(registered[0], {
      format: "dc+sd-jwt",
      meta: { vct_values: ["urn:eu.europa.ec.eudi:pid:1"] },
      claims: [{ path: ["family_name"] }],
    })).to.equal(true);
  });

  it("treats the local issuer role map as a lookup hint when credential scope is undeclared", async () => {
    const sessions = new Map();
    setWalletTrustSessionStorageForTests({
      get: async (key) => sessions.get(key) || null,
      set: async (key, value) => sessions.set(key, value),
    });
    sessions.set("wallet:test-session:undeclared-issuer-scope", JSON.stringify({
      sessionId: "undeclared-issuer-scope",
      status: "pending",
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    }));
    const resolve = sinon.stub().callsFake(({ role }) => Promise.resolve({
      trusted: role === "pub-eaa-provider",
      state: role === "pub-eaa-provider" ? "trusted" : "not_trusted",
      reasonCode: role === "pub-eaa-provider" ? "TRUSTED" : "ENTITY_NOT_LISTED",
      evidence: { role },
    }));
    setTrustResolverForTests({ resolve });
    const cert = await fs.readFile(path.join(TRUST_FIXTURE_DIR, "pid.crt"), "utf8");
    const x5c = [Buffer.from(cert.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64").toString("base64")];
    await enforceIssuedCredentialTrust({
      sessionId: "undeclared-issuer-scope",
      payload: { iss: "issuer.example", vct: "urn:eu.europa.ec.eudi:pid:1" },
      header: { x5c },
      format: "dc+sd-jwt",
      vct: "urn:eu.europa.ec.eudi:pid:1",
    });
    expect(resolve.callCount).to.equal(2);
    expect(JSON.parse(sessions.get("wallet:test-session:undeclared-issuer-scope")).sessionContext.trust.decisions[0].evidence.scopeOmission.code)
      .to.equal("TRUST_SCOPE_NOT_DECLARED");
  });

  it("rejects a JWT VC whose presented x5c did not verify its signature", async () => {
    const sessions = new Map();
    setWalletTrustSessionStorageForTests({
      get: async (key) => sessions.get(key) || null,
      set: async (key, value) => sessions.set(key, value),
    });
    sessions.set("wallet:test-session:unverified-jwt-vc", JSON.stringify({
      sessionId: "unverified-jwt-vc",
      status: "pending",
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    }));
    try {
      await enforceIssuedCredentialTrust({
        sessionId: "unverified-jwt-vc",
        payload: { vc: { type: ["VerifiableCredential", "UniversityCredential"] } },
        header: { x5c: ["attacker-controlled-header"] },
        format: "jwt_vc_json",
        vct: "UniversityCredential",
        trustEvidenceBound: false,
      });
      expect.fail("Expected unverified JWT VC rejection");
    } catch (error) {
      expect(error.errorCode).to.equal("CREDENTIAL_SIGNATURE_UNVERIFIED");
    }
  });

  it("rejects an undeclared verifier registration scope and explicit mismatches", () => {
    expect(authorizeVerifierRegistrationScope({
      registration: { intendedUse: [] },
      requested: [{ format: "dc+sd-jwt", meta: { vct_values: ["pilot-vct"] }, claims: [] }],
    })).to.deep.include({ authorized: false });
    expect(authorizeVerifierRegistrationScope({
      registration: { credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["other-vct"] }, claims: [] }] },
      requested: [{ format: "dc+sd-jwt", meta: { vct_values: ["pilot-vct"] }, claims: [] }],
    })).to.deep.include({ authorized: false });
    expect(authorizeVerifierRegistrationScope({
      registration: {
        credentials: [
          { format: "dc+sd-jwt", meta: { vct_values: ["pilot-vct"] }, claims: [] },
          { format: "dc+sd-jwt", meta: {}, claims: [] },
        ],
      },
      requested: [{ format: "dc+sd-jwt", meta: {}, claims: [] }],
    })).to.deep.include({ authorized: false });
  });

  it("requires an X.509 verifier certificate to have both a matching SAN and an entity identifier", async () => {
    const cert = await fs.readFile(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../x509EC/client_certificate.crt"), "utf8");
    expect(() => assertVerifierCertificateBinding({
      clientId: "x509_san_dns:dev-i4mlab.aegean.gr",
      certificatePem: cert,
      entityId: "pilot-verifier-001",
    })).not.to.throw();
    expect(() => assertVerifierCertificateBinding({
      clientId: "x509_san_dns:unrelated.example",
      certificatePem: cert,
      entityId: "pilot-verifier-001",
    })).to.throw("SAN does not match");
    expect(() => assertVerifierCertificateBinding({
      clientId: "x509_san_dns:dev-i4mlab.aegean.gr",
      certificatePem: cert,
      entityId: null,
    })).to.throw("missing an entity identifier");
  });

  it("requires verifier-attestation JWT subject to match the client ID suffix", async () => {
    const now = Math.floor(Date.now() / 1000);
    const part = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const makeAttestation = (sub) => [
      part({ alg: "ES256", typ: "JWT" }),
      part({ iss: "https://attester.example", sub, iat: now - 5, exp: now + 300 }),
      "signature",
    ].join(".");
    await assertVerifierAttestationBinding({
      clientId: "verifier_attestation:pilot-verifier-001",
      requestHeader: { jwt: makeAttestation("pilot-verifier-001") },
    });
    try {
      await assertVerifierAttestationBinding({
        clientId: "verifier_attestation:pilot-verifier-001",
        requestHeader: { jwt: makeAttestation("other-verifier") },
      });
      expect.fail("Expected client-unbound verifier attestation rejection");
    } catch (error) {
      expect(error.message).to.include("not bound");
    }
  });

  it("enforces issuer trust only for an opted-in wallet session and persists its decision", async () => {
    const sessions = new Map();
    setWalletTrustSessionStorageForTests({
      get: async (key) => sessions.get(key) || null,
      set: async (key, value) => sessions.set(key, value),
    });
    sessions.set("wallet:test-session:trusted-session", JSON.stringify({
      sessionId: "trusted-session",
      status: "pending",
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    }));
    const resolve = sinon.stub().resolves({ trusted: true, state: "trusted", reasonCode: "TRUSTED", evidence: {} });
    setTrustResolverForTests({ resolve });
    const cert = await fs.readFile(path.join(TRUST_FIXTURE_DIR, "pid.crt"), "utf8");
    const x5c = [Buffer.from(cert.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64").toString("base64")];
    await enforceIssuedCredentialTrust({
      sessionId: "trusted-session",
      payload: { iss: "issuer.example", vct: "urn:eu.europa.ec.eudi:pid:1" },
      header: { x5c },
      format: "dc+sd-jwt",
      vct: "urn:eu.europa.ec.eudi:pid:1",
    });
    expect(resolve.firstCall.args[0].role).to.equal("pid-provider");
    expect(JSON.parse(sessions.get("wallet:test-session:trusted-session")).sessionContext.trust.decisions).to.have.length(1);
  });

  it("rejects an opted-in X.509 verifier whose WRPAC lacks an identity for WRPRC binding", async () => {
    const sessions = new Map();
    setWalletTrustSessionStorageForTests({
      get: async (key) => sessions.get(key) || null,
      set: async (key, value) => sessions.set(key, value),
    });
    sessions.set("wallet:test-session:vp-session", JSON.stringify({
      sessionId: "vp-session",
      status: "pending",
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    }));
    const cert = await fs.readFile(path.join(TRUST_FIXTURE_DIR, "pid.crt"), "utf8");
    const x5c = [Buffer.from(cert.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64").toString("base64")];
    try {
      await enforceVerifierPresentationTrust({
        sessionId: "vp-session",
        requestHeader: { x5c },
        requestPayload: {
          client_id: "x509_san_dns:verifier.example",
          dcql_query: {
            credentials: [{
              format: "dc+sd-jwt",
              meta: { vct_values: ["urn:eu.europa.ec.eudi:pid:1"] },
              claims: [],
            }],
          },
        },
      });
      expect.fail("Expected trust enforcement to reject an unbindable verifier certificate");
    } catch (error) {
      expect(error.message).to.include("missing an entity identifier");
    }
  });

  it("rejects PEX and unscoped verifier requests when trust enforcement is enabled", async () => {
    const sessions = new Map();
    setWalletTrustSessionStorageForTests({
      get: async (key) => sessions.get(key) || null,
      set: async (key, value) => sessions.set(key, value),
    });
    sessions.set("wallet:test-session:pex-session", JSON.stringify({
      sessionId: "pex-session",
      status: "pending",
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    }));
    for (const requestPayload of [
      { client_id: "x509_san_dns:verifier.example", presentation_definition: { id: "legacy-pex" } },
      { client_id: "x509_san_dns:verifier.example" },
    ]) {
      try {
        await enforceVerifierPresentationTrust({ sessionId: "pex-session", requestHeader: {}, requestPayload });
        expect.fail("Expected non-DCQL request rejection");
      } catch (error) {
        expect(error.message).to.include("non-empty dcql_query.credentials");
      }
    }
  });


  it("rejects hash verifier trust evidence that did not verify the request", async () => {
    setWalletTrustSessionStorageForTests({
      get: async () => JSON.stringify({ trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } }),
      set: async () => {},
    });
    let failure;
    try {
      await enforceVerifierPresentationTrust({
        sessionId: "hash-unbound",
        requestHeader: {},
        requestPayload: { client_id: "x509_hash:unbound" },
        trustEvidenceBound: false,
      });
    } catch (error) { failure = error; }
    expect(failure?.message).to.include("WRPAC x5c certificate to verify");
  });

  it("rejects an untrusted hash verifier through WRPAC evaluation instead of the DID bypass", async () => {
    const sessions = new Map([["wallet:test-session:hash-untrusted", JSON.stringify({
      sessionId: "hash-untrusted", status: "pending",
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    })]]);
    setWalletTrustSessionStorageForTests({
      get: async key => sessions.get(key),
      set: async (key, value) => sessions.set(key, value),
    });
    // Give the fixture an entity identifier so the test reaches certificate trust evaluation.
    const certificate = forge.pki.certificateFromPem(await fs.readFile(path.join(TRUST_FIXTURE_DIR, "pid.crt"), "utf8"));
    certificate.setSubject([...certificate.subject.attributes, { name: "serialNumber", value: "test-verifier-001" }]);
    certificate.sign(forge.pki.privateKeyFromPem(await fs.readFile(path.join(TRUST_FIXTURE_DIR, "pid.key"), "utf8")), forge.md.sha256.create());
    const leaf = forge.pki.certificateToPem(certificate).replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const resolve = sinon.stub().resolves({ trusted: false, state: "not_trusted", reasonCode: "ENTITY_NOT_LISTED" });
    setTrustResolverForTests({ resolve });
    let failure;
    try {
      await enforceVerifierPresentationTrust({
        sessionId: "hash-untrusted", requestHeader: { x5c: [leaf] },
        requestPayload: {
          client_id: computeX509HashClientIdFromLeafCertBase64(leaf),
          dcql_query: { credentials: [{ format: "dc+sd-jwt", meta: { vct_values: ["urn:eu.europa.ec.eudi:pid:1"] }, claims: [] }] },
        },
      });
    } catch (error) { failure = error; }
    expect(failure?.message).to.include("Verifier access certificate trust rejected: ENTITY_NOT_LISTED");
    expect(resolve.firstCall.args[0].role).to.equal("wrpac-provider");
    expect(resolve.firstCall.args[0].presentedIdentity.entityId).to.equal("test-verifier-001");
    expect(JSON.parse(sessions.get("wallet:test-session:hash-untrusted")).trustDecision.trusted).to.equal(false);
  });

  it("rejects verifier trust evidence when the WRPAC x5c did not verify the request", async () => {
    const sessions = new Map();
    setWalletTrustSessionStorageForTests({
      get: async (key) => sessions.get(key) || null,
      set: async (key, value) => sessions.set(key, value),
    });
    sessions.set("wallet:test-session:unbound-wrpac", JSON.stringify({
      sessionId: "unbound-wrpac",
      status: "pending",
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    }));
    try {
      await enforceVerifierPresentationTrust({
        sessionId: "unbound-wrpac",
        requestHeader: { x5c: ["unverified"] },
        requestPayload: { client_id: "x509_san_dns:verifier.example", dcql_query: { credentials: [{ format: "dc+sd-jwt", meta: {}, claims: [] }] } },
        trustEvidenceBound: false,
      });
      expect.fail("Expected unbound WRPAC rejection");
    } catch (error) {
      expect(error.message).to.include("WRPAC x5c certificate to verify");
    }
  });
});


describe("wallet registration certificate request boundary", () => {
  const type = "urn:eu.europa.ec.eudi:pid:1";
  const credential = { format: "dc+sd-jwt", meta: { vct_values: [type] }, claims: [{ path: ["address", "country"] }] };
  let leaf, key, sessions;
  before(async () => {
    const certificate = forge.pki.certificateFromPem(await fs.readFile(path.join(TRUST_FIXTURE_DIR, "pid.crt"), "utf8"));
    const privateKey = forge.pki.privateKeyFromPem(await fs.readFile(path.join(TRUST_FIXTURE_DIR, "pid.key"), "utf8"));
    certificate.setSubject([...certificate.subject.attributes, { name: "serialNumber", value: "test-verifier-001" }, { name: "organizationalUnitName", value: "test-service-001" }]);
    certificate.sign(privateKey, forge.md.sha256.create());
    leaf = forge.pki.certificateToPem(certificate).replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    key = await importPKCS8(forge.pki.privateKeyInfoToPem(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(privateKey))), "RS256");
  });
  beforeEach(() => {
    sessions = new Map([["wallet:test-session:wrprc", JSON.stringify({ sessionId: "wrprc", status: "pending", trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } })]]);
    setWalletTrustSessionStorageForTests({ get: async k => sessions.get(k), set: async (k,v) => sessions.set(k,v) });
    setTrustResolverForTests({ resolve: sinon.stub().resolves({ trusted: true, state: "trusted", reasonCode: "TRUSTED", evidence: {} }) });
  });
  afterEach(() => { clearTrustResolverForTests(); setWalletTrustSessionStorageForTests(null); });
  async function request(overrides = {}, datasetOverrides = {}) {
    const payload = { sub: "test-verifier-001", entitlements: ["https://uri.etsi.org/19475/Entitlement/Service_Provider"], credentials: [credential], purpose: [{ lang: "en", content: "Testing" }], privacyPolicy: [{ url: "https://www.aegean.gr/" }], ...overrides };
    const token = await new SignJWT(payload).setProtectedHeader({ alg: "RS256", typ: "rc-wrp+jwt", x5c: [leaf] }).setIssuedAt().setExpirationTime(overrides.exp ?? "5m").sign(key);
    return { client_id: computeX509HashClientIdFromLeafCertBase64(leaf), dcql_query: { credentials: [credential] }, verifier_info: [
      { format: "registrar_dataset", data: { identifier: "test-verifier-001", intendedUseIdentifier: "pid", registryURI: "https://registrar.example", srvDescription: [{ lang: "en", value: "Test" }], purpose: payload.purpose, policyURI: "https://www.aegean.gr/", ...datasetOverrides } },
      { format: "registration_cert", data: encodeRegistrationCertificate(token) },
    ] };
  }
  async function check(payload) {
    return enforceVerifierPresentationTrust({ sessionId: "wrprc", requestHeader: { x5c: [leaf] }, requestPayload: payload });
  }
  async function rejects(payload, message) {
    let failure; try { await check(payload); } catch (error) { failure = error; }
    expect(failure?.message).to.include(message);
  }
  it("accepts an authenticated CS-02 verifier_info array with matching scope", async () => {
    expect((await check(await request())).trusted).to.equal(true);
  });
  it("rejects object, missing, duplicate, raw JWT and padded certificate encodings", async () => {
    const payload = await request();
    for (const value of [undefined, {}, [payload.verifier_info[0]], [...payload.verifier_info, payload.verifier_info[1]]]) {
      expect(() => parseVerifierInfo(value)).to.throw();
    }
    for (const data of [Buffer.from(payload.verifier_info[1].data, "base64url").toString(), payload.verifier_info[1].data + "="]) {
      expect(() => parseVerifierInfo([payload.verifier_info[0], { format: "registration_cert", data }])).to.throw();
    }
  });
  it("rejects signature tampering and expired certificates", async () => {
    const payload = await request();
    const token = Buffer.from(payload.verifier_info[1].data, "base64url").toString();
    const parts = token.split("."); parts[1] = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(parts[1], "base64url")), sub: "attacker" })).toString("base64url");
    payload.verifier_info[1].data = encodeRegistrationCertificate(parts.join("."));
    await rejects(payload, "signature verification failed");
    await rejects(await request({ exp: 1 }), '"exp" claim');
  });
  it("rejects WRPAC identity and registrar dataset mismatches", async () => {
    await rejects(await request({ sub: "another-rp" }), "subject does not match WRPAC");
    await rejects(await request({}, { policyURI: "https://attacker.example/" }), "privacy policy mismatch");
    await rejects(await request({}, { identifier: "another-rp" }), "identity mismatch");
  });
  it("binds dataset service to the WRPAC OU even when the signed token omits service", async () => {
    await rejects(await request({}, { serviceId: "another-service" }), "service does not match WRPAC");
    expect((await check(await request({}, { serviceId: "test-service-001" }))).trusted).to.equal(true);
  });
  it("rejects omitted scope and untrusted registrar signing certificates", async () => {
    await rejects(await request({ credentials: [] }), "scope is not declared");
    expect(JSON.parse(sessions.get("wallet:test-session:wrprc")).trustDecision).to.include({ trusted: false, reasonCode: "VERIFIER_REGISTRATION_INVALID" });
    setTrustResolverForTests({ resolve: sinon.stub().callsFake(({ role }) => Promise.resolve({ trusted: role === "wrpac-provider" })) });
    await rejects(await request(), "signing chain is not trusted");
  });
  it("checks every VCT alternative, nested path and optional claim", async () => {
    for (const altered of [
      { ...credential, meta: { vct_values: [type, "unregistered"] } },
      { ...credential, claims: [{ path: ["address", "street"] }] },
      { ...credential, claims: [...credential.claims, { id: "optional", path: ["picture"] }], claim_sets: [["optional"]] },
    ]) { const payload = await request(); payload.dcql_query.credentials = [altered]; await rejects(payload, "exceeds intended-use"); }
  });
  it("never combines separate intended uses to authorize one query", () => {
    const second = { ...credential, meta: { vct_values: ["other"] } };
    expect(authorizeVerifierRegistrationScope({ registration: { intendedUse: [{ id: "a", credentials: [credential] }, { id: "b", credentials: [second] }] }, requested: [credential, second] }).authorized).to.equal(false);
    expect(authorizeVerifierRegistrationScope({ registration: { intendedUse: [{ id: "a", credentials: [credential] }, { id: "b", credentials: [second] }] }, intendedUseId: "a", requested: [credential, second] }).authorized).to.equal(false);
  });
  it("preserves trust-disabled behavior even without verifier_info", async () => {
    sessions.clear(); expect(await check({ client_id: "x509_hash:test" })).to.equal(null);
  });
});
