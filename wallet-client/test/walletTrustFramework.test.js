import { expect } from "chai";
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
  setWalletTrustSessionStorageForTests,
} from "../src/lib/trustFramework.js";
import {
  clearTrustResolverForTests,
  setTrustResolverForTests,
} from "../../utils/trustFrameworkPolicy.js";
import fs from "node:fs/promises";
import sinon from "sinon";
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

  it("reads TS5 credential authorization from every intended-use record", () => {
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

  it("accepts an undeclared verifier registration scope but rejects an explicit mismatch", () => {
    expect(authorizeVerifierRegistrationScope({
      registration: { intendedUse: [] },
      requested: [{ format: "dc+sd-jwt", meta: { vct_values: ["pilot-vct"] }, claims: [] }],
    })).to.deep.include({ authorized: true });
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
