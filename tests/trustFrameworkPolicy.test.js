import { expect } from "chai";
import fs from "node:fs/promises";
import sinon from "sinon";
import {
  clearTrustResolverForTests,
  checkWalletProviderTrust,
  checkVerifierCredentialTrust,
  checkAccessCertificateTrust,
  loadConfiguredAccessCertificate,
  isTrustFrameworkSession,
  recordTrustDecision,
  setTrustResolverForTests,
  trustFrameworkSessionProps,
  resolveVerifierCredentialContext,
} from "../utils/trustFrameworkPolicy.js";

describe("Phase 3 Wallet Provider trust policy", () => {
  afterEach(() => clearTrustResolverForTests());

  it("normalizes the explicit request flag into a session policy", () => {
    expect(trustFrameworkSessionProps({ trustFramework: true })).to.deep.equal({
      trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" },
    });
    expect(trustFrameworkSessionProps({ trustFramework: false })).to.deep.equal({});
    expect(isTrustFrameworkSession({ trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } })).to.equal(true);
  });

  it("resolves Wallet Provider identity from the WIA/KA x5c certificate", async () => {
    const resolve = sinon.stub().resolves({ trusted: true, state: "trusted", reasonCode: "TRUSTED", evidence: { entity: "Test Wallet Provider" } });
    setTrustResolverForTests({ resolve });
    const cert = await fs.readFile("tests/fixtures/trust/webuild-wp4/keys/pid.crt", "utf8");
    const certB64 = Buffer.from(cert.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64").toString("base64");
    const session = { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } };
    const result = await checkWalletProviderTrust({
      session,
      payload: { iss: "wallet-provider.example" },
      header: { x5c: [certB64] },
      operation: "verify-wia",
    });
    expect(result.trusted).to.equal(true);
    expect(resolve.calledOnce).to.equal(true);
    expect(resolve.firstCall.args[0].role).to.equal("wallet-provider");
    expect(resolve.firstCall.args[0].presentedIdentity.certificateFingerprint).to.match(/^[a-f0-9]{64}$/);
  });

  it("records the decision and reason in the issuance session", async () => {
    const session = { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } };
    const store = sinon.stub().resolves();
    await recordTrustDecision({
      session,
      decision: { trusted: false, state: "indeterminate", reasonCode: "BOOTSTRAP_UNTRUSTED", evidence: { role: "wallet-provider" } },
      store,
      sessionKey: "session-1",
      slog: sinon.stub(),
    });
    expect(session.trustDecision).to.include({ trusted: false, reasonCode: "BOOTSTRAP_UNTRUSTED" });
    expect(store.calledOnceWith("session-1", session)).to.equal(true);
  });

  it("maps verifier credential context to an explicit WP4 role", () => {
    expect(resolveVerifierCredentialContext({ format: "dc+sd-jwt", vct: "urn:eu.europa.ec.eudi:pid:1" }))
      .to.deep.equal({ role: "pid-provider", credentialType: "pid" });
    expect(resolveVerifierCredentialContext({ format: "mso_mdoc", doctype: "urn:eu.europa.ec.eudi:pid:1" }).role)
      .to.equal("pid-provider");
    expect(resolveVerifierCredentialContext({ format: "dc+sd-jwt", vct: "unknown" }).role).to.equal(null);
  });

  it("enforces verifier issuer trust only for an opted-in session", async () => {
    const resolve = sinon.stub().resolves({ trusted: true, state: "trusted", reasonCode: "TRUSTED", evidence: {} });
    setTrustResolverForTests({ resolve });
    const cert = await fs.readFile("tests/fixtures/trust/webuild-wp4/keys/pid.crt", "utf8");
    const certB64 = Buffer.from(cert.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64").toString("base64");
    const result = await checkVerifierCredentialTrust({
      session: { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } },
      payload: { iss: "pid-provider.example", vct: "urn:eu.europa.ec.eudi:pid:1" },
      header: { x5c: [certB64] },
      format: "dc+sd-jwt",
      vct: "urn:eu.europa.ec.eudi:pid:1",
    });
    expect(result.trusted).to.equal(true);
    expect(resolve.firstCall.args[0].role).to.equal("pid-provider");
    expect(await checkVerifierCredentialTrust({ payload: { iss: "unlisted" } })).to.equal(null);
  });

  it("uses the mdoc issuer certificate when no JWT issuer claim exists", async () => {
    const resolve = sinon.stub().resolves({ trusted: true, state: "trusted", reasonCode: "TRUSTED", evidence: {} });
    setTrustResolverForTests({ resolve });
    const certificatePem = await fs.readFile("tests/fixtures/trust/webuild-wp4/keys/pid.crt", "utf8");
    const result = await checkVerifierCredentialTrust({
      session: { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } },
      certificatePem,
      format: "mso_mdoc",
      doctype: "urn:eu.europa.ec.eudi:pid:1",
    });
    expect(result.trusted).to.equal(true);
    expect(resolve.firstCall.args[0].role).to.equal("pid-provider");
    expect(resolve.firstCall.args[0].presentedIdentity.certificateFingerprint).to.match(/^[a-f0-9]{64}$/);
  });

  it("accepts an explicit wallet credential role and forwards registration scope evidence", async () => {
    const resolve = sinon.stub().resolves({ trusted: true, state: "trusted", reasonCode: "TRUSTED", evidence: {} });
    setTrustResolverForTests({ resolve });
    const certificatePem = await fs.readFile("tests/fixtures/trust/webuild-wp4/keys/pid.crt", "utf8");
    await checkVerifierCredentialTrust({
      session: { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } },
      payload: { iss: "issuer.example" },
      certificatePem,
      certificateChain: [certificatePem],
      role: "pub-eaa-provider",
      format: "mso_mdoc",
      doctype: "eu.europa.ec.av.1",
      scopeEvidence: { verified: true, credentialTypes: ["eu.europa.ec.av.1"] },
    });
    expect(resolve.firstCall.args[0].role).to.equal("pub-eaa-provider");
    expect(resolve.firstCall.args[0].credentialContext.scopeEvidence).to.deep.equal({ verified: true, credentialTypes: ["eu.europa.ec.av.1"] });
    expect(resolve.firstCall.args[0].presentedIdentity.certificateChain).to.have.length(1);
  });

  it("resolves an opted-in verifier access certificate as WRPAC", async () => {
    const resolve = sinon.stub().resolves({ trusted: true, state: "trusted", reasonCode: "TRUSTED", evidence: {} });
    setTrustResolverForTests({ resolve });
    const certificatePem = await fs.readFile("tests/fixtures/trust/webuild-wp4/keys/pid.crt", "utf8");
    const result = await checkAccessCertificateTrust({
      session: { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } },
      certificatePem,
      entityId: "x509_san_dns:verifier.example",
    });
    expect(result.trusted).to.equal(true);
    expect(resolve.firstCall.args[0].role).to.equal("wrpac-provider");
    expect(resolve.firstCall.args[0].presentedIdentity.entityId).to.equal("x509_san_dns:verifier.example");
  });

  it("passes an access-certificate chain to the resolver for CA-anchor matching", async () => {
    const resolve = sinon.stub().resolves({ trusted: true, state: "trusted", reasonCode: "TRUSTED", evidence: {} });
    setTrustResolverForTests({ resolve });
    const leaf = await fs.readFile("tests/fixtures/trust/webuild-wp4/keys/pid.crt", "utf8");
    const anchor = await fs.readFile("tests/fixtures/trust/webuild-wp4/keys/lotl.crt", "utf8");
    await checkAccessCertificateTrust({
      session: { trustPolicy: { mode: "webuild", profile: "webuild-wp4-pilot" } },
      certificatePem: leaf,
      certificateChain: [leaf, anchor],
    });
    expect(resolve.firstCall.args[0].presentedIdentity.certificateChain).to.deep.equal([leaf, anchor]);
  });

  it("loads the optional WRPRC certificate only when configured", async () => {
    const previous = process.env.TRUST_WRPRC_CERT_PATH;
    delete process.env.TRUST_WRPRC_CERT_PATH;
    expect(await loadConfiguredAccessCertificate("wrprc-provider")).to.equal(null);
    process.env.TRUST_WRPRC_CERT_PATH = "tests/fixtures/trust/webuild-wp4/keys/pid.crt";
    const certificate = await loadConfiguredAccessCertificate("wrprc-provider");
    expect(certificate).to.include("BEGIN CERTIFICATE");
    if (previous === undefined) delete process.env.TRUST_WRPRC_CERT_PATH;
    else process.env.TRUST_WRPRC_CERT_PATH = previous;
  });
});
