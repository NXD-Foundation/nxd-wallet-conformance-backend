import { expect } from "chai";
import {
  ATTESTATION_SOURCES,
  AttestationSourceError,
  LOCAL_KEY_ATTESTATION_NOTE,
  resolveAttestationSource,
  describeAttestationConfiguration,
  allowsLegacyBodyClientAssertion,
  createWalletUnitAttestationClientAuth,
  createWalletUnitCredentialKeyAttestation,
  getWalletUnitAttestationLifecycleStateForTests,
  resetWalletUnitAttestationLifecycleForTests,
} from "../src/lib/walletUnitAttestation.js";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { WALLET_PROFILES } from "../src/lib/profile.js";
import { decodeJwt, decodeProtectedHeader } from "jose";

const CS01 = WALLET_PROFILES.WEBUILD_CS01;
const COMPAT = WALLET_PROFILES.COMPATIBILITY;

describe("wallet-client walletUnitAttestation (Phase 7)", () => {
  beforeEach(() => resetWalletUnitAttestationLifecycleForTests());

  it("uses local-key attestation as the only supported source", () => {
    expect(resolveAttestationSource(CS01, {})).to.equal(ATTESTATION_SOURCES.LOCAL_KEY);
    expect(resolveAttestationSource(COMPAT, {})).to.equal(ATTESTATION_SOURCES.LOCAL_KEY);
  });

  it("rejects trust-framework attestation source until implemented", () => {
    expect(() =>
      resolveAttestationSource(CS01, {
        WALLET_ATTESTATION_SOURCE: "trust-framework",
      }),
    ).to.throw(AttestationSourceError);
  });

  it("describes local fixture attestation configuration", () => {
    const config = describeAttestationConfiguration(CS01);
    expect(config.source).to.equal(ATTESTATION_SOURCES.LOCAL_KEY);
    expect(config.trustFrameworkIntegrated).to.equal(false);
    expect(config.localKeyAttestationOnly).to.equal(true);
    expect(config.cs01UsesHeadersOnly).to.equal(true);
    expect(config.implementationNote).to.equal(LOCAL_KEY_ATTESTATION_NOTE);
  });

  it("disables legacy body client_assertion in CS-01 mode", () => {
    expect(allowsLegacyBodyClientAssertion(CS01)).to.equal(false);
    expect(allowsLegacyBodyClientAssertion(COMPAT)).to.equal(true);
  });

  it("generates TS03-shaped WIA OAuth client auth headers in CS-01 mode", async () => {
    const result = await createWalletUnitAttestationClientAuth({
      profile: CS01,
      keyPath: undefined,
      clientId: "wallet-client",
      endpointAudience: "https://issuer.example.com/par",
      authorizationServerIssuer: "https://issuer.example.com",
      stage: "PAR",
    });

    const wia = result.headers["OAuth-Client-Attestation"];
    const header = decodeProtectedHeader(wia);
    const payload = decodeJwt(wia);

    expect(result.source).to.equal(ATTESTATION_SOURCES.LOCAL_KEY);
    expect(result.trustFrameworkIntegrated).to.equal(false);
    expect(header).to.have.property("typ", "oauth-client-attestation+jwt");
    expect(header).to.have.property("x5c").that.is.an("array").with.length.greaterThan(0);
    expect(header).to.not.have.property("jwk");
    expect(payload).to.not.have.property("iss");
    expect(payload).to.have.property("sub", "wallet-client");
    expect(payload).to.have.property("wallet_name", "Test Wallet Client");
    expect(payload).to.have.property("wallet_version", "1.0.0");
    expect(payload).to.have.property("wallet_solution_certification_information");
    expect(payload).to.have.nested.property("client_status.status.status_list.uri");
    expect(payload.client_status.exp - Math.floor(Date.now() / 1000)).to.be.greaterThan(30 * 24 * 60 * 60);
    expect(payload.exp - payload.iat).to.be.lessThan(24 * 60 * 60);
    expect(result.headers["OAuth-Client-Attestation-PoP"]).to.be.a("string");
  });

  it("keeps compatibility mode on the legacy self-contained JWK header shape", async () => {
    const result = await createWalletUnitAttestationClientAuth({
      profile: COMPAT,
      keyPath: undefined,
      clientId: "wallet-client",
      endpointAudience: "https://issuer.example.com/token",
      authorizationServerIssuer: "https://issuer.example.com",
    });

    const header = decodeProtectedHeader(result.headers["OAuth-Client-Attestation"]);
    const payload = decodeJwt(result.headers["OAuth-Client-Attestation"]);
    expect(header).to.have.property("jwk");
    expect(header).to.not.have.property("x5c");
    expect(payload).to.have.property("iss", "wallet-client");
  });

  it("omits challenge claim in PoP when no challenge is provided", async () => {
    const result = await createWalletUnitAttestationClientAuth({
      profile: CS01,
      keyPath: undefined,
      clientId: "wallet-client",
      endpointAudience: "https://issuer.example.com/par",
      authorizationServerIssuer: "https://issuer.example.com",
      stage: "PAR",
    });

    const popPayload = decodeJwt(result.headers["OAuth-Client-Attestation-PoP"]);
    expect(popPayload).to.not.have.property("challenge");
  });

  it("generates TS03-shaped KA for CS-01 credential proof binding", async () => {
    const proofKey = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const result = await createWalletUnitCredentialKeyAttestation({
      profile: CS01,
      keyPath: undefined,
      proofPublicJwk: proofKey.publicJwk,
      credentialEndpoint: "https://issuer.example.com/credential",
      subjectPrivateJwk: proofKey.privateJwk,
      subjectPublicJwk: proofKey.publicJwk,
    });

    const header = decodeProtectedHeader(result.attestationJwt);
    const payload = decodeJwt(result.attestationJwt);
    expect(header).to.have.property("typ", "key-attestation+jwt");
    expect(header).to.have.property("x5c").that.is.an("array").with.length.greaterThan(0);
    expect(header).to.not.have.property("jwk");
    expect(payload).to.not.have.property("iss");
    expect(payload).to.not.have.property("eudi_wallet_info");
    expect(payload.attested_keys[0]).to.include({ kty: proofKey.publicJwk.kty, crv: proofKey.publicJwk.crv });
    expect(payload).to.have.property("key_storage").that.deep.equals(["iso_18045_high"]);
    expect(payload).to.have.property("user_authentication").that.deep.equals(["iso_18045_high"]);
    expect(payload).to.have.property("certification");
    expect(payload).to.have.nested.property("key_storage_status.status.status_list.uri");
    expect(payload.key_storage_status.exp - Math.floor(Date.now() / 1000)).to.be.greaterThan(30 * 24 * 60 * 60);
    expect(payload.exp - payload.iat).to.be.lessThan(24 * 60 * 60);
  });

  it("tracks generated WIA and KA jti values for in-memory single-use lifecycle", async () => {
    const before = getWalletUnitAttestationLifecycleStateForTests();
    expect(before.usedJwtIds).to.deep.equal([]);

    const wia = await createWalletUnitAttestationClientAuth({
      profile: CS01,
      keyPath: undefined,
      clientId: "wallet-client",
      endpointAudience: "https://issuer.example.com/token",
      authorizationServerIssuer: "https://issuer.example.com",
    });
    const proofKey = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const ka = await createWalletUnitCredentialKeyAttestation({
      profile: CS01,
      keyPath: undefined,
      proofPublicJwk: proofKey.publicJwk,
      credentialEndpoint: "https://issuer.example.com/credential",
      subjectPrivateJwk: proofKey.privateJwk,
      subjectPublicJwk: proofKey.publicJwk,
    });

    const after = getWalletUnitAttestationLifecycleStateForTests();
    expect(after.usedJwtIds).to.include(wia.attestationJti);
    expect(after.usedJwtIds).to.include(ka.attestationJti);
    expect(after.usedJwtIds).to.have.length(2);
  });
});
