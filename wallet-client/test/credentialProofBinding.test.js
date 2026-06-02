import { expect } from "chai";
import { decodeProtectedHeader, decodeJwt } from "jose";
import {
  WALLET_UNIT_SUBJECT_KEY_ROLE,
  CredentialProofBindingError,
  selectProofSigningAlgorithm,
  resolveWalletUnitSubjectKey,
  buildCredentialProofBindingContext,
  buildCredentialProofRequest,
  assertDeferredIssuanceBindingContext,
  buildDeferredCredentialPollRequest,
  toKeyBindingMaterial,
} from "../src/lib/credentialProofBinding.js";
import { WALLET_PROFILES } from "../src/lib/profile.js";

describe("wallet-client credentialProofBinding (Phase 8)", () => {
  const issuerMeta = {
    credential_issuer: "https://issuer.example.com",
    credential_configurations_supported: {
      PID: {
        proof_types_supported: {
          jwt: { proof_signing_alg_values_supported: ["ES256", "ES384"] },
        },
      },
    },
  };

  it("selects a supported proof signing algorithm", () => {
    expect(selectProofSigningAlgorithm(issuerMeta, "PID")).to.equal("ES256");
    expect(selectProofSigningAlgorithm({}, "PID")).to.equal("ES256");
  });

  it("resolves a Wallet Unit subject key with explicit role metadata", async () => {
    const subjectKey = await resolveWalletUnitSubjectKey({ keyPath: undefined, proofAlg: "ES256" });
    expect(subjectKey.keyRole).to.equal(WALLET_UNIT_SUBJECT_KEY_ROLE);
    expect(subjectKey.subjectDidJwk).to.match(/^did:jwk:/);
    expect(subjectKey.privateJwk).to.have.property("d");
    expect(subjectKey.publicJwk).to.not.have.property("d");
  });

  it("builds a credential proof request bound to the Wallet Unit subject key", async () => {
    const result = await buildCredentialProofRequest({
      profile: WALLET_PROFILES.WEBUILD_CS01,
      keyPath: undefined,
      issuerMeta,
      apiBase: "https://issuer.example.com",
      configurationId: "PID",
      cNonce: "nonce-123",
      credentialEndpoint: "https://issuer.example.com/credential",
    });

    expect(result.proofJwt).to.be.a("string");
    expect(result.credentialRequest.credential_configuration_id).to.equal("PID");
    expect(result.credentialRequest.proofs.jwt).to.have.length(1);

    const header = decodeProtectedHeader(result.proofJwt);
    const payload = decodeJwt(result.proofJwt);
    expect(header.typ).to.equal("openid4vci-proof+jwt");
    expect(header).to.have.property("key_attestation");
    expect(payload.nonce).to.equal("nonce-123");
    expect(payload.iss).to.equal(result.subjectKey.subjectDidJwk);
  });

  it("describes proof and sender-constraining binding context", () => {
    const context = buildCredentialProofBindingContext({
      profile: WALLET_PROFILES.WEBUILD_CS01,
      subjectKey: {
        keyRole: WALLET_UNIT_SUBJECT_KEY_ROLE,
        proofAlg: "ES256",
        subjectDidJwk: "did:jwk:abc",
        publicJwk: { kty: "EC", crv: "P-256" },
        privateJwk: { kty: "EC" },
      },
      dpopBinding: { privateJwk: { kty: "EC" }, publicJwk: { kty: "EC" } },
      tokenBody: { token_type: "DPoP" },
      accessToken: "access-token",
      keyAttestation: { source: "local-key", trustFrameworkIntegrated: false },
    });

    expect(context.walletUnitSubjectKey.keyRole).to.equal(WALLET_UNIT_SUBJECT_KEY_ROLE);
    expect(context.senderConstraining.mechanism).to.equal("dpop");
    expect(context.senderConstraining.dpopKeyRetained).to.equal(true);
    expect(context.deferredIssuanceUsesSameBinding).to.equal(true);
  });

  it("requires retained binding context for deferred issuance in CS-01 mode", () => {
    expect(() =>
      assertDeferredIssuanceBindingContext({
        profile: WALLET_PROFILES.WEBUILD_CS01,
        dpopBinding: {},
        tokenBody: { token_type: "DPoP" },
        accessToken: "token",
        subjectKey: null,
      }),
    ).to.throw(CredentialProofBindingError);

    expect(() =>
      assertDeferredIssuanceBindingContext({
        profile: WALLET_PROFILES.WEBUILD_CS01,
        dpopBinding: { privateJwk: { kty: "EC" }, publicJwk: { kty: "EC" } },
        tokenBody: { token_type: "DPoP" },
        accessToken: "token",
        subjectKey: { privateJwk: { kty: "EC" }, publicJwk: { kty: "EC" } },
      }),
    ).to.not.throw();
  });

  it("builds deferred poll requests with retained DPoP context", async () => {
    const subjectKey = await resolveWalletUnitSubjectKey({ keyPath: undefined, proofAlg: "ES256" });
    const poll = await buildDeferredCredentialPollRequest({
      profile: WALLET_PROFILES.WEBUILD_CS01,
      dpopBinding: {
        privateJwk: subjectKey.privateJwk,
        publicJwk: subjectKey.publicJwk,
      },
      tokenBody: { token_type: "DPoP" },
      accessToken: "test-access-token",
      subjectKey,
      deferredEndpoint: "https://issuer.example.com/credential_deferred",
      transactionId: "tx-123",
    });

    expect(poll.body.transaction_id).to.equal("tx-123");
    expect(poll.headers.authorization).to.match(/^Bearer /);
    expect(poll.headers.DPoP).to.be.a("string");
    expect(poll.senderContextRetained).to.equal(true);
    expect(poll.walletUnitSubjectKeyRetained).to.equal(true);
  });

  it("exports key-binding material from the Wallet Unit subject key", async () => {
    const subjectKey = await resolveWalletUnitSubjectKey({ keyPath: undefined, proofAlg: "ES256" });
    const material = toKeyBindingMaterial(subjectKey);
    expect(material.didJwk).to.equal(subjectKey.subjectDidJwk);
    expect(material.publicJwk).to.deep.equal(subjectKey.publicJwk);
    expect(material.privateJwk).to.deep.equal(subjectKey.privateJwk);
  });
});
