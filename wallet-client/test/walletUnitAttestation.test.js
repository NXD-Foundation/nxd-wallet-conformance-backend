import { expect } from "chai";
import {
  ATTESTATION_SOURCES,
  AttestationSourceError,
  LOCAL_KEY_ATTESTATION_NOTE,
  resolveAttestationSource,
  describeAttestationConfiguration,
  allowsLegacyBodyClientAssertion,
  createWalletUnitAttestationClientAuth,
} from "../src/lib/walletUnitAttestation.js";
import { WALLET_PROFILES } from "../src/lib/profile.js";

describe("wallet-client walletUnitAttestation (Phase 7)", () => {
  it("uses local-key attestation as the only supported source", () => {
    expect(resolveAttestationSource(WALLET_PROFILES.WEBUILD_CS01, {})).to.equal(
      ATTESTATION_SOURCES.LOCAL_KEY,
    );
    expect(resolveAttestationSource(WALLET_PROFILES.COMPATIBILITY, {})).to.equal(
      ATTESTATION_SOURCES.LOCAL_KEY,
    );
  });

  it("rejects trust-framework attestation source until implemented", () => {
    expect(() =>
      resolveAttestationSource(WALLET_PROFILES.WEBUILD_CS01, {
        WALLET_ATTESTATION_SOURCE: "trust-framework",
      }),
    ).to.throw(AttestationSourceError);
  });

  it("describes local-key-only attestation configuration", () => {
    const config = describeAttestationConfiguration(WALLET_PROFILES.WEBUILD_CS01);
    expect(config.source).to.equal(ATTESTATION_SOURCES.LOCAL_KEY);
    expect(config.trustFrameworkIntegrated).to.equal(false);
    expect(config.localKeyAttestationOnly).to.equal(true);
    expect(config.cs01UsesHeadersOnly).to.equal(true);
    expect(config.implementationNote).to.equal(LOCAL_KEY_ATTESTATION_NOTE);
  });

  it("disables legacy body client_assertion in CS-01 mode", () => {
    expect(allowsLegacyBodyClientAssertion(WALLET_PROFILES.WEBUILD_CS01)).to.equal(false);
    expect(allowsLegacyBodyClientAssertion(WALLET_PROFILES.COMPATIBILITY)).to.equal(true);
  });

  it("generates Wallet Unit Attestation OAuth client auth headers from local keys", async () => {
    const result = await createWalletUnitAttestationClientAuth({
      profile: WALLET_PROFILES.WEBUILD_CS01,
      keyPath: undefined,
      clientId: "wallet-client",
      endpointAudience: "https://issuer.example.com/par",
      authorizationServerIssuer: "https://issuer.example.com",
      stage: "PAR",
    });

    expect(result.source).to.equal(ATTESTATION_SOURCES.LOCAL_KEY);
    expect(result.trustFrameworkIntegrated).to.equal(false);
    expect(result.headers["OAuth-Client-Attestation"]).to.be.a("string");
    expect(result.headers["OAuth-Client-Attestation-PoP"]).to.be.a("string");
    expect(result.implementationNote).to.include("not yet implemented");
  });
});
