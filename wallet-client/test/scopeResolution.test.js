import { expect } from "chai";
import {
  ScopeResolutionError,
  extractOfferGrantScope,
  extractMetadataScope,
  resolveCredentialScope,
} from "../src/lib/scopeResolution.js";
import { WALLET_PROFILES } from "../src/lib/profile.js";

const issuerMeta = {
  credential_configurations_supported: {
    "VerifiableIdCard": {
      scope: "VerifiableIdCard",
      format: "dc+sd-jwt",
    },
    "PID": {
      scope: "PID",
      format: "dc+sd-jwt",
    },
    "UnscopedCredential": {
      format: "dc+sd-jwt",
    },
  },
};

describe("wallet-client scopeResolution (Phase 5)", () => {
  it("reads scope from credential offer authorization_code grant", () => {
    expect(
      extractOfferGrantScope({
        grants: { authorization_code: { scope: "PID", issuer_state: "abc" } },
      }),
    ).to.equal("PID");
  });

  it("reads scope from issuer metadata credential configuration", () => {
    expect(extractMetadataScope(issuerMeta, "VerifiableIdCard")).to.equal("VerifiableIdCard");
    expect(extractMetadataScope(issuerMeta, "Missing")).to.equal(null);
  });

  it("prefers offer scope when it matches metadata in CS-01 mode", () => {
    const resolved = resolveCredentialScope({
      profile: WALLET_PROFILES.WEBUILD_CS01,
      configurationId: "PID",
      issuerMeta,
      offerConfig: { grants: { authorization_code: { scope: "PID" } } },
      scopesSupported: ["openid", "PID"],
    });

    expect(resolved.scope).to.equal("PID");
    expect(resolved.source).to.equal("offer+metadata");
  });

  it("resolves scope from issuer metadata when offer grant has no scope", () => {
    const resolved = resolveCredentialScope({
      profile: WALLET_PROFILES.WEBUILD_CS01,
      configurationId: "VerifiableIdCard",
      issuerMeta,
      offerConfig: { grants: { authorization_code: { issuer_state: "abc" } } },
      scopesSupported: ["openid", "VerifiableIdCard"],
    });

    expect(resolved.scope).to.equal("VerifiableIdCard");
    expect(resolved.source).to.equal("metadata");
  });

  it("rejects missing scope mapping in CS-01 mode", () => {
    expect(() =>
      resolveCredentialScope({
        profile: WALLET_PROFILES.WEBUILD_CS01,
        configurationId: "UnscopedCredential",
        issuerMeta,
        offerConfig: { grants: { authorization_code: {} } },
        scopesSupported: ["openid"],
      }),
    ).to.throw(ScopeResolutionError);
  });

  it("rejects conflicting offer and metadata scopes", () => {
    expect(() =>
      resolveCredentialScope({
        profile: WALLET_PROFILES.WEBUILD_CS01,
        configurationId: "PID",
        issuerMeta,
        offerConfig: { grants: { authorization_code: { scope: "VerifiableIdCard" } } },
        scopesSupported: ["openid", "PID", "VerifiableIdCard"],
      }),
    ).to.throw(/Conflicting scope mapping/);
  });

  it("rejects scopes not advertised by the authorization server", () => {
    expect(() =>
      resolveCredentialScope({
        profile: WALLET_PROFILES.WEBUILD_CS01,
        configurationId: "PID",
        issuerMeta,
        offerConfig: { grants: { authorization_code: { scope: "PID" } } },
        scopesSupported: ["openid"],
      }),
    ).to.throw(/not listed in authorization server scopes_supported/);
  });

  it("allows compatibility fallback to configurationId", () => {
    const resolved = resolveCredentialScope({
      profile: WALLET_PROFILES.COMPATIBILITY,
      configurationId: "UnscopedCredential",
      issuerMeta,
      offerConfig: { grants: { authorization_code: {} } },
      scopesSupported: ["openid", "UnscopedCredential"],
    });

    expect(resolved.scope).to.equal("UnscopedCredential");
    expect(resolved.source).to.equal("compatibility:configurationId-in-scopes_supported");
  });

  it("keeps legacy configurationId stand-in outside CS-01 when metadata is missing", () => {
    const resolved = resolveCredentialScope({
      profile: WALLET_PROFILES.COMPATIBILITY,
      configurationId: "UnscopedCredential",
      issuerMeta,
      offerConfig: { grants: { authorization_code: {} } },
      scopesSupported: null,
    });

    expect(resolved.scope).to.equal("UnscopedCredential");
    expect(resolved.source).to.equal("compatibility:configurationId-fallback");
  });
});
