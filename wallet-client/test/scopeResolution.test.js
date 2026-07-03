import { expect } from "chai";
import {
  ScopeResolutionError,
  CredentialSelectionError,
  extractOfferGrantScope,
  extractMetadataScope,
  extractOfferedConfigurationIds,
  resolveCredentialScope,
  resolvePreAuthorizedCredentialSelection,
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

describe("wallet-client preAuthorizedCredentialSelection (Phase 3)", () => {
  const singleConfigOffer = {
    credential_configuration_ids: ["VerifiableIdCard"],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "session-123",
      },
    },
  };

  const multiConfigOffer = {
    credential_configuration_ids: ["VerifiableIdCard", "PID"],
    credential_issuer: "https://issuer.example.com",
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "session-456",
      },
    },
  };

  it("reads offered configuration ids from credential_configuration_ids", () => {
    expect(extractOfferedConfigurationIds(singleConfigOffer)).to.deep.equal(["VerifiableIdCard"]);
    expect(extractOfferedConfigurationIds({ credentials: ["LegacyCredential"] })).to.deep.equal([
      "LegacyCredential",
    ]);
  });

  it("allows single-configuration pre-auth selection without authorization_details", () => {
    const selection = resolvePreAuthorizedCredentialSelection({
      configurationId: "VerifiableIdCard",
      issuerMeta,
      offerConfig: singleConfigOffer,
    });

    expect(selection.includeAuthorizationDetails).to.equal(false);
    expect(selection.authorizationDetails).to.equal(null);
    expect(selection.source).to.equal("offer:single-configuration");
  });

  it("requires authorization_details for multi-configuration pre-auth offers", () => {
    const selection = resolvePreAuthorizedCredentialSelection({
      configurationId: "PID",
      issuerMeta,
      offerConfig: multiConfigOffer,
    });

    expect(selection.includeAuthorizationDetails).to.equal(true);
    expect(selection.authorizationDetails).to.deep.equal([
      {
        type: "openid_credential",
        credential_configuration_id: "PID",
      },
    ]);
    expect(selection.source).to.equal("offer:multi-configuration");
  });

  it("proceeds for unscoped metadata configurations without grant scope", () => {
    const selection = resolvePreAuthorizedCredentialSelection({
      configurationId: "UnscopedCredential",
      issuerMeta,
      offerConfig: {
        credential_configuration_ids: ["UnscopedCredential"],
        grants: {
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "session-789",
          },
        },
      },
    });

    expect(selection.includeAuthorizationDetails).to.equal(false);
    expect(selection.metadataFormat).to.equal("dc+sd-jwt");
  });

  it("rejects configuration ids missing from the offer", () => {
    expect(() =>
      resolvePreAuthorizedCredentialSelection({
        configurationId: "PID",
        issuerMeta,
        offerConfig: singleConfigOffer,
      }),
    ).to.throw(CredentialSelectionError, /not listed in offer credential_configuration_ids/);
  });

  it("rejects configuration ids missing from issuer metadata", () => {
    expect(() =>
      resolvePreAuthorizedCredentialSelection({
        configurationId: "MissingCredential",
        issuerMeta,
        offerConfig: {
          credential_configuration_ids: ["MissingCredential"],
          grants: {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
              "pre-authorized_code": "session-000",
            },
          },
        },
      }),
    ).to.throw(CredentialSelectionError, /not present in issuer metadata/);
  });
});
