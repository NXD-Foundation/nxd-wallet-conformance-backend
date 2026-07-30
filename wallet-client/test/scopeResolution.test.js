import { expect } from "chai";
import {
  resolveScopeForCredentialConfiguration,
  readScopeFromOfferGrant,
} from "../src/lib/scopeResolution.js";
import { buildIssuanceAuthorizationFields } from "../src/lib/issuance.js";

describe("scope resolution (RFC001 Phase 4)", () => {
  const issuerMeta = {
    credential_issuer: "https://issuer.example",
    credential_configurations_supported: {
      "urn:eu.europa.ec.eudi:pid:1": {
        scope: "urn:eu.europa.ec.eudi:pid:1",
        format: "vc+sd-jwt",
      },
      ETSIRfc001PidVcSdJwt: {
        scope: "ETSIRfc001PidVcSdJwt",
        format: "vc+sd-jwt",
      },
      LegacyPidConfig: {
        format: "vc+sd-jwt",
      },
    },
  };

  it("prefers scope from credential_configurations_supported", () => {
    expect(
      resolveScopeForCredentialConfiguration({
        configurationId: "ETSIRfc001PidVcSdJwt",
        issuerMeta,
      }),
    ).to.equal("ETSIRfc001PidVcSdJwt");
  });

  it("does not use configurationId when metadata defines a different scope", () => {
    const scope = resolveScopeForCredentialConfiguration({
      configurationId: "ETSIRfc001PidVcSdJwt",
      issuerMeta,
    });
    expect(scope).to.not.equal("WrongConfigId");
    expect(scope).to.equal("ETSIRfc001PidVcSdJwt");
  });

  it("reads scope from offer grant when metadata omits scope", () => {
    const offer = {
      grants: {
        authorization_code: {
          scope: "openid ETSIRfc001PidVcSdJwt",
          issuer_state: "sess-1",
        },
      },
    };
    expect(
      resolveScopeForCredentialConfiguration({
        configurationId: "LegacyPidConfig",
        issuerMeta,
        offer,
        grantType: "authorization_code",
      }),
    ).to.equal("ETSIRfc001PidVcSdJwt");
  });

  it("readScopeFromOfferGrant supports pre-authorized_code grant", () => {
    const offer = {
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          scope: "urn:eu.europa.ec.eudi:pid:1",
          "pre-authorized_code": "abc",
        },
      },
    };
    expect(
      readScopeFromOfferGrant(offer, "urn:ietf:params:oauth:grant-type:pre-authorized_code"),
    ).to.equal("urn:eu.europa.ec.eudi:pid:1");
  });

  it("rejects missing scope when neither metadata nor offer defines one", () => {
    expect(() =>
      resolveScopeForCredentialConfiguration({
        configurationId: "LegacyPidConfig",
        issuerMeta,
      }),
    ).to.throw(/issuer-defined scope required/i);
  });

  it("buildIssuanceAuthorizationFields returns scope and authorization_details", () => {
    const fields = buildIssuanceAuthorizationFields({
      configurationId: "urn:eu.europa.ec.eudi:pid:1",
      issuerMeta,
      grantType: "authorization_code",
    });
    expect(fields.scope).to.equal("urn:eu.europa.ec.eudi:pid:1");
    const details = JSON.parse(fields.authorization_details);
    expect(details).to.have.length(1);
    expect(details[0]).to.include({
      type: "openid_credential",
      credential_configuration_id: "urn:eu.europa.ec.eudi:pid:1",
    });
    expect(details[0].locations).to.deep.equal(["https://issuer.example"]);
  });

  it("buildIssuanceAuthorizationFields succeeds for scope-less config with authorization_details only", () => {
    const fields = buildIssuanceAuthorizationFields({
      configurationId: "LegacyPidConfig",
      issuerMeta,
      grantType: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    });
    expect(fields).to.not.have.property("scope");
    const details = JSON.parse(fields.authorization_details);
    expect(details).to.have.length(1);
    expect(details[0]).to.include({
      type: "openid_credential",
      credential_configuration_id: "LegacyPidConfig",
    });
    expect(details[0].locations).to.deep.equal(["https://issuer.example"]);
  });
});
