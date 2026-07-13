import { expect } from "chai";

describe("wallet-client authorization server metadata validation", () => {
  let validateAuthorizationServerMetadata;

  before(async () => {
    process.env.NODE_ENV = "test";
    ({ validateAuthorizationServerMetadata } = await import("../src/server.js"));
  });

  it("accepts AS metadata without openid in scopes_supported when credential scopes are advertised", () => {
    expect(() =>
      validateAuthorizationServerMetadata({
        issuer: "https://lsps.demo.eudiw.cz/pid-issuer-as",
        authorization_endpoint: "https://lsps.demo.eudiw.cz/pid-issuer-as/oauth2/authorize",
        token_endpoint: "https://lsps.demo.eudiw.cz/pid-issuer-as/oauth2/token",
        token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        scopes_supported: [
          "eu.europa.ec.eudi.pid_vc_sd_jwt",
          "eu.europa.ec.eudi.pid_mdoc",
          "technical_activation",
        ],
        client_attestation_signing_alg_values_supported: ["ES256"],
        client_attestation_pop_signing_alg_values_supported: ["ES256"],
      }),
    ).to.not.throw();
  });

  it("accepts missing scopes_supported when other core AS metadata is valid", () => {
    expect(() =>
      validateAuthorizationServerMetadata({
        issuer: "https://issuer.example/as",
        token_endpoint: "https://issuer.example/as/token",
        token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
        grant_types_supported: ["authorization_code"],
        client_attestation_signing_alg_values_supported: ["ES256"],
        client_attestation_pop_signing_alg_values_supported: ["ES256"],
      }),
    ).to.not.throw();
  });

  it("rejects non-array authorization_details_types_supported when present", () => {
    expect(() =>
      validateAuthorizationServerMetadata({
        issuer: "https://issuer.example/as",
        token_endpoint: "https://issuer.example/as/token",
        token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
        grant_types_supported: ["authorization_code"],
        client_attestation_signing_alg_values_supported: ["ES256"],
        client_attestation_pop_signing_alg_values_supported: ["ES256"],
        authorization_details_types_supported: "openid_credential",
      }),
    ).to.throw(/authorization_details_types_supported/);
  });
});
