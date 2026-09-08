import { expect } from "chai";

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

function statusResponse(status) {
  return {
    ok: false,
    status,
    json: async () => {
      throw new Error("no body");
    },
  };
}

const validAuthCodeMeta = {
  issuer: "https://issuer.example/as",
  token_endpoint: "https://issuer.example/as/token",
  token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
  grant_types_supported: ["authorization_code"],
  client_attestation_signing_alg_values_supported: ["ES256"],
  client_attestation_pop_signing_alg_values_supported: ["ES256"],
};

const validPreAuthMeta = {
  issuer: "https://issuer.example/as",
  token_endpoint: "https://issuer.example/as/token",
  grant_types_supported: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
  client_attestation_signing_alg_values_supported: ["ES256"],
  client_attestation_pop_signing_alg_values_supported: ["ES256"],
};

describe("wallet-client authorization server metadata validation", () => {
  let validateAuthorizationServerMetadata;
  let discoverAuthorizationServerMetadata;

  before(async () => {
    process.env.NODE_ENV = "test";
    ({
      validateAuthorizationServerMetadata,
      discoverAuthorizationServerMetadata,
    } = await import("../src/server.js"));
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
      validateAuthorizationServerMetadata(validAuthCodeMeta),
    ).to.not.throw();
  });

  it("rejects non-array authorization_details_types_supported when present", () => {
    expect(() =>
      validateAuthorizationServerMetadata({
        ...validAuthCodeMeta,
        authorization_details_types_supported: "openid_credential",
      }),
    ).to.throw(/authorization_details_types_supported/);
  });

  it("accepts pre-auth metadata without authorization_code or attest_jwt_client_auth", () => {
    expect(() =>
      validateAuthorizationServerMetadata(validPreAuthMeta, {
        grant: "pre-authorized_code",
      }),
    ).to.not.throw();
  });

  it("accepts pre-auth metadata without token_endpoint_auth_methods_supported", () => {
    const meta = { ...validPreAuthMeta };
    delete meta.token_endpoint_auth_methods_supported;
    expect(() =>
      validateAuthorizationServerMetadata(meta, { grant: "pre-authorized_code" }),
    ).to.not.throw();
  });

  it("rejects authorization-code metadata missing authorization_code in grant_types_supported", () => {
    expect(() =>
      validateAuthorizationServerMetadata({
        ...validAuthCodeMeta,
        grant_types_supported: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
      }),
    ).to.throw(/authorization_code/);
  });

  it("rejects authorization-code metadata missing attest_jwt_client_auth", () => {
    expect(() =>
      validateAuthorizationServerMetadata({
        ...validAuthCodeMeta,
        token_endpoint_auth_methods_supported: ["none"],
      }),
    ).to.throw(/attest_jwt_client_auth/);
  });

  it("rejects missing token_endpoint_auth_methods_supported on authorization-code with invalid_as_metadata", () => {
    const meta = { ...validAuthCodeMeta };
    delete meta.token_endpoint_auth_methods_supported;
    expect(() => validateAuthorizationServerMetadata(meta)).to.throw(/invalid_as_metadata/);
    try {
      validateAuthorizationServerMetadata(meta);
      expect.fail("expected missing methods rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Error);
      expect(error).to.not.be.instanceOf(TypeError);
      expect(error.message).to.match(/token_endpoint_auth_methods_supported/);
    }
  });

  describe("discovery error precedence", () => {
    it("keeps the RFC 8414 validation error when the OIDC fallback returns 404", async () => {
      const fetchImpl = async (url) => {
        if (String(url).includes("oauth-authorization-server")) {
          return jsonResponse({
            token_endpoint: "https://issuer.example/as/token",
            grant_types_supported: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
            client_attestation_signing_alg_values_supported: ["ES256"],
            client_attestation_pop_signing_alg_values_supported: ["ES256"],
          });
        }
        return statusResponse(404);
      };

      try {
        await discoverAuthorizationServerMetadata(
          "https://issuer.example/as",
          null,
          fetchImpl,
          { grant: "authorization_code" },
        );
        expect.fail("expected discovery to fail");
      } catch (error) {
        expect(error.message).to.match(/invalid_as_metadata/);
        expect(error.message).to.not.match(/AS metadata fetch error 404/);
      }
    });

    it("reports AS metadata fetch error 404 when no candidate returns a document", async () => {
      const fetchImpl = async () => statusResponse(404);
      try {
        await discoverAuthorizationServerMetadata(
          "https://issuer.example/as",
          null,
          fetchImpl,
        );
        expect.fail("expected discovery to fail");
      } catch (error) {
        expect(error.message).to.equal("AS metadata fetch error 404");
      }
    });

    it("returns valid RFC 8414 metadata without trying to require a later 404", async () => {
      const fetchImpl = async (url) => {
        if (String(url).includes("oauth-authorization-server")) {
          return jsonResponse(validAuthCodeMeta);
        }
        return statusResponse(404);
      };
      const meta = await discoverAuthorizationServerMetadata(
        "https://issuer.example/as",
        null,
        fetchImpl,
        { grant: "authorization_code" },
      );
      expect(meta.token_endpoint).to.equal(validAuthCodeMeta.token_endpoint);
    });

    it("accepts pre-auth discovery when RFC 8414 metadata omits attest_jwt_client_auth", async () => {
      const fetchImpl = async (url) => {
        if (String(url).includes("oauth-authorization-server")) {
          return jsonResponse(validPreAuthMeta);
        }
        return statusResponse(404);
      };
      const meta = await discoverAuthorizationServerMetadata(
        "https://issuer.example/as",
        null,
        fetchImpl,
        { grant: "pre-authorized_code" },
      );
      expect(meta.grant_types_supported).to.include(
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      );
    });
  });
});
