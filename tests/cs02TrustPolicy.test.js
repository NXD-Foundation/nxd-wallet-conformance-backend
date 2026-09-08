import { expect } from "chai";
import {
  buildStrictCs02ClientMetadata,
  Cs02TrustPolicyError,
  filterClientMetadataForCs02Enforcement,
  getCs02EnforcedMetadataProfile,
  getCs02CapabilityProfile,
  selectCs02VerifierEncryptionJwk,
  validateCs02ClientMetadata,
  validateCs02RequestUriQueryPrecedence,
  validateDidJwkTrustRules,
  validateDidWebKidResolution,
  mergeCs02ClientMetadata,
  resolveCs02EffectiveClientMetadata,
  validateCs02ClientMetadataUri,
  validateVerifierAttestationTrust,
  validateX509SanDnsTrustAnchor,
  validateCs02TrustedAuthoritiesPolicy,
  setCs02TrustPlaceholderRecorder,
} from "../utils/cs02TrustPolicy.js";

describe("CS-02 trust and metadata policy (Phase 5)", () => {
  it("exposes enforced metadata profile aligned with runtime checks", () => {
    const profile = getCs02EnforcedMetadataProfile();
    expect(profile.jar_alg).to.equal("ES256");
    expect(profile.vp_formats_supported).to.include("dc+sd-jwt");
    expect(profile.response_modes_supported).to.include("direct_post.jwt");
  });

  it("exposes one CS-02 capability profile for applicability tracking", () => {
    const profile = getCs02CapabilityProfile();
    expect(profile.profile).to.equal("webuild-cs02");
    expect(profile.request.jarAlg).to.equal("ES256");
    expect(profile.request.responseModes).to.include("direct_post.jwt");
    expect(profile.trust.structuralOnly).to.equal(true);
    expect(profile.trust.trustAnchorsEnforced).to.equal(false);
    expect(profile.exclusions).to.include("PID mdoc Rulebook");
  });

  it("selects only a structurally valid CS-02 verifier encryption JWK", () => {
    expect(selectCs02VerifierEncryptionJwk({
      jwks: { keys: [{ kid: "enc-1", use: "enc", kty: "EC", crv: "P-256", alg: "ECDH-ES+A256KW" }] },
    })).to.include({ kid: "enc-1", alg: "ECDH-ES+A256KW" });
    expect(selectCs02VerifierEncryptionJwk({
      jwks: { keys: [{ kid: "bad", use: "sig", kty: "RSA", alg: "RS256" }] },
    })).to.equal(null);
  });

  it("returns placeholder trust for x509_san_dns until anchors are configured", async () => {
    const result = await validateX509SanDnsTrustAnchor("x509_san_dns:example.com", {}, "pem");
    expect(result.placeholder).to.equal(true);
    expect(result.enforced).to.equal(false);
    expect(result.trustConfigured).to.equal(false);
    expect(result.futureBehavior).to.match(/SAN DNS/);
    expect(result.structureValid).to.equal(false);
  });

  it("recognizes structurally encoded x5c entries without evaluating trust", async () => {
    const result = await validateX509SanDnsTrustAnchor(
      "x509_san_dns:example.com",
      { x5c: [Buffer.from("certificate-bytes").toString("base64")] },
      "pem",
    );
    expect(result.structureValid).to.equal(true);
    expect(result.trusted).to.equal(true);
    expect(result.enforced).to.equal(false);
  });

  it("returns placeholder trust for verifier_attestation until trusted issuers are configured", async () => {
    const result = await validateVerifierAttestationTrust(
      { jwt: "header.payload.signature" },
      "verifier_attestation:verifier-1",
    );
    expect(result.placeholder).to.equal(true);
    expect(result.enforced).to.equal(false);
    expect(result.trustConfigured).to.equal(false);
    expect(result.nonProduction).to.equal(true);
    expect(result.hasJwtHeader).to.equal(true);
    expect(result.structureValid).to.equal(false);
  });

  it("validates trusted_authorities structure without making a trust decision", async () => {
    const result = await validateCs02TrustedAuthoritiesPolicy({ trusted_authorities: ["etsi:example"] });
    expect(result).to.include({ enforced: false, structureValid: true });
    try {
      await validateCs02TrustedAuthoritiesPolicy({ trusted_authorities: [42] });
      throw new Error("expected trusted_authorities validation to fail");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02TrustPolicyError);
      expect(error.message).to.match(/non-empty array/);
    }
  });

  it("requires did:jwk keys to be EC/P-256 ES256", () => {
    expect(() =>
      validateDidJwkTrustRules({ kty: "RSA", n: "abc", e: "AQAB" }),
    ).to.throw(Cs02TrustPolicyError, /EC\/P-256/);
    expect(validateDidJwkTrustRules({ kty: "EC", crv: "P-256", x: "a", y: "b" }).ok).to.equal(true);
  });

  it("rejects client_metadata advertising unsupported vp formats in strict mode", () => {
    expect(() =>
      validateCs02ClientMetadata(
        { vp_formats_supported: { "jwt_vc_json": { alg_values: ["ES256"] } } },
        { responseMode: "direct_post", strict: true },
      ),
    ).to.throw(Cs02TrustPolicyError, /unsupported vp format/);
  });

  it("filters verifier metadata to enforced CS-02 formats and algs", () => {
    const filtered = filterClientMetadataForCs02Enforcement(
      {
        vp_formats_supported: {
          "jwt_vc_json": { alg_values: ["ES256"] },
          "dc+sd-jwt": {
            "sd-jwt_alg_values": ["ES256", "RS256"],
            "kb-jwt_alg_values": ["ES256", "RS256"],
          },
        },
        encrypted_response_alg_values_supported: ["ECDH-ES+A256KW", "RSA-OAEP-999"],
        encrypted_response_enc_values_supported: ["A256GCM", "A999GCM"],
        redirect_uris: ["https://verifier.example/response"],
      },
      "direct_post.jwt",
      { strict: true },
    );

    expect(filtered.vp_formats_supported).to.have.keys(["dc+sd-jwt"]);
    expect(filtered.vp_formats_supported["dc+sd-jwt"]["sd-jwt_alg_values"]).to.deep.equal(["ES256"]);
    expect(filtered.vp_formats_supported["dc+sd-jwt"]["kb-jwt_alg_values"]).to.deep.equal(["ES256"]);
    expect(filtered.encrypted_response_alg_values_supported).to.deep.equal(["ECDH-ES+A256KW"]);
    expect(filtered.encrypted_response_enc_values_supported).to.deep.equal(["A256GCM"]);
    expect(filtered).to.not.have.property("redirect_uris");
  });

  it("builds strict CS-02 metadata from broad verifier capabilities", () => {
    const broad = {
      vp_formats_supported: {
        "jwt_vc_json": { alg_values: ["ES256"] },
        "https://cloudsignatureconsortium.org/2025/x509": {},
        "dc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256", "ES384", "RS256"],
          "kb-jwt_alg_values": ["ES256", "ES384"],
        },
        "mso_mdoc": { issuerauth_alg_values: [-7, -35] },
      },
      encrypted_response_alg_values_supported: ["ECDH-ES+A256KW"],
      encrypted_response_enc_values_supported: ["A256GCM"],
    };
    const strict = buildStrictCs02ClientMetadata(
      broad,
      "direct_post",
    );

    expect(strict.vp_formats_supported).to.have.keys(["dc+sd-jwt", "mso_mdoc"]);
    expect(strict.vp_formats_supported["dc+sd-jwt"]["sd-jwt_alg_values"]).to.deep.equal([
      "ES256",
      "ES384",
    ]);
    expect(strict.vp_formats_supported["dc+sd-jwt"]["kb-jwt_alg_values"]).to.deep.equal([
      "ES256",
    ]);
    expect(strict).to.not.have.property("encrypted_response_alg_values_supported");
    expect(strict).to.not.have.property("encrypted_response_enc_values_supported");
    expect(broad.vp_formats_supported["dc+sd-jwt"]["kb-jwt_alg_values"]).to.deep.equal([
      "ES256",
      "ES384",
    ]);
  });

  it("rejects deep-link query parameters that contradict signed JAR values", () => {
    const deepLink =
      "openid4vp://?client_id=x509_san_dns:a.example&request_uri=https%3A%2F%2Fverifier.example%2Fjar";
    expect(() =>
      validateCs02RequestUriQueryPrecedence(
        deepLink,
        { client_id: "x509_san_dns:b.example", request_uri: "https://verifier.example/jar" },
      ),
    ).to.throw(Cs02TrustPolicyError, /must not contradict/);
  });

  it("accepts matching deep-link query and signed JAR values", () => {
    const deepLink =
      "openid4vp://?client_id=x509_san_dns:a.example&request_uri=https%3A%2F%2Fverifier.example%2Fjar";
    const result = validateCs02RequestUriQueryPrecedence(deepLink, {
      client_id: "x509_san_dns:a.example",
      request_uri: "https://verifier.example/jar",
      response_mode: "direct_post",
    });
    expect(result.ok).to.equal(true);
  });
});

describe("CS-02 production trust placeholders (Phase F)", () => {
  afterEach(() => {
    setCs02TrustPlaceholderRecorder(null);
  });

  it("records x509_san_dns placeholder decisions", async () => {
    const records = [];
    setCs02TrustPlaceholderRecorder((record) => records.push(record));

    await validateX509SanDnsTrustAnchor(
      "x509_san_dns:example.com",
      { x5c: ["leaf"] },
      "pem",
    );

    expect(records).to.have.length(1);
    expect(records[0]).to.include({
      kind: "x509_san_dns",
      enforced: false,
      placeholder: true,
      hasX5c: true,
    });
  });

  it("records verifier_attestation placeholder decisions", async () => {
    const records = [];
    setCs02TrustPlaceholderRecorder((record) => records.push(record));

    await validateVerifierAttestationTrust(
      { jwt: "header.payload.signature" },
      "verifier_attestation:verifier-1",
    );

    expect(records).to.have.length(1);
    expect(records[0]).to.include({
      kind: "verifier_attestation",
      enforced: false,
      placeholder: true,
      hasJwtHeader: true,
    });
  });

});

describe("CS-02 DID trust policy (Phase A)", () => {
  const did = "did:web:example.org";
  const p256Jwk = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
  const otherP256Jwk = { kty: "EC", crv: "P-256", x: "ghi", y: "jkl" };

  function didDocumentWithKeys() {
    return {
      id: did,
      verificationMethod: [
        { id: `${did}#keys-1`, type: "JsonWebKey2020", publicKeyJwk: p256Jwk },
        { id: `${did}#keys-2`, type: "JsonWebKey2020", publicKeyJwk: otherP256Jwk },
      ],
    };
  }

  it("requires did:web JAR kid", () => {
    expect(() =>
      validateDidWebKidResolution(didDocumentWithKeys(), undefined, did, {
        resolutionUrl: "https://example.org/.well-known/did.json",
      }),
    ).to.throw(Cs02TrustPolicyError, /must include kid/);
  });

  it("requires HTTPS did:web resolution URL", () => {
    expect(() =>
      validateDidWebKidResolution(didDocumentWithKeys(), `${did}#keys-1`, did, {
        resolutionUrl: "http://example.org/.well-known/did.json",
      }),
    ).to.throw(Cs02TrustPolicyError, /HTTPS/);
  });

  it("requires resolvedOverHttps when no resolution URL is provided", () => {
    expect(() =>
      validateDidWebKidResolution(didDocumentWithKeys(), `${did}#keys-1`, did),
    ).to.throw(Cs02TrustPolicyError, /HTTPS/);
  });

  it("requires did:web document id to match the resolved DID when present", () => {
    expect(() =>
      validateDidWebKidResolution(
        { ...didDocumentWithKeys(), id: "did:web:attacker.example" },
        `${did}#keys-1`,
        did,
        { resolvedOverHttps: true },
      ),
    ).to.throw(Cs02TrustPolicyError, /document id/);
  });

  it("accepts exact did:web kid with HTTPS resolution URL", () => {
    const result = validateDidWebKidResolution(
      didDocumentWithKeys(),
      `${did}#keys-1`,
      did,
      { resolutionUrl: "https://example.org/.well-known/did.json" },
    );
    expect(result.ok).to.equal(true);
    expect(result.verificationMethod.publicKeyJwk).to.deep.equal(p256Jwk);
  });

  it("accepts canonical fragment did:web kid form", () => {
    const result = validateDidWebKidResolution(didDocumentWithKeys(), "keys-1", did, {
      resolvedOverHttps: true,
    });
    expect(result.verificationMethod.id).to.equal(`${did}#keys-1`);
  });

  it("rejects did:web kid pointing to a different verification method", () => {
    expect(() =>
      validateDidWebKidResolution(didDocumentWithKeys(), `${did}#keys-99`, did, {
        resolvedOverHttps: true,
      }),
    ).to.throw(Cs02TrustPolicyError, /does not resolve/);
  });

  it("rejects did:web kid belonging to a different DID", () => {
    expect(() =>
      validateDidWebKidResolution(didDocumentWithKeys(), "did:web:attacker.example#keys-1", did, {
        resolvedOverHttps: true,
      }),
    ).to.throw(Cs02TrustPolicyError, /client_id DID/);
  });

  it("rejects did:jwk keys that are not EC/P-256 ES256", () => {
    expect(() =>
      validateDidJwkTrustRules({ kty: "EC", crv: "P-384", x: "a", y: "b" }),
    ).to.throw(Cs02TrustPolicyError, /EC\/P-256/);
    expect(() =>
      validateDidJwkTrustRules({ kty: "EC", crv: "P-256", alg: "ES384", x: "a", y: "b" }),
    ).to.throw(Cs02TrustPolicyError, /ES256/);
  });
});

describe("CS-02 client_metadata_uri policy (Phase B)", () => {
  const metadataUri = "https://verifier.example/client-metadata";
  const validMetadata = {
    vp_formats_supported: {
      "dc+sd-jwt": {
        "sd-jwt_alg_values": ["ES256"],
        "kb-jwt_alg_values": ["ES256"],
      },
    },
    jwks: { keys: [{ kty: "EC", crv: "P-256", x: "abc", y: "def", use: "enc" }] },
  };

  function mockMetadataFetch(metadata, { contentType = "application/json", status = 200 } = {}) {
    return async () => ({
      ok: status >= 200 && status < 300,
      status,
      headers: {
        get: (name) => {
          const key = String(name || "").toLowerCase();
          if (key === "content-type") return contentType;
          return null;
        },
      },
      text: async () => JSON.stringify(metadata),
    });
  }

  function mockRedirectThenMetadataFetch(metadata) {
    let callCount = 0;
    return async () => {
      callCount += 1;
      if (callCount === 1) {
        return {
          ok: false,
          status: 302,
          headers: {
            get: (name) => (String(name || "").toLowerCase() === "location"
              ? "https://verifier.example/redirected-client-metadata"
              : null),
          },
          text: async () => "",
        };
      }
      return {
        ok: true,
        status: 200,
        headers: {
          get: (name) => (String(name || "").toLowerCase() === "content-type"
            ? "application/json"
            : null),
        },
        text: async () => JSON.stringify(metadata),
      };
    };
  }

  it("prefers inline client_metadata over remote metadata for overlapping fields", () => {
    const merged = mergeCs02ClientMetadata(
      { jwks: { keys: [{ kid: "inline" }] }, client_name: "Inline Verifier" },
      { jwks: { keys: [{ kid: "remote" }] }, client_name: "Remote Verifier" },
    );
    expect(merged.jwks.keys[0].kid).to.equal("inline");
    expect(merged.client_name).to.equal("Inline Verifier");
  });

  it("fills verifier key metadata from remote when inline metadata omits it", async () => {
    const resolved = await resolveCs02EffectiveClientMetadata(
      {
        response_mode: "direct_post",
        client_metadata_uri: metadataUri,
      },
      { fetchImpl: mockMetadataFetch(validMetadata), strict: true },
    );
    expect(resolved.sources.remote).to.equal(true);
    expect(resolved.effectiveMetadata.jwks.keys).to.have.length(1);
  });

  it("passes redirect limits through effective client metadata resolution", async () => {
    try {
      await resolveCs02EffectiveClientMetadata(
        {
          response_mode: "direct_post",
          client_metadata_uri: metadataUri,
        },
        {
          fetchImpl: mockRedirectThenMetadataFetch(validMetadata),
          strict: true,
          maxRedirects: 0,
        },
      );
      expect.fail("expected redirect limit rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02TrustPolicyError);
      expect(error.message).to.match(/redirect limit/);
    }
  });

  it("rejects non-HTTPS client_metadata_uri in strict mode", async () => {
    try {
      await validateCs02ClientMetadataUri("http://verifier.example/client-metadata", {
        fetchImpl: mockMetadataFetch(validMetadata),
        responseMode: "direct_post",
        strict: true,
      });
      expect.fail("expected non-HTTPS rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02TrustPolicyError);
      expect(error.message).to.match(/HTTPS/);
    }
  });

  it("rejects relative client_metadata_uri", async () => {
    try {
      await validateCs02ClientMetadataUri("/client-metadata", {
        fetchImpl: mockMetadataFetch(validMetadata),
        responseMode: "direct_post",
        strict: true,
      });
      expect.fail("expected relative URI rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02TrustPolicyError);
      expect(error.message).to.match(/absolute URI/);
    }
  });

  it("rejects remote metadata with unsupported vp formats", async () => {
    try {
      await validateCs02ClientMetadataUri(metadataUri, {
        fetchImpl: mockMetadataFetch({
          vp_formats_supported: { "jwt_vc_json": { alg_values: ["ES256"] } },
        }),
        responseMode: "direct_post",
        strict: true,
      });
      expect.fail("expected unsupported vp format rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02TrustPolicyError);
      expect(error.message).to.match(/unsupported vp format/);
    }
  });

  it("rejects remote metadata advertising unsupported KB-JWT algs", async () => {
    try {
      await validateCs02ClientMetadataUri(metadataUri, {
        fetchImpl: mockMetadataFetch({
          vp_formats_supported: {
            "dc+sd-jwt": {
              "sd-jwt_alg_values": ["ES256"],
              "kb-jwt_alg_values": ["ES384"],
            },
          },
        }),
        responseMode: "direct_post",
        strict: true,
      });
      expect.fail("expected unsupported KB-JWT alg rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02TrustPolicyError);
      expect(error.message).to.match(/unsupported KB-JWT alg/);
    }
  });

  it("rejects remote metadata advertising encrypted response settings for direct_post", async () => {
    try {
      await validateCs02ClientMetadataUri(metadataUri, {
        fetchImpl: mockMetadataFetch({
          authorization_encrypted_response_alg: "ECDH-ES+A256KW",
        }),
        responseMode: "direct_post",
        strict: true,
      });
      expect.fail("expected direct_post encrypted metadata rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02TrustPolicyError);
      expect(error.message).to.match(/encrypted response settings/);
    }
  });

  it("rejects remote metadata advertising encrypted response alg/enc arrays for direct_post", async () => {
    try {
      await validateCs02ClientMetadataUri(metadataUri, {
        fetchImpl: mockMetadataFetch({
          encrypted_response_alg_values_supported: ["ECDH-ES+A256KW"],
          encrypted_response_enc_values_supported: ["A256GCM"],
        }),
        responseMode: "direct_post",
        strict: true,
      });
      expect.fail("expected direct_post encrypted metadata arrays rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02TrustPolicyError);
      expect(error.message).to.match(/encrypted response settings/);
    }
  });

  it("requires encrypted response encoding metadata for direct_post.jwt", () => {
    expect(() => validateCs02ClientMetadata({
      jwks: { keys: [{ kid: "enc", kty: "EC", crv: "P-256", use: "enc" }] },
    }, { responseMode: "direct_post.jwt", strict: true })).to.throw(/encrypted response encoding/);
  });

  it("ignores client_metadata.redirect_uris under OpenID4VP §5.1", () => {
    expect(() => validateCs02ClientMetadata({ redirect_uris: ["http://verifier.example/response"] }, { strict: true }))
      .not.to.throw();
    expect(() => validateCs02ClientMetadata({ redirect_uris: [] }, { strict: true }))
      .not.to.throw();
  });

  it("allows omitted redirect_uris under the explicit strict optional-field policy", () => {
    expect(() => validateCs02ClientMetadata({ client_name: "Verifier" }, { strict: true })).not.to.throw();
  });

  it("accepts valid HTTPS remote metadata with supported JWKs", async () => {
    const result = await validateCs02ClientMetadataUri(metadataUri, {
      fetchImpl: mockMetadataFetch(validMetadata),
      responseMode: "direct_post",
      strict: true,
    });
    expect(result.ok).to.equal(true);
    expect(result.metadata.jwks.keys).to.have.length(1);
  });
});
