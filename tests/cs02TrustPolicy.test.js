import { expect } from "chai";
import {
  Cs02TrustPolicyError,
  filterClientMetadataForCs02Enforcement,
  getCs02EnforcedMetadataProfile,
  validateCs02ClientMetadata,
  validateCs02RequestUriQueryPrecedence,
  validateDidJwkTrustRules,
  validateDidWebKidResolution,
  validateX509SanDnsTrustAnchor,
} from "../utils/cs02TrustPolicy.js";

describe("CS-02 trust and metadata policy (Phase 5)", () => {
  it("exposes enforced metadata profile aligned with runtime checks", () => {
    const profile = getCs02EnforcedMetadataProfile();
    expect(profile.jar_alg).to.equal("ES256");
    expect(profile.vp_formats_supported).to.include("dc+sd-jwt");
    expect(profile.response_modes_supported).to.include("direct_post.jwt");
  });

  it("returns placeholder trust for x509_san_dns until anchors are configured", async () => {
    const result = await validateX509SanDnsTrustAnchor("x509_san_dns:example.com", {}, "pem");
    expect(result.placeholder).to.equal(true);
    expect(result.enforced).to.equal(false);
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
      },
      "direct_post.jwt",
      { strict: true },
    );

    expect(filtered.vp_formats_supported).to.have.keys(["dc+sd-jwt"]);
    expect(filtered.vp_formats_supported["dc+sd-jwt"]["sd-jwt_alg_values"]).to.deep.equal(["ES256"]);
    expect(filtered.vp_formats_supported["dc+sd-jwt"]["kb-jwt_alg_values"]).to.deep.equal(["ES256"]);
    expect(filtered.encrypted_response_alg_values_supported).to.deep.equal(["ECDH-ES+A256KW"]);
    expect(filtered.encrypted_response_enc_values_supported).to.deep.equal(["A256GCM"]);
  });

  it("rejects deep-link query parameters that contradict signed JAR values", () => {
    const deepLink =
      "openid4vp://present?client_id=x509_san_dns:a.example&request_uri=https%3A%2F%2Fverifier.example%2Fjar";
    expect(() =>
      validateCs02RequestUriQueryPrecedence(
        deepLink,
        { client_id: "x509_san_dns:b.example", request_uri: "https://verifier.example/jar" },
      ),
    ).to.throw(Cs02TrustPolicyError, /must not contradict/);
  });

  it("accepts matching deep-link query and signed JAR values", () => {
    const deepLink =
      "openid4vp://present?client_id=x509_san_dns:a.example&request_uri=https%3A%2F%2Fverifier.example%2Fjar";
    const result = validateCs02RequestUriQueryPrecedence(deepLink, {
      client_id: "x509_san_dns:a.example",
      request_uri: "https://verifier.example/jar",
      response_mode: "direct_post",
    });
    expect(result.ok).to.equal(true);
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
