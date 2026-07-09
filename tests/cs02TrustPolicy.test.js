import { expect } from "chai";
import {
  Cs02TrustPolicyError,
  filterClientMetadataForCs02Enforcement,
  getCs02EnforcedMetadataProfile,
  validateCs02ClientMetadata,
  validateCs02RequestUriQueryPrecedence,
  validateDidJwkTrustRules,
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
