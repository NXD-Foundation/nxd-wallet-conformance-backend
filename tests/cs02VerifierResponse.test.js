import { expect } from "chai";
import * as jose from "jose";
import { createHash } from "crypto";
import {
  Cs02VerifierResponseError,
  validateCs02DcqlVpTokenResponse,
  validateCs02JweResponseHeader,
  validateCs02KeyBindingJwtClaims,
  validateCs02ResponseSubmission,
  validateCs02SdJwtIssuerAuthenticity,
  validateCs02SdJwtPresentation,
  verifyCs02OuterResponseJwt,
} from "../utils/cs02VerifierResponse.js";

function sampleDcqlQuery(overrides = {}) {
  return {
    credentials: [
      { id: "cmwallet", format: "dc+sd-jwt", meta: { vct_values: ["test"] } },
      { id: "mdoc-id", format: "mso_mdoc", meta: { doctype_value: "test" } },
    ],
    ...overrides,
  };
}

async function signResponseJwt(payload, privateJwk, header = {}) {
  const signingKey = await jose.importJWK(privateJwk, "ES256");
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", typ: "JWT", jwk: header.jwk, ...header })
    .sign(signingKey);
}

function b64Json(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function disclosure(name, value, salt = "salt") {
  return Buffer.from(JSON.stringify([salt, name, value])).toString("base64url");
}

function disclosureDigest(encodedDisclosure) {
  return createHash("sha256").update(encodedDisclosure, "ascii").digest("base64url");
}

async function buildSdJwtPresentation({
  issuerPrivateJwk,
  holderPrivateJwk,
  holderPublicJwk,
  issuerPayload = {},
  issuerHeader = {},
  disclosures = [disclosure("family_name", "Neslo")],
  kbPayload = {},
} = {}) {
  const issuerKey = await jose.importJWK(issuerPrivateJwk, issuerHeader.alg || "ES256");
  const now = Math.floor(Date.now() / 1000);
  const sdDigests = disclosures.map(disclosureDigest);
  const issuerJwt = await new jose.SignJWT({
    iss: "https://issuer.example",
    iat: now,
    exp: now + 300,
    vct: "test",
    cnf: { jwk: holderPublicJwk },
    _sd_alg: "sha-256",
    _sd: sdDigests,
    ...issuerPayload,
  })
    .setProtectedHeader({ alg: "ES256", typ: "dc+sd-jwt", kid: "issuer-key", ...issuerHeader })
    .sign(issuerKey);

  const holderKey = await jose.importJWK(holderPrivateJwk, "ES256");
  const kbJwt = await new jose.SignJWT({
    nonce: "nonce-1",
    aud: "x509_san_dns:verifier.example",
    iat: now,
    sd_hash: "test-sd-hash",
    ...kbPayload,
  })
    .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
    .sign(holderKey);

  return `${issuerJwt}~${disclosures.join("~")}~${kbJwt}`;
}

describe("CS-02 verifier response validation (Phase 4)", () => {
  it("rejects bare vp_token when session expects direct_post.jwt", () => {
    expect(() =>
      validateCs02ResponseSubmission(
        { vp_token: "abc", state: "s1" },
        { response_mode: "direct_post.jwt", state: "s1" },
        { strict: true },
      ),
    ).to.throw(Cs02VerifierResponseError);
  });

  it("rejects response-only submission when session expects direct_post", () => {
    expect(() =>
      validateCs02ResponseSubmission(
        { response: "jwt.compact.value" },
        { response_mode: "direct_post", state: "s1" },
        { strict: true },
      ),
    ).to.throw(Cs02VerifierResponseError);
  });

  it("surfaces wallet-reported protocol errors", () => {
    const result = validateCs02ResponseSubmission(
      { error: "access_denied", error_description: "User declined" },
      { response_mode: "direct_post" },
      { strict: true },
    );
    expect(result.walletError.error).to.equal("access_denied");
    expect(result.walletError.error_description).to.equal("User declined");
  });

  it("rejects unknown DCQL credential ids in strict mode", () => {
    expect(() =>
      validateCs02DcqlVpTokenResponse(
        { cmwallet: "eyJ...", unknown: "eyJ..." },
        sampleDcqlQuery(),
        { strict: true },
      ),
    ).to.throw(Cs02VerifierResponseError, /Unknown DCQL credential id/);
  });

  it("rejects missing required DCQL credential ids in strict mode", () => {
    expect(() =>
      validateCs02DcqlVpTokenResponse(
        { cmwallet: "eyJ..." },
        sampleDcqlQuery(),
        { strict: true },
      ),
    ).to.throw(Cs02VerifierResponseError, /missing required credential id/);
  });

  it("accepts credential_sets satisfied options instead of all credential ids", () => {
    const vpToken = validateCs02DcqlVpTokenResponse(
      { "mdoc-id": "mdoc-data" },
      sampleDcqlQuery({
        credential_sets: [{ required: true, options: [["mdoc-id"], ["cmwallet"]] }],
      }),
      { strict: true },
    );
    expect(vpToken).to.deep.equal({ "mdoc-id": "mdoc-data" });
  });

  it("rejects empty credential arrays", () => {
    expect(() =>
      validateCs02DcqlVpTokenResponse(
        { cmwallet: [], "mdoc-id": "mdoc-data" },
        sampleDcqlQuery({
          credential_sets: [{ required: true, options: [["cmwallet", "mdoc-id"]] }],
        }),
        { strict: true },
      ),
    ).to.throw(Cs02VerifierResponseError, /empty array/);
  });

  it("rejects multiple presentations when multiple=false", () => {
    expect(() =>
      validateCs02DcqlVpTokenResponse(
        { cmwallet: ["one", "two"], "mdoc-id": "mdoc-data" },
        sampleDcqlQuery({
          credential_sets: [{ required: true, options: [["cmwallet", "mdoc-id"]] }],
        }),
        { strict: true },
      ),
    ).to.throw(Cs02VerifierResponseError, /multiple presentations/);
  });

  it("accepts arrays when multiple=true", () => {
    const vpToken = validateCs02DcqlVpTokenResponse(
      { cmwallet: ["one", "two"], "mdoc-id": "mdoc-data" },
      sampleDcqlQuery({
        credentials: [
          { id: "cmwallet", format: "dc+sd-jwt", multiple: true, meta: { vct_values: ["test"] } },
          { id: "mdoc-id", format: "mso_mdoc", meta: { doctype_value: "test" } },
        ],
        credential_sets: [{ required: true, options: [["cmwallet", "mdoc-id"]] }],
      }),
      { strict: true },
    );
    expect(vpToken.cmwallet).to.deep.equal(["one", "two"]);
  });

  it("validates JWE header alg, enc, and kid against metadata", () => {
    expect(() =>
      validateCs02JweResponseHeader(
        { alg: "RSA-OAEP-999", enc: "A256GCM", kid: "enc-1" },
        {
          authorization_encrypted_response_alg: "ECDH-ES+A256KW",
          authorization_encrypted_response_enc: "A256GCM",
        },
      ),
    ).to.throw(Cs02VerifierResponseError, /Unsupported JWE alg/);
  });

  it("requires kb+jwt typ in strict key-binding validation", () => {
    expect(() =>
      validateCs02KeyBindingJwtClaims({
        kbHeader: { typ: "JWT", alg: "ES256" },
        kbPayload: {
          nonce: "n1",
          aud: "client",
          iat: Math.floor(Date.now() / 1000),
          sd_hash: "abc",
        },
        sessionNonce: "n1",
        clientId: "client",
        options: { strict: true },
      }),
    ).to.throw(Cs02VerifierResponseError, /typ kb\+jwt/);
  });

  it("verifies outer response JWT signature and aud/state claims", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
    const privateJwk = await jose.exportJWK(privateKey);
    const publicJwk = await jose.exportJWK(publicKey);

    const jwt = await signResponseJwt(
      {
        vp_token: "presentation",
        iss: "wallet",
        aud: "x509_san_dns:example.com",
        state: "state-1",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      privateJwk,
      { jwk: publicJwk },
    );

    const verified = await verifyCs02OuterResponseJwt(jwt, {
      clientId: "x509_san_dns:example.com",
      state: "state-1",
    });

    expect(verified.payload.vp_token).to.equal("presentation");
  });

  it("rejects outer response JWT with invalid signature", async () => {
    const holder = await jose.generateKeyPair("ES256", { extractable: true });
    const other = await jose.generateKeyPair("ES256", { extractable: true });
    const privateJwk = await jose.exportJWK(holder.privateKey);
    const otherPublicJwk = await jose.exportJWK(other.publicKey);

    const jwt = await signResponseJwt(
      {
        vp_token: "presentation",
        iss: "wallet",
        aud: "client",
        state: "state-1",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      privateJwk,
      { jwk: otherPublicJwk },
    );

    try {
      await verifyCs02OuterResponseJwt(jwt, { clientId: "client", state: "state-1" });
      expect.fail("expected invalid signature rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02VerifierResponseError);
      expect(error.errorCode).to.equal("invalid_response");
    }
  });

  it("rejects outer response JWT with wrong aud", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
    const privateJwk = await jose.exportJWK(privateKey);
    const publicJwk = await jose.exportJWK(publicKey);

    const jwt = await signResponseJwt(
      {
        vp_token: "presentation",
        iss: "wallet",
        aud: "wrong-client",
        state: "state-1",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      privateJwk,
      { jwk: publicJwk },
    );

    try {
      await verifyCs02OuterResponseJwt(jwt, { clientId: "expected-client", state: "state-1" });
      expect.fail("expected aud mismatch rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02VerifierResponseError);
      expect(error.errorCode).to.equal("invalid_audience");
    }
  });

  it("rejects outer response JWT missing required aud", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });
    const privateJwk = await jose.exportJWK(privateKey);
    const publicJwk = await jose.exportJWK(publicKey);

    const jwt = await signResponseJwt(
      {
        vp_token: "presentation",
        iss: "wallet",
        state: "state-1",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      privateJwk,
      { jwk: publicJwk },
    );

    try {
      await verifyCs02OuterResponseJwt(jwt, { clientId: "expected-client", state: "state-1" });
      expect.fail("expected missing aud rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02VerifierResponseError);
      expect(error.errorCode).to.equal("invalid_audience");
    }
  });

  it("rejects kb-jwt missing aud when verifier client_id is known", () => {
    expect(() =>
      validateCs02KeyBindingJwtClaims({
        kbHeader: { typ: "kb+jwt", alg: "ES256" },
        kbPayload: {
          nonce: "n1",
          iat: Math.floor(Date.now() / 1000),
          sd_hash: "abc",
        },
        sessionNonce: "n1",
        clientId: "client",
        options: { strict: true },
      }),
    ).to.throw(Cs02VerifierResponseError, /missing aud/);
  });

  describe("SD-JWT-VC issuer authenticity (Phase D)", () => {
    async function keyMaterial() {
      const issuer = await jose.generateKeyPair("ES256", { extractable: true });
      const holder = await jose.generateKeyPair("ES256", { extractable: true });
      return {
        issuerPrivateJwk: await jose.exportJWK(issuer.privateKey),
        issuerPublicJwk: await jose.exportJWK(issuer.publicKey),
        holderPrivateJwk: await jose.exportJWK(holder.privateKey),
        holderPublicJwk: await jose.exportJWK(holder.publicKey),
      };
    }

    it("accepts a valid issuer signature and matching cnf.jwk when local issuer key material is available", async () => {
      const keys = await keyMaterial();
      const sdJwt = await buildSdJwtPresentation(keys);

      const result = await validateCs02SdJwtPresentation({
        sdJwt,
        sessionNonce: "nonce-1",
        clientId: "x509_san_dns:verifier.example",
        credQuery: {
          id: "cmwallet",
          format: "dc+sd-jwt",
          meta: { vct_values: ["test"] },
          claims: [{ path: ["family_name"] }],
        },
        options: {
          strict: true,
          issuerVerificationJwk: keys.issuerPublicJwk,
          rejectUnsolicitedDisclosures: true,
        },
      });

      expect(result.ok).to.equal(true);
      expect(result.issuerAuthenticity.issuerSignature).to.include({
        verified: true,
        enforced: true,
        placeholder: false,
      });
      expect(result.issuerTrust).to.include({ placeholder: true });
      expect(result.issuerAuthenticity.claims.family_name).to.equal("Neslo");
    });

    it("rejects SD-JWT with invalid issuer signature when a local issuer key is available", async () => {
      const keys = await keyMaterial();
      const otherIssuer = await jose.generateKeyPair("ES256", { extractable: true });
      const otherIssuerPublicJwk = await jose.exportJWK(otherIssuer.publicKey);
      const sdJwt = await buildSdJwtPresentation(keys);

      try {
        await validateCs02SdJwtIssuerAuthenticity({
          sdJwt,
          credQuery: { meta: { vct_values: ["test"] }, claims: [{ path: ["family_name"] }] },
          options: { strict: true, issuerVerificationJwk: otherIssuerPublicJwk },
        });
        expect.fail("expected issuer signature rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02VerifierResponseError);
        expect(error.message).to.match(/issuer signature/);
      }
    });

    it("checks issuer signature before disclosure reconstruction when issuer key is available", async () => {
      const keys = await keyMaterial();
      const otherIssuer = await jose.generateKeyPair("ES256", { extractable: true });
      const otherIssuerPublicJwk = await jose.exportJWK(otherIssuer.publicKey);
      const sdJwt = await buildSdJwtPresentation({
        ...keys,
        issuerPayload: { _sd: ["not-the-real-disclosure-digest"] },
      });

      try {
        await validateCs02SdJwtIssuerAuthenticity({
          sdJwt,
          options: { strict: true, issuerVerificationJwk: otherIssuerPublicJwk },
        });
        expect.fail("expected issuer signature rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02VerifierResponseError);
        expect(error.message).to.match(/issuer signature/);
      }
    });

    it("rejects SD-JWT with unsupported issuer alg", async () => {
      const keys = await keyMaterial();
      const sdJwt = await buildSdJwtPresentation(keys);
      const [issuerJwt, ...tail] = sdJwt.split("~");
      const [, payload, signature] = issuerJwt.split(".");
      const tampered = `${b64Json({ alg: "none", typ: "dc+sd-jwt" })}.${payload}.${signature}~${tail.join("~")}`;

      try {
        await validateCs02SdJwtIssuerAuthenticity({
          sdJwt: tampered,
          options: { strict: true, issuerVerificationJwk: keys.issuerPublicJwk },
        });
        expect.fail("expected unsupported alg rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02VerifierResponseError);
        expect(error.message).to.match(/supported alg/);
      }
    });

    it("rejects SD-JWT missing cnf.jwk when holder binding is required", async () => {
      const keys = await keyMaterial();
      const sdJwt = await buildSdJwtPresentation({
        ...keys,
        issuerPayload: { cnf: undefined },
      });

      try {
        await validateCs02SdJwtIssuerAuthenticity({
          sdJwt,
          options: { strict: true, issuerVerificationJwk: keys.issuerPublicJwk },
        });
        expect.fail("expected missing cnf.jwk rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02VerifierResponseError);
        expect(error.message).to.match(/cnf\.jwk/);
      }
    });

    it("returns an explicit issuer-signature placeholder when no issuer key source exists", async () => {
      const keys = await keyMaterial();
      const sdJwt = await buildSdJwtPresentation(keys);

      const result = await validateCs02SdJwtIssuerAuthenticity({
        sdJwt,
        credQuery: { meta: { vct_values: ["test"] }, claims: [{ path: ["family_name"] }] },
        options: { strict: true },
      });

      expect(result.issuerSignature).to.include({
        verified: false,
        enforced: false,
        placeholder: true,
      });
    });

    it("rejects presented disclosures that do not reconstruct against the issuer payload", async () => {
      const keys = await keyMaterial();
      const sdJwt = await buildSdJwtPresentation({
        ...keys,
        issuerPayload: { _sd: ["not-the-real-disclosure-digest"] },
      });

      try {
        await validateCs02SdJwtIssuerAuthenticity({
          sdJwt,
          options: { strict: true, issuerVerificationJwk: keys.issuerPublicJwk },
        });
        expect.fail("expected disclosure digest rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02VerifierResponseError);
        expect(error.message).to.match(/disclosure digest/);
      }
    });

    it("rejects missing requested claims after disclosure reconstruction", async () => {
      const keys = await keyMaterial();
      const sdJwt = await buildSdJwtPresentation(keys);

      try {
        await validateCs02SdJwtIssuerAuthenticity({
          sdJwt,
          credQuery: { claims: [{ path: ["given_name"] }] },
          options: { strict: true, issuerVerificationJwk: keys.issuerPublicJwk },
        });
        expect.fail("expected missing requested claim rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02VerifierResponseError);
        expect(error.message).to.match(/missing requested claim path/);
      }
    });

    it("rejects unsolicited disclosures in strict mode", async () => {
      const keys = await keyMaterial();
      const sdJwt = await buildSdJwtPresentation({
        ...keys,
        disclosures: [disclosure("family_name", "Neslo"), disclosure("given_name", "Alice")],
      });

      try {
        await validateCs02SdJwtIssuerAuthenticity({
          sdJwt,
          credQuery: { claims: [{ path: ["family_name"] }] },
          options: { strict: true, issuerVerificationJwk: keys.issuerPublicJwk },
        });
        expect.fail("expected unsolicited disclosure rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02VerifierResponseError);
        expect(error.message).to.match(/unsolicited disclosed claim/);
      }
    });

    it("rejects wrong vct for the requested DCQL credential", async () => {
      const keys = await keyMaterial();
      const sdJwt = await buildSdJwtPresentation(keys);

      try {
        await validateCs02SdJwtIssuerAuthenticity({
          sdJwt,
          credQuery: { meta: { vct_values: ["different-vct"] }, claims: [{ path: ["family_name"] }] },
          options: { strict: true, issuerVerificationJwk: keys.issuerPublicJwk },
        });
        expect.fail("expected vct rejection");
      } catch (error) {
        expect(error).to.be.instanceOf(Cs02VerifierResponseError);
        expect(error.message).to.match(/vct/);
      }
    });

    it.skip("rejects untrusted SD-JWT issuers once configured issuer trust exists", () => {});
  });
});
