import { expect } from "chai";
import * as jose from "jose";
import {
  Cs02VerifierResponseError,
  validateCs02DcqlVpTokenResponse,
  validateCs02JweResponseHeader,
  validateCs02KeyBindingJwtClaims,
  validateCs02ResponseSubmission,
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
});
