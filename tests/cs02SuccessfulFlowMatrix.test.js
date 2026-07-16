import { expect } from "chai";
import * as jose from "jose";
import { encode } from "cbor-x";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { DEFAULT_DCQL_QUERY } from "../utils/routeUtils.js";
import { buildStrictCs02ClientMetadata, selectCs02VerifierEncryptionJwk } from "../utils/cs02TrustPolicy.js";
import {
  validateCs02EncryptedAuthorizationResponse,
  validateCs02JweResponseHeader,
  validateCs02ResponseSubmission,
  validateCs02DcqlVpTokenResponse,
  validateCs02MdocPresentation,
} from "../utils/cs02VerifierResponse.js";

describe("CS-02 successful flow matrix", () => {
  it("completes the direct_post.jwt selected-key response path", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ECDH-ES", { crv: "P-256" });
    const publicJwk = await jose.exportJWK(publicKey);
    publicJwk.kid = "enc-1";
    publicJwk.use = "enc";
    publicJwk.alg = "ECDH-ES";
    const session = {
      response_mode: "direct_post.jwt",
      state: "state-1",
      encryption_key: publicJwk,
    };
    const payload = { vp_token: { pid: "credential" }, state: "state-1" };
    const compactJwe = await new jose.EncryptJWT(payload)
      .setProtectedHeader({ alg: "ECDH-ES", enc: "A256GCM", kid: "enc-1" })
      .encrypt(publicKey);
    const header = jose.decodeProtectedHeader(compactJwe);
    validateCs02JweResponseHeader(header, {}, session.encryption_key);
    const { plaintext } = await jose.compactDecrypt(compactJwe, privateKey);
    const decrypted = JSON.parse(new TextDecoder().decode(plaintext));
    expect(validateCs02EncryptedAuthorizationResponse(decrypted, session)).to.deep.equal(payload);
  });

  it("accepts a successful direct_post form with correlated state", () => {
    const session = { response_mode: "direct_post", state: "state-2" };
    expect(validateCs02ResponseSubmission(
      { vp_token: "vp-token", state: "state-2" },
      session,
      { strict: true },
    )).to.equal(null);
  });

  it("generates a strict DID:jwk direct_post.jwt authorization request", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const jwk = await jose.exportJWK(publicKey);
    const encoded = Buffer.from(JSON.stringify(jwk)).toString("base64url");
    const clientId = `decentralized_identifier:did:jwk:${encoded}`;
    const request = await buildVpRequestJWT(
      clientId,
      "https://verifier.example/response",
      null,
      null,
      { client_name: "Matrix verifier" },
      `did:jwk:${encoded}#0`,
      "https://verifier.example",
      "vp_token",
      "matrix-nonce",
      DEFAULT_DCQL_QUERY,
      null,
      "direct_post.jwt",
      undefined,
      undefined,
      null,
      null,
      "matrix-state",
      "ES256",
    );
    const payload = jose.decodeJwt(request);
    expect(payload.client_id).to.equal(clientId);
    expect(payload.response_mode).to.equal("direct_post.jwt");
    expect(payload.state).to.equal("matrix-state");
    expect(payload.nonce).to.equal("matrix-nonce");
  });

  it("accepts a successful multi-credential DCQL response", () => {
    const query = {
      credentials: [
        { id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["pid"] }, multiple: true },
        { id: "license", format: "mso_mdoc", meta: { doctype_value: "org.iso.18013.5.1.mDL" } },
      ],
      credential_sets: [{ required: true, options: [["pid", "license"]] }],
    };
    const vpToken = { pid: ["sd-jwt-1", "sd-jwt-2"], license: "mdoc-token" };
    expect(validateCs02DcqlVpTokenResponse(vpToken, query, { strict: true })).to.deep.equal(vpToken);
  });

  it("retains the selected encryption key in strict client metadata", () => {
    const metadata = buildStrictCs02ClientMetadata({
      jwks: {
        keys: [
          { kid: "enc-1", use: "enc", kty: "EC", crv: "P-256", alg: "ECDH-ES+A256KW" },
          { kid: "sig-1", use: "sig", kty: "EC", crv: "P-256", alg: "ES256" },
        ],
      },
      vp_formats_supported: {
        "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"] },
      },
    }, "direct_post.jwt");
    expect(selectCs02VerifierEncryptionJwk(metadata)).to.include({ kid: "enc-1", alg: "ECDH-ES+A256KW" });
    expect(metadata.vp_formats_supported).to.have.property("dc+sd-jwt");
  });

  it("accepts a structurally valid mso_mdoc doctype flow", () => {
    const presentation = Buffer.from(encode({
      version: "1.0",
      documents: [{
        docType: "org.iso.18013.5.1.mDL",
        issuerSigned: { nameSpaces: {}, issuerAuth: new Uint8Array([1]) },
        deviceSigned: { nameSpaces: {}, deviceAuth: {} },
      }],
    })).toString("base64url");
    expect(validateCs02MdocPresentation({
      presentation,
      credQuery: { id: "license", format: "mso_mdoc", meta: { doctype_value: "org.iso.18013.5.1.mDL" } },
    })).to.deep.include({ ok: true });
  });

  it("generates the strict X.509 SD-JWT direct_post request shape", async function () {
    let request;
    try {
      request = await buildVpRequestJWT(
      "x509_san_dns:verifier.example",
      "https://verifier.example/response",
      null,
      null,
      { client_name: "X509 matrix verifier" },
      null,
      "https://verifier.example",
      "vp_token",
      "x509-nonce",
      DEFAULT_DCQL_QUERY,
      null,
      "direct_post",
      undefined,
      undefined,
      null,
      null,
      "x509-state",
        "ES256",
      );
    } catch (error) {
      if (/spawnSync.*EPERM|Failed to extract cert\/key/.test(String(error?.message))) return this.skip();
      throw error;
    }
    const payload = jose.decodeJwt(request);
    expect(payload.client_id).to.equal("x509_san_dns:verifier.example");
    expect(payload.response_mode).to.equal("direct_post");
    expect(payload.nonce).to.equal("x509-nonce");
    expect(payload.state).to.equal("x509-state");
    expect(payload.dcql_query).to.deep.equal(DEFAULT_DCQL_QUERY);
  });
});
