import { expect } from "chai";
import fs from "fs";
import * as jose from "jose";
import { buildVpRequestJWT } from "../utils/cryptoUtils.js";
import { DEFAULT_DCQL_QUERY } from "../utils/routeUtils.js";
import {
  Cs02VerifierRequestError,
  createOpenId4VpRequestUrl,
  filterClientMetadataForCs02,
  resolveVerifierCs02Options,
  validateCs02TransactionDataEntries,
} from "../utils/cs02VerifierRequest.js";
import { setCs02TrustPlaceholderRecorder } from "../utils/cs02TrustPolicy.js";

function validDcqlQuery() {
  return structuredClone(DEFAULT_DCQL_QUERY);
}

function encodeTxData(payload) {
  return Buffer.from(JSON.stringify(payload)).toString("base64url");
}

async function buildStandardCs02Jar(overrides = {}) {
  const env = { VERIFIER_CS02_COMPATIBILITY: "false", ...overrides.env };
  const previous = { ...process.env };
  Object.assign(process.env, env);
  try {
    return await buildVpRequestJWT(
      overrides.client_id || "x509_san_dns:dev-i4mlab.aegean.gr",
      "https://example.com/direct_post/session-1",
      null,
      null,
      overrides.client_metadata || { client_name: "Test Verifier" },
      null,
      "https://example.com",
      "vp_token",
      "nonce-phase3",
      overrides.dcql_query !== undefined ? overrides.dcql_query : validDcqlQuery(),
      overrides.transaction_data !== undefined ? overrides.transaction_data : null,
      overrides.response_mode || "direct_post",
      undefined,
      undefined,
      null,
      null,
      "state-phase3",
      "ES256",
    );
  } finally {
    process.env = previous;
  }
}

describe("CS-02 verifier request generation (Phase 3)", () => {
  const originalCompatibility = process.env.VERIFIER_CS02_COMPATIBILITY;

  afterEach(() => {
    setCs02TrustPlaceholderRecorder(null);
    if (originalCompatibility === undefined) {
      delete process.env.VERIFIER_CS02_COMPATIBILITY;
    } else {
      process.env.VERIFIER_CS02_COMPATIBILITY = originalCompatibility;
    }
  });

  it("is strict by default", () => {
    delete process.env.VERIFIER_CS02_COMPATIBILITY;
    expect(resolveVerifierCs02Options({}).strict).to.equal(true);
  });

  it("allows compatibility mode when VERIFIER_CS02_COMPATIBILITY=true", () => {
    expect(resolveVerifierCs02Options({ VERIFIER_CS02_COMPATIBILITY: "true" }).strict).to.equal(false);
  });

  it("generates ES256 signed JAR with required CS-02 payload fields", async () => {
    const requestJwt = await buildStandardCs02Jar();
    const header = jose.decodeProtectedHeader(requestJwt);
    const payload = jose.decodeJwt(requestJwt);

    expect(header.alg).to.equal("ES256");
    expect(header.typ).to.equal("oauth-authz-req+jwt");
    expect(payload.response_type).to.equal("vp_token");
    expect(payload.response_mode).to.equal("direct_post");
    expect(payload.dcql_query.credentials[0].id).to.equal("cmwallet");
    expect(payload.state).to.equal("state-phase3");
    expect(payload.exp - payload.iat).to.be.at.most(300);
    expect(payload.presentation_definition).to.equal(undefined);
  });

  it("invokes x509 trust placeholder during strict verifier request generation", async () => {
    const records = [];
    setCs02TrustPlaceholderRecorder((record) => records.push(record));

    await buildStandardCs02Jar();

    expect(records.some((record) =>
      record.kind === "x509_san_dns" &&
      record.placeholder === true &&
      record.enforced === false &&
      record.hasX5c === true
    )).to.equal(true);
  });

  it("rejects missing dcql_query in strict mode", async () => {
    try {
      await buildStandardCs02Jar({ dcql_query: null });
      expect.fail("expected missing dcql_query rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02VerifierRequestError);
    }
  });

  it("rejects malformed transaction_data decoding in strict mode", () => {
    expect(() =>
      validateCs02TransactionDataEntries(["not-json"], validDcqlQuery(), { strict: true }),
    ).to.throw(Cs02VerifierRequestError);
  });

  it("rejects transaction_data credential_ids that do not match DCQL ids", () => {
    expect(() =>
      validateCs02TransactionDataEntries(
        [
          encodeTxData({
            type: "qes_authorization",
            credential_ids: ["missing-id"],
          }),
        ],
        validDcqlQuery(),
        { strict: true },
      ),
    ).to.throw(Cs02VerifierRequestError);
  });

  it("accepts transaction_data without credential_ids (applies to all DCQL queries)", () => {
    expect(() =>
      validateCs02TransactionDataEntries(
        [encodeTxData({ type: "qes_authorization", purpose: "demo" })],
        validDcqlQuery(),
        { strict: true },
      ),
    ).to.not.throw();
  });

  it("filters verifier metadata to enforced CS-02 formats", () => {
    const filtered = filterClientMetadataForCs02(
      {
        client_name: "Verifier",
        vp_formats_supported: {
          "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] },
          "vc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] },
          "jwt_vc_json": { alg_values: ["ES256"] },
          "mso_mdoc": { issuerauth_alg_values: [-7] },
        },
        encrypted_response_enc_values_supported: ["A256GCM"],
      },
      "direct_post",
    );

    expect(filtered.vp_formats_supported).to.have.keys(["dc+sd-jwt", "vc+sd-jwt", "mso_mdoc"]);
    expect(filtered.vp_formats_supported["dc+sd-jwt"]["kb-jwt_alg_values"]).to.deep.equal(["ES256"]);
    expect(filtered).to.not.have.property("encrypted_response_alg_values_supported");
    expect(filtered).to.not.have.property("encrypted_response_enc_values_supported");
  });

  it("keeps broad verifier-config capabilities out of strict CS-02 metadata", () => {
    const broadConfig = JSON.parse(fs.readFileSync("./data/verifier-config.json", "utf8"));
    expect(broadConfig.vp_formats_supported).to.have.property(
      "https://cloudsignatureconsortium.org/2025/x509",
    );

    const strict = filterClientMetadataForCs02(broadConfig, "direct_post");
    expect(strict.vp_formats_supported).to.not.have.property("jwt_vc_json");
    expect(strict.vp_formats_supported).to.not.have.property(
      "https://cloudsignatureconsortium.org/2025/x509",
    );
    expect(strict.vp_formats_supported["dc+sd-jwt"]["kb-jwt_alg_values"]).to.deep.equal(["ES256"]);
    expect(strict).to.not.have.property("encrypted_response_alg_values_supported");
    expect(strict).to.not.have.property("encrypted_response_enc_values_supported");
  });

  it("does not reintroduce unsupported metadata formats for direct_post", async () => {
    const requestJwt = await buildStandardCs02Jar({
      client_metadata: {
        client_name: "Test Verifier",
        vp_formats_supported: {
          "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"] },
          "jwt_vc_json": { alg_values: ["ES256"] },
          "mso_mdoc": { issuerauth_alg_values: [-7] },
        },
        encrypted_response_enc_values_supported: ["A256GCM"],
      },
    });
    const payload = jose.decodeJwt(requestJwt);

    expect(payload.client_metadata.vp_formats_supported).to.have.keys(["dc+sd-jwt", "mso_mdoc"]);
    expect(payload.client_metadata).to.not.have.property("encrypted_response_alg_values_supported");
    expect(payload.client_metadata).to.not.have.property("encrypted_response_enc_values_supported");
  });

  it("rejects non-string transaction_data credential_ids", () => {
    expect(() =>
      validateCs02TransactionDataEntries(
        [
          encodeTxData({
            type: "qes_authorization",
            credential_ids: ["cmwallet", 42],
          }),
        ],
        validDcqlQuery(),
        { strict: true },
      ),
    ).to.throw(Cs02VerifierRequestError);
  });

  it("emits openid4vp://present deep links in strict mode", () => {
    delete process.env.VERIFIER_CS02_COMPATIBILITY;
    const url = createOpenId4VpRequestUrl(
      "https://verifier.example/request/1",
      "x509_san_dns:verifier.example.org",
      true,
      {},
    );
    expect(url.startsWith("openid4vp://present?")).to.equal(true);
    expect(url).to.include("request_uri_method=post");
  });
});
