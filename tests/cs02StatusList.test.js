import { expect } from "chai";
import {
  Cs02StatusListError,
  decodeSdJwtIssuerPayload,
  validateCs02CredentialStatusList,
  validateCs02StatusListReference,
} from "../utils/cs02StatusList.js";

function b64Json(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function sdJwtWithPayload(payload) {
  return `${b64Json({ alg: "ES256", typ: "dc+sd-jwt" })}.${b64Json(payload)}.sig~kb.jwt.part`;
}

describe("CS-02 status-list validation (Phase 5 placeholder)", () => {
  it("allows missing status by default", () => {
    const result = validateCs02StatusListReference(undefined, { strictMissingStatus: false });
    expect(result.present).to.equal(false);
    expect(result.statusState).to.equal("absent");
    expect(result.enforced).to.equal(false);
    expect(result.placeholder).to.equal(true);
  });

  it("rejects missing status when CS02_STRICT_STATUS_VALIDATION is enabled", () => {
    expect(() =>
      validateCs02StatusListReference(undefined, { strictMissingStatus: true }),
    ).to.throw(Cs02StatusListError, /missing required status/);
  });

  it("rejects malformed status_list idx", () => {
    expect(() =>
      validateCs02StatusListReference(
        { status_list: { idx: -1, uri: "https://issuer.example/status/1" } },
        { strictMissingStatus: false },
      ),
    ).to.throw(Cs02StatusListError, /non-negative integer/);
  });

  it("rejects non-HTTPS status_list uri", () => {
    expect(() =>
      validateCs02StatusListReference(
        { status_list: { idx: 0, uri: "http://issuer.example/status/1" } },
        { strictMissingStatus: false },
      ),
    ).to.throw(Cs02StatusListError, /HTTPS/);
  });

  it("accepts well-formed status_list reference", () => {
    const result = validateCs02StatusListReference(
      { status_list: { idx: 42, uri: "https://issuer.example/status/1" } },
      { strictMissingStatus: false },
    );
    expect(result.present).to.equal(true);
    expect(result.statusState).to.equal("structurally_valid_placeholder");
    expect(result.enforced).to.equal(false);
    expect(result.idx).to.equal(42);
    expect(result.todos).to.be.an("array").that.is.not.empty;
    expect(result.todos.join(" ")).to.match(/trusted status-list issuers/);
    expect(result.todos.join(" ")).to.match(/maximum response size/);
  });

  it("decodes issuer payload from SD-JWT and validates status placeholder", async () => {
    const sdJwt = sdJwtWithPayload({
      iss: "https://issuer.example",
      status: { status_list: { idx: 1, uri: "https://issuer.example/status/1" } },
    });
    const payload = decodeSdJwtIssuerPayload(sdJwt);
    expect(payload.iss).to.equal("https://issuer.example");

    const result = await validateCs02CredentialStatusList(sdJwt, {});
    expect(result.present).to.equal(true);
    expect(result.statusState).to.equal("structurally_valid_placeholder");
    expect(result.placeholder).to.equal(true);
    expect(result.trustPolicy.strictStatus).to.equal(false);
  });

  it("uses trust-policy strictStatus for missing status decisions", async () => {
    const sdJwt = sdJwtWithPayload({ iss: "https://issuer.example" });

    try {
      await validateCs02CredentialStatusList(sdJwt, {
        trustPolicyOptions: { strictStatus: true },
      });
      expect.fail("expected strict missing status rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.statusState).to.equal("structurally_invalid");
      expect(error.message).to.match(/missing required status/);
    }
  });

  it("does not let local status options weaken trust-policy strictStatus", async () => {
    const sdJwt = sdJwtWithPayload({ iss: "https://issuer.example" });

    try {
      await validateCs02CredentialStatusList(sdJwt, {
        strictMissingStatus: false,
        trustPolicyOptions: { strictStatus: true },
      });
      expect.fail("expected trust-policy strict status rejection");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.message).to.match(/missing required status/);
    }
  });

  it("logs placeholder decisions without treating them as enforced status proof", async () => {
    const logs = [];
    const sdJwt = sdJwtWithPayload({
      iss: "https://issuer.example",
      status: { status_list: { idx: 1, uri: "https://issuer.example/status/1" } },
    });

    const result = await validateCs02CredentialStatusList(sdJwt, {
      trustPolicyOptions: { strictStatus: false, hasTrustRegistry: false },
      log: (...args) => logs.push(args),
    });

    expect(result.enforced).to.equal(false);
    expect(logs).to.have.length(1);
    expect(logs[0][0]).to.equal("[CS02] status-list placeholder decision");
    expect(logs[0][1].level).to.equal("debug");
    expect(logs[0][1].statusState).to.equal("structurally_valid_placeholder");
  });

  it.skip("rejects revoked SD-JWT-VC credentials once status-list trust exists", () => {});
  it.skip("rejects suspended SD-JWT-VC credentials once status-list trust exists", () => {});
  it.skip("fails closed on status-list fetch timeout once fetching is implemented", () => {});
  it.skip("fails closed on oversized status-list responses once fetching is implemented", () => {});
});
