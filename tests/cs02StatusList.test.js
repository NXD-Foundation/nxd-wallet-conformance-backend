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

describe("CS-02 status-list reference validation", () => {
  it("allows missing status by default", () => {
    const result = validateCs02StatusListReference(undefined, { strictMissingStatus: false });
    expect(result.present).to.equal(false);
    expect(result.statusState).to.equal("absent");
    expect(result.enforced).to.equal(false);
  });

  it("rejects missing status when CS02_STRICT_STATUS_VALIDATION is enabled", () => {
    expect(() =>
      validateCs02StatusListReference(undefined, { strictMissingStatus: true }),
    ).to.throw(Cs02StatusListError, /missing required status/);
  });

  it("rejects a present status claim without a status_list reference", () => {
    expect(() =>
      validateCs02StatusListReference({ status_type: "revocation" }, { strictMissingStatus: false }),
    ).to.throw(Cs02StatusListError, /missing status_list/);
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
    expect(result.idx).to.equal(42);
    expect(result.uri).to.equal("https://issuer.example/status/1");
  });

  it("rejects a present status reference when the credential issuer key is missing", async () => {
    const sdJwt = sdJwtWithPayload({
      iss: "https://issuer.example",
      status: { status_list: { idx: 1, uri: "https://issuer.example/status/1" } },
    });
    const payload = decodeSdJwtIssuerPayload(sdJwt);
    expect(payload.iss).to.equal("https://issuer.example");

    try {
      await validateCs02CredentialStatusList(sdJwt, {});
      expect.fail("expected status validation to require the issuer key");
    } catch (error) {
      expect(error).to.be.instanceOf(Cs02StatusListError);
      expect(error.statusState).to.equal("status_unavailable");
    }
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

});
