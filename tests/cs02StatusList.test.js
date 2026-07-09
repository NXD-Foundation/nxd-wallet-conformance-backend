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
    expect(result.idx).to.equal(42);
    expect(result.todos).to.be.an("array").that.is.not.empty;
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
    expect(result.placeholder).to.equal(true);
  });
});
