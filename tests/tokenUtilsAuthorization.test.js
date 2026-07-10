import { expect } from "chai";
import jwt from "jsonwebtoken";
import {
  parseResourceAuthorizationHeader,
  parseAndValidateResourceAuthorizationHeader,
  isDpopBoundAccessTokenJwt,
} from "../utils/tokenUtils.js";

describe("tokenUtils resource authorization (RFC 9449)", () => {
  const dpopBoundToken = jwt.sign({ cnf: { jkt: "abc123" } }, "secret");

  it("parses DPoP authorization scheme", () => {
    const parsed = parseResourceAuthorizationHeader(`DPoP ${dpopBoundToken}`);
    expect(parsed.ok).to.equal(true);
    expect(parsed.scheme).to.equal("DPoP");
    expect(parsed.accessToken).to.equal(dpopBoundToken);
  });

  it("parses Bearer authorization scheme", () => {
    const parsed = parseResourceAuthorizationHeader("Bearer plain-token");
    expect(parsed.ok).to.equal(true);
    expect(parsed.scheme).to.equal("Bearer");
    expect(parsed.accessToken).to.equal("plain-token");
  });

  it("rejects missing Authorization header", () => {
    const parsed = parseResourceAuthorizationHeader(undefined);
    expect(parsed.ok).to.equal(false);
    expect(parsed.error).to.equal("invalid_token");
  });

  it("detects DPoP-bound JWT access tokens via cnf.jkt", () => {
    expect(isDpopBoundAccessTokenJwt(dpopBoundToken)).to.equal(true);
    expect(isDpopBoundAccessTokenJwt("opaque-token")).to.equal(false);
  });

  it("rejects DPoP-bound token sent as Bearer per RFC 9449 section 7.2", () => {
    const parsed = parseAndValidateResourceAuthorizationHeader(`Bearer ${dpopBoundToken}`);
    expect(parsed.ok).to.equal(false);
    expect(parsed.error).to.equal("invalid_token");
    expect(parsed.error_description).to.match(/DPoP authorization scheme/i);
  });

  it("accepts DPoP-bound token sent with DPoP scheme", () => {
    const parsed = parseAndValidateResourceAuthorizationHeader(`DPoP ${dpopBoundToken}`);
    expect(parsed.ok).to.equal(true);
    expect(parsed.scheme).to.equal("DPoP");
  });
});
