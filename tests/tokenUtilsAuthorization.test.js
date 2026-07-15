import { expect } from "chai";
import jwt from "jsonwebtoken";
import {
  parseAndValidateResourceAuthorizationHeader,
  parseResourceAuthorizationHeader,
} from "../utils/tokenUtils.js";

describe("resource authorization header parsing", () => {
  const dpopToken = jwt.sign({ cnf: { jkt: "thumbprint" } }, "test-secret");

  it("accepts Bearer tokens that are not DPoP-bound", () => {
    const parsed = parseAndValidateResourceAuthorizationHeader("Bearer opaque-token");
    expect(parsed).to.include({ ok: true, scheme: "Bearer", accessToken: "opaque-token" });
  });

  it("accepts DPoP-bound tokens only with the DPoP scheme", () => {
    expect(parseAndValidateResourceAuthorizationHeader(`DPoP ${dpopToken}`)).to.include({
      ok: true,
      scheme: "DPoP",
    });
    const rejected = parseAndValidateResourceAuthorizationHeader(`Bearer ${dpopToken}`);
    expect(rejected).to.include({ ok: false, status: 401, error: "invalid_token" });
  });

  it("rejects malformed authorization values", () => {
    expect(parseResourceAuthorizationHeader("Basic abc")).to.include({ ok: false, status: 401 });
  });
});
