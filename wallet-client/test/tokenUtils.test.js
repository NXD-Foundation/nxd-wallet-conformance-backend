import { expect } from "chai";
import crypto from "crypto";
import { computeAthForDpop, isDpopBoundAccessToken, formatResourceAuthorizationHeader } from "../utils/tokenUtils.js";

function referenceAth(accessToken) {
  return crypto
    .createHash("sha256")
    .update(accessToken, "utf8")
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function minimalJwt(payloadObj) {
  const header = Buffer.from(JSON.stringify({ alg: "ES256" }), "utf8").toString("base64url");
  const payload = Buffer.from(JSON.stringify(payloadObj), "utf8").toString("base64url");
  return `${header}.${payload}.sig`;
}

describe("tokenUtils DPoP helpers", () => {
  describe("computeAthForDpop", () => {
    it("MUST match SHA-256 base64url (no padding) of the access token string (RFC 9449 ath)", () => {
      const token = "eyJhbGciOiJFUzI1NiJ9.payload.signature";
      expect(computeAthForDpop(token)).to.equal(referenceAth(token));
    });

    it("MUST be stable for empty string edge case", () => {
      expect(computeAthForDpop("")).to.equal(referenceAth(""));
    });
  });

  describe("formatResourceAuthorizationHeader", () => {
    it("MUST use DPoP scheme when token_type is DPoP", () => {
      expect(formatResourceAuthorizationHeader("opaque-token", { token_type: "DPoP" })).to.equal(
        "DPoP opaque-token",
      );
    });

    it("MUST use DPoP scheme when JWT access token contains cnf.jkt", () => {
      const jwt = minimalJwt({ cnf: { jkt: "abc" } });
      expect(formatResourceAuthorizationHeader(jwt, { token_type: "Bearer" })).to.equal(`DPoP ${jwt}`);
    });

    it("MUST use Bearer scheme for non-DPoP-bound tokens", () => {
      expect(formatResourceAuthorizationHeader("opaque-token", { token_type: "Bearer" })).to.equal(
        "Bearer opaque-token",
      );
    });
  });

  describe("isDpopBoundAccessToken", () => {
    it("MUST be true when token_type is DPoP (any case)", () => {
      expect(isDpopBoundAccessToken({ token_type: "DPoP" }, "opaque")).to.equal(true);
      expect(isDpopBoundAccessToken({ token_type: "dpop" }, undefined)).to.equal(true);
    });

    it("MUST be true when JWT access token payload contains cnf.jkt (even if token_type is Bearer)", () => {
      const jwt = minimalJwt({ cnf: { jkt: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsTGCtkXk" } });
      expect(isDpopBoundAccessToken({ token_type: "Bearer" }, jwt)).to.equal(true);
    });

    it("MUST be false for Bearer token response and JWT without cnf.jkt", () => {
      const jwt = minimalJwt({ sub: "user", scope: "openid" });
      expect(isDpopBoundAccessToken({ token_type: "Bearer" }, jwt)).to.equal(false);
    });

    it("MUST be false for opaque access token without DPoP token_type", () => {
      expect(isDpopBoundAccessToken({ token_type: "Bearer" }, "not-a-jwt")).to.equal(false);
    });

    it("MUST be false when token_body or access_token is missing usable signals", () => {
      expect(isDpopBoundAccessToken({}, "not-enough-parts")).to.equal(false);
      expect(isDpopBoundAccessToken({ token_type: "Bearer" }, "")).to.equal(false);
    });

    it("MUST be false for malformed JWT payload (invalid base64/json)", () => {
      expect(isDpopBoundAccessToken({ token_type: "Bearer" }, "aaa.b!!!.ccc")).to.equal(false);
    });
  });
});
