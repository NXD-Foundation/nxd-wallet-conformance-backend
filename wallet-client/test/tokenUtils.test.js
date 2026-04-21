import { expect } from "chai";
import crypto from "crypto";
import {
  computeAthForDpop,
  isDpopBoundAccessToken,
  deriveAuthorizationServerIssuer,
  buildPreAuthorizedCodeTokenFormParams,
  buildCliTokenEndpointHeaders,
  extractFirstCredentialIdentifierFromTokenResponse,
  buildCredentialRequestSelector,
} from "../utils/tokenUtils.js";

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

  describe("CLI token endpoint (form body + OAuth Client Attestation headers)", () => {
    it("MUST use application/x-www-form-urlencoded fields (not JSON) for pre-authorized_code exchange", () => {
      const authz = [
        {
          type: "openid_credential",
          credential_configuration_id: "Pid",
          locations: ["https://issuer.example"],
        },
      ];
      const form = buildPreAuthorizedCodeTokenFormParams({
        preAuthorizedCode: "sess-abc",
        txCode: undefined,
        authorizationDetails: authz,
        clientAssertion: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJjbGllbnQifQ.sig",
      });
      const body = form.toString();
      expect(body).to.include("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code");
      expect(body).to.include("pre-authorized_code=sess-abc");
      expect(body).to.match(/authorization_details=/);
      expect(body).to.include("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer");
      expect(body.startsWith("{")).to.equal(false);
    });

    it("MUST include OAuth-Client-Attestation and OAuth-Client-Attestation-PoP on token request headers", () => {
      const h = buildCliTokenEndpointHeaders({
        dpopJwt: "dpop.jwt.here",
        oauthClientAttestation: "attest.jwt.here",
        oauthClientAttestationPop: "pop.jwt.here",
      });
      expect(h["content-type"]).to.equal("application/x-www-form-urlencoded");
      expect(h["DPoP"]).to.equal("dpop.jwt.here");
      expect(h["OAuth-Client-Attestation"]).to.equal("attest.jwt.here");
      expect(h["OAuth-Client-Attestation-PoP"]).to.equal("pop.jwt.here");
    });

    it("deriveAuthorizationServerIssuer MUST prefer fallback and otherwise use token endpoint origin", () => {
      expect(deriveAuthorizationServerIssuer("https://as.example/token", "https://ci.example")).to.equal(
        "https://ci.example",
      );
      expect(deriveAuthorizationServerIssuer("https://as.example/token", undefined)).to.equal("https://as.example");
    });
  });

  describe("credential_identifiers from token response (RFC001 / OIDC4VCI)", () => {
    it("extractFirstCredentialIdentifierFromTokenResponse returns first credential_identifiers entry", () => {
      const tok = {
        access_token: "at",
        authorization_details: [
          {
            type: "openid_credential",
            credential_identifiers: ["cred-id-from-as", "backup"],
          },
        ],
      };
      expect(extractFirstCredentialIdentifierFromTokenResponse(tok)).to.equal("cred-id-from-as");
    });

    it("parses authorization_details when returned as JSON string", () => {
      const tok = {
        authorization_details: JSON.stringify([
          { type: "openid_credential", credential_identifiers: ["x-1"] },
        ]),
      };
      expect(extractFirstCredentialIdentifierFromTokenResponse(tok)).to.equal("x-1");
    });

    it("buildCredentialRequestSelector prefers credential_identifier when token has identifiers", () => {
      const sel = buildCredentialRequestSelector("OfferConfigId", {
        authorization_details: [{ credential_identifiers: ["issued-cred-uuid"] }],
      });
      expect(sel).to.deep.equal({ credential_identifier: "issued-cred-uuid" });
    });

    it("buildCredentialRequestSelector falls back to credential_configuration_id", () => {
      const sel = buildCredentialRequestSelector("Pid", { access_token: "a" });
      expect(sel).to.deep.equal({ credential_configuration_id: "Pid" });
    });
  });
});
