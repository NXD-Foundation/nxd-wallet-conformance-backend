import { expect } from "chai";
import {
  applyTokenClientBindingToSession,
  assertOpenid4VciProofIssClaim,
  getProofIssBindingFromSession,
  resolveTokenClientBinding,
} from "../utils/openid4vciProofIss.js";

const PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

describe("OpenID4VCI 1.0 F.1 proof JWT iss", () => {
  describe("resolveTokenClientBinding", () => {
    it("treats pre-auth without client_id or attestation as anonymous", () => {
      expect(
        resolveTokenClientBinding({
          grantType: PRE_AUTH,
          bodyClientId: undefined,
          attestationResult: { skip: true },
        }),
      ).to.deep.equal({ tokenClientId: null, anonymousAccess: true });
    });

    it("uses attestation sub as client_id when ABCA succeeds without a form client_id", () => {
      expect(
        resolveTokenClientBinding({
          grantType: PRE_AUTH,
          bodyClientId: undefined,
          attestationResult: { ok: true, attestationPayload: { sub: "wallet-client" } },
        }),
      ).to.deep.equal({ tokenClientId: "wallet-client", anonymousAccess: false });
    });

    it("prefers the token request client_id when both body and attestation sub are present", () => {
      expect(
        resolveTokenClientBinding({
          grantType: PRE_AUTH,
          bodyClientId: "wallet-client",
          attestationResult: { ok: true, attestationPayload: { sub: "wallet-client" } },
        }),
      ).to.deep.equal({ tokenClientId: "wallet-client", anonymousAccess: false });
    });

    it("never treats authorization_code as anonymous even without a recorded client_id", () => {
      expect(
        resolveTokenClientBinding({
          grantType: "authorization_code",
          bodyClientId: undefined,
          attestationResult: { skip: true },
        }),
      ).to.deep.equal({ tokenClientId: null, anonymousAccess: false });
    });
  });

  describe("assertOpenid4VciProofIssClaim", () => {
    it("rejects iss on anonymous pre-authorized access", () => {
      expect(() =>
        assertOpenid4VciProofIssClaim({
          iss: "did:jwk:abc",
          tokenClientId: null,
          anonymousAccess: true,
        }),
      )
        .to.throw(/must be omitted for anonymous pre-authorized access/)
        .with.property("errorCode", "invalid_proof");
    });

    it("allows omitted iss on anonymous pre-authorized access", () => {
      expect(() =>
        assertOpenid4VciProofIssClaim({
          iss: undefined,
          tokenClientId: null,
          anonymousAccess: true,
        }),
      ).to.not.throw();
    });

    it("allows omitted iss when the client authenticated (OPTIONAL)", () => {
      expect(() =>
        assertOpenid4VciProofIssClaim({
          iss: undefined,
          tokenClientId: "wallet-client",
          anonymousAccess: false,
        }),
      ).to.not.throw();
    });

    it("accepts iss equal to the authenticated client_id", () => {
      expect(() =>
        assertOpenid4VciProofIssClaim({
          iss: "wallet-client",
          tokenClientId: "wallet-client",
          anonymousAccess: false,
        }),
      ).to.not.throw();
    });

    it("rejects holder DID iss when the client authenticated with a known client_id", () => {
      expect(() =>
        assertOpenid4VciProofIssClaim({
          iss: "did:jwk:eyJrdHkiOiJFQyJ9",
          tokenClientId: "wallet-client",
          anonymousAccess: false,
        }),
      )
        .to.throw(/Issuer claim must be the client_id of the request: wallet-client/)
        .with.property("proofValidationError", true);
    });

    it("does not compare iss when the session has no recorded client binding", () => {
      expect(() =>
        assertOpenid4VciProofIssClaim({
          iss: "did:jwk:legacy-test",
          tokenClientId: null,
          anonymousAccess: false,
        }),
      ).to.not.throw();
    });
  });

  describe("session binding", () => {
    it("persists token client identity for later /credential checks", () => {
      const session = { status: "success" };
      applyTokenClientBindingToSession(session, {
        tokenClientId: "wallet-client",
        anonymousAccess: false,
      });
      expect(getProofIssBindingFromSession(session)).to.deep.equal({
        tokenClientId: "wallet-client",
        anonymousAccess: false,
      });
    });
  });
});
