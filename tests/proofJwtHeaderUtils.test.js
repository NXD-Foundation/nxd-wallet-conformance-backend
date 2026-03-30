import { expect } from "chai";
import { ProofJwtHeaderValidator } from "../utils/proofJwtHeaderUtils.js";

describe("ProofJwtHeaderValidator", () => {
  describe("assertX5cExclusiveWithKidOrJwk", () => {
    it("does not throw when header has only jwk", () => {
      expect(() =>
        ProofJwtHeaderValidator.assertX5cExclusiveWithKidOrJwk(
          { alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: "a", y: "b" } },
          { invalidProofMessage: "No proof information found", specRef: "urn:spec" }
        )
      ).to.not.throw();
    });

    it("does not throw when header has only kid", () => {
      expect(() =>
        ProofJwtHeaderValidator.assertX5cExclusiveWithKidOrJwk(
          { alg: "ES256", kid: "did:key:z6MkhaXgBZDvotDkLTC7ZRhhhaa63qA4fxetvPMeRErF" },
          { invalidProofMessage: "No proof information found" }
        )
      ).to.not.throw();
    });

    it("does not throw when header has only x5c", () => {
      expect(() =>
        ProofJwtHeaderValidator.assertX5cExclusiveWithKidOrJwk(
          { alg: "ES256", x5c: ["MIIBkTCB+wIJAKHf"] },
          { invalidProofMessage: "No proof information found" }
        )
      ).to.not.throw();
    });

    it("throws when x5c is present with jwk", () => {
      expect(() =>
        ProofJwtHeaderValidator.assertX5cExclusiveWithKidOrJwk(
          {
            alg: "ES256",
            x5c: ["MIIB"],
            jwk: { kty: "EC", crv: "P-256", x: "a", y: "b" },
          },
          { invalidProofMessage: "No proof information found", specRef: "urn:oid4vci" }
        )
      ).to.throw(/x5c MUST NOT be present when kid or jwk is present/);
    });

    it("throws when x5c is present with kid", () => {
      expect(() =>
        ProofJwtHeaderValidator.assertX5cExclusiveWithKidOrJwk(
          { alg: "ES256", x5c: ["MIIB"], kid: "did:web:example.com#key-1" },
          { invalidProofMessage: "No proof information found", specRef: "urn:oid4vci" }
        )
      ).to.throw(/x5c MUST NOT be present/);
    });
  });
});
