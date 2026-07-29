import { expect } from "chai";
import {
  getDcqlPathValue,
  validateDcqlClaims,
  validateMdocDcqlClaims,
} from "../utils/dcqlClaimValidation.js";

describe("DCQL claim validation", () => {
  const claims = {
    credentialSubject: {
      address: { country: "GR" },
    },
  };

  it("resolves nested claim paths and values constraints", () => {
    expect(getDcqlPathValue(claims, ["credentialSubject", "address", "country"])).to.equal("GR");
    expect(validateDcqlClaims(claims, [{
      path: ["credentialSubject", "address", "country"],
      values: ["GR", "DE"],
    }])).to.deep.equal({ ok: true, errors: [] });
  });

  it("reports missing paths and value mismatches", () => {
    const result = validateDcqlClaims(claims, [
      { path: ["credentialSubject", "birth_date"] },
      { path: ["credentialSubject", "address", "country"], values: ["DE"] },
    ]);
    expect(result.ok).to.equal(false);
    expect(result.errors).to.have.length(2);
  });

  it("validates DCQL paths against extracted one-credential arrays", () => {
    const extractedClaims = [{
      given_name: "Hanna",
      family_name: "Matkalainen",
      birth_date: "01.07.2005",
      age_over_18: true,
      issuance_date: 1784041631559,
      expiry_date: 1815577631559,
      issuing_authority: "UAegean Test Issuer",
      issuing_country: "Finland",
    }];
    const requestedClaims = [
      { path: ["given_name"] },
      { path: ["family_name"] },
      { path: ["birth_date"] },
      { path: ["age_over_18"], values: [true] },
      { path: ["issuance_date"] },
      { path: ["expiry_date"] },
      { path: ["issuing_authority"] },
      { path: ["issuing_country"] },
    ];

    expect(validateDcqlClaims(extractedClaims, requestedClaims)).to.deep.equal({
      ok: true,
      errors: [],
    });
  });

  it("requires a constrained value to match in at least one extracted credential", () => {
    const extractedClaims = [
      { nationality: "FI" },
      { nationality: "GR" },
    ];

    expect(validateDcqlClaims(extractedClaims, [{
      path: ["nationality"],
      values: ["GR"],
    }])).to.deep.equal({ ok: true, errors: [] });

    const mismatch = validateDcqlClaims(extractedClaims, [{
      path: ["nationality"],
      values: ["DE"],
    }]);
    expect(mismatch.ok).to.equal(false);
    expect(mismatch.errors).to.deep.equal([
      "DCQL value constraint failed for 'nationality'",
    ]);
  });

  it("validates mdoc namespace paths against extracted elements", () => {
    const result = validateMdocDcqlClaims(
      { age_over_18: true, family_name: "Doe" },
      {
        credentials: [{
          format: "mso_mdoc",
          claims: [
            { path: ["org.iso.18013.5.1", "age_over_18"], values: [true] },
            { path: ["org.iso.18013.5.1", "family_name"], value: "Doe" },
          ],
        }],
      },
    );
    expect(result).to.deep.equal({ ok: true, errors: [] });
  });
});
