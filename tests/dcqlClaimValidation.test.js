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

  it("resolves paths across an array of extracted credential objects", () => {
    const extracted = [{
      given_name: "Hanna",
      family_name: "Matkalainen",
      birthdate: "2005-07-01",
      date_of_issuance: "2026-08-25",
      date_of_expiry: "2027-08-25",
      issuing_authority: "UAegean Test Issuer",
      issuing_country: "FI",
    }];
    const dcqlClaims = [
      { path: ["given_name"] },
      { path: ["family_name"] },
      { path: ["birthdate"] },
      { path: ["date_of_issuance"] },
      { path: ["date_of_expiry"] },
      { path: ["issuing_authority"] },
      { path: ["issuing_country"] },
    ];
    expect(getDcqlPathValue(extracted, ["given_name"])).to.equal("Hanna");
    expect(validateDcqlClaims(extracted, dcqlClaims)).to.deep.equal({ ok: true, errors: [] });
  });

  it("matches DCQL claims split across multiple presented credentials", () => {
    const extracted = [
      { booking_reference: "ABC123" },
      { family_name: "Matkalainen" },
    ];
    expect(validateDcqlClaims(extracted, [
      { path: ["booking_reference"] },
      { path: ["family_name"] },
    ])).to.deep.equal({ ok: true, errors: [] });
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
