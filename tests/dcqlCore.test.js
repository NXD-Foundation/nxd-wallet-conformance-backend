import { expect } from "chai";
import {
  evaluateCredentialSets,
  selectClaimPathValues,
  selectSatisfiedClaimSet,
  validateSupportedClaimPath,
  dcqlValuesInclude,
} from "../utils/dcqlCore.js";
import {
  disclosedPathMatchesDcqlPath,
  getSdJwtPathValue,
  sdJwtDisclosureHashesForPath,
  claimSatisfiesSdJwtConstraints,
  selectSatisfiedSdJwtClaimSet,
} from "../utils/sdJwtClaims.js";
import {
  getMdocPathValue,
  claimSatisfiesMdocConstraints,
  selectSatisfiedMdocClaimSet,
} from "../utils/mdocClaims.js";

describe("dcqlCore", () => {
  it("evaluates required credential_sets against matched credential ids", () => {
    const evaluation = evaluateCredentialSets(
      {
        credentials: [{ id: "a" }, { id: "b" }],
        credential_sets: [{ required: true, options: [["a", "b"]] }],
      },
      { a: true, b: true },
    );
    expect(evaluation.satisfied).to.equal(true);
    expect(Array.from(evaluation.allowedIds).sort()).to.deep.equal(["a", "b"]);
  });

  it("selects the first satisfied claim_set", () => {
    const credQuery = {
      claims: [
        { id: "c1", path: ["family_name"] },
        { id: "c2", path: ["given_name"] },
      ],
      claim_sets: [["c2"], ["c1"]],
    };
    const selected = selectSatisfiedClaimSet(credQuery, (claim) =>
      claim.path[0] === "family_name",
    );
    expect(selected).to.deep.equal(new Set(["c1"]));
  });

  it("rejects unsupported claim path segments", () => {
    expect(() => validateSupportedClaimPath(["a", "b[0]"])).to.throw(/unsupported segment/i);
  });

  it("accepts integer and null path segments for array navigation", () => {
    expect(validateSupportedClaimPath(["citizenship", null, "country"])).to.deep.equal([
      "citizenship",
      null,
      "country",
    ]);
    expect(validateSupportedClaimPath(["education", 0, "degree"])).to.deep.equal([
      "education",
      0,
      "degree",
    ]);
  });

  it("selects claim path values through arrays and wildcards", () => {
    const claims = {
      citizenship: [{ country: "DE" }, { country: "AT" }],
      education: [{ degree: "MSc" }, { degree: "BSc" }],
    };
    expect(selectClaimPathValues(claims, ["citizenship", null, "country"])).to.deep.equal([
      "DE",
      "AT",
    ]);
    expect(selectClaimPathValues(claims, ["education", 1, "degree"])).to.deep.equal(["BSc"]);
  });
});

describe("sdJwtClaims", () => {
  it("resolves dotted disclosure keys and nested paths", () => {
    const claims = {
      family_name: "Neslo",
      "identifier.schemeID": "European Student Identifier",
      address: { locality: "Athens" },
    };
    expect(getSdJwtPathValue(claims, ["family_name"])).to.equal("Neslo");
    expect(getSdJwtPathValue(claims, ["identifier", "schemeID"])).to.equal(
      "European Student Identifier",
    );
    expect(getSdJwtPathValue(claims, ["address", "locality"])).to.equal("Athens");
  });

  it("selects satisfied SD-JWT claim sets", () => {
    const credQuery = {
      claims: [
        { id: "family_name_claim", path: ["family_name"], values: ["Neslo"] },
        { id: "given_name_claim", path: ["given_name"] },
      ],
      claim_sets: [["given_name_claim"], ["family_name_claim"]],
    };
    const selected = selectSatisfiedSdJwtClaimSet(credQuery, { family_name: "Neslo" });
    expect(selected).to.deep.equal(new Set(["family_name_claim"]));
    expect(
      claimSatisfiesSdJwtConstraints(
        { path: ["family_name"], values: ["Neslo"] },
        { family_name: "Neslo" },
      ),
    ).to.equal(true);
    expect(
      claimSatisfiesSdJwtConstraints(
        { path: ["age_over_18"], values: [true] },
        { age_over_18: true },
      ),
    ).to.equal(true);
    expect(
      claimSatisfiesSdJwtConstraints(
        { path: ["citizenship", null, "country"], values: ["DE"] },
        { citizenship: [{ country: "AT" }, { country: "DE" }] },
      ),
    ).to.equal(true);
  });

  it("matches SD-JWT disclosure keymap paths with DCQL wildcards and indices", () => {
    const keymap = {
      "citizenship.0.country": "hash-0",
      "citizenship.1.country": "hash-1",
      citizenship: "hash-parent",
    };
    expect(
      Array.from(
        sdJwtDisclosureHashesForPath(["citizenship", null, "country"], keymap),
      ).sort(),
    ).to.deep.equal(["hash-0", "hash-1", "hash-parent"]);
    expect(
      Array.from(sdJwtDisclosureHashesForPath(["citizenship", 1, "country"], keymap)).sort(),
    ).to.deep.equal(["hash-1", "hash-parent"]);
    expect(disclosedPathMatchesDcqlPath("citizenship.0.country", ["citizenship", null, "country"]))
      .to.equal(true);
  });
});

describe("mdocClaims", () => {
  it("resolves namespace claim paths", () => {
    const claimsByNamespace = {
      "urn:eu.europa.ec.eudi:pid:1": { family_name: "Neslo" },
    };
    expect(
      getMdocPathValue(claimsByNamespace, ["urn:eu.europa.ec.eudi:pid:1", "family_name"]),
    ).to.equal("Neslo");
    expect(
      claimSatisfiesMdocConstraints(
        {
          path: ["urn:eu.europa.ec.eudi:pid:1", "family_name"],
          values: ["Neslo"],
        },
        claimsByNamespace,
      ),
    ).to.equal(true);
    expect(
      selectSatisfiedMdocClaimSet(
        {
          claims: [
            {
              id: "family_name_claim",
              path: ["urn:eu.europa.ec.eudi:pid:1", "family_name"],
              values: ["Neslo"],
            },
          ],
          claim_sets: [["family_name_claim"]],
        },
        claimsByNamespace,
      ),
    ).to.deep.equal(new Set(["family_name_claim"]));
  });
});
