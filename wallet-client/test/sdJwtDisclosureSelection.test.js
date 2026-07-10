import { expect } from "chai";
import {
  filterSdJwtByDcqlClaims,
  sdJwtWithoutKbJwt,
} from "../src/lib/sdJwtDisclosureSelection.js";
import { Cs02ValidationError } from "../src/lib/cs02RequestValidation.js";

function b64Json(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function unsignedJwt(payload) {
  return `${b64Json({ alg: "none", typ: "dc+sd-jwt" })}.${b64Json(payload)}.sig`;
}

function disclosure(name, value) {
  return b64Json(["salt", name, value]);
}

describe("sdJwtDisclosureSelection", () => {
  it("filters SD-JWT disclosures to the requested DCQL claim paths", () => {
    const familyName = disclosure("family_name", "Neslo");
    const givenName = disclosure("given_name", "Alice");
    const kbJwt = unsignedJwt({ typ: "kb+jwt" });
    const sdJwt = `${unsignedJwt({ vct: "urn:test", _sd: ["digest"] })}~${familyName}~${givenName}~${kbJwt}`;

    const filtered = filterSdJwtByDcqlClaims(sdJwt, {
      id: "cmwallet",
      format: "dc+sd-jwt",
      claims: [{ path: ["family_name"] }],
    });

    const { disclosures } = sdJwtWithoutKbJwt(filtered);
    expect(disclosures).to.deep.equal([familyName]);
    expect(filtered).to.not.include(kbJwt);
    expect(filtered).to.match(/~$/);
  });

  it("throws when a requested DCQL claim is neither clear nor disclosed", () => {
    const sdJwt = `${unsignedJwt({ vct: "urn:test", _sd: ["digest"] })}~${disclosure(
      "given_name",
      "Alice",
    )}~`;

    expect(() =>
      filterSdJwtByDcqlClaims(sdJwt, {
        id: "cmwallet",
        format: "dc+sd-jwt",
        claims: [{ path: ["family_name"] }],
      }),
    ).to.throw("missing requested DCQL disclosure");
  });

  it("does not require a disclosure for requested clear-text claims", () => {
    const sdJwt = `${unsignedJwt({ vct: "urn:test", family_name: "Neslo" })}~`;

    const filtered = filterSdJwtByDcqlClaims(sdJwt, {
      id: "cmwallet",
      format: "dc+sd-jwt",
      claims: [{ path: ["family_name"] }],
    });

    expect(sdJwtWithoutKbJwt(filtered).disclosures).to.deep.equal([]);
  });

  it("keeps only the disclosures from the satisfied DCQL claim_sets option", () => {
    const familyName = disclosure("family_name", "Neslo");
    const birthDate = disclosure("birth_date", "1990-01-01");
    const kbJwt = unsignedJwt({ typ: "kb+jwt" });
    const sdJwt = `${unsignedJwt({ vct: "urn:test", _sd: ["digest"] })}~${familyName}~${birthDate}~${kbJwt}`;

    const filtered = filterSdJwtByDcqlClaims(sdJwt, {
      id: "cmwallet",
      format: "dc+sd-jwt",
      claims: [
        { id: "family_name_claim", path: ["family_name"] },
        { id: "given_name_claim", path: ["given_name"] },
        { id: "birth_date_claim", path: ["birth_date"] },
      ],
      claim_sets: [["family_name_claim", "given_name_claim"], ["birth_date_claim"]],
    });

    expect(sdJwtWithoutKbJwt(filtered).disclosures).to.deep.equal([birthDate]);
  });

  it("throws when stored disclosures satisfy no DCQL claim_sets option", () => {
    const familyName = disclosure("family_name", "Neslo");
    const sdJwt = `${unsignedJwt({ vct: "urn:test", _sd: ["digest"] })}~${familyName}~`;

    expect(() =>
      filterSdJwtByDcqlClaims(sdJwt, {
        id: "cmwallet",
        format: "dc+sd-jwt",
        claims: [
          { id: "given_name_claim", path: ["given_name"] },
          { id: "birth_date_claim", path: ["birth_date"] },
        ],
        claim_sets: [["given_name_claim"], ["birth_date_claim"]],
      }),
    ).to.throw(/claim_sets option/);
  });

  it("throws when a requested DCQL claim path is invalid", () => {
    const sdJwt = `${unsignedJwt({ vct: "urn:test", family_name: "Neslo" })}~`;

    expect(() =>
      filterSdJwtByDcqlClaims(sdJwt, {
        id: "cmwallet",
        format: "dc+sd-jwt",
        claims: [{ path: [] }],
      }),
    ).to.throw(Cs02ValidationError);
  });

  it("throws when an SD-JWT request uses a nested claim path", () => {
    const sdJwt = `${unsignedJwt({ vct: "urn:test", family_name: "Neslo" })}~`;

    expect(() =>
      filterSdJwtByDcqlClaims(sdJwt, {
        id: "cmwallet",
        format: "dc+sd-jwt",
        claims: [{ path: ["address", "locality"] }],
      }),
    ).to.throw(Cs02ValidationError, /top-level claim paths/);
  });
});
