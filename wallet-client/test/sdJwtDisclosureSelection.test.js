import { expect } from "chai";
import {
  filterSdJwtByDcqlClaims,
  sdJwtWithoutKbJwt,
} from "../src/lib/sdJwtDisclosureSelection.js";

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
});
