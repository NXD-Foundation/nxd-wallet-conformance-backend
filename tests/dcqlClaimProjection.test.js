import { expect } from "chai";
import {
  hasOnlyAllowedFields,
  selectClaimsByDcqlPaths,
} from "../utils/vpHeplers.js";

describe("DCQL claim projection", () => {
  it("keeps non-selectively disclosable SD-JWT VC claims when the query selects by vct_values", () => {
    const reconstructed = {
      iss: "https://issuer.example",
      iat: 1700000000,
      nbf: 1700000000,
      exp: 1700003600,
      vct: "urn:eu.europa.ec.eudi:pid:1",
      cnf: { jwk: { kty: "EC", crv: "P-256" } },
      status: { status_list: { idx: 1, uri: "https://issuer.example/status" } },
      family_name: "Garcia",
      given_name: "Ada",
      aud: "https://rp.example",
      _sd: ["digest"],
      _sd_alg: "sha-256",
    };

    const projected = selectClaimsByDcqlPaths(reconstructed, [["family_name"]]);

    expect(projected.vct).to.equal("urn:eu.europa.ec.eudi:pid:1");
    expect(projected.iss).to.equal("https://issuer.example");
    expect(projected.iat).to.equal(1700000000);
    expect(projected.nbf).to.equal(1700000000);
    expect(projected.exp).to.equal(1700003600);
    expect(projected.cnf).to.deep.equal(reconstructed.cnf);
    expect(projected.status).to.deep.equal(reconstructed.status);
    expect(projected.family_name).to.equal("Garcia");
    expect(projected).to.not.have.property("given_name");
    expect(projected).to.not.have.property("aud");
    expect(projected).to.not.have.property("_sd");
    expect(projected).to.not.have.property("_sd_alg");
    expect(hasOnlyAllowedFields(projected, ["$.family_name"])).to.equal(true);
  });

  it("does not invent vct when the presented credential has none", () => {
    const projected = selectClaimsByDcqlPaths({ family_name: "Garcia" }, [["family_name"]]);
    expect(projected).to.deep.equal({ family_name: "Garcia" });
  });
});
