import { expect } from "chai";
import fs from "fs";
import {
  getPIDSDJWTData,
  getPIDSDJWTDataMsoMdoc,
} from "../utils/credPayloadUtil.js";

const mandatorySdJwtClaims = [
  "family_name",
  "given_name",
  "birthdate",
  "place_of_birth",
  "nationalities",
  "picture",
  "issuing_authority",
  "issuing_country",
];

const mandatoryMdocClaims = [
  "family_name",
  "given_name",
  "birth_date",
  "place_of_birth",
  "nationality",
  "portrait",
  "issuing_authority",
  "issuing_country",
];

describe("PID Rulebook 1.7 data model", () => {
  it("creates a complete canonical SD-JWT mock", () => {
    const { claims, disclosureFrame } = getPIDSDJWTData();

    expect(claims).to.include.all.keys(mandatorySdJwtClaims);
    expect(claims).to.not.have.property("age_over_18");
    expect(claims.birthdate).to.match(/^\d{4}-\d{2}-\d{2}$/);
    expect(claims.issuing_country).to.match(/^[A-Z]{2}$/);
    expect(claims.nationalities).to.deep.equal(["FI"]);
    expect(claims.place_of_birth).to.have.property("country");
    expect(claims.picture).to.match(/^data:image\/jpeg;base64,/);
    expect(disclosureFrame._sd).to.have.members(Object.keys(claims));
  });

  it("creates a complete ISO PID mock in the rulebook namespace", () => {
    const { claims, disclosureFrame, doctype } = getPIDSDJWTDataMsoMdoc();
    const pidClaims = claims["urn:eu.europa.ec.eudi:pid:1"];

    expect(doctype).to.equal("urn:eu.europa.ec.eudi:pid:1");
    expect(pidClaims).to.include.all.keys(mandatoryMdocClaims);
    expect(pidClaims.portrait).to.be.instanceOf(Buffer);
    expect(pidClaims.birth_date).to.match(/^\d{4}-\d{2}-\d{2}$/);
    expect(pidClaims.nationality).to.deep.equal(["FI"]);
    expect(pidClaims).to.not.have.property("age_over_18");
    expect(disclosureFrame["urn:eu.europa.ec.eudi:pid:1"]._sd)
      .to.have.members(Object.keys(pidClaims));
  });

  it("publishes wallet-compatible canonical PID configurations", () => {
    const config = JSON.parse(fs.readFileSync("./data/issuer-config.json", "utf8"));
    const sdJwt = config.credential_configurations_supported["urn:eu.europa.ec.eudi:pid:1"];
    const mdoc = config.credential_configurations_supported["urn:eu.europa.ec.eudi:pid:1:mso_mdoc"];

    expect(sdJwt.vct).to.equal("urn:eu.europa.ec.eudi:pid:1");
    expect(sdJwt.format).to.equal("dc+sd-jwt");

    const sdJwtClaimNames = sdJwt.credential_metadata.claims.map(
      (claim) => claim.path[0]
    );
    expect(sdJwtClaimNames).to.include.members([
      "birthdate",
      "nationalities",
      "date_of_issuance",
      "date_of_expiry",
    ]);
    expect(sdJwtClaimNames).to.not.include.members([
      "age_over_18",
      "birth_date",
      "issuance_date",
      "expiry_date",
    ]);

    expect(mdoc.doctype).to.equal("urn:eu.europa.ec.eudi:pid:1");
    expect(mdoc.credential_metadata.claims[0].path[0])
      .to.equal("urn:eu.europa.ec.eudi:pid:1");

    const mdocClaimNames = mdoc.credential_metadata.claims.map(
      (claim) => claim.path[1]
    );
    expect(mdocClaimNames).to.include("nationality");
    expect(mdocClaimNames).to.not.include("age_over_18");

    const nationalityClaim = mdoc.credential_metadata.claims.find(
      (claim) => claim.path[1] === "nationality"
    );
    expect(nationalityClaim.display[0].name).to.equal("Nationality");
  });
});
