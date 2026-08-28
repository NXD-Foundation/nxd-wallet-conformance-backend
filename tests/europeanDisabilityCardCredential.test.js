import { expect } from "chai";
import fs from "fs";
import {
  getEuropeanDisabilityCardSDJWTData,
  getEuropeanDisabilityCardSDJWTDataWithPayload,
} from "../utils/credPayloadUtil.js";
import {
  credentialConfigRequiresJwtProofKeyAttestation,
  EUROPEAN_DISABILITY_CARD_VCT,
} from "../utils/routeUtils.js";

describe("European Disability Card (european_disability_card)", () => {
  it("publishes EDC display metadata with provisional VCT", () => {
    const issuerConfig = JSON.parse(
      fs.readFileSync("./data/issuer-config.json", "utf8"),
    );
    const configuration =
      issuerConfig.credential_configurations_supported.european_disability_card;

    expect(configuration).to.include({
      scope: "european_disability_card",
      format: "dc+sd-jwt",
      vct: EUROPEAN_DISABILITY_CARD_VCT,
    });
    expect(configuration.credential_metadata.display[0]).to.include({
      name: "European Disability Card",
      locale: "en-GB",
      background_color: "#004494",
      text_color: "#FFFFFF",
    });
    expect(configuration.credential_metadata.display[0].description).to.match(
      /Directive \(EU\) 2024\/2841/i,
    );
    expect(
      configuration.credential_metadata.claims.map(({ path }) => path),
    ).to.deep.equal([
      ["family_name"],
      ["given_name"],
      ["birth_date"],
      ["serial_number"],
      ["issue_date"],
      ["expiry_date"],
      ["issuing_country"],
      ["portrait"],
      ["assistant_entitlement"],
      ["disability_status_recognised"],
    ]);
    expect(configuration.proof_types_supported.jwt).to.have.property(
      "key_attestations_required",
    ).that.deep.equals({});
    expect(credentialConfigRequiresJwtProofKeyAttestation(configuration)).to.equal(
      true,
    );

    const oauthConfig = JSON.parse(fs.readFileSync("./data/oauth-config.json", "utf8"));
    expect(oauthConfig.scopes_supported).to.include("european_disability_card");
  });

  it("generates Annex I-aligned mock claims by default", () => {
    const defaults = getEuropeanDisabilityCardSDJWTData();

    expect(Object.keys(defaults.claims)).to.deep.equal([
      "id",
      "family_name",
      "given_name",
      "birth_date",
      "serial_number",
      "issue_date",
      "expiry_date",
      "issuing_country",
      "portrait",
      "assistant_entitlement",
      "disability_status_recognised",
    ]);
    expect(defaults.disclosureFrame._sd).to.deep.equal([
      "id",
      "family_name",
      "given_name",
      "birth_date",
      "serial_number",
      "issue_date",
      "expiry_date",
      "issuing_country",
      "portrait",
      "assistant_entitlement",
      "disability_status_recognised",
    ]);
    expect(defaults.claims.portrait).to.match(/^data:image\/jpeg;base64,/);
    expect(defaults.claims.assistant_entitlement).to.equal(false);
    expect(defaults.claims.disability_status_recognised).to.equal(true);
  });

  it("accepts payload overrides and legacy field aliases", () => {
    const customised = getEuropeanDisabilityCardSDJWTDataWithPayload({
      surname: "Example",
      forename: "Alex",
      file_number: "EDC-DE-2026-0009999",
      assistant_indicator: "A",
      disability_status_recognised: true,
    });

    expect(customised.claims.family_name).to.equal("Example");
    expect(customised.claims.given_name).to.equal("Alex");
    expect(customised.claims.serial_number).to.equal("EDC-DE-2026-0009999");
    expect(customised.claims.assistant_entitlement).to.equal(true);
  });

  it("accepts assistant_entitlement as a boolean override", () => {
    const customised = getEuropeanDisabilityCardSDJWTDataWithPayload({
      assistant_entitlement: true,
    });

    expect(customised.claims.assistant_entitlement).to.equal(true);
  });
});
