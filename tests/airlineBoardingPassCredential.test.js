import { expect } from "chai";
import fs from "fs";
import {
  getAirlineBoardingPassSDJWTData,
  getAirlineBoardingPassSDJWTDataWithPayload,
} from "../utils/credPayloadUtil.js";
import { credentialConfigRequiresJwtProofKeyAttestation } from "../utils/routeUtils.js";

const EXPECTED_CLAIM_PATHS = [
  ["pnr"],
  ["given_name"],
  ["family_name"],
  ["passenger_name"],
  ["carrier_name"],
  ["carrier_code"],
  ["flight_number"],
  ["from"],
  ["to"],
  ["departure_datetime"],
  ["arrival_datetime"],
  ["terminal"],
  ["gate"],
  ["boarding_time"],
  ["seat"],
  ["boarding_group"],
  ["sequence_number"],
  ["cabin_class"],
  ["ticket_number"],
  ["baggage_allowance"],
];

describe("airline boarding pass credential", () => {
  it("publishes an SD-JWT credential configuration with boarding pass claims", () => {
    const issuerConfig = JSON.parse(
      fs.readFileSync("./data/issuer-config.json", "utf8"),
    );
    const configuration =
      issuerConfig.credential_configurations_supported.airline_boarding_pass;

    expect(configuration).to.include({
      scope: "airline_boarding_pass",
      format: "dc+sd-jwt",
      vct: "urn:eu.aptitude:airline.boardingpass:1",
    });
    expect(
      configuration.credential_metadata.claims.map(({ path }) => path),
    ).to.deep.equal(EXPECTED_CLAIM_PATHS);
    expect(configuration.proof_types_supported.jwt).to.have.property(
      "key_attestations_required",
    ).that.deep.equals({});
    expect(credentialConfigRequiresJwtProofKeyAttestation(configuration)).to.equal(
      true,
    );

    const oauthConfig = JSON.parse(
      fs.readFileSync("./data/oauth-config.json", "utf8"),
    );
    expect(oauthConfig.scopes_supported).to.include("airline_boarding_pass");
  });

  it("uses mock defaults and selectively discloses supplied boarding details", () => {
    const defaults = getAirlineBoardingPassSDJWTData();
    expect(defaults.claims).to.deep.equal({
      pnr: "ABC123",
      given_name: "NIKOS",
      family_name: "MATKALAINEN",
      passenger_name: "NIKOS MATKALAINEN",
      carrier_name: "AEGEAN Connect",
      carrier_code: "AC",
      flight_number: "A3 604",
      from: "ATH",
      to: "HER",
      departure_datetime: "2026-08-01T08:15:00+03:00",
      arrival_datetime: "2026-08-01T09:05:00+03:00",
      terminal: "Main",
      gate: "B12",
      boarding_time: "07:35",
      seat: "14A",
      boarding_group: "2",
      sequence_number: "042",
      cabin_class: "Economy",
      ticket_number: "3901234567890",
      baggage_allowance: "1 cabin bag + 1 personal item",
    });
    expect(defaults.disclosureFrame._sd).to.deep.equal(
      EXPECTED_CLAIM_PATHS.map(([claim]) => claim),
    );

    expect(
      getAirlineBoardingPassSDJWTDataWithPayload({
        pnr: "XYZ999",
        seat: "1A",
        flight_number: "A3 100",
      }).claims,
    ).to.include({
      pnr: "XYZ999",
      seat: "1A",
      flight_number: "A3 100",
      given_name: "NIKOS",
      from: "ATH",
    });
  });
});
