import { expect } from "chai";
import fs from "fs";
import {
  buildIataBcbpDataString,
  getAirlineBoardingPassSDJWTData,
  getAirlineBoardingPassSDJWTDataWithPayload,
} from "../utils/airlineBoardingPassUtil.js";
import { credentialConfigRequiresJwtProofKeyAttestation } from "../utils/routeUtils.js";

const EXPECTED_CLAIM_PATHS = [
  ["format_code"],
  ["number_of_legs"],
  ["passenger_name"],
  ["electronic_ticket_indicator"],
  ["pnr"],
  ["from_airport"],
  ["to_airport"],
  ["operating_carrier"],
  ["flight_number"],
  ["date_of_flight_julian"],
  ["compartment_code"],
  ["seat"],
  ["check_in_sequence_number"],
  ["passenger_status"],
  ["bcbp_data"],
  ["given_name"],
  ["family_name"],
  ["carrier_name"],
  ["departure_datetime"],
  ["arrival_datetime"],
  ["terminal"],
  ["gate"],
  ["boarding_time"],
  ["boarding_group"],
  ["ticket_number"],
  ["baggage_allowance"],
];

const EXPECTED_DEFAULT_CLAIMS = {
  format_code: "M",
  number_of_legs: "1",
  passenger_name: "MATKALAINEN/NIKOS",
  electronic_ticket_indicator: "E",
  pnr: "ABC123",
  from_airport: "ATH",
  to_airport: "HER",
  operating_carrier: "A3",
  flight_number: "0604",
  date_of_flight_julian: "213",
  compartment_code: "Y",
  seat: "014A",
  check_in_sequence_number: "00042",
  passenger_status: "0",
  bcbp_data: "M1MATKALAINEN/NIKOS   EABC123 ATHHERA3 0604 213Y014A00042000",
  given_name: "NIKOS",
  family_name: "MATKALAINEN",
  carrier_name: "AEGEAN",
  departure_datetime: "2026-08-01T08:15:00+03:00",
  arrival_datetime: "2026-08-01T09:05:00+03:00",
  terminal: "Main",
  gate: "B12",
  boarding_time: "07:35",
  boarding_group: "2",
  ticket_number: "3901234567890",
  baggage_allowance: "1PC",
};

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

  it("uses IATA BCBP mock defaults and selectively discloses supplied boarding details", () => {
    const defaults = getAirlineBoardingPassSDJWTData();
    expect(defaults.claims).to.deep.equal(EXPECTED_DEFAULT_CLAIMS);
    expect(defaults.claims.bcbp_data).to.have.lengthOf(60);
    expect(defaults.disclosureFrame._sd).to.deep.equal(
      EXPECTED_CLAIM_PATHS.map(([claim]) => claim),
    );

    expect(
      getAirlineBoardingPassSDJWTDataWithPayload({
        pnr: "XYZ999",
        seat: "1A",
        flight_number: "A3 100",
        from: "SKG",
      }).claims,
    ).to.include({
      pnr: "XYZ999",
      seat: "001A",
      flight_number: "0100",
      from_airport: "SKG",
      given_name: "NIKOS",
      operating_carrier: "A3",
    });
  });

  it("builds a 60-character IATA Res 792 mandatory BCBP block", () => {
    const bcbp = buildIataBcbpDataString({
      passenger_name: "MATKALAINEN/NIKOS",
      pnr: "ABC123",
      from_airport: "ATH",
      to_airport: "HER",
      operating_carrier: "A3",
      flight_number: "604",
      date_of_flight_julian: "213",
      compartment_code: "Y",
      seat: "14A",
      check_in_sequence_number: "42",
      passenger_status: "0",
    });

    expect(bcbp).to.equal(
      "M1MATKALAINEN/NIKOS   EABC123 ATHHERA3 0604 213Y014A00042000",
    );
    expect(bcbp).to.have.lengthOf(60);
  });
});
