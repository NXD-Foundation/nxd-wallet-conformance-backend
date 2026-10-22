import { expect } from "chai";
import fs from "fs";
import {
  getAirlinePnrSDJWTData,
  getAirlinePnrSDJWTDataWithPayload,
} from "../utils/credPayloadUtil.js";
import { credentialConfigRequiresJwtProofKeyAttestation } from "../utils/routeUtils.js";

describe("airline PNR credential", () => {
  it("publishes an SD-JWT credential configuration with PNR and flight context claims", () => {
    const issuerConfig = JSON.parse(fs.readFileSync("./data/issuer-config.json", "utf8"));
    const configuration = issuerConfig.credential_configurations_supported.airline_pnr_credential;

    expect(configuration).to.include({
      scope: "airline_pnr_credential",
      format: "dc+sd-jwt",
      vct: "urn:eu.aptitude:airline.pnr:1",
    });
    expect(configuration.credential_metadata.claims.map(({ path }) => path)).to.deep.equal([
      ["pnr"],
      ["from"],
      ["to"],
      ["flight_date"],
      ["airline_name"],
    ]);
    // The EUDI Reference Wallet requires this explicit (unconstrained)
    // declaration in its issuer-metadata parser. It consequently submits the
    // same key-attested JWT proof as it does for the hotel credential.
    expect(configuration.proof_types_supported.jwt).to.have.property(
      "key_attestations_required",
    ).that.deep.equals({});
    expect(credentialConfigRequiresJwtProofKeyAttestation(configuration)).to.equal(true);

    const oauthConfig = JSON.parse(fs.readFileSync("./data/oauth-config.json", "utf8"));
    expect(oauthConfig.scopes_supported).to.include("airline_pnr_credential");
  });

  it("uses mock defaults and selectively discloses supplied flight details", () => {
    expect(getAirlinePnrSDJWTData()).to.deep.equal({
      claims: {
        pnr: "Q7X2LM",
        from: "ATH",
        to: "RHO",
        flight_date: "2026-07-31",
        airline_name: "Aegean Airlines",
      },
      disclosureFrame: {
        _sd: ["pnr", "from", "to", "flight_date", "airline_name"],
      },
    });
    expect(
      getAirlinePnrSDJWTDataWithPayload({
        pnr: "ABC123",
        from: "LHR",
        to: "CDG",
        flight_date: "2026-08-01",
        airline_name: "Example Air",
      }),
    ).to.deep.equal({
      claims: {
        pnr: "ABC123",
        from: "LHR",
        to: "CDG",
        flight_date: "2026-08-01",
        airline_name: "Example Air",
      },
      disclosureFrame: {
        _sd: ["pnr", "from", "to", "flight_date", "airline_name"],
      },
    });
  });
});
