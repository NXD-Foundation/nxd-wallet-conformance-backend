import { expect } from "chai";
import fs from "fs";
import {
  getAirlinePnrSDJWTData,
  getAirlinePnrSDJWTDataWithPayload,
} from "../utils/credPayloadUtil.js";
import { credentialConfigRequiresJwtProofKeyAttestation } from "../utils/routeUtils.js";

describe("airline PNR credential", () => {
  it("publishes a minimal SD-JWT credential configuration with a pnr claim", () => {
    const issuerConfig = JSON.parse(fs.readFileSync("./data/issuer-config.json", "utf8"));
    const configuration = issuerConfig.credential_configurations_supported.airline_pnr_credential;

    expect(configuration).to.include({
      scope: "airline_pnr_credential",
      format: "dc+sd-jwt",
      vct: "airline_pnr_credential",
    });
    expect(configuration.credential_metadata.claims.map(({ path }) => path)).to.deep.equal([
      ["pnr"],
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

  it("uses the mock default and selectively discloses a supplied PNR", () => {
    expect(getAirlinePnrSDJWTData()).to.deep.equal({
      claims: { pnr: "Q7X2LM" },
      disclosureFrame: { _sd: ["pnr"] },
    });
    expect(getAirlinePnrSDJWTDataWithPayload({ pnr: "ABC123" })).to.deep.equal({
      claims: { pnr: "ABC123" },
      disclosureFrame: { _sd: ["pnr"] },
    });
  });
});
