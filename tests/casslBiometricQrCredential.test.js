import { expect } from "chai";
import fs from "fs";
import {
  getCasslBiometricQrSDJWTData,
  getCasslBiometricQrSDJWTDataWithPayload,
} from "../utils/casslBiometricQrUtil.js";
import { credentialConfigRequiresJwtProofKeyAttestation } from "../utils/routeUtils.js";

describe("cassl biometric QR credential", () => {
  it("publishes an SD-JWT credential configuration with a single picture claim", () => {
    const issuerConfig = JSON.parse(
      fs.readFileSync("./data/issuer-config.json", "utf8"),
    );
    const configuration =
      issuerConfig.credential_configurations_supported.cassl_biometric_qr;

    expect(configuration).to.include({
      scope: "cassl_biometric_qr",
      format: "dc+sd-jwt",
      vct: "urn:eu.aptitude:cassl.biometricqr:1",
    });
    expect(
      configuration.credential_metadata.claims.map(({ path }) => path),
    ).to.deep.equal([["picture"]]);
    expect(configuration.proof_types_supported.jwt).to.have.property(
      "key_attestations_required",
    ).that.deep.equals({});
    expect(credentialConfigRequiresJwtProofKeyAttestation(configuration)).to.equal(
      true,
    );

    const oauthConfig = JSON.parse(
      fs.readFileSync("./data/oauth-config.json", "utf8"),
    );
    expect(oauthConfig.scopes_supported).to.include("cassl_biometric_qr");
  });

  it("issues a single picture claim as a png data URL encoding the biometric JSON", async () => {
    const defaults = await getCasslBiometricQrSDJWTData();

    expect(Object.keys(defaults.claims)).to.deep.equal(["picture"]);
    expect(defaults.disclosureFrame._sd).to.deep.equal(["picture"]);
    expect(defaults.claims.picture).to.match(/^data:image\/png;base64,/);

    const overridden = await getCasslBiometricQrSDJWTDataWithPayload({
      biometric_qr_payload: {
        passenger: { name: "HANNA MATKALAINEN" },
        journey: { flight: "A3999" },
      },
    });
    expect(overridden.claims.picture).to.match(/^data:image\/png;base64,/);
    expect(overridden.claims.picture).to.not.equal(defaults.claims.picture);
  });

  it("maps flat boarding-pass + portrait offer claims into a generated QR picture", async () => {
    const portrait = `data:image/jpeg;base64,${Buffer.from("fake-jpeg").toString("base64")}`;
    const result = await getCasslBiometricQrSDJWTDataWithPayload({
      claims: {
        pnr: "ABC123",
        given_name: "Hanna",
        family_name: "Matkalainen",
        flight_number: "A3 604",
        from: "ATH",
        to: "HER",
        departure_datetime: "2026-08-01T08:15:00+03:00",
        picture: portrait,
        valid_from: "2026-07-31T08:10:28.805Z",
        valid_until: "2026-07-31T20:10:28.805Z",
      },
    });

    // Issued claim is a QR image, not the inbound portrait.
    expect(result.claims.picture).to.match(/^data:image\/png;base64,/);
    expect(result.claims.picture).to.not.equal(portrait);
  });

  it("accepts a pre-rendered qr_code / picture_qr data URL", async () => {
    const picture_qr = "data:image/png;base64,AAAA";
    const result = await getCasslBiometricQrSDJWTDataWithPayload({ picture_qr });
    expect(result.claims).to.deep.equal({ picture: picture_qr });

    const viaQrCode = await getCasslBiometricQrSDJWTDataWithPayload({
      qr_code: "data:image/png;base64,BBBB",
    });
    expect(viaQrCode.claims).to.deep.equal({
      picture: "data:image/png;base64,BBBB",
    });
  });
});
