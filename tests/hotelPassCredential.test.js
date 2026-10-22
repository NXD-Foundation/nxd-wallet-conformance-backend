import { expect } from "chai";
import fs from "fs";
import {
  getRoomKeySDJWTData,
  getRoomKeySDJWTDataWithPayload,
} from "../utils/credPayloadUtil.js";
import { credentialConfigRequiresJwtProofKeyAttestation } from "../utils/routeUtils.js";

describe("Hotel Pass (room_key_credential)", () => {
  it("publishes Hotel Pass display metadata while retaining legacy configuration identifiers", () => {
    const issuerConfig = JSON.parse(
      fs.readFileSync("./data/issuer-config.json", "utf8"),
    );
    const configuration =
      issuerConfig.credential_configurations_supported.room_key_credential;

    expect(configuration).to.include({
      scope: "room_key_credential",
      format: "dc+sd-jwt",
      vct: "room_key_credential",
    });
    expect(configuration.credential_metadata.display[0]).to.include({
      name: "Hotel Pass",
      locale: "en-GB",
    });
    expect(configuration.credential_metadata.display[0].description).to.match(
      /not a cryptographic mobile-room-key or door-access credential/i,
    );
    expect(
      configuration.credential_metadata.claims.map(({ path }) => path),
    ).to.deep.equal([["room_number"], ["picture"]]);
    expect(configuration.proof_types_supported.jwt).to.have.property(
      "key_attestations_required",
    ).that.deep.equals({});
    expect(credentialConfigRequiresJwtProofKeyAttestation(configuration)).to.equal(
      true,
    );

    const oauthConfig = JSON.parse(fs.readFileSync("./data/oauth-config.json", "utf8"));
    expect(oauthConfig.scopes_supported).to.include("room_key_credential");
  });

  it("generates a QR picture from reservationReference by default", async () => {
    const defaults = await getRoomKeySDJWTData();

    expect(Object.keys(defaults.claims)).to.deep.equal([
      "id",
      "room_number",
      "picture",
    ]);
    expect(defaults.disclosureFrame._sd).to.deep.equal([
      "id",
      "room_number",
      "picture",
    ]);
    expect(defaults.claims.picture).to.match(/^data:image\/png;base64,/);
    expect(defaults.claims).to.not.have.property("reservationReference");
    expect(defaults.claims).to.not.have.property("reservationId");
  });

  it("accepts reservationReference as the preferred QR source field", async () => {
    const preferred = await getRoomKeySDJWTDataWithPayload({
      reservationReference: "RES-PREFERRED-01",
      room_number: "801",
    });
    const legacy = await getRoomKeySDJWTDataWithPayload({
      reservationId: "RES-PREFERRED-01",
      room_number: "801",
    });

    expect(preferred.claims.room_number).to.equal("801");
    expect(preferred.claims.picture).to.match(/^data:image\/png;base64,/);
    expect(legacy.claims.picture).to.equal(preferred.claims.picture);
  });

  it("accepts a pre-rendered picture or qr_code data URL", async () => {
    const picture = "data:image/png;base64,AAAA";
    const viaPicture = await getRoomKeySDJWTDataWithPayload({ picture });
    expect(viaPicture.claims.picture).to.equal(picture);

    const viaQrCode = await getRoomKeySDJWTDataWithPayload({
      qr_code: "data:image/png;base64,BBBB",
    });
    expect(viaQrCode.claims.picture).to.equal("data:image/png;base64,BBBB");
  });
});
