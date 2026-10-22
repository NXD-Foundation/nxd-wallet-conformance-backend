import { expect } from "chai";
import fs from "fs";
import {
  getBookingReferenceSDJWTData,
  getBookingReferenceSDJWTDataWithPayload,
} from "../utils/credPayloadUtil.js";
import { credentialConfigRequiresJwtProofKeyAttestation } from "../utils/routeUtils.js";

const CANONICAL_DISCLOSURE_FRAME = {
  _sd: [
    "id",
    "reservationReference",
    "supplierReference",
    "property",
    "stay",
    "room",
    "ratePlanCode",
    "reservationStatus",
    "voucherReference",
    "guest",
  ],
};

const LEGACY_CLAIM_KEYS = [
  "booking_reference",
  "hotel_id",
  "hotel_name",
  "arrival_date",
  "departure_date",
  "booking_platform",
];

describe("Accommodation Voucher (booking_reference_credential)", () => {
  it("publishes canonical claim paths while retaining legacy configuration identifiers", () => {
    const issuerConfig = JSON.parse(
      fs.readFileSync("./data/issuer-config.json", "utf8"),
    );
    const configuration =
      issuerConfig.credential_configurations_supported.booking_reference_credential;

    expect(configuration).to.include({
      scope: "booking_reference_credential",
      format: "dc+sd-jwt",
      vct: "booking_reference_credential",
    });
    expect(configuration.credential_metadata.display[0]).to.include({
      name: "Accommodation Voucher",
      locale: "en-GB",
    });
    expect(configuration.credential_metadata.claims.map(({ path }) => path)).to.deep.equal([
      ["reservationReference"],
      ["supplierReference"],
      ["property"],
      ["stay"],
      ["room"],
      ["ratePlanCode"],
      ["reservationStatus"],
      ["voucherReference"],
      ["guest"],
    ]);
    expect(configuration.proof_types_supported.jwt).to.have.property(
      "key_attestations_required",
    ).that.deep.equals({});
    expect(credentialConfigRequiresJwtProofKeyAttestation(configuration)).to.equal(
      true,
    );

    const oauthConfig = JSON.parse(fs.readFileSync("./data/oauth-config.json", "utf8"));
    expect(oauthConfig.scopes_supported).to.include("booking_reference_credential");
  });

  it("issues canonical claims with demonstration defaults and selective disclosure", () => {
    const result = getBookingReferenceSDJWTData();

    expect(result.disclosureFrame).to.deep.equal(CANONICAL_DISCLOSURE_FRAME);
    expect(result.claims).to.include.keys([
      "id",
      "reservationReference",
      "supplierReference",
      "property",
      "stay",
      "room",
      "ratePlanCode",
      "reservationStatus",
      "voucherReference",
      "guest",
    ]);
    expect(result.claims.stay.checkInDate).to.match(/^\d{4}-\d{2}-\d{2}$/);
    expect(result.claims.stay.checkOutDate).to.match(/^\d{4}-\d{2}-\d{2}$/);
    LEGACY_CLAIM_KEYS.forEach((key) => {
      expect(result.claims).to.not.have.property(key);
    });
  });

  it("translates legacy booking payloads into canonical issued claims", () => {
    const result = getBookingReferenceSDJWTDataWithPayload({
      booking_reference: "OTA-MS62DP17-VQPSKP",
      hotel_id: "9213",
      hotel_name: "Test Hotel Rhodes",
      arrival_date: "2026-07-31",
      departure_date: "2026-08-04",
      booking_platform: "SEDIT-X OTA Booking Portal",
    });

    expect(result.disclosureFrame).to.deep.equal(CANONICAL_DISCLOSURE_FRAME);
    expect(result.claims.reservationReference).to.equal("OTA-MS62DP17-VQPSKP");
    expect(result.claims.supplierReference).to.equal("SEDIT-X OTA Booking Portal");
    expect(result.claims.property).to.deep.equal({
      id: "9213",
      name: "Test Hotel Rhodes",
    });
    expect(result.claims.stay).to.deep.equal({
      checkInDate: "2026-07-31",
      checkOutDate: "2026-08-04",
    });
    LEGACY_CLAIM_KEYS.forEach((key) => {
      expect(result.claims).to.not.have.property(key);
    });
  });

  it("accepts canonical payload input directly", () => {
    const result = getBookingReferenceSDJWTDataWithPayload({
      reservationReference: "RES-123",
      supplierReference: "SUP-456",
      property: { id: "prop-1", name: "Harbor Hotel" },
      stay: { checkInDate: "2026-09-01", checkOutDate: "2026-09-05" },
      room: { type: "Deluxe King" },
      ratePlanCode: "NRF",
      reservationStatus: "Confirmed",
      voucherReference: "VCH-789",
      guest: { givenName: "Alex", familyName: "Rivera" },
    });

    expect(result.claims.reservationReference).to.equal("RES-123");
    expect(result.claims.supplierReference).to.equal("SUP-456");
    expect(result.claims.property).to.deep.equal({
      id: "prop-1",
      name: "Harbor Hotel",
    });
    expect(result.claims.stay).to.deep.equal({
      checkInDate: "2026-09-01",
      checkOutDate: "2026-09-05",
    });
    expect(result.claims.room).to.deep.equal({ type: "Deluxe King" });
    expect(result.claims.ratePlanCode).to.equal("NRF");
    expect(result.claims.reservationStatus).to.equal("Confirmed");
    expect(result.claims.voucherReference).to.equal("VCH-789");
    expect(result.claims.guest).to.deep.equal({
      givenName: "Alex",
      familyName: "Rivera",
    });
  });
});
