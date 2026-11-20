import { strict as assert } from "node:assert";
import * as jose from "jose";
import {
  BU6_EUCC_VCT,
  BU6_PID_VCT,
  BU6_POX_VCT,
  bu6AlwaysPublishesStatusList,
  bu6SdJwtPayload,
} from "../utils/bu6CredentialPayloads.js";
import { handleCredentialGenerationBasedOnFormat } from "../utils/credGenerationUtils.js";
import { readFileSync } from "node:fs";

const ISSUED_AT = new Date("2026-11-16T10:00:00.000Z");

describe("BU6 credential payloads", () => {
  it("builds a Swedish PID whose vct is distinct from the existing PID fixture", () => {
    const payload = bu6SdJwtPayload(BU6_PID_VCT, { issuedAt: ISSUED_AT });
    assert.equal(payload.expiresAt, "2028-01-01T00:00:00.000Z");
    assert.deepEqual(payload.claims, {
      given_name: "Anna Maria",
      family_name: "Andersson",
      birthdate: "1985-04-17",
      place_of_birth: { locality: "Stockholm" },
      nationalities: ["SE"],
      personal_administrative_number: "TestPID001",
      nonce: "8d0025f3d371aa9425edbbf6991ce8173249c1afffa1ae80ff1b051b99b9b8af",
      date_of_expiry: "2028-01-01",
      issuing_authority: "Bolagsverket",
      issuing_country: "SE",
      attestation_legal_category: "PUB-EAA",
    });
    assert.deepEqual(payload.disclosureFrame._sd, Object.keys(payload.claims));
    assert.equal(bu6AlwaysPublishesStatusList(BU6_PID_VCT), true);
  });

  it("builds the Swedish power of representation from the workbook table", () => {
    const payload = bu6SdJwtPayload(BU6_POX_VCT, { issuedAt: ISSUED_AT });
    assert.equal(payload.expiresAt, "2027-07-01T00:00:00.000Z");
    assert.equal(payload.claims.credential.type, "power_of_representation");
    assert.equal(payload.claims.credential.legal_category, "QEAA");
    assert.deepEqual(payload.claims.represented_economic_operator, {
      identifier: { scheme: "EBWOID", value: "SEBOL.12345789" },
      legal_name: "Testlegalperson WB",
    });
    assert.equal(payload.claims.proxy.entity_type, "natural_entity");
    assert.deepEqual(payload.claims.proxy.natural_entity_proxy, {
      family_name: "Andersson",
      given_name: "Anna Maria",
      birth_date: "1985-04-17",
      birth_place: "Stockholm",
      nationality: ["SE"],
    });
    assert.equal(payload.claims.authority.authority_source, "proxy_position");
    assert.equal(payload.claims.authority.proxy_position.position, "Sole Administrator");
    assert.equal(payload.claims.authority.proxy_position.inscription_date, "2020-07-08");
    assert.equal(payload.claims.authority.proxy_position.assurance_level, "HIGH");
    assert.equal(payload.claims.authority.proxy_position.evidence.uri, "https://www.bolagsverket.se");
    assert.equal(payload.claims.credential_metadata.schema.id, "https://schemas.webuild.eu/power-of-x/v7");
    assert.equal(payload.claims.credential_metadata.schema.version, "7.0.0");
    assert.equal(payload.claims.credential_metadata.validity.not_before, "2026-07-14T00:00:00.000Z");
    assert.equal(payload.claims.credential_metadata.validity.not_after, "2027-07-01T00:00:00.000Z");
    assert.equal(payload.claims.credential_metadata.trust.trust_anchor, "https://eidas.ec.europa.eu");
    assert.deepEqual(payload.claims.credential_metadata.status.revocation_distribution_points, [
      "https://status.webuild.eu/pox/rl",
    ]);
    assert.deepEqual(payload.disclosureFrame.represented_economic_operator.identifier._sd, ["value"]);
    assert.deepEqual(payload.disclosureFrame.represented_economic_operator._sd, ["legal_name"]);
    assert.deepEqual(payload.disclosureFrame.proxy._sd, ["natural_entity_proxy"]);
    assert.deepEqual(payload.disclosureFrame.authority._sd, ["proxy_position"]);
    assert.equal(payload.disclosureFrame._sd, undefined);
    assert.equal(payload.disclosureFrame.credential, undefined);
    assert.equal(payload.disclosureFrame.credential_metadata, undefined);
    assert.equal(bu6AlwaysPublishesStatusList(BU6_POX_VCT), true);
  });

  it("builds an EU Company Certificate whose company claims stay in the clear", () => {
    const payload = bu6SdJwtPayload(BU6_EUCC_VCT, { issuedAt: ISSUED_AT });
    assert.equal(payload.expiresAt, "2028-01-01T00:00:00.000Z");
    assert.equal(payload.claims.attestation_legal_category, "PUB-EAA");
    assert.equal(payload.claims.legal_person_name, "Testlegalperson WB");
    assert.equal(payload.claims.legal_person_id, "SEBOL.12345789");
    assert.equal(payload.claims.registration_member_state, "SE");
    assert.equal(payload.claims.registered_address.full_address, "Storgata 1; 9008; Stockholm; SE");
    assert.equal(payload.claims.registration_date, "2003-10-10");
    assert.equal(payload.claims.legal_person_activity.code, "62010");
    assert.equal(payload.claims.legal_representative[0].full_name, "Lysende Blomst");
    assert.equal(payload.claims.legal_representative[0].date_of_birth, "1981-02-01");
    assert.equal(payload.claims.legal_representative[0].signatory_rule, "alone");
    assert.equal(Object.hasOwn(payload.claims.legal_representative[0], "identifier"), false);
    assert.equal(payload.claims.issuing_authority, "Bolagsverket");
    assert.equal(payload.claims.issuing_authority_id, "BOLSE-E81458556");
    assert.equal(payload.claims.authentic_source_id, "BOLSE-E81458556");
    assert.equal(payload.claims.authentic_source_name, "Bolagsverket");
    assert.equal(payload.claims.issuing_country, "SE");
    assert.equal(payload.claims.issuance_date, "2026-11-16T10:00:00.000Z");
    assert.deepEqual(payload.disclosureFrame, {});
    assert.equal(bu6AlwaysPublishesStatusList(BU6_EUCC_VCT), true);
  });

  it("advertises the three BU6 configuration ids on the default issuer", () => {
    const config = JSON.parse(readFileSync(new URL("../data/issuer-config.json", import.meta.url), "utf8"));
    for (const id of [BU6_PID_VCT, BU6_POX_VCT, BU6_EUCC_VCT]) {
      const entry = config.credential_configurations_supported[id];
      assert.equal(entry.format, "dc+sd-jwt");
      assert.equal(entry.vct, id);
    }
    assert.equal(config.credential_configurations_supported["urn:eudi:pid:1"].vct, "urn:eudi:pid:1");
  });

  it("returns no payload for an unrelated credential type", () => {
    assert.equal(bu6SdJwtPayload("urn:eu.europa.ec.eudi:pid:1"), null);
  });

  it("issues the EU Company Certificate with the workbook expiry and a clear legal name", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const jwk = await jose.exportJWK(publicKey);
    const proof = await new jose.SignJWT({ iss: "holder", aud: "http://localhost:3000", nonce: "test" })
      .setProtectedHeader({ alg: "ES256", typ: "openid4vci-proof+jwt", jwk })
      .sign(privateKey);
    const credential = await handleCredentialGenerationBasedOnFormat({
      vct: BU6_EUCC_VCT,
      proofs: { jwt: [proof] },
    }, { signatureType: "kid-jwk", isHaip: false }, "http://localhost:3000", "dc+sd-jwt");
    const issued = jose.decodeJwt(credential.split("~")[0]);
    assert.equal(issued.vct, BU6_EUCC_VCT);
    assert.equal(issued.exp, Date.parse("2028-01-01T00:00:00.000Z") / 1000);
    assert.equal(issued.legal_person_name, "Testlegalperson WB");
    assert.equal(issued.registration_member_state, "SE");
    assert.equal(issued._sd, undefined);
  });
});
