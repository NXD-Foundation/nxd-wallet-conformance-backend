export const BU6_PID_VCT = "urn:eudi:pid:se:1";
export const BU6_POX_VCT = "https://credentials.webuild.eu/power-of-x/v7";
export const BU6_EUCC_VCT = "uri:eu.eudi.eucc.1";

const PID_AND_EUCC_EXPIRES_AT = "2028-01-01T00:00:00.000Z";
const POX_EXPIRES_AT = "2027-07-01T00:00:00.000Z";
const BOLAGSVERKET_ID = "BOLSE-E81458556";

export function bu6AlwaysPublishesStatusList(configurationId) {
  return configurationId === BU6_EUCC_VCT;
}

function swedishPidClaims() {
  return {
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
  };
}

function powerOfRepresentationClaims() {
  return {
    credential: {
      type: "power_of_representation",
      legal_category: "QEAA",
    },
    represented_economic_operator: {
      identifier: { scheme: "EBWOID", value: "SEBOL.12345789" },
      legal_name: "Testlegalperson WB",
    },
    proxy: {
      entity_type: "natural_entity",
      natural_entity_proxy: {
        family_name: "Andersson",
        given_name: "Anna Maria",
        birth_date: "1985-04-17",
        birth_place: "Stockholm",
        nationality: ["SE"],
      },
    },
    authority: {
      authority_source: "proxy_position",
      proxy_position: {
        position: "Sole Administrator",
        inscription_date: "2020-07-08",
        issuing_authority: { name: "Bolagsverket", type: "QEAA", country: "SE" },
        authentic_source: { id: BOLAGSVERKET_ID, name: "Bolagsverket" },
        evidence: {
          uri: "https://www.bolagsverket.se",
          description: "Business Registry Certification",
        },
        assurance_level: "HIGH",
      },
    },
    credential_metadata: {
      schema: {
        id: "https://schemas.webuild.eu/power-of-x/v7",
        version: "7.0.0",
        location: "https://schemas.webuild.eu/power-of-x",
      },
      validity: {
        not_before: "2026-07-14T00:00:00.000Z",
        not_after: "2027-07-01T00:00:00.000Z",
      },
      trust: { trust_anchor: "https://eidas.ec.europa.eu" },
      display: { language: "en", name: "WE BUILD Power of X" },
      status: {
        serial_number: "POX-2026-000001",
        revocation_distribution_points: ["https://status.webuild.eu/pox/rl"],
      },
    },
  };
}

function euccClaims(issuedAt) {
  return {
    attestation_legal_category: "PUB-EAA",
    issuing_authority: "Bolagsverket",
    issuing_authority_id: BOLAGSVERKET_ID,
    issuing_country: "SE",
    issuance_date: issuedAt.toISOString(),
    authentic_source_id: BOLAGSVERKET_ID,
    authentic_source_name: "Bolagsverket",
    legal_person_name: "Testlegalperson WB",
    legal_person_id: "SEBOL.12345789",
    legal_form_type: "AB",
    registration_member_state: "SE",
    registered_address: { full_address: "Storgata 1; 9008; Stockholm; SE" },
    registration_date: "2003-10-10",
    legal_person_status: "active",
    legal_person_activity: {
      code: "62010",
      description: "Computer programming activities",
    },
    legal_representative: [{
      full_name: "Lysende Blomst",
      date_of_birth: "1981-02-01",
      nationality: "Swedish",
      signatory_rule: "alone",
    }],
  };
}

export function bu6SdJwtPayload(credentialType, { issuedAt = new Date() } = {}) {
  if (credentialType === BU6_PID_VCT) {
    const claims = swedishPidClaims();
    return { claims, disclosureFrame: { _sd: Object.keys(claims) }, expiresAt: PID_AND_EUCC_EXPIRES_AT };
  }
  if (credentialType === BU6_POX_VCT) {
    return {
      claims: powerOfRepresentationClaims(),
      disclosureFrame: {
        represented_economic_operator: { _sd: ["legal_name"], identifier: { _sd: ["value"] } },
        proxy: { _sd: ["natural_entity_proxy"] },
        authority: { _sd: ["proxy_position"] },
      },
      expiresAt: POX_EXPIRES_AT,
    };
  }
  if (credentialType === BU6_EUCC_VCT) {
    return { claims: euccClaims(issuedAt), disclosureFrame: {}, expiresAt: PID_AND_EUCC_EXPIRES_AT };
  }
  return null;
}
