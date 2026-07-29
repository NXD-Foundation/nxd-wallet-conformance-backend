import { expect } from "chai";
import fs from "fs";
import { credentialConfigRequiresJwtProofKeyAttestation } from "../utils/routeUtils.js";

describe("Aptitude credential proof metadata", () => {
  it("advertises JWT and attestation proof support for every credential configuration", () => {
    const issuerConfig = JSON.parse(fs.readFileSync("./data/issuer-config.json", "utf8"));

    for (const [configurationId, configuration] of Object.entries(
      issuerConfig.credential_configurations_supported,
    )) {
      const proofTypes = configuration.proof_types_supported;
      expect(proofTypes, configurationId).to.include.keys("jwt", "attestation");

      for (const proofType of ["jwt", "attestation"]) {
        expect(proofTypes[proofType], `${configurationId}.${proofType}`).to.deep.include({
          proof_signing_alg_values_supported: ["ES256"],
        });
        expect(proofTypes[proofType], `${configurationId}.${proofType}`).to.have.property(
          "key_attestations_required",
        );
      }

      expect(
        credentialConfigRequiresJwtProofKeyAttestation(configuration),
        `${configurationId}.jwt key-attestation metadata must match its declaration`,
      ).to.equal(true);
    }
  });
});
