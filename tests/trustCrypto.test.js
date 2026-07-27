import { expect } from "chai";
import fs from "node:fs/promises";
import { verifyJadesJson, verifyXadesXml, certificateFingerprint, stableJsonStringify } from "../trust/crypto.js";

const artifact = "tests/fixtures/trust/webuild-wp4/artifacts";
const keyDir = "tests/fixtures/trust/webuild-wp4/keys";

describe("Phase 1 signed trust-list validation", () => {
  let lotl;
  let lotlCert;
  let pidXml;

  before(async () => {
    lotl = JSON.parse(await fs.readFile(`${artifact}/list_of_trusted_lists.json`, "utf8"));
    lotlCert = await fs.readFile(`${keyDir}/lotl.crt`, "utf8");
    pidXml = await fs.readFile(`${artifact}/pid.xml`);
  });

  it("verifies WP4-shaped JAdES JSON and returns signer evidence", async () => {
    const verified = await verifyJadesJson(lotl, { allowedFingerprints: [certificateFingerprint(lotlCert)] });
    expect(verified.unsigned).to.have.property("LoTE");
    expect(verified.signer.algorithm).to.equal("RS256");
  });

  it("reproduces WP4 canonical JSON bytes", () => {
    expect(stableJsonStringify({ z: "vä", a: { z: 1, a: "é" } }))
      .to.equal('{"a":{"a":"\\u00e9","z":1},"z":"v\\u00e4"}');
  });

  it("rejects a JSON signature when the configured anchor does not match", async () => {
    try {
      await verifyJadesJson(lotl, { allowedFingerprints: ["00".repeat(32)] });
      expect.fail("expected anchor rejection");
    } catch (error) {
      expect(error.reasonCode).to.equal("BOOTSTRAP_UNTRUSTED");
    }
  });

  it("verifies an enveloped XML signature", async () => {
    const pidCert = await fs.readFile(`${keyDir}/pid.crt`, "utf8");
    const verified = verifyXadesXml(pidXml, { allowedFingerprints: [certificateFingerprint(pidCert)] });
    expect(verified.document.documentElement.localName).to.equal("TrustServiceStatusList");
  });
});
