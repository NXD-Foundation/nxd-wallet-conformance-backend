import { expect } from "chai";
import fs from "node:fs/promises";
import { verifyJadesJson, verifyXadesXml, certificateFingerprint, stableJsonStringify, validateCertificatePath } from "../trust/crypto.js";
import { normalizeCrlTime } from "../trust/revocation.js";

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

  it("permits embedded bootstrap only when explicitly enabled for tests", async () => {
    const verified = await verifyJadesJson(lotl, { allowEmbeddedCertificate: true });
    expect(verified.signer.bootstrapMode).to.equal("unsafe-embedded-x5c");
  });

  it("accepts a listed service leaf only during its validity period", async () => {
    const accepted = validateCertificatePath({ certificateChain: [lotlCert], anchorCertificates: [lotlCert], evaluationTime: "2027-01-01T00:00:00Z", requireDigitalSignature: false });
    expect(accepted.anchorFingerprint).to.equal(certificateFingerprint(lotlCert));
    expect(() => validateCertificatePath({ certificateChain: [lotlCert], anchorCertificates: [lotlCert], evaluationTime: "2040-01-01T00:00:00Z", requireDigitalSignature: false }))
      .to.throw(/validity period/);
  });

  it("normalizes numeric CRL timestamps before evidence serialization", () => {
    expect(normalizeCrlTime(1_767_000_000_000).toISOString()).to.equal("2025-12-29T09:20:00.000Z");
  });

  it("verifies an enveloped XML signature", async () => {
    const pidCert = await fs.readFile(`${keyDir}/pid.crt`, "utf8");
    const verified = verifyXadesXml(pidXml, { allowedFingerprints: [certificateFingerprint(pidCert)] });
    expect(verified.document.documentElement.localName).to.equal("TrustServiceStatusList");
  });
});
