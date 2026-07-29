import { expect } from "chai";
import crypto from "crypto";
import { loadAptitudeIssuerSigningMaterial } from "../utils/aptitudeIssuerSigningMaterial.js";

describe("Aptitude issuer signing material", () => {
  it("uses the EUDI-issued leaf and omits its trust anchor from x5c", () => {
    const material = loadAptitudeIssuerSigningMaterial();
    const leaf = new crypto.X509Certificate(material.leafCertificatePem);

    expect(leaf.issuer).to.include("PID Issuer CA 02");
    expect(material.certChain).to.deep.equal([
      material.leafCertificatePem
        .replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, ""),
    ]);
  });
});
