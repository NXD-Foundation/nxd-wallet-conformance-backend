import { expect } from "chai";
import fs from "node:fs/promises";
import { execSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import xmlCrypto from "xml-crypto";
import {
  verifyJadesJson,
  verifyXadesXml,
  certificateFingerprint,
  stableJsonStringify,
  validateCertificatePath,
  XMLDSIG_ECDSA_SHA256,
  XMLDSIG_RSA_SHA256,
  XmlDsigEcdsaSha256,
} from "../trust/crypto.js";

const { SignedXml } = xmlCrypto;

function createEcSelfSignedCert() {
  const dir = mkdtempSync(join(tmpdir(), "ecdsa-trust-xml-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");
  execSync(`openssl ecparam -name prime256v1 -genkey -noout -out "${keyPath}"`);
  execSync(`openssl req -new -x509 -key "${keyPath}" -out "${certPath}" -days 365 -subj "/CN=ecdsa-trust-list-test"`);
  const keyPem = readFileSync(keyPath, "utf8");
  const certPem = readFileSync(certPath, "utf8");
  rmSync(dir, { recursive: true, force: true });
  return { keyPem, certPem };
}

function signEnvelopedEcdsaXml(unsignedXml, keyPem, certPem) {
  const signer = new SignedXml({ privateKey: keyPem, publicCert: certPem });
  signer.SignatureAlgorithms[XMLDSIG_ECDSA_SHA256] = XmlDsigEcdsaSha256;
  signer.addReference({
    xpath: "/*",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    isEmptyUri: true,
  });
  signer.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  signer.signatureAlgorithm = XMLDSIG_ECDSA_SHA256;
  signer.computeSignature(unsignedXml, { location: { reference: "/*", action: "append" } });
  return signer.getSignedXml();
}
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
    const verified = verifyXadesXml(pidXml, {
      allowedFingerprints: [certificateFingerprint(pidCert)],
      algorithms: [XMLDSIG_RSA_SHA256],
    });
    expect(verified.document.documentElement.localName).to.equal("TrustServiceStatusList");
    expect(verified.signer.algorithm).to.equal(XMLDSIG_RSA_SHA256);
  });

  it("verifies an enveloped XML signature signed with ecdsa-sha256", () => {
    const { keyPem, certPem } = createEcSelfSignedCert();
    const unsignedXml = `<?xml version="1.0"?><TrustedEntitiesList xmlns="http://uri.etsi.org/019602/v1#"><ListAndSchemeInformation><LoTEType>http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList</LoTEType></ListAndSchemeInformation></TrustedEntitiesList>`;
    const signedXml = signEnvelopedEcdsaXml(unsignedXml, keyPem, certPem);
    const fingerprint = certificateFingerprint(certPem);
    const verified = verifyXadesXml(signedXml, {
      allowedFingerprints: [fingerprint],
      algorithms: [XMLDSIG_ECDSA_SHA256, XMLDSIG_RSA_SHA256],
    });
    expect(verified.document.documentElement.localName).to.equal("TrustedEntitiesList");
    expect(verified.signer.algorithm).to.equal(XMLDSIG_ECDSA_SHA256);
    const tampered = signedXml.replace(
      "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList",
      "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList-tampered",
    );
    try {
      verifyXadesXml(tampered, {
        allowedFingerprints: [fingerprint],
        algorithms: [XMLDSIG_ECDSA_SHA256],
      });
      expect.fail("expected tampered XML to fail verification");
    } catch (error) {
      expect(error.reasonCode).to.equal("LIST_SIGNATURE_INVALID");
    }
  });
});
