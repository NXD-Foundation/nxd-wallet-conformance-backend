import { strict as assert } from "node:assert";
import forge from "node-forge";
import { buildPresentationRequestX5c } from "../utils/cryptoUtils.js";

// A real leaf -> intermediate -> self-signed root path distinguishes roots
// from intermediate CAs: CA=true alone must not cause an entry to be removed.
function issueCertificate(name, issuer = null, ca = false) {
  const keys = forge.pki.rsa.generateKeyPair(512);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = issuer ? (ca ? "02" : "03") : "01";
  cert.validity.notBefore = new Date("2026-01-01");
  cert.validity.notAfter = new Date("2030-01-01");
  cert.setSubject([{ name: "commonName", value: name }]);
  cert.setIssuer(issuer ? issuer.cert.subject.attributes : cert.subject.attributes);
  cert.setExtensions([{ name: "basicConstraints", cA: ca }]);
  cert.sign(issuer ? issuer.keys.privateKey : keys.privateKey, forge.md.sha256.create());
  return { cert, keys, der: Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), "binary").toString("base64") };
}

describe("presentation request x5c regression", () => {
  let leaf, intermediate, root;
  before(() => {
    root = issueCertificate("root", null, true);
    intermediate = issueCertificate("intermediate", root, true);
    leaf = issueCertificate("leaf", intermediate);
  });

  it("excludes the self-signed trust anchor while preserving leaf and intermediate order", () => {
    const chain = [leaf.der, intermediate.der, root.der];
    assert.deepEqual(buildPresentationRequestX5c(chain), [leaf.der, intermediate.der]);
    assert.deepEqual(chain, [leaf.der, intermediate.der, root.der]);
  });

  it("preserves the intermediate when the input already excludes the trust anchor", () => {
    assert.deepEqual(buildPresentationRequestX5c([leaf.der, intermediate.der]), [leaf.der, intermediate.der]);
  });

  it("allows a leaf-only request chain for a leaf issued directly by the root", () => {
    const directLeaf = issueCertificate("direct leaf", root);
    assert.deepEqual(buildPresentationRequestX5c([directLeaf.der, root.der]), [directLeaf.der]);
  });
});
