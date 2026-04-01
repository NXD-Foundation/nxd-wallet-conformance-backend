/**
 * The mdoc issuance path loads the leaf X.509 from ./x509EC/client_certificate.crt
 * (see utils/credGenerationUtils.js). Holders may reject credentials if the leaf
 * used in issuerAuth x5chain lacks Key Usage with digitalSignature (RFC 5280 / mDL PKI).
 *
 * We parse with @peculiar/x509 because Node's crypto.X509Certificate.keyUsage is
 * often undefined even when the extension is present (OpenSSL shows it correctly).
 */
import { expect } from "chai";
import fs from "fs";
import path from "path";
import * as jose from "jose";
import { decode } from "cbor-x";
import {
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
} from "@peculiar/x509";
import { handleCredentialGenerationBasedOnFormat } from "../utils/credGenerationUtils.js";
import { pemToBase64Der } from "../utils/sdjwtUtils.js";

const MDOC_LEAF_CERT_PATH = path.join(
  process.cwd(),
  "x509EC",
  "client_certificate.crt"
);
const MDOC_LEAF_KEY_PATH = path.join(
  process.cwd(),
  "x509EC",
  "ec_private_pkcs8.key"
);

function getLeafKeyUsage(cert) {
  return cert.getExtension(KeyUsagesExtension);
}

describe("mdoc issuance leaf certificate (x509EC/client_certificate.crt)", () => {
  it("includes Key Usage with the digitalSignature bit set", function () {
    if (!fs.existsSync(MDOC_LEAF_CERT_PATH)) {
      this.skip();
    }

    const pem = fs.readFileSync(MDOC_LEAF_CERT_PATH, "utf8");
    const cert = new X509Certificate(pem);

    const keyUsage = getLeafKeyUsage(cert);
    expect(
      keyUsage,
      "Key Usage extension must be present on the mdoc document-signing leaf"
    ).to.be.instanceOf(KeyUsagesExtension);

    const hasDigitalSignature =
      (keyUsage.usages & KeyUsageFlags.digitalSignature) ===
      KeyUsageFlags.digitalSignature;
    expect(
      hasDigitalSignature,
      "Key Usage must include digitalSignature for MSO signing per typical profiles"
    ).to.equal(true);
  });

  it("matches the configured mdoc issuer private key", async function () {
    if (
      !fs.existsSync(MDOC_LEAF_CERT_PATH) ||
      !fs.existsSync(MDOC_LEAF_KEY_PATH)
    ) {
      this.skip();
    }

    const certPem = fs.readFileSync(MDOC_LEAF_CERT_PATH, "utf8");
    const pkcs8Pem = fs.readFileSync(MDOC_LEAF_KEY_PATH, "utf8");

    const certKey = await jose.importX509(certPem, "ES256", {
      extractable: true,
    });
    const privateKey = await jose.importPKCS8(pkcs8Pem, "ES256");

    const certJwk = await jose.exportJWK(certKey);
    const privateJwk = await jose.exportJWK(privateKey);

    expect(privateJwk.kty).to.equal(certJwk.kty);
    expect(privateJwk.crv).to.equal(certJwk.crv);
    expect(privateJwk.x).to.equal(certJwk.x);
    expect(privateJwk.y).to.equal(certJwk.y);
  });

  it("emits the same leaf certificate in issuerAuth x5chain with digitalSignature key usage", async function () {
    if (
      !fs.existsSync(MDOC_LEAF_CERT_PATH) ||
      !fs.existsSync(MDOC_LEAF_KEY_PATH)
    ) {
      this.skip();
    }

    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const proofJwk = await jose.exportJWK(publicKey);
    const proofJwt = await new jose.SignJWT({
      iss: "did:example:holder",
      aud: "http://localhost:3000",
      nonce: "test-nonce-mdoc-leaf-x5chain",
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "openid4vci-proof+jwt",
        jwk: proofJwk,
      })
      .sign(privateKey);

    const credential = await handleCredentialGenerationBasedOnFormat(
      {
        vct: "urn:eu.europa.ec.eudi:pid:1:mso_mdoc",
        proofs: { jwt: [proofJwt] },
      },
      {
        signatureType: "x509",
        isHaip: false,
      },
      "http://localhost:3000",
      "mDL"
    );

    const issuerSigned = decode(Buffer.from(credential, "base64url"));
    expect(issuerSigned).to.have.property("issuerAuth");
    expect(issuerSigned.issuerAuth).to.be.an("array").with.length(4);

    const unprotectedHeaders = issuerSigned.issuerAuth[1];
    expect(unprotectedHeaders).to.be.an("object");
    expect(unprotectedHeaders).to.have.property("33");

    const x5chain = unprotectedHeaders["33"];
    expect(x5chain).to.be.an("array").that.is.not.empty;

    const emittedLeafDer = x5chain[0];
    expect(Buffer.isBuffer(emittedLeafDer) || emittedLeafDer instanceof Uint8Array)
      .to.equal(true);

    const configuredLeafPem = fs.readFileSync(MDOC_LEAF_CERT_PATH, "utf8");
    expect(Buffer.from(emittedLeafDer).toString("base64")).to.equal(
      pemToBase64Der(configuredLeafPem)
    );

    const emittedLeafCert = new X509Certificate(Buffer.from(emittedLeafDer));
    const keyUsage = getLeafKeyUsage(emittedLeafCert);
    expect(keyUsage).to.be.instanceOf(KeyUsagesExtension);
    expect(
      (keyUsage.usages & KeyUsageFlags.digitalSignature) ===
        KeyUsageFlags.digitalSignature
    ).to.equal(true);
  });
});
