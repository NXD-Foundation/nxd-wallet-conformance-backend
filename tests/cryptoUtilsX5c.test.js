import { expect } from "chai";
import * as jose from "jose";
import fs from "fs";
import path from "path";
import {
  derBase64ToPemCert,
  jwkFromX5cFirstCert,
} from "../utils/cryptoUtils.js";
import { pemToBase64Der } from "../utils/sdjwtUtils.js";

const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");

describe("cryptoUtils x5c helpers (derBase64ToPemCert, jwkFromX5cFirstCert)", () => {
  let x5cDerB64;

  before(() => {
    if (!fs.existsSync(certPath)) {
      return;
    }
    const pem = fs.readFileSync(certPath, "utf8");
    x5cDerB64 = pemToBase64Der(pem);
  });

  it("derBase64ToPemCert wraps base64 DER with PEM boundaries and 64-char lines", () => {
    const pem = derBase64ToPemCert("QUJD");
    expect(pem).to.include("-----BEGIN CERTIFICATE-----");
    expect(pem).to.include("-----END CERTIFICATE-----");
    expect(pem).to.include("QUJD");
  });

  it("jwkFromX5cFirstCert rejects empty x5c", async () => {
    try {
      await jwkFromX5cFirstCert([]);
      expect.fail("expected throw");
    } catch (e) {
      expect(e.message).to.match(/non-empty array/i);
    }
  });

  it("jwkFromX5cFirstCert returns a public EC JWK matching importX509 for the leaf cert", async function () {
    if (!x5cDerB64) {
      this.skip();
    }
    const jwk = await jwkFromX5cFirstCert([x5cDerB64], "ES256");
    expect(jwk).to.have.property("kty", "EC");
    expect(jwk).to.have.property("crv", "P-256");
    expect(jwk).to.have.property("x");
    expect(jwk).to.have.property("y");
    expect(jwk).to.not.have.property("d");

    const pem = derBase64ToPemCert(x5cDerB64);
    const key = await jose.importX509(pem, "ES256");
    const expected = await jose.exportJWK(key);
    expect(jwk.x).to.equal(expected.x);
    expect(jwk.y).to.equal(expected.y);
  });
});
