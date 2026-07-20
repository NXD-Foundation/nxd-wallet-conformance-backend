import fs from "fs";
import { expect } from "chai";
import {
  assertVerifierEncryptionKeyPair,
  loadVerifierEncryptionKey,
} from "../utils/verifierEncryptionKeys.js";

describe("verifier response-encryption key registry", () => {
  it("proves the advertised verifier JWK matches its private key", () => {
    const material = loadVerifierEncryptionKey();
    expect(material.kid).to.equal("enc-key-1");
    expect(material.publicJwk.x).to.equal(material.derivedPublicJwk.x);
    expect(material.publicJwk.y).to.equal(material.derivedPublicJwk.y);
  });

  it("rejects metadata copied from an unrelated key pair", () => {
    const privateKeyPem = fs.readFileSync("./x509EC/ec_private_pkcs8.key", "utf8");
    expect(() => assertVerifierEncryptionKeyPair({
      publicJwk: {
        kty: "EC", crv: "P-256", kid: "wrong", alg: "ECDH-ES+A256KW",
        x: "7ymGipkLd1oxRGYCIat84OqzuPfL0YoL-rYAoKqPjxk",
        y: "EJLD8Db88LP2sd2HClVkZrdxl0yipmGUfKF85IfUU6Q",
      },
      privateKeyPem,
    })).to.throw(/key mismatch/);
  });
});

