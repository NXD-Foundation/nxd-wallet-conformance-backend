import fs from "fs";
import { expect } from "chai";
import * as jose from "jose";
import crypto from "node:crypto";
import { decryptJWE } from "../utils/cryptoUtils.js";
import { loadVerifierEncryptionKey } from "../utils/verifierEncryptionKeys.js";

describe("verifier response-encryption key", () => {
  it("decrypts direct_post.jwt with the key advertised in verifier metadata", async () => {
    const configured = loadVerifierEncryptionKey();
    const publicKey = await jose.importJWK(configured.publicJwk, configured.publicJwk.alg);
    const jwe = await new jose.EncryptJWT({ vp_token: "vp-token" })
      .setProtectedHeader({
        alg: configured.publicJwk.alg,
        enc: "A256GCM",
        kid: configured.publicJwk.kid,
      })
      .encrypt(publicKey);

    const decrypted = await decryptJWE(jwe, configured.privateKeyPem, "direct_post.jwt");
    expect(decrypted).to.deep.equal({ vp_token: "vp-token" });
  });

  it("does not use the verifier signing key for direct_post.jwt decryption", async () => {
    const configured = loadVerifierEncryptionKey();
    const signingKeyPem = fs.readFileSync("./private-key.pem", "utf8");
    const signingPublicJwk = crypto.createPublicKey(signingKeyPem).export({ format: "jwk" });
    expect(signingPublicJwk.x).to.not.equal(configured.publicJwk.x);
    expect(signingPublicJwk.y).to.not.equal(configured.publicJwk.y);

    const publicKey = await jose.importJWK(configured.publicJwk, configured.publicJwk.alg);
    const jwe = await new jose.EncryptJWT({ vp_token: "vp-token" })
      .setProtectedHeader({
        alg: configured.publicJwk.alg,
        enc: "A256GCM",
        kid: configured.publicJwk.kid,
      })
      .encrypt(publicKey);

    let error;
    try {
      await decryptJWE(jwe, signingKeyPem, "direct_post.jwt");
    } catch (caught) {
      error = caught;
    }
    expect(error).to.exist;
    expect(error.message).to.match(/decryption operation failed|no suitable key/i);
  });

  it("wires direct_post.jwt to the response-encryption key loader", () => {
    const verifierRoute = fs.readFileSync("./routes/verify/verifierRoutes.js", "utf8");
    expect(verifierRoute).to.include(
      "const privateKeyForDecryption = loadVerifierEncryptionKey().privateKeyPem;",
    );
    expect(verifierRoute).to.not.include(
      'decryptJWE(jwtResponse, privateKey, "direct_post.jwt")',
    );
  });
});
import {
  assertVerifierEncryptionKeyPair,
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
