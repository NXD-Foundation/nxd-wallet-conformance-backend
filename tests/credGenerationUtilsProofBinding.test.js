import { expect } from "chai";
import * as jose from "jose";
import fs from "fs";
import path from "path";
import {
  buildHolderCnfFromProofJwtHeader,
  handleCredentialGenerationBasedOnFormat,
} from "../utils/credGenerationUtils.js";
import { pemToBase64Der } from "../utils/sdjwtUtils.js";

const originalServerUrl = process.env.SERVER_URL;
const originalIssuerSigType = process.env.ISSUER_SIGNATURE_TYPE;

process.env.SERVER_URL = process.env.SERVER_URL || "http://localhost:3000";
process.env.ISSUER_SIGNATURE_TYPE = process.env.ISSUER_SIGNATURE_TYPE || "kid-jwk";

function restoreEnv() {
  if (originalServerUrl !== undefined) process.env.SERVER_URL = originalServerUrl;
  else delete process.env.SERVER_URL;
  if (originalIssuerSigType !== undefined)
    process.env.ISSUER_SIGNATURE_TYPE = originalIssuerSigType;
  else delete process.env.ISSUER_SIGNATURE_TYPE;
}

describe("buildHolderCnfFromProofJwtHeader", () => {
  it("returns cnf.jwk when header has jwk", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const jwk = await jose.exportJWK(publicKey);
    const cnf = await buildHolderCnfFromProofJwtHeader({ alg: "ES256", jwk });
    expect(cnf).to.deep.equal({ jwk });
  });

  it("returns cnf.kid for did:* kids", async () => {
    const kid = "did:web:example.com#keys-1";
    const cnf = await buildHolderCnfFromProofJwtHeader({ alg: "ES256", kid });
    expect(cnf).to.deep.equal({ kid });
  });

  it("returns cnf.jwk from x5c when kid is absent", async function () {
    const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");
    if (!fs.existsSync(certPath)) {
      this.skip();
    }
    const pem = fs.readFileSync(certPath, "utf8");
    const x5c = [pemToBase64Der(pem)];
    const cnf = await buildHolderCnfFromProofJwtHeader({
      alg: "ES256",
      x5c,
    });
    expect(cnf).to.have.property("jwk");
    expect(cnf.jwk).to.have.property("kty", "EC");
    expect(cnf.jwk).to.not.have.property("d");
  });
});

describe("handleCredentialGenerationBasedOnFormat (proof binding + issuance)", () => {
  const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");
  const keyPath = path.join(process.cwd(), "x509EC", "ec_private_pkcs8.key");

  after(() => {
    restoreEnv();
  });

  it("embeds holder cnf.jwk from x5c proof JWT in issued dc+sd-jwt", async function () {
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
      this.skip();
    }
    const pemCert = fs.readFileSync(certPath, "utf8");
    const x5c = [pemToBase64Der(pemCert)];
    const pkcs8 = fs.readFileSync(keyPath, "utf8");
    const privateKey = await jose.importPKCS8(pkcs8, "ES256");
    const expectedPub = await jose.exportJWK(privateKey);
    delete expectedPub.d;

    const proofJwt = await new jose.SignJWT({
      iss: "did:example:holder",
      aud: process.env.SERVER_URL,
      nonce: "test-nonce-x5c-binding",
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "openid4vci-proof+jwt",
        x5c,
      })
      .sign(privateKey);

    const requestBody = {
      vct: "test-cred-config",
      proofs: { jwt: [proofJwt] },
    };
    const sessionObject = {
      signatureType: "kid-jwk",
      isHaip: false,
    };

    const credential = await handleCredentialGenerationBasedOnFormat(
      requestBody,
      sessionObject,
      process.env.SERVER_URL,
      "dc+sd-jwt"
    );

    const compactJwt = credential.split("~")[0];
    const payload = jose.decodeJwt(compactJwt);
    expect(payload.cnf).to.have.property("jwk");
    expect(payload.cnf.jwk.x).to.equal(expectedPub.x);
    expect(payload.cnf.jwk.y).to.equal(expectedPub.y);
  });
});
