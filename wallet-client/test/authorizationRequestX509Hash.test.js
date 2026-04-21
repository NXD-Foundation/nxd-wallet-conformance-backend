import { expect } from "chai";
import crypto from "node:crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { SignJWT, importPKCS8 } from "jose";
import {
  computeX509HashClientIdFromLeafX5c,
  verifyAuthorizationRequestJwt,
} from "../src/lib/presentation.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoWalletRoot = path.join(__dirname, "..");
const x509CertPath = path.join(repoWalletRoot, "x509", "client_certificate.crt");
const x509KeyPath = path.join(repoWalletRoot, "x509", "client_private_pkcs8.key");

function certToX5c0() {
  const certPem = fs.readFileSync(x509CertPath, "utf8");
  return certPem
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\s+/g, "");
}

describe("authorization request JWT (RFC002 x509_hash)", () => {
  it("computeX509HashClientIdFromLeafX5c matches verifier computeX509HashClientId (SHA-256 DER, base64url)", () => {
    const x5c0 = certToX5c0();
    const got = computeX509HashClientIdFromLeafX5c(x5c0);
    expect(got).to.match(/^x509_hash:[A-Za-z0-9_-]+$/);
    const der = Buffer.from(x5c0, "base64");
    const manual = `x509_hash:${crypto.createHash("sha256").update(der).digest("base64url")}`;
    expect(got).to.equal(manual);
  });

  it("verifyAuthorizationRequestJwt accepts x509_hash JAR signed with leaf x5c", async () => {
    const x5c0 = certToX5c0();
    const client_id = computeX509HashClientIdFromLeafX5c(x5c0);
    const privateKeyPem = fs.readFileSync(x509KeyPath, "utf8");
    const key = await importPKCS8(privateKeyPem, "RS256");

    const requestJwt = await new SignJWT({
      response_type: "vp_token",
      response_mode: "direct_post",
      client_id,
      client_id_scheme: "x509_hash",
      redirect_uri: "https://rp.example/cb",
      nonce: "n1",
      state: "s1",
    })
      .setProtectedHeader({
        alg: "RS256",
        typ: "oauth-authz-req+jwt",
        x5c: [x5c0],
      })
      .sign(key);

    const { payload } = await verifyAuthorizationRequestJwt(requestJwt, {
      expectedClientId: client_id,
    });
    expect(payload.client_id).to.equal(client_id);
  });

  it("verifyAuthorizationRequestJwt rejects x509_hash when client_id does not match leaf hash", async () => {
    const x5c0 = certToX5c0();
    const privateKeyPem = fs.readFileSync(x509KeyPath, "utf8");
    const key = await importPKCS8(privateKeyPem, "RS256");

    const requestJwt = await new SignJWT({
      response_type: "vp_token",
      response_mode: "direct_post",
      client_id: "x509_hash:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      client_id_scheme: "x509_hash",
      redirect_uri: "https://rp.example/cb",
      nonce: "n1",
      state: "s1",
    })
      .setProtectedHeader({
        alg: "RS256",
        typ: "oauth-authz-req+jwt",
        x5c: [x5c0],
      })
      .sign(key);

    try {
      await verifyAuthorizationRequestJwt(requestJwt, { expectedClientId: null });
      expect.fail("expected invalid_request");
    } catch (e) {
      expect(e.message).to.include("invalid_request");
      expect(e.message).to.include("x509_hash client_id does not match");
    }
  });

  it("verifyAuthorizationRequestJwt rejects x509_hash without x5c header", async () => {
    const x5c0 = certToX5c0();
    const client_id = computeX509HashClientIdFromLeafX5c(x5c0);
    const privateKeyPem = fs.readFileSync(x509KeyPath, "utf8");
    const key = await importPKCS8(privateKeyPem, "RS256");

    const requestJwt = await new SignJWT({
      response_type: "vp_token",
      client_id,
      client_id_scheme: "x509_hash",
      redirect_uri: "https://rp.example/cb",
      nonce: "n1",
    })
      .setProtectedHeader({
        alg: "RS256",
        typ: "oauth-authz-req+jwt",
      })
      .sign(key);

    try {
      await verifyAuthorizationRequestJwt(requestJwt, { expectedClientId: client_id });
      expect.fail("expected invalid_request");
    } catch (e) {
      expect(e.message).to.include("invalid_request");
      expect(e.message).to.match(/x5c/i);
    }
  });

  it("verifyAuthorizationRequestJwt rejects unknown client_id_scheme (non-DID)", async () => {
    const x5c0 = certToX5c0();
    const privateKeyPem = fs.readFileSync(x509KeyPath, "utf8");
    const key = await importPKCS8(privateKeyPem, "RS256");

    const requestJwt = await new SignJWT({
      response_type: "vp_token",
      response_mode: "direct_post",
      client_id: "x509_san_dns:example.com",
      client_id_scheme: "verifiable_credential",
      redirect_uri: "https://rp.example/cb",
      nonce: "n1",
    })
      .setProtectedHeader({
        alg: "RS256",
        typ: "oauth-authz-req+jwt",
        x5c: [x5c0],
      })
      .sign(key);

    try {
      await verifyAuthorizationRequestJwt(requestJwt, { expectedClientId: null });
      expect.fail("expected invalid_request");
    } catch (e) {
      expect(e.message).to.include("invalid_request");
      expect(e.message).to.include("unsupported client_id_scheme");
    }
  });
});
