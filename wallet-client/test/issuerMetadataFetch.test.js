import { strict as assert } from "assert";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { SignJWT, importPKCS8 } from "jose";
import { parseIssuerMetadataHttpResponse } from "../src/lib/issuerMetadataFetch.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe("issuer metadata JWS (RFC001 P2-W-5)", () => {
  it("parses application/jwt metadata, verifies x5c, surfaces issuer_info.registration_certificate", async () => {
    const crtPath = path.join(__dirname, "../x509EC/client_certificate.crt");
    const keyPath = path.join(__dirname, "../x509EC/ec_private_pkcs8.key");
    const pem = fs.readFileSync(crtPath, "utf8");
    const pkcs8 = fs.readFileSync(keyPath, "utf8");
    const x5c = [
      pem
        .replace(/-----BEGIN CERTIFICATE-----/g, "")
        .replace(/-----END CERTIFICATE-----/g, "")
        .replace(/\s+/g, ""),
    ];
    const expectedReg = "MIIB-test-registration-der-b64";
    const jwt = await new SignJWT({
      credential_issuer: "https://wallet-test.example/issuer",
      token_endpoint: "https://wallet-test.example/token",
      credential_endpoint: "https://wallet-test.example/credential",
      issuer_info: { registration_certificate: expectedReg },
    })
      .setProtectedHeader({ alg: "ES256", typ: "jwt", x5c })
      .sign(await importPKCS8(pkcs8, "ES256"));

    const res = new Response(jwt, {
      status: 200,
      headers: { "content-type": "application/jwt" },
    });

    const { meta, debug } = await parseIssuerMetadataHttpResponse(res);
    assert.strictEqual(meta.credential_issuer, "https://wallet-test.example/issuer");
    assert.strictEqual(meta.token_endpoint, "https://wallet-test.example/token");
    assert.deepStrictEqual(debug, {
      signed_metadata_jws: true,
      issuer_info_registration_certificate: expectedReg,
    });
  });

  it("parses plain JSON when not a JWS", async () => {
    const body = JSON.stringify({
      credential_issuer: "https://ci",
      token_endpoint: "https://as/t",
    });
    const res = new Response(body, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
    const { meta, debug } = await parseIssuerMetadataHttpResponse(res);
    assert.strictEqual(debug, null);
    assert.strictEqual(meta.credential_issuer, "https://ci");
  });

  it("rejects compact JWS without JWT declaration", async () => {
    const crtPath = path.join(__dirname, "../x509EC/client_certificate.crt");
    const keyPath = path.join(__dirname, "../x509EC/ec_private_pkcs8.key");
    const pem = fs.readFileSync(crtPath, "utf8");
    const pkcs8 = fs.readFileSync(keyPath, "utf8");
    const x5c = [
      pem
        .replace(/-----BEGIN CERTIFICATE-----/g, "")
        .replace(/-----END CERTIFICATE-----/g, "")
        .replace(/\s+/g, ""),
    ];
    const jwt = await new SignJWT({ credential_issuer: "https://x" })
      .setProtectedHeader({ alg: "ES256", typ: "oauth-authz-req+jwt", x5c })
      .sign(await importPKCS8(pkcs8, "ES256"));

    const res = new Response(jwt, {
      status: 200,
      headers: { "content-type": "application/json" },
    });

    await assert.rejects(() => parseIssuerMetadataHttpResponse(res), /application\/jwt|typ: jwt/i);
  });
});
