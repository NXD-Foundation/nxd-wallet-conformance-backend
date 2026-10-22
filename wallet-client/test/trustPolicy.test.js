import assert from "node:assert/strict";
import fs from "node:fs";
import { X509Certificate } from "node:crypto";
import { SignJWT, importPKCS8 } from "jose";
import { handleUnestablishedTrust, assertCertificateValidity } from "../src/lib/trustPolicy.js";
import { verifyIssuerMetadataJws } from "../src/lib/issuerMetadataFetch.js";

describe("wallet framework trust policy", () => {
  const certPem = fs.readFileSync(new URL("../x509EC/client_certificate.crt", import.meta.url), "utf8");
  const keyPem = fs.readFileSync(new URL("../x509EC/ec_private_pkcs8.key", import.meta.url), "utf8");
  const x5c = [new X509Certificate(certPem).raw.toString("base64")];
  let original;
  beforeEach(() => { original = process.env.WALLET_TRUST_MODE; delete process.env.WALLET_TRUST_MODE; });
  afterEach(() => {
    if (original === undefined) delete process.env.WALLET_TRUST_MODE;
    else process.env.WALLET_TRUST_MODE = original;
  });
  it("warns by default and supports strict rejection", () => {
    assert.doesNotThrow(() => handleUnestablishedTrust("test", {}));
    assert.throws(() => handleUnestablishedTrust("test", { WALLET_TRUST_MODE: "strict" }), /not established/);
    assert.throws(() => handleUnestablishedTrust("test", { WALLET_TRUST_MODE: "typo" }), /Invalid/);
  });
  it("rejects malformed and expired signing certificates in warn mode", () => {
    assert.throws(() => assertCertificateValidity(["invalid"]));
    const now = Date.now;
    Date.now = () => Date.parse(new X509Certificate(certPem).validTo) + 1000;
    try { assert.throws(() => assertCertificateValidity(x5c), /validity period/); }
    finally { Date.now = now; }
  });
  it("accepts valid signed metadata by default but rejects unestablished trust in strict mode", async () => {
    const key = await importPKCS8(keyPem, "ES256");
    const compact = await new SignJWT({ credential_issuer: "https://issuer.example" })
      .setProtectedHeader({ alg: "ES256", x5c }).setExpirationTime("5m").sign(key);
    assert.equal((await verifyIssuerMetadataJws(compact)).payload.credential_issuer, "https://issuer.example");
    process.env.WALLET_TRUST_MODE = "strict";
    await assert.rejects(verifyIssuerMetadataJws(compact), /not established/);
  });
  it("still rejects tampered signed metadata in default warn mode", async () => {
    const key = await importPKCS8(keyPem, "ES256");
    const parts = (await new SignJWT({}).setProtectedHeader({ alg: "ES256", x5c }).sign(key)).split(".");
    const signature = Buffer.from(parts[2], "base64url"); signature[0] ^= 1;
    parts[2] = signature.toString("base64url");
    await assert.rejects(verifyIssuerMetadataJws(parts.join(".")), /signature/i);
  });
});
