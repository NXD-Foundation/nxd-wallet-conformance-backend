import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync, X509Certificate } from "node:crypto";
import { compactVerify, decodeProtectedHeader, SignJWT, importPKCS8 } from "jose";
import { loadWuaSigningMaterial, validateExternalWuaSignature } from "../src/lib/wuaSigningMaterial.js";
import { createWUA } from "../src/lib/crypto.js";

describe("certificate-backed WUA signing material", () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), "wua-signer-")); });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("signs a key attestation using the first x5c certificate without jwk", async () => {
    const material = loadWuaSigningMaterial({});
    const jwt = await createWUA({
      privateKeyPem: material.privateKeyPem, publicJwk: material.publicJwk,
      issuer: "provider", audience: "https://issuer.example/credential", attestedKeys: [material.publicJwk],
      headerParams: { x5c: material.x5c }, includeJwkHeader: false,
    });
    const header = decodeProtectedHeader(jwt);
    assert.equal(header.jwk, undefined);
    assert.equal(header.typ, "key-attestation+jwt");
    await compactVerify(jwt, new X509Certificate(Buffer.from(header.x5c[0], "base64")).publicKey);
    await validateExternalWuaSignature(jwt);
  });

  it("rejects incomplete configuration and missing files clearly", () => {
    assert.throws(() => loadWuaSigningMaterial({ WALLET_WUA_SIGNING_KEY_PATH: "missing" }), /requires both/);
    assert.throws(() => loadWuaSigningMaterial({ WALLET_WUA_SIGNING_KEY_PATH: "missing", WALLET_WUA_SIGNING_CERT_PATH: "missing" }), /WUA signing material.*ENOENT/);
  });

  it("rejects mismatched signing key and certificate", () => {
    const material = loadWuaSigningMaterial({});
    const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const keyPath = path.join(dir, "key.pem"), certPath = path.join(dir, "cert.pem");
    fs.writeFileSync(keyPath, keys.privateKey.export({ type: "pkcs8", format: "pem" }));
    fs.writeFileSync(certPath, new X509Certificate(Buffer.from(material.x5c[0], "base64")).toString());
    assert.throws(() => loadWuaSigningMaterial({ WALLET_WUA_SIGNING_KEY_PATH: keyPath, WALLET_WUA_SIGNING_CERT_PATH: certPath }), /does not match/);
  });

  it("rejects invalid certificate material", () => {
    const material = loadWuaSigningMaterial({});
    const keyPath = path.join(dir, "key.pem"), certPath = path.join(dir, "cert.pem");
    fs.writeFileSync(keyPath, material.privateKeyPem);
    fs.writeFileSync(certPath, "not a certificate");
    assert.throws(() => loadWuaSigningMaterial({ WALLET_WUA_SIGNING_KEY_PATH: keyPath, WALLET_WUA_SIGNING_CERT_PATH: certPath }), /no PEM certificates/);
  });

  it("rejects externally supplied jwk headers and signatures from another key", async () => {
    const material = loadWuaSigningMaterial({});
    const key = await importPKCS8(material.privateKeyPem, "ES256");
    const jwkJwt = await new SignJWT({}).setProtectedHeader({ alg: "ES256", typ: "key-attestation+jwt", jwk: material.publicJwk }).sign(key);
    await assert.rejects(validateExternalWuaSignature(jwkJwt), /requires.*x5c/);
    const other = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const wrongJwt = await new SignJWT({}).setProtectedHeader({ alg: "ES256", typ: "key-attestation+jwt", x5c: material.x5c }).sign(other.privateKey);
    await assert.rejects(validateExternalWuaSignature(wrongJwt), /signature verification failed/);
  });
});
