import { expect } from "chai";
import fs from "fs";
import path from "path";
import jwt from "jsonwebtoken";
import * as jose from "jose";
import {
  validateWUA,
  proofKeyMatchesWUAAttestedKeys,
  verifyWuaJwtSignature,
  isWuaWalletProviderTrustedByPolicy,
} from "../utils/routeUtils.js";
import { pemToBase64Der } from "../utils/sdjwtUtils.js";

async function buildMinimalWua({ privateKey, publicJwk, attestedKeys }) {
  const key = await jose.importJWK(await jose.exportJWK(privateKey), "ES256");
  return new jose.SignJWT({
    iss: "https://wallet.example",
    aud: "https://issuer.example/credential",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: "wua-test-jti",
    eudi_wallet_info: {
      general_info: { name: "test-wallet" },
      key_storage_info: { level: "tee" },
    },
    attested_keys: attestedKeys,
    status: { status_list: { uri: "https://example.com/status", idx: 0 } },
  })
    .setProtectedHeader({ alg: "ES256", typ: "key-attestation+jwt", jwk: publicJwk })
    .sign(key);
}

describe("WUA validation (routeUtils)", () => {
  it("isWuaWalletProviderTrustedByPolicy is stub true (Trusted List not wired)", () => {
    expect(
      isWuaWalletProviderTrustedByPolicy({ iss: "https://any.wallet-provider.example" }, {}, {})
    ).to.equal(true);
  });

  it("validateWUA rejects invalid signature when header.jwk does not match signing key", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
    const { publicKey: otherPub } = await jose.generateKeyPair("ES256");
    const wrongPubJwk = await jose.exportJWK(otherPub);
    const holderJwk = await jose.exportJWK(publicKey);
    const jwt = await buildMinimalWua({
      privateKey,
      publicJwk: wrongPubJwk,
      attestedKeys: [holderJwk],
    });
    const result = await validateWUA(jwt, null, {});
    expect(result.valid).to.equal(false);
    expect(result.error).to.match(/signature verification failed/i);
  });

  it("validateWUA accepts valid WUA signed with key matching header.jwk", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
    const pubJwk = await jose.exportJWK(publicKey);
    const jwt = await buildMinimalWua({
      privateKey,
      publicJwk: pubJwk,
      attestedKeys: [pubJwk],
    });
    const result = await validateWUA(jwt, null, {});
    expect(result.valid).to.equal(true);
    expect(result.payload?.iss).to.equal("https://wallet.example");
  });

  it("validateWUA accepts a valid x5c-only WUA in default interoperability mode", async function () {
    const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");
    const keyPath = path.join(process.cwd(), "x509EC", "ec_private_pkcs8.key");
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) this.skip();

    const signer = await jose.importPKCS8(fs.readFileSync(keyPath, "utf8"), "ES256");
    const holder = await jose.generateKeyPair("ES256");
    const holderJwk = await jose.exportJWK(holder.publicKey);
    const wua = await new jose.SignJWT({
      eudi_wallet_info: { general_info: { name: "test-wallet" }, key_storage_info: { level: "tee" } },
      attested_keys: [holderJwk],
      status: { status_list: { uri: "https://example.com/status", idx: 0 } },
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "key-attestation+jwt",
        x5c: [pemToBase64Der(fs.readFileSync(certPath, "utf8"))],
      })
      .sign(signer);

    const result = await validateWUA(wua, null, {});
    expect(result.valid).to.equal(true);
    expect(result.verificationKeySource).to.equal("header_x5c");

    const previous = process.env.ENFORCE_WUA_TRUST_FRAMEWORK;
    process.env.ENFORCE_WUA_TRUST_FRAMEWORK = "true";
    try {
      const strictResult = await validateWUA(wua, null, {});
      expect(strictResult.valid).to.equal(false);
      expect(strictResult.error).to.match(/ENFORCE_WUA_TRUST_FRAMEWORK/);
    } finally {
      if (previous === undefined) delete process.env.ENFORCE_WUA_TRUST_FRAMEWORK;
      else process.env.ENFORCE_WUA_TRUST_FRAMEWORK = previous;
    }
  });

  it("rejects a self-contained WUA when trust-framework enforcement is enabled without configured keys", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
    const pubJwk = await jose.exportJWK(publicKey);
    const wua = await buildMinimalWua({ privateKey, publicJwk: pubJwk, attestedKeys: [pubJwk] });
    const previous = process.env.ENFORCE_WUA_TRUST_FRAMEWORK;
    process.env.ENFORCE_WUA_TRUST_FRAMEWORK = "true";
    try {
      const result = await validateWUA(wua, null, {});
      expect(result.valid).to.equal(false);
      expect(result.error).to.match(/ENFORCE_WUA_TRUST_FRAMEWORK/);
    } finally {
      if (previous === undefined) delete process.env.ENFORCE_WUA_TRUST_FRAMEWORK;
      else process.env.ENFORCE_WUA_TRUST_FRAMEWORK = previous;
    }
  });

  it("verifyWuaJwtSignature uses wallet_unit_attestation_jwks when kid matches", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
    const pubJwk = await jose.exportJWK(publicKey);
    pubJwk.kid = "wua-signer-1";
    const wuaCompact = await new jose.SignJWT({
      iss: "https://wallet.example",
      aud: "https://issuer.example/credential",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: "x",
      eudi_wallet_info: {
        general_info: { a: 1 },
        key_storage_info: { b: 2 },
      },
      attested_keys: [pubJwk],
      status: { status_list: { uri: "https://x", idx: 0 } },
    })
      .setProtectedHeader({
        alg: "ES256",
        typ: "key-attestation+jwt",
        kid: "wua-signer-1",
      })
      .sign(await jose.importJWK(await jose.exportJWK(privateKey), "ES256"));

    const issuerMetadata = {
      wallet_unit_attestation_jwks: { keys: [{ ...pubJwk, kid: "wua-signer-1" }] },
    };
    const decoded = jwt.decode(wuaCompact, { complete: true });
    const v = await verifyWuaJwtSignature(wuaCompact, decoded.header, issuerMetadata);
    expect(v.ok).to.equal(true);
  });

  describe("proofKeyMatchesWUAAttestedKeys (first key only)", () => {
    it("returns true when proof key equals first attested key", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const { publicKey: p2 } = await jose.generateKeyPair("ES256");
      const j1 = await jose.exportJWK(publicKey);
      const j2 = await jose.exportJWK(p2);
      const wuaPayload = { attested_keys: [j1, j2] };
      expect(proofKeyMatchesWUAAttestedKeys(j1, wuaPayload)).to.equal(true);
    });

    it("returns false when proof key only matches second attested key", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const { publicKey: p2 } = await jose.generateKeyPair("ES256");
      const j1 = await jose.exportJWK(publicKey);
      const j2 = await jose.exportJWK(p2);
      const wuaPayload = { attested_keys: [j1, j2] };
      expect(proofKeyMatchesWUAAttestedKeys(j2, wuaPayload)).to.equal(false);
    });
  });
});
