import { expect } from "chai";
import * as jose from "jose";
import fs from "fs";
import path from "path";
import {
  resolveWalletProviderAttestationVerificationJwk,
  resolveWalletProviderAttestationVerificationKey,
  collectWalletProviderAttestationJwks,
  isWuaTrustFrameworkEnforced,
  jwkFromAttestationHeaderX5c,
} from "../utils/wuaVerificationKeyResolver.js";
import { pemToBase64Der } from "../utils/sdjwtUtils.js";

const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");

describe("wuaVerificationKeyResolver", () => {
  const originalEnforcement = process.env.ENFORCE_WUA_TRUST_FRAMEWORK;

  afterEach(() => {
    if (originalEnforcement !== undefined) {
      process.env.ENFORCE_WUA_TRUST_FRAMEWORK = originalEnforcement;
    } else {
      delete process.env.ENFORCE_WUA_TRUST_FRAMEWORK;
    }
  });

  it("prefers wallet_unit_attestation_jwks over the compatibility alias", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const pub = await jose.exportJWK(publicKey);
    pub.kid = "wp-1";
    const { publicKey: other } = await jose.generateKeyPair("ES256");
    const otherPub = await jose.exportJWK(other);
    otherPub.kid = "wp-2";

    const keys = collectWalletProviderAttestationJwks({
      wallet_unit_attestation_jwks: { keys: [pub] },
      key_attestation_jwks: { keys: [pub, otherPub] },
    });
    expect(keys).to.have.length(1);
    expect(keys[0].kid).to.equal("wp-1");
  });

  it("resolveWalletProviderAttestationVerificationJwk uses pinned kid match", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const pub = await jose.exportJWK(publicKey);
    pub.kid = "wp-signer";
    const jwk = resolveWalletProviderAttestationVerificationJwk(
      { kid: "wp-signer", alg: "ES256" },
      { wallet_unit_attestation_jwks: { keys: [pub] } },
    );
    expect(jwk.kid).to.equal("wp-signer");
  });

  it("resolveWalletProviderAttestationVerificationJwk rejects unknown kid when JWKS configured", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const pub = await jose.exportJWK(publicKey);
    pub.kid = "wp-signer";
    expect(() =>
      resolveWalletProviderAttestationVerificationJwk(
        { kid: "other-kid", alg: "ES256" },
        { key_attestation_jwks: { keys: [pub] } },
      ),
    ).to.throw(/no configured Wallet Provider key matches kid/);
  });

  it("accepts header.jwk by default when no pinned JWKS exists", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const pub = await jose.exportJWK(publicKey);
    delete process.env.ENFORCE_WUA_TRUST_FRAMEWORK;
    const jwk = resolveWalletProviderAttestationVerificationJwk({ jwk: pub, alg: "ES256" }, {});
    expect(jwk).to.deep.equal(pub);
  });

  it("accepts x5c-only header by default when no pinned JWKS exists", function () {
    if (!fs.existsSync(certPath)) {
      this.skip();
    }
    delete process.env.ENFORCE_WUA_TRUST_FRAMEWORK;
    const pem = fs.readFileSync(certPath, "utf8");
    const x5c = [pemToBase64Der(pem)];
    expect(resolveWalletProviderAttestationVerificationJwk({ x5c, alg: "ES256" }, {})).to.have.property("kty", "EC");
  });

  it("rejects header.jwk and x5c when trust-framework enforcement is enabled without configured keys", function () {
    if (!fs.existsSync(certPath)) {
      this.skip();
    }
    process.env.ENFORCE_WUA_TRUST_FRAMEWORK = "true";
    const pem = fs.readFileSync(certPath, "utf8");
    const x5c = [pemToBase64Der(pem)];
    expect(() => resolveWalletProviderAttestationVerificationJwk({ x5c, alg: "ES256" }, {})).to.throw(/ENFORCE_WUA_TRUST_FRAMEWORK/);
    expect(() => resolveWalletProviderAttestationVerificationJwk({ jwk: { kty: "EC" }, alg: "ES256" }, {})).to.throw(/ENFORCE_WUA_TRUST_FRAMEWORK/);
    expect(jwkFromAttestationHeaderX5c({ x5c })).to.have.property("kty", "EC");
  });

  it("reports provenance and parses the enforcement flag", async () => {
    const { publicKey } = await jose.generateKeyPair("ES256");
    const pub = await jose.exportJWK(publicKey);
    expect(resolveWalletProviderAttestationVerificationKey({ jwk: pub }, {}).source).to.equal("header_jwk");
    process.env.ENFORCE_WUA_TRUST_FRAMEWORK = "true";
    expect(isWuaTrustFrameworkEnforced()).to.equal(true);
    process.env.ENFORCE_WUA_TRUST_FRAMEWORK = "false";
    expect(isWuaTrustFrameworkEnforced()).to.equal(false);
  });
});
