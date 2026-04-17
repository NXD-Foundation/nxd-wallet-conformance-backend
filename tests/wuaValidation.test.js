import { expect } from "chai";
import jwt from "jsonwebtoken";
import * as jose from "jose";
import {
  validateWUA,
  proofKeyMatchesWUAAttestedKeys,
  proofKeyMatchesAnyWUAAttestedKey,
  verifyWuaJwtSignature,
  isWuaWalletProviderTrustedByPolicy,
  credentialConfigRequiresJwtProofKeyAttestation,
} from "../utils/routeUtils.js";

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
  describe("credentialConfigRequiresJwtProofKeyAttestation (RFC001 §7.5.1)", () => {
    it("is true for ETSI PID vc+sd-jwt / vc+jwt / x509_attr with EUDI PID vct", () => {
      expect(
        credentialConfigRequiresJwtProofKeyAttestation({
          format: "vc+sd-jwt",
          vct: "urn:eu.europa.ec.eudi:pid:1",
          proof_types_supported: { jwt: { proof_signing_alg_values_supported: ["ES256"] } },
        })
      ).to.equal(true);
      expect(
        credentialConfigRequiresJwtProofKeyAttestation({
          format: "vc+jwt",
          vct: "urn:eu.europa.ec.eudi:pid:1",
          proof_types_supported: { jwt: {} },
        })
      ).to.equal(true);
      expect(
        credentialConfigRequiresJwtProofKeyAttestation({
          format: "x509_attr",
          vct: "urn:eu.europa.ec.eudi:pid:1",
          proof_types_supported: { jwt: {} },
        })
      ).to.equal(true);
    });

    it("is true when proof_types_supported.jwt.key_attestation_required is true", () => {
      expect(
        credentialConfigRequiresJwtProofKeyAttestation({
          format: "dc+sd-jwt",
          proof_types_supported: {
            jwt: { proof_signing_alg_values_supported: ["ES256"], key_attestation_required: true },
          },
        })
      ).to.equal(true);
    });

    it("is false for generic configs without opt-in", () => {
      expect(
        credentialConfigRequiresJwtProofKeyAttestation({
          format: "dc+sd-jwt",
          vct: "urn:eu.europa.ec.eudi:pid:1",
          proof_types_supported: { jwt: { proof_signing_alg_values_supported: ["ES256"] } },
        })
      ).to.equal(false);
      expect(
        credentialConfigRequiresJwtProofKeyAttestation({
          format: "vc+sd-jwt",
          vct: "urn:other:vct",
          proof_types_supported: { jwt: {} },
        })
      ).to.equal(false);
    });
  });

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

  describe("proofKeyMatchesAnyWUAAttestedKey (RFC001 P1-12)", () => {
    it("returns true when proof key matches any attested key", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const { publicKey: p2 } = await jose.generateKeyPair("ES256");
      const j1 = await jose.exportJWK(publicKey);
      const j2 = await jose.exportJWK(p2);
      const wuaPayload = { attested_keys: [j1, j2] };
      expect(proofKeyMatchesAnyWUAAttestedKey(j1, wuaPayload)).to.equal(true);
      expect(proofKeyMatchesAnyWUAAttestedKey(j2, wuaPayload)).to.equal(true);
    });
  });
});
