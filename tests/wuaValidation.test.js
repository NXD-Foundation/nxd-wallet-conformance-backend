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

async function buildMinimalWuaX5c({ fixtures, attestedKeys, claims = {} }) {
  const { buildSignedKeyAttestationJwt } = await import("./helpers/wpKeyAttestationCertFixtures.mjs");
  return buildSignedKeyAttestationJwt({ fixtures, attestedKeys, claims });
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

    it("is true when metadata advertises key_attestations_required", () => {
      expect(
        credentialConfigRequiresJwtProofKeyAttestation({
          format: "dc+sd-jwt",
          proof_types_supported: {
            jwt: { proof_signing_alg_values_supported: ["ES256"], key_attestations_required: {} },
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

  it("isWuaWalletProviderTrustedByPolicy requires x5c chain to configured anchors", async () => {
    const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
      m.createWalletProviderKeyAttestationCertFixtures()
    );
    expect(
      isWuaWalletProviderTrustedByPolicy(
        { iss: "https://wallet-provider.example" },
        { alg: "ES256", x5c: fixtures.x5c },
        { wallet_provider_trust_anchors: fixtures.issuerConfigAnchors }
      )
    ).to.equal(true);
    expect(isWuaWalletProviderTrustedByPolicy({}, { alg: "ES256", jwk: {} }, {})).to.equal(false);
  });

  it("validateWUA rejects jwk-only key attestation header", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
    const pubJwk = await jose.exportJWK(publicKey);
    const holderJwk = await jose.exportJWK((await jose.generateKeyPair("ES256")).publicKey);
    const wuaCompact = await new jose.SignJWT({
      iss: "https://wallet.example",
      aud: "https://issuer.example/credential",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: "wua-jwk-only",
      eudi_wallet_info: {
        general_info: { name: "test-wallet" },
        key_storage_info: { level: "tee" },
      },
      attested_keys: [holderJwk],
      status: { status_list: { uri: "https://example.com/status", idx: 0 } },
    })
      .setProtectedHeader({ alg: "ES256", typ: "key-attestation+jwt", jwk: pubJwk })
      .sign(privateKey);
    const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
      m.createWalletProviderKeyAttestationCertFixtures()
    );
    const result = await validateWUA(wuaCompact, null, {
      wallet_provider_trust_anchors: fixtures.issuerConfigAnchors,
    });
    expect(result.valid).to.equal(false);
    expect(result.error).to.match(/header\.jwk|x5c/i);
  });

  it("validateWUA accepts valid WUA signed under x5c with trust anchor", async () => {
    const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
      m.createWalletProviderKeyAttestationCertFixtures()
    );
    const { publicKey } = await jose.generateKeyPair("ES256");
    const pubJwk = await jose.exportJWK(publicKey);
    const compact = await buildMinimalWuaX5c({
      fixtures,
      attestedKeys: [pubJwk],
    });
    const result = await validateWUA(compact, null, {
      wallet_provider_trust_anchors: fixtures.issuerConfigAnchors,
    });
    expect(result.valid).to.equal(true);
    expect(result.payload?.iss).to.equal("https://wallet-provider.example");
  });

  it("validateWUA accepts a KA without iss (TS3 certificate identifies the Wallet Provider)", async () => {
    const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
      m.createWalletProviderKeyAttestationCertFixtures()
    );
    const { publicKey } = await jose.generateKeyPair("ES256");
    const pubJwk = await jose.exportJWK(publicKey);
    const compact = await buildMinimalWuaX5c({
      fixtures,
      attestedKeys: [pubJwk],
      claims: { iss: undefined },
    });
    const result = await validateWUA(compact, null, {
      wallet_provider_trust_anchors: fixtures.issuerConfigAnchors,
    });
    expect(result.valid).to.equal(true);
    expect(result.payload?.attested_keys).to.be.an("array").with.length(1);
  });

  it("validateWUA accepts a trusted KA without the legacy eudi_wallet_info extension", async () => {
    const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
      m.createWalletProviderKeyAttestationCertFixtures()
    );
    const { publicKey } = await jose.generateKeyPair("ES256");
    const pubJwk = await jose.exportJWK(publicKey);
    const compact = await buildMinimalWuaX5c({
      fixtures,
      attestedKeys: [pubJwk],
      claims: { eudi_wallet_info: undefined },
    });
    const result = await validateWUA(compact, null, {
      wallet_provider_trust_anchors: fixtures.issuerConfigAnchors,
    });
    expect(result.valid).to.equal(true);
    expect(result.payload).not.to.have.property("eudi_wallet_info");
  });

  for (const legacyInfo of [{}, { general_info: {} }, null]) {
    it(`does not require nested legacy wallet info: ${JSON.stringify(legacyInfo)}`, async () => {
      const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
        m.createWalletProviderKeyAttestationCertFixtures()
      );
      const pubJwk = await jose.exportJWK((await jose.generateKeyPair("ES256")).publicKey);
      const compact = await buildMinimalWuaX5c({
        fixtures, attestedKeys: [pubJwk], claims: { eudi_wallet_info: legacyInfo },
      });
      expect((await validateWUA(compact, null, {
        wallet_provider_trust_anchors: fixtures.issuerConfigAnchors,
      })).valid).to.equal(true);
    });
  }

  for (const failure of ["signature", "trust", "expiration"]) {
    it(`still rejects invalid ${failure} without legacy wallet info`, async () => {
      const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
        m.createWalletProviderKeyAttestationCertFixtures()
      );
      const pubJwk = await jose.exportJWK((await jose.generateKeyPair("ES256")).publicKey);
      let compact = await buildMinimalWuaX5c({
        fixtures,
        attestedKeys: [pubJwk],
        claims: {
          eudi_wallet_info: undefined,
          ...(failure === "expiration" ? { exp: Math.floor(Date.now() / 1000) - 60 } : {}),
        },
      });
      if (failure === "signature") {
        const parts = compact.split(".");
        const signature = Buffer.from(parts[2], "base64url");
        signature[0] ^= 1;
        parts[2] = signature.toString("base64url");
        compact = parts.join(".");
      }
      const result = await validateWUA(compact, null, {
        wallet_provider_trust_anchors: failure === "trust" ? [] : fixtures.issuerConfigAnchors,
      });
      expect(result.valid).to.equal(false);
      expect(result.error).to.match(failure === "expiration" ? /expired/i : /signature|trust anchor/i);
    });
  }

  it("verifyWuaJwtSignature verifies x5c-signed WUA with trust anchors", async () => {
    const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
      m.createWalletProviderKeyAttestationCertFixtures()
    );
    const { publicKey } = await jose.generateKeyPair("ES256");
    const pubJwk = await jose.exportJWK(publicKey);
    const wuaCompact = await buildMinimalWuaX5c({ fixtures, attestedKeys: [pubJwk] });
    const issuerMetadata = { wallet_provider_trust_anchors: fixtures.issuerConfigAnchors };
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
