import { expect } from "chai";
import * as jose from "jose";
import {
  parseProofAttestationJwtFromCredentialProofs,
  isKeyAttestationTrustedByIssuer,
  resolveKeyAttestationVerificationJwk,
  verifyKeyAttestationJwtSignature,
  validateKeyAttestationHeaderForCredentialConfig,
  validateAttestationClaimsAndExtractAttestedKeys,
  buildCredentialBindingCnfFromAttestedKeys,
  verifyKeyAttestationProofChain,
  KEY_ATTESTATION_JWT_TYP,
} from "../utils/keyAttestationProof.js";

describe("keyAttestationProof", () => {
  describe("parseProofAttestationJwtFromCredentialProofs", () => {
    it("returns the single JWT string from a one-element array", () => {
      const jwt = "a.b.c";
      expect(parseProofAttestationJwtFromCredentialProofs([jwt])).to.equal(jwt);
    });

    it("rejects non-array", () => {
      expect(() => parseProofAttestationJwtFromCredentialProofs("x")).to.throw(/must be a JSON array/);
    });

    it("rejects empty array", () => {
      expect(() => parseProofAttestationJwtFromCredentialProofs([])).to.throw(/must not be empty/);
    });

    it("rejects more than one JWT", () => {
      expect(() => parseProofAttestationJwtFromCredentialProofs(["a.b.c", "d.e.f"])).to.throw(
        /exactly one JWT/
      );
    });
  });

  it("isKeyAttestationTrustedByIssuer requires x5c and configured anchors", async () => {
    const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
      m.createWalletProviderKeyAttestationCertFixtures()
    );
    expect(
      isKeyAttestationTrustedByIssuer(
        { alg: "ES256", x5c: fixtures.x5c },
        {},
        { wallet_provider_trust_anchors: fixtures.issuerConfigAnchors }
      )
    ).to.equal(true);
    expect(isKeyAttestationTrustedByIssuer({ alg: "ES256", jwk: {} }, {}, {})).to.equal(false);
  });

  describe("validateKeyAttestationHeaderForCredentialConfig", () => {
    const credConfig = {
      proof_types_supported: {
        attestation: { proof_signing_alg_values_supported: ["ES256"] },
      },
    };

    it("accepts key-attestation+jwt and ES256", () => {
      validateKeyAttestationHeaderForCredentialConfig(
        { typ: KEY_ATTESTATION_JWT_TYP, alg: "ES256" },
        credConfig
      );
    });

    it("rejects wrong typ", () => {
      expect(() =>
        validateKeyAttestationHeaderForCredentialConfig({ typ: "jwt", alg: "ES256" }, credConfig)
      ).to.throw(/invalid typ/);
    });

    it("rejects unsupported alg", () => {
      expect(() =>
        validateKeyAttestationHeaderForCredentialConfig(
          { typ: KEY_ATTESTATION_JWT_TYP, alg: "RS256" },
          credConfig
        )
      ).to.throw(/unsupported algorithm/);
    });
  });

  describe("validateAttestationClaimsAndExtractAttestedKeys", () => {
    it("returns attested_keys when valid", () => {
      const keys = [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }];
      const out = validateAttestationClaimsAndExtractAttestedKeys({ attested_keys: keys });
      expect(out).to.deep.equal(keys);
    });

    it("rejects missing attested_keys", () => {
      expect(() => validateAttestationClaimsAndExtractAttestedKeys({})).to.throw(/attested_keys/);
    });

    it("rejects non-JWK entries", () => {
      expect(() =>
        validateAttestationClaimsAndExtractAttestedKeys({ attested_keys: [{}] })
      ).to.throw(/must be a JWK/);
    });

    it("rejects certification when it is a JSON object instead of a URL string", () => {
      expect(() =>
        validateAttestationClaimsAndExtractAttestedKeys({
          attested_keys: [{ kty: "EC", crv: "P-256", x: "a", y: "b" }],
          certification: { scheme: "local" },
        })
      ).to.throw(/not a JSON object/);
    });

    it("accepts certification as an absolute https URL", () => {
      const keys = [{ kty: "EC", crv: "P-256", x: "abc", y: "def" }];
      const out = validateAttestationClaimsAndExtractAttestedKeys({
        attested_keys: keys,
        certification: "https://wallet-provider.example/certification/wscd/",
      });
      expect(out).to.deep.equal(keys);
    });
  });

  it("buildCredentialBindingCnfFromAttestedKeys uses first key as cnf.jwk", () => {
    const k1 = { kty: "EC", crv: "P-256", x: "a", y: "b" };
    const k2 = { kty: "EC", crv: "P-256", x: "c", y: "d" };
    expect(buildCredentialBindingCnfFromAttestedKeys([k1, k2])).to.deep.equal({ jwk: k1 });
  });

  describe("resolveKeyAttestationVerificationJwk", () => {
    it("resolves JWK from x5c leaf under wallet_provider_trust_anchors", async () => {
      const fixtures = await import("./helpers/wpKeyAttestationCertFixtures.mjs").then((m) =>
        m.createWalletProviderKeyAttestationCertFixtures()
      );
      const decoded = { header: { alg: "ES256", x5c: fixtures.x5c } };
      const jwk = resolveKeyAttestationVerificationJwk(decoded, {
        wallet_provider_trust_anchors: fixtures.issuerConfigAnchors,
      });
      expect(jwk).to.have.property("kty", "EC");
    });

    it("rejects header.jwk", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const pub = await jose.exportJWK(publicKey);
      const decoded = { header: { alg: "ES256", jwk: pub } };
      expect(() => resolveKeyAttestationVerificationJwk(decoded, {})).to.throw(/header\.jwk is not accepted/i);
    });

    it("rejects configured JWKS without x5c", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const pub = await jose.exportJWK(publicKey);
      const decoded = { header: { kid: "attester-1", alg: "ES256" } };
      expect(() =>
        resolveKeyAttestationVerificationJwk(decoded, {
          key_attestation_jwks: { keys: [pub] },
        })
      ).to.throw(/must include x5c/i);
    });
  });

  describe("verifyKeyAttestationJwtSignature and verifyKeyAttestationProofChain", () => {
    async function makeSignedAttestationJwt({ includeAttestedKeys = true } = {}) {
      const attester = await jose.generateKeyPair("ES256");
      const holder = await jose.generateKeyPair("ES256");
      const attesterPub = await jose.exportJWK(attester.publicKey);
      attesterPub.kid = "attester-kid";
      const holderPub = await jose.exportJWK(holder.publicKey);

      const payload = { nonce: "test-nonce-xyz" };
      if (includeAttestedKeys) payload.attested_keys = [holderPub];

      const jwt = await new jose.SignJWT(payload)
        .setProtectedHeader({
          alg: "ES256",
          typ: KEY_ATTESTATION_JWT_TYP,
          kid: "attester-kid",
        })
        .sign(attester.privateKey);

      return { jwt, attesterPub, holderPub };
    }

    it("verifyKeyAttestationJwtSignature succeeds with correct public JWK", async () => {
      const { jwt, attesterPub } = await makeSignedAttestationJwt();
      const payload = await verifyKeyAttestationJwtSignature(jwt, attesterPub);
      expect(payload.nonce).to.equal("test-nonce-xyz");
      expect(payload.attested_keys).to.be.an("array").with.length(1);
    });

    it("verifyKeyAttestationJwtSignature fails with wrong key (invalid_proof / signature)", async () => {
      const { jwt } = await makeSignedAttestationJwt();
      const other = await jose.generateKeyPair("ES256");
      const wrongPub = await jose.exportJWK(other.publicKey);
      try {
        await verifyKeyAttestationJwtSignature(jwt, wrongPub);
        expect.fail("expected verification error");
      } catch (e) {
        expect(e.message).to.match(/Proof JWT signature verification failed|signature/i);
      }
    });

    it("verifyKeyAttestationProofChain end-to-end with x5c and trust anchors", async () => {
      const { createWalletProviderKeyAttestationCertFixtures, buildSignedKeyAttestationJwt } =
        await import("./helpers/wpKeyAttestationCertFixtures.mjs");
      const fixtures = await createWalletProviderKeyAttestationCertFixtures();
      const holder = await jose.generateKeyPair("ES256");
      const holderPub = await jose.exportJWK(holder.publicKey);
      const kaJwt = await buildSignedKeyAttestationJwt({
        fixtures,
        attestedKeys: [holderPub],
        claims: { nonce: "test-nonce-xyz" },
      });
      const credConfig = {
        proof_types_supported: {
          attestation: { proof_signing_alg_values_supported: ["ES256"] },
        },
      };
      const issuerConfig = { wallet_provider_trust_anchors: fixtures.issuerConfigAnchors };
      const { cnf, attestedKeys, signatureVerified } = await verifyKeyAttestationProofChain(
        kaJwt,
        credConfig,
        issuerConfig
      );
      expect(signatureVerified).to.equal(true);
      expect(attestedKeys).to.have.length(1);
      expect(attestedKeys[0].x).to.equal(holderPub.x);
      expect(cnf).to.deep.equal({ jwk: holderPub });
    });

    it("rejects attestation proof when no trust anchors are configured", async () => {
      const { createWalletProviderKeyAttestationCertFixtures, buildSignedKeyAttestationJwt } =
        await import("./helpers/wpKeyAttestationCertFixtures.mjs");
      const fixtures = await createWalletProviderKeyAttestationCertFixtures();
      const holder = await jose.generateKeyPair("ES256");
      const holderPub = await jose.exportJWK(holder.publicKey);
      const kaJwt = await buildSignedKeyAttestationJwt({
        fixtures,
        attestedKeys: [holderPub],
        claims: { nonce: "test-nonce-xyz" },
      });
      const credConfig = {
        proof_types_supported: {
          attestation: { proof_signing_alg_values_supported: ["ES256"] },
        },
      };
      try {
        await verifyKeyAttestationProofChain(kaJwt, credConfig, {});
        expect.fail("expected rejection");
      } catch (e) {
        expect(String(e.message)).to.match(/wallet_provider_trust_anchors|x5c|not trusted by issuer policy/i);
      }
    });
  });
});
