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

  it("isKeyAttestationTrustedByIssuer always returns true (stub)", () => {
    expect(isKeyAttestationTrustedByIssuer({}, {}, {})).to.equal(true);
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
  });

  it("buildCredentialBindingCnfFromAttestedKeys uses first key as cnf.jwk", () => {
    const k1 = { kty: "EC", crv: "P-256", x: "a", y: "b" };
    const k2 = { kty: "EC", crv: "P-256", x: "c", y: "d" };
    expect(buildCredentialBindingCnfFromAttestedKeys([k1, k2])).to.deep.equal({ jwk: k1 });
  });

  describe("resolveKeyAttestationVerificationJwk", () => {
    it("uses issuer key_attestation_jwks key matching kid", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const pub = await jose.exportJWK(publicKey);
      pub.kid = "attester-1";
      const decoded = { header: { kid: "attester-1", alg: "ES256" } };
      const jwk = resolveKeyAttestationVerificationJwk(decoded, {
        key_attestation_jwks: { keys: [pub] },
      });
      expect(jwk.kid).to.equal("attester-1");
    });

    it("falls back to first JWKS key when kid does not match", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const pub = await jose.exportJWK(publicKey);
      const decoded = { header: { kid: "unknown", alg: "ES256" } };
      const jwk = resolveKeyAttestationVerificationJwk(decoded, {
        key_attestation_jwks: { keys: [pub] },
      });
      expect(jwk.x).to.equal(pub.x);
    });

    it("falls back to header.jwk when no JWKS configured", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const pub = await jose.exportJWK(publicKey);
      const decoded = { header: { alg: "ES256", jwk: pub } };
      const jwk = resolveKeyAttestationVerificationJwk(decoded, {});
      expect(jwk).to.deep.equal(pub);
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

    it("verifyKeyAttestationProofChain end-to-end with configured JWKS", async () => {
      const { jwt, attesterPub, holderPub } = await makeSignedAttestationJwt();
      const credConfig = {
        proof_types_supported: {
          attestation: { proof_signing_alg_values_supported: ["ES256"] },
        },
      };
      const issuerConfig = { key_attestation_jwks: { keys: [attesterPub] } };
      const { cnf, attestedKeys } = await verifyKeyAttestationProofChain(
        jwt,
        credConfig,
        issuerConfig
      );
      expect(attestedKeys).to.have.length(1);
      expect(attestedKeys[0].x).to.equal(holderPub.x);
      expect(cnf).to.deep.equal({ jwk: holderPub });
    });
  });
});
