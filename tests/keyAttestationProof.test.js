import { expect } from "chai";
import * as jose from "jose";
import fs from "fs";
import path from "path";
import {
  parseProofAttestationJwtFromCredentialProofs,
  isKeyAttestationTrustedByIssuer,
  resolveKeyAttestationVerificationJwk,
  resolveKeyAttestationVerificationKey,
  verifyKeyAttestationJwtSignature,
  validateKeyAttestationHeaderForCredentialConfig,
  validateAttestationClaimsAndExtractAttestedKeys,
  buildCredentialBindingCnfFromAttestedKeys,
  verifyKeyAttestationProofChain,
  KEY_ATTESTATION_JWT_TYP,
} from "../utils/keyAttestationProof.js";
import { pemToBase64Der } from "../utils/sdjwtUtils.js";

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

    it("rejects an unknown kid when configured JWKS is present", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const pub = await jose.exportJWK(publicKey);
      const decoded = { header: { kid: "unknown", alg: "ES256" } };
      expect(() => resolveKeyAttestationVerificationJwk(decoded, {
        key_attestation_jwks: { keys: [pub] },
      })).to.throw(/no configured Wallet Provider key matches kid/);
    });

    it("falls back to header.jwk when no JWKS configured", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const pub = await jose.exportJWK(publicKey);
      const decoded = { header: { alg: "ES256", jwk: pub } };
      const jwk = resolveKeyAttestationVerificationJwk(decoded, {});
      expect(jwk).to.deep.equal(pub);
    });
  });

  it("resolves a public key from the leaf certificate in header.x5c", async function () {
    const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");
    if (!fs.existsSync(certPath)) this.skip();
    const x5c = [pemToBase64Der(fs.readFileSync(certPath, "utf8"))];
    const key = await resolveKeyAttestationVerificationKey(
      { header: { alg: "ES256", x5c } },
      {}
    );
    const jwk = await jose.exportJWK(key);
    expect(jwk).to.include({ kty: "EC", crv: "P-256" });
    expect(jwk).to.have.property("x");
    expect(jwk).to.have.property("y");
    expect(jwk).to.not.have.property("d");
  });

  it("rejects malformed header.x5c certificate material", async () => {
    try {
      await resolveKeyAttestationVerificationKey(
        { header: { alg: "ES256", x5c: ["not-a-certificate"] } },
        {}
      );
      expect.fail("expected malformed x5c to be rejected");
    } catch (error) {
      expect(error.message).to.match(/certificate|key|PEM|decoder|unsupported/i);
    }
  });

  describe("verifyKeyAttestationJwtSignature and verifyKeyAttestationProofChain", () => {
    async function makeSignedAttestationJwt({ includeAttestedKeys = true } = {}) {
      const attester = await jose.generateKeyPair("ES256");
      const holder = await jose.generateKeyPair("ES256");
      const attesterPub = await jose.exportJWK(attester.publicKey);
      attesterPub.kid = "attester-kid";
      const holderPub = await jose.exportJWK(holder.publicKey);

      const now = Math.floor(Date.now() / 1000);
      const payload = {
        nonce: "test-nonce-xyz",
        key_storage: ["iso_18045_high"],
        user_authentication: ["iso_18045_high"],
        certification: { scheme: "test" },
        key_storage_status: {
          status: { status_list: { uri: "https://example.com/status", idx: 0 } },
          exp: now + 3600,
        },
      };
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

    it("verifyKeyAttestationProofChain end-to-end with an x5c signer", async function () {
      const certPath = path.join(process.cwd(), "x509EC", "client_certificate.crt");
      const keyPath = path.join(process.cwd(), "x509EC", "ec_private_pkcs8.key");
      if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) this.skip();

      const x5c = [pemToBase64Der(fs.readFileSync(certPath, "utf8"))];
      const attesterPrivateKey = await jose.importPKCS8(
        fs.readFileSync(keyPath, "utf8"),
        "ES256"
      );
      const holder = await jose.generateKeyPair("ES256");
      const holderPub = await jose.exportJWK(holder.publicKey);
      const jwt = await new jose.SignJWT({
        nonce: "test-nonce-xyz",
        attested_keys: [holderPub],
        key_storage: ["iso_18045_high"],
        user_authentication: ["iso_18045_high"],
        certification: { scheme: "test" },
        key_storage_status: {
          status: { status_list: { uri: "https://example.com/status", idx: 0 } },
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
      })
        .setProtectedHeader({ alg: "ES256", typ: KEY_ATTESTATION_JWT_TYP, x5c })
        .sign(attesterPrivateKey);

      const { cnf } = await verifyKeyAttestationProofChain(
        jwt,
        { proof_types_supported: { attestation: { proof_signing_alg_values_supported: ["ES256"] } } },
        {}
      );
      expect(cnf).to.deep.equal({ jwk: holderPub });
    });
  });
});
