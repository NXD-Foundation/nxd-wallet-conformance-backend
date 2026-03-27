import { strict as assert } from "assert";
import { expect } from "chai";
import * as jose from "jose";
import { randomUUID } from "crypto";
import {
  CLIENT_ATTESTATION_JWT_TYP,
  CLIENT_ATTESTATION_POP_TYP,
  assertCnfJwkIsPublicOnly,
  verifyClientAttestationJwt,
  verifyClientAttestationPopJwt,
  validateOAuthClientAttestationFromRequest,
  getOAuthClientAttestationHeaders,
} from "../utils/oauthClientAttestation.js";

const AS_ISSUER = "http://localhost:3000";
const ALG = "ES256";

async function mintKeyPairs() {
  const attester = await jose.generateKeyPair(ALG, { extractable: true });
  const wallet = await jose.generateKeyPair(ALG, { extractable: true });
  const attesterPub = await jose.exportJWK(attester.publicKey);
  attesterPub.kid = "test-attester-kid";
  attesterPub.use = "sig";
  const walletPub = await jose.exportJWK(wallet.publicKey);
  return { attester, wallet, attesterPub, walletPub };
}

async function signAttestation({ attesterPrivateKey, walletPub, clientId = "conf-client", attesterIss = "https://wallet-attester.example" }) {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    iss: attesterIss,
    sub: clientId,
    iat: now,
    nbf: now,
    exp: now + 300,
    cnf: { jwk: walletPub },
  })
    .setProtectedHeader({ alg: ALG, typ: CLIENT_ATTESTATION_JWT_TYP, kid: "test-attester-kid" })
    .sign(attesterPrivateKey);
}

async function signPop({ walletPrivateKey, clientId, audience = AS_ISSUER }) {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    iss: clientId,
    aud: audience,
    iat: now,
    nbf: now,
    exp: now + 300,
    jti: randomUUID(),
  })
    .setProtectedHeader({ alg: ALG, typ: CLIENT_ATTESTATION_POP_TYP })
    .sign(walletPrivateKey);
}

function corruptJwtSignature(jwt) {
  const parts = jwt.split(".");
  expect(parts).to.have.length(3);
  // Replace signature segment with syntactically valid base64url that cannot verify
  parts[2] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  return parts.join(".");
}

describe("oauthClientAttestation", () => {
  describe("getOAuthClientAttestationHeaders", () => {
    it("reads lowercase Node header names", () => {
      const { attestationJwt, popJwt } = getOAuthClientAttestationHeaders({
        "oauth-client-attestation": "a.b.c",
        "oauth-client-attestation-pop": "d.e.f",
      });
      expect(attestationJwt).to.equal("a.b.c");
      expect(popJwt).to.equal("d.e.f");
    });
  });

  describe("assertCnfJwkIsPublicOnly", () => {
    it("throws when private parameter d is present", () => {
      expect(() =>
        assertCnfJwkIsPublicOnly({ kty: "EC", crv: "P-256", x: "abc", y: "def", d: "secret" })
      ).to.throw(/private key material/);
    });
  });

  describe("verifyClientAttestationJwt / verifyClientAttestationPopJwt", () => {
    it("accepts a valid attestation signed by a trusted attester key", async () => {
      const { attester, wallet, attesterPub, walletPub } = await mintKeyPairs();
      const att = await signAttestation({ attesterPrivateKey: attester.privateKey, walletPub });
      const trusted = { keys: [attesterPub] };
      const { payload } = await verifyClientAttestationJwt(att, trusted);
      expect(payload.sub).to.be.a("string");
      expect(payload.cnf.jwk.kty).to.equal("EC");
    });

    it("rejects attestation when signature does not verify (wrong key)", async () => {
      const { attester, wallet, walletPub } = await mintKeyPairs();
      const other = await jose.generateKeyPair(ALG);
      const otherPub = await jose.exportJWK(other.publicKey);
      otherPub.kid = "other";
      const att = await signAttestation({ attesterPrivateKey: attester.privateKey, walletPub });
      await assert.rejects(() => verifyClientAttestationJwt(att, { keys: [otherPub] }));
    });

    it("rejects attestation when signature bytes are corrupted", async () => {
      const { attester, wallet, attesterPub, walletPub } = await mintKeyPairs();
      const att = corruptJwtSignature(await signAttestation({ attesterPrivateKey: attester.privateKey, walletPub }));
      await assert.rejects(() => verifyClientAttestationJwt(att, { keys: [attesterPub] }));
    });

    it("verifies PoP with the cnf.jwk key and audience", async () => {
      const { attester, wallet, attesterPub, walletPub } = await mintKeyPairs();
      const clientId = "my-client";
      const att = await signAttestation({
        attesterPrivateKey: attester.privateKey,
        walletPub,
        clientId,
      });
      const { payload: ap } = await verifyClientAttestationJwt(att, { keys: [attesterPub] });
      const pop = await signPop({ walletPrivateKey: wallet.privateKey, clientId });
      const { payload: pp } = await verifyClientAttestationPopJwt(pop, ap.cnf.jwk, {
        authorizationServerIssuer: AS_ISSUER,
      });
      expect(pp.aud).to.equal(AS_ISSUER);
    });

    it("rejects PoP when signature is corrupted", async () => {
      const { attester, wallet, attesterPub, walletPub } = await mintKeyPairs();
      const clientId = "my-client";
      const att = await signAttestation({ attesterPrivateKey: attester.privateKey, walletPub, clientId });
      const { payload: ap } = await verifyClientAttestationJwt(att, { keys: [attesterPub] });
      const pop = corruptJwtSignature(await signPop({ walletPrivateKey: wallet.privateKey, clientId }));
      await assert.rejects(() =>
        verifyClientAttestationPopJwt(pop, ap.cnf.jwk, { authorizationServerIssuer: AS_ISSUER })
      );
    });

    it("rejects PoP signed with a different key than cnf.jwk (valid signatures, mismatched binding)", async () => {
      const { attester, wallet, attesterPub, walletPub } = await mintKeyPairs();
      const wallet2 = await jose.generateKeyPair(ALG, { extractable: true });
      const clientId = "my-client";
      const att = await signAttestation({ attesterPrivateKey: attester.privateKey, walletPub, clientId });
      const { payload: ap } = await verifyClientAttestationJwt(att, { keys: [attesterPub] });
      const pop = await signPop({ walletPrivateKey: wallet2.privateKey, clientId });
      await assert.rejects(() =>
        verifyClientAttestationPopJwt(pop, ap.cnf.jwk, { authorizationServerIssuer: AS_ISSUER })
      );
    });
  });

  describe("validateOAuthClientAttestationFromRequest", () => {
    it("skips when no attestation headers are sent", async () => {
      const r = await validateOAuthClientAttestationFromRequest({
        headers: {},
        clientId: "x",
        authorizationServerIssuer: AS_ISSUER,
        trustedJwks: { keys: [] },
      });
      expect(r.skip).to.equal(true);
    });

    it("returns invalid_client when only one header is present", async () => {
      const r = await validateOAuthClientAttestationFromRequest({
        headers: { "oauth-client-attestation": "a.b.c" },
        clientId: "x",
        authorizationServerIssuer: AS_ISSUER,
        trustedJwks: { keys: [] },
      });
      expect(r.skip).to.equal(false);
      expect(r.ok).to.equal(false);
      expect(r.oauthError).to.equal("invalid_client");
    });

    it("succeeds end-to-end for a valid pair", async () => {
      const { attester, wallet, attesterPub, walletPub } = await mintKeyPairs();
      const clientId = "wallet-instance-42";
      const att = await signAttestation({ attesterPrivateKey: attester.privateKey, walletPub, clientId });
      const pop = await signPop({ walletPrivateKey: wallet.privateKey, clientId });
      const r = await validateOAuthClientAttestationFromRequest({
        headers: {
          "oauth-client-attestation": att,
          "oauth-client-attestation-pop": pop,
        },
        clientId,
        authorizationServerIssuer: AS_ISSUER,
        trustedJwks: { keys: [attesterPub] },
      });
      expect(r.ok).to.equal(true);
      expect(r.attestationPayload.sub).to.equal(clientId);
    });

    it("succeeds with empty trusted JWKS: attester signature not verified, PoP still verified", async () => {
      const { attester, wallet, walletPub } = await mintKeyPairs();
      const clientId = "wallet-instance-99";
      const att = await signAttestation({ attesterPrivateKey: attester.privateKey, walletPub, clientId });
      const pop = await signPop({ walletPrivateKey: wallet.privateKey, clientId });
      const r = await validateOAuthClientAttestationFromRequest({
        headers: {
          "oauth-client-attestation": att,
          "oauth-client-attestation-pop": pop,
        },
        clientId,
        authorizationServerIssuer: AS_ISSUER,
        trustedJwks: { keys: [] },
      });
      expect(r.skip).to.equal(false);
      expect(r.ok).to.equal(true);
      expect(r.attestationPayload.sub).to.equal(clientId);
    });

    it("fails when client_id does not match attestation sub", async () => {
      const { attester, wallet, attesterPub, walletPub } = await mintKeyPairs();
      const att = await signAttestation({
        attesterPrivateKey: attester.privateKey,
        walletPub,
        clientId: "attested-sub",
      });
      const pop = await signPop({ walletPrivateKey: wallet.privateKey, clientId: "attested-sub" });
      const r = await validateOAuthClientAttestationFromRequest({
        headers: {
          "oauth-client-attestation": att,
          "oauth-client-attestation-pop": pop,
        },
        clientId: "different",
        authorizationServerIssuer: AS_ISSUER,
        trustedJwks: { keys: [attesterPub] },
      });
      expect(r.ok).to.equal(false);
      expect(r.oauthError).to.equal("invalid_client");
    });
  });
});
