/**
 * WUA enforcement policy and strict WIA/KA validation tests (CS-04 scoped to VerifiablePIDSDJWTWUA).
 */

import { expect } from "chai";
import fs from "fs";
import path from "path";
import * as jose from "jose";
import { randomUUID } from "crypto";
import {
  WUA_REQUIRED_CREDENTIAL_ID,
  isWuaRequiredCredentialId,
  issuanceRequestRequiresWua,
  credentialConfigRequiresKeyAttestation,
  validateKaLevelsAgainstMetadata,
  extractRequestedCredentialConfigurationIds,
} from "../utils/wuaEnforcementPolicy.js";
import {
  CLIENT_ATTESTATION_JWT_TYP,
  CLIENT_ATTESTATION_POP_TYP,
  validateOAuthClientAttestationFromRequest,
  validateWiaStructureClaims,
  computeWiaCnfJkt,
} from "../utils/oauthClientAttestation.js";
import { createPreAuthSessionData, validateWUA } from "../utils/routeUtils.js";

const AS_ISSUER = "http://localhost:3000";
const ALG = "ES256";

async function signSelfContainedWia({ privateKey, publicJwk, clientId = "wua-test-client", clientStatusExpOffsetSeconds = 86400 * 60 }) {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    sub: clientId,
    iat: now,
    exp: now + 3600,
    cnf: { jwk: publicJwk },
    client_status: {
      status: { status_list: { uri: "https://example.com/wia-status", idx: 1 } },
      exp: now + clientStatusExpOffsetSeconds,
    },
  })
    .setProtectedHeader({ alg: ALG, typ: CLIENT_ATTESTATION_JWT_TYP, jwk: publicJwk })
    .sign(privateKey);
}

async function signPop({ walletPrivateKey, clientId, audience = AS_ISSUER }) {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    iss: clientId,
    aud: audience,
    iat: now,
    exp: now + 300,
    jti: randomUUID(),
  })
    .setProtectedHeader({ alg: ALG, typ: CLIENT_ATTESTATION_POP_TYP })
    .sign(walletPrivateKey);
}

async function buildMinimalKa({ privateKey, publicJwk, attestedKeys, includeStatus = true, statusExpOffsetSeconds = 86400 * 60, typ = "key-attestation+jwt" }) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now,
    exp: now + 3600,
    attested_keys: attestedKeys,
    key_storage: ["iso_18045_high"],
    user_authentication: ["iso_18045_high"],
    certification: { scheme: "test" },
  };
  if (includeStatus) {
    payload.key_storage_status = {
      status: { status_list: { uri: "https://example.com/ka-status", idx: 1 } },
      exp: now + statusExpOffsetSeconds,
    };
  }
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg: ALG, typ, jwk: publicJwk })
    .sign(privateKey);
}

describe("WUA enforcement policy", () => {
  it("identifies VerifiablePIDSDJWTWUA as WUA-required", () => {
    expect(isWuaRequiredCredentialId(WUA_REQUIRED_CREDENTIAL_ID)).to.equal(true);
    expect(isWuaRequiredCredentialId("VerifiablePIDSDJWT")).to.equal(false);
  });

  it("detects WUA requirement from scope and authorization_details", () => {
    expect(
      issuanceRequestRequiresWua({ scope: "VerifiablePIDSDJWTWUA openid" })
    ).to.equal(true);
    expect(
      issuanceRequestRequiresWua({
        authorization_details: [
          { credential_configuration_id: WUA_REQUIRED_CREDENTIAL_ID },
        ],
      })
    ).to.equal(true);
    expect(issuanceRequestRequiresWua({ scope: "PID" })).to.equal(false);
  });

  it("extracts credential configuration IDs from mixed inputs", () => {
    const ids = extractRequestedCredentialConfigurationIds({
      scope: "openid VerifiablePIDSDJWTWUA",
      authorization_details: [{ credential_configuration_id: "OtherCred" }],
    });
    expect(ids).to.include("openid");
    expect(ids).to.include("VerifiablePIDSDJWTWUA");
    expect(ids).to.include("OtherCred");
  });

  it("validates KA levels against metadata requirements", () => {
    const credConfig = {
      proof_types_supported: {
        jwt: {
          key_attestations_required: {
            key_storage: ["iso_18045_high"],
            user_authentication: ["iso_18045_high"],
          },
        },
      },
    };
    expect(
      validateKaLevelsAgainstMetadata(
        { key_storage: ["iso_18045_high"], user_authentication: ["iso_18045_high"] },
        credConfig
      ).ok
    ).to.equal(true);
    expect(
      validateKaLevelsAgainstMetadata(
        { key_storage: ["iso_18045_low"], user_authentication: ["iso_18045_high"] },
        credConfig
      ).ok
    ).to.equal(false);
  });

  it("marks pre-auth sessions for WUA-required credential types", () => {
    const wuaSession = createPreAuthSessionData({ credentialType: WUA_REQUIRED_CREDENTIAL_ID });
    expect(wuaSession.requiresWua).to.equal(true);
    expect(wuaSession.credentialConfigurationId).to.equal(WUA_REQUIRED_CREDENTIAL_ID);
    expect(wuaSession.requestedCredentialConfigurationIds).to.include(WUA_REQUIRED_CREDENTIAL_ID);

    const regularSession = createPreAuthSessionData({ credentialType: "VerifiablePIDSDJWT" });
    expect(regularSession.requiresWua).to.not.equal(true);
  });

  it("issuer metadata advertises VerifiablePIDSDJWTWUA with key_attestations_required", () => {
    const cfg = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "data/issuer-config.json"), "utf8")
    );
    const wuaCfg = cfg.credential_configurations_supported[WUA_REQUIRED_CREDENTIAL_ID];
    expect(wuaCfg).to.be.an("object");
    expect(wuaCfg.vct).to.equal(WUA_REQUIRED_CREDENTIAL_ID);
    expect(credentialConfigRequiresKeyAttestation(wuaCfg)).to.equal(true);
    expect(wuaCfg.proof_types_supported.jwt.key_attestations_required.key_storage).to.include(
      "iso_18045_high"
    );
  });
});

describe("strict WIA validation (oauthClientAttestation)", () => {
  it("requireAttestation rejects missing headers", async () => {
    const r = await validateOAuthClientAttestationFromRequest({
      headers: {},
      clientId: "c1",
      authorizationServerIssuer: AS_ISSUER,
      trustedJwks: { keys: [] },
      requireAttestation: true,
      strictWiaSignature: true,
    });
    expect(r.ok).to.equal(false);
    expect(r.oauthError).to.equal("invalid_client");
  });

  it("strict mode accepts self-contained WIA (header.jwk) + PoP", async () => {
    const wallet = await jose.generateKeyPair(ALG, { extractable: true });
    const walletPub = await jose.exportJWK(wallet.publicKey);
    const clientId = "wua-wallet-1";
    const att = await signSelfContainedWia({
      privateKey: wallet.privateKey,
      publicJwk: walletPub,
      clientId,
    });
    const pop = await signPop({ walletPrivateKey: wallet.privateKey, clientId });
    const r = await validateOAuthClientAttestationFromRequest({
      headers: {
        "oauth-client-attestation": att,
        "oauth-client-attestation-pop": pop,
      },
      clientId,
      authorizationServerIssuer: AS_ISSUER,
      trustedJwks: { keys: [] },
      requireAttestation: true,
      strictWiaSignature: true,
    });
    expect(r.ok).to.equal(true);
    expect(r.wiaCnfJkt).to.be.a("string");
    const expected = await computeWiaCnfJkt(walletPub);
    expect(r.wiaCnfJkt).to.equal(expected);
    expect(r.wiaWarnings || []).to.have.length(0);
  });

  it("validateWiaStructureClaims rejects expired client_status", () => {
    const now = Math.floor(Date.now() / 1000);
    expect(() => validateWiaStructureClaims({
      sub: "client-1",
      iat: now - 3600,
      exp: now + 3600,
      cnf: { jwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" } },
      client_status: {
        status: { status_list: { uri: "https://example.com/status", idx: 1 } },
        exp: now - 1,
      },
    }, { requireClientStatus: true })).to.throw(/expired/i);
  });

  it("validateWiaStructureClaims warns when client_status is absent unless required", () => {
    const now = Math.floor(Date.now() / 1000);
    const { warnings } = validateWiaStructureClaims({
      sub: "client-1",
      iat: now,
      exp: now + 3600,
      cnf: { jwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" } },
    });
    expect(warnings.some((w) => /client_status/i.test(w))).to.equal(true);
    expect(() => validateWiaStructureClaims({
      sub: "client-1",
      iat: now,
      exp: now + 3600,
      cnf: { jwk: { kty: "EC", crv: "P-256", x: "abc", y: "def" } },
    }, { requireClientStatus: true })).to.throw(/client_status/i);
  });
});

describe("KA validation (validateWUA)", () => {
  it("rejects KA when key_storage_status is missing", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair(ALG, { extractable: true });
    const pubJwk = await jose.exportJWK(publicKey);
    const holderJwk = await jose.exportJWK(publicKey);
    const ka = await buildMinimalKa({
      privateKey,
      publicJwk: pubJwk,
      attestedKeys: [holderJwk],
      includeStatus: false,
    });
    const result = await validateWUA(ka, null, {});
    expect(result.valid).to.equal(false);
    expect(result.error).to.match(/key_storage_status/i);
  });

  it("rejects KA when key_storage_status is expired", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair(ALG, { extractable: true });
    const pubJwk = await jose.exportJWK(publicKey);
    const holderJwk = await jose.exportJWK(publicKey);
    const ka = await buildMinimalKa({
      privateKey,
      publicJwk: pubJwk,
      attestedKeys: [holderJwk],
      statusExpOffsetSeconds: -1,
    });
    const result = await validateWUA(ka, null, {});
    expect(result.valid).to.equal(false);
    expect(result.error).to.match(/expired/i);
  });

  it("rejects KA with invalid signature", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair(ALG, { extractable: true });
    const { publicKey: otherPub } = await jose.generateKeyPair(ALG, { extractable: true });
    const wrongPubJwk = await jose.exportJWK(otherPub);
    const holderJwk = await jose.exportJWK(publicKey);
    const ka = await buildMinimalKa({
      privateKey,
      publicJwk: wrongPubJwk,
      attestedKeys: [holderJwk],
    });
    const result = await validateWUA(ka, null, {});
    expect(result.valid).to.equal(false);
    expect(result.error).to.match(/signature/i);
  });

  it("rejects KA with unhyphenated typ keyattestation+jwt", async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair(ALG, { extractable: true });
    const pubJwk = await jose.exportJWK(publicKey);
    const holderJwk = await jose.exportJWK(publicKey);
    const ka = await buildMinimalKa({
      privateKey,
      publicJwk: pubJwk,
      attestedKeys: [holderJwk],
      typ: "keyattestation+jwt",
    });
    const result = await validateWUA(ka, null, {});
    expect(result.valid).to.equal(false);
    expect(result.error).to.match(/invalid typ/i);
    expect(result.error).to.match(/key-attestation\+jwt/);
    expect(result.error).to.match(/OpenID4VCI 1\.0 Appendix D\.1/);
    expect(result.error).to.match(/CS-04 Annex A\.2/);
  });
});
