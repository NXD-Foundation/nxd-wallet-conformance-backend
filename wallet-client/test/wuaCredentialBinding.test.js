import { expect } from "chai";
import fs from "fs";
import os from "os";
import path from "path";
import { decodeJwt, decodeProtectedHeader } from "jose";
import {
  ensureOrCreateEcKeyPair,
  createWUA,
  createProofJwt,
  generateDidJwkFromPrivateJwk,
} from "../src/lib/crypto.js";
import { buildCredentialRequestProofs } from "../src/lib/credentialRequestProofs.js";
import {
  publicJwksMatch,
  validateWuaMatchesAttestedKeyPairs,
  validateCredentialProofsBeforeDispatch,
} from "../src/lib/wuaCredentialBinding.js";

describe("WUA credential binding (RFC001 Phase 5)", () => {
  let tmpKey;
  const saved = {};

  beforeEach(() => {
    for (const k of ["WALLET_PROVIDER_KEY_PATH", "WALLET_PROVIDER_ID", "WALLET_INSTANCE_ID", "WALLET_USE_EXTERNAL_ATTESTATION"]) {
      saved[k] = process.env[k];
    }
    tmpKey = path.join(os.tmpdir(), `wp-ec-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    process.env.WALLET_PROVIDER_KEY_PATH = tmpKey;
    process.env.WALLET_PROVIDER_ID = "did:example:wallet-provider";
    process.env.WALLET_INSTANCE_ID = "11111111-1111-1111-1111-111111111111";
    delete process.env.WALLET_USE_EXTERNAL_ATTESTATION;
  });

  afterEach(() => {
    try {
      fs.unlinkSync(tmpKey);
    } catch {
      // ignore
    }
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  async function makeKeyPair() {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(undefined, "ES256");
    return { privateJwk, publicJwk, didJwk: generateDidJwkFromPrivateJwk(publicJwk) };
  }

  it("buildCredentialRequestProofs (jwt): one proof, WUA in key_attestation, signed with first key", async () => {
    const kp = await makeKeyPair();
    const { proofs, proofJwt, wuaJwt } = await buildCredentialRequestProofs({
      proofMode: "jwt",
      credentialEndpoint: "https://issuer.example/credential",
      aud: "https://issuer.example",
      c_nonce: "nonce-1",
      keyPairs: [kp],
      selectedAlg: "ES256",
    });
    expect(proofs.jwt).to.have.length(1);
    expect(proofs.jwt[0]).to.equal(proofJwt);
    const h = decodeProtectedHeader(proofJwt);
    expect(h.key_attestation).to.equal(wuaJwt);
    const wua = decodeJwt(wuaJwt);
    expect(wua.attested_keys).to.have.length(1);
    expect(wua.nonce).to.equal("nonce-1");
    expect(await publicJwksMatch(wua.attested_keys[0], kp.publicJwk)).to.equal(true);
  });

  it("buildCredentialRequestProofs (attestation): exactly one WUA", async () => {
    const kp = await makeKeyPair();
    const { proofs, proofJwt } = await buildCredentialRequestProofs({
      proofMode: "attestation",
      credentialEndpoint: "https://issuer.example/credential",
      aud: "https://issuer.example",
      c_nonce: "nonce-1",
      keyPairs: [kp],
      selectedAlg: "ES256",
    });
    expect(proofJwt).to.equal(null);
    expect(proofs.attestation).to.have.length(1);
    expect(decodeProtectedHeader(proofs.attestation[0]).typ).to.equal("key-attestation+jwt");
  });

  it("preserves multi-key attested_keys order", async () => {
    const a = await makeKeyPair();
    const b = await makeKeyPair();
    const { wuaJwt } = await buildCredentialRequestProofs({
      proofMode: "attestation",
      credentialEndpoint: "https://issuer.example/credential",
      aud: "https://issuer.example",
      c_nonce: "n",
      keyPairs: [a, b],
      selectedAlg: "ES256",
    });
    const wua = decodeJwt(wuaJwt);
    expect(wua.attested_keys).to.have.length(2);
    expect(await publicJwksMatch(wua.attested_keys[0], a.publicJwk)).to.equal(true);
    expect(await publicJwksMatch(wua.attested_keys[1], b.publicJwk)).to.equal(true);
  });

  it("rejects WUA when attested_keys[0] does not match proof key", async () => {
    const kp = await makeKeyPair();
    const other = await makeKeyPair();
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(tmpKey, "ES256");
    const wuaJwt = await createWUA({
      privateJwk,
      publicJwk,
      issuer: "did:example:provider",
      audience: "https://issuer.example/credential",
      attestedKeys: [other.publicJwk],
      eudiWalletInfo: {
        general_info: { name: "t", version: "1" },
        key_storage_info: { storage_type: "software", protection_level: "software" },
      },
    });
    let err = null;
    try {
      await validateWuaMatchesAttestedKeyPairs(wuaJwt, [kp]);
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect(String(err.message)).to.match(/attested_keys\[0\]/);
  });

  it("rejects WUA when c_nonce does not match WUA nonce", async () => {
    const kp = await makeKeyPair();
    const { wuaJwt } = await buildCredentialRequestProofs({
      proofMode: "attestation",
      credentialEndpoint: "https://issuer.example/credential",
      aud: "https://issuer.example",
      c_nonce: "expected-nonce",
      keyPairs: [kp],
      selectedAlg: "ES256",
    });
    let err = null;
    try {
      await validateCredentialProofsBeforeDispatch({
        proofMode: "attestation",
        proofs: { attestation: [wuaJwt] },
        wuaJwt,
        keyPairs: [kp],
        expectedCNonce: "other-nonce",
      });
    } catch (e) {
      err = e;
    }
    expect(String(err?.message || "")).to.match(/c_nonce/);
  });

  it("rejects proofs.jwt without key_attestation", async () => {
    const kp = await makeKeyPair();
    const proofJwt = await createProofJwt({
      privateJwk: kp.privateJwk,
      publicJwk: kp.publicJwk,
      audience: "https://issuer.example",
      nonce: "n",
      issuer: kp.didJwk,
      typ: "openid4vci-proof+jwt",
      alg: "ES256",
    });
    let err = null;
    try {
      await validateCredentialProofsBeforeDispatch({
        proofMode: "jwt",
        proofs: { jwt: [proofJwt] },
        wuaJwt: "dummy.wua",
        keyPairs: [kp],
      });
    } catch (e) {
      err = e;
    }
    expect(String(err?.message || "")).to.match(/key_attestation/);
  });
});
