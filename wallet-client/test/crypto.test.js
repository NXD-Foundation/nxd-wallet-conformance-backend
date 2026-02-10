import { expect } from "chai";
import {
  ensureOrCreateEcKeyPair,
  createDPoP,
  createWUA,
  createProofJwt,
} from "../src/lib/crypto.js";
import { decodeProtectedHeader, decodeJwt } from "jose";

describe("wallet-client crypto building blocks", () => {
  it("createWUA MUST use typ key-attestation+jwt", async () => {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(undefined, "ES256");

    const issuer = "did:example:wallet";
    const audience = "https://issuer.example.com/credential";

    const wuaJwt = await createWUA({
      privateJwk,
      publicJwk,
      issuer,
      audience,
      attestedKeys: [publicJwk],
      eudiWalletInfo: {
        general_info: { name: "Test Wallet", version: "1.0.0" },
        key_storage_info: { storage_type: "software", protection_level: "software" },
      },
    });

    const header = decodeProtectedHeader(wuaJwt);
    const payload = decodeJwt(wuaJwt);

    expect(header).to.have.property("typ", "key-attestation+jwt");
    expect(header).to.have.property("jwk");
    expect(payload).to.have.property("iss", issuer);
    expect(payload).to.have.property("aud", audience);
    expect(payload).to.have.property("attested_keys");
  });

  it("createDPoP MUST use typ dpop+jwt and include htm/htu", async () => {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(undefined, "ES256");

    const htu = "https://issuer.example.com/token_endpoint";
    const htm = "POST";

    const dpopJwt = await createDPoP({
      privateJwk,
      publicJwk,
      htu,
      htm,
      alg: "ES256",
    });

    const header = decodeProtectedHeader(dpopJwt);
    const payload = decodeJwt(dpopJwt);

    expect(header).to.have.property("typ", "dpop+jwt");
    expect(header).to.have.property("jwk");
    expect(payload).to.have.property("htu");
    expect(payload).to.have.property("htm");
    expect(payload.htm).to.equal(htm);
  });

  it("createDPoP MUST include ath claim when provided (for credential requests)", async () => {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(undefined, "ES256");

    const htu = "https://issuer.example.com/credential";
    const htm = "POST";
    const ath = "test-access-token-hash";

    const dpopJwt = await createDPoP({
      privateJwk,
      publicJwk,
      htu,
      htm,
      ath,
      alg: "ES256",
    });

    const payload = decodeJwt(dpopJwt);
    expect(payload).to.have.property("ath", ath);
  });

  it("createProofJwt MUST set key_attestation header when provided", async () => {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(undefined, "ES256");

    const dummyKeyAttestation = "dummy-wua-jwt";
    const aud = "https://issuer.example.com/credential";
    const nonce = "test-nonce";
    const issuer = "did:jwk:example";

    const proofJwt = await createProofJwt({
      privateJwk,
      publicJwk,
      audience: aud,
      nonce,
      issuer,
      typ: "openid4vci-proof+jwt",
      alg: "ES256",
      key_attestation: dummyKeyAttestation,
    });

    const header = decodeProtectedHeader(proofJwt);
    const payload = decodeJwt(proofJwt);

    expect(header).to.have.property("typ", "openid4vci-proof+jwt");
    expect(header).to.have.property("key_attestation", dummyKeyAttestation);
    expect(payload).to.have.property("aud", aud);
    expect(payload).to.have.property("nonce", nonce);
  });
});

