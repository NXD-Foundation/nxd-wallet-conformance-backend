import { expect } from "chai";
import { SignJWT, importJWK } from "jose";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import {
  DEFAULT_WALLET_CLIENT_ID,
  ClientIdAttestationMismatchError,
  resolveWalletClientId,
  assertClientIdMatchesAttestationSubject,
  assertOutboundClientIdAligned,
} from "../src/lib/walletClientId.js";

async function signTestJwt(payload) {
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(undefined, "ES256");
  const key = await importJWK(privateJwk, "ES256");
  return new SignJWT(payload).setProtectedHeader({ alg: "ES256", typ: "test+jwt", jwk: publicJwk }).sign(key);
}

describe("wallet-client walletClientId (Phase 4)", () => {
  it("defaults to wallet-client when WALLET_CLIENT_ID is unset", () => {
    expect(resolveWalletClientId({})).to.equal(DEFAULT_WALLET_CLIENT_ID);
    expect(resolveWalletClientId({}, undefined)).to.equal(DEFAULT_WALLET_CLIENT_ID);
  });

  it("reads WALLET_CLIENT_ID from the environment", () => {
    expect(resolveWalletClientId({ WALLET_CLIENT_ID: "wu-test-instance-01" })).to.equal(
      "wu-test-instance-01",
    );
  });

  it("prefers an explicit override over the environment", () => {
    expect(resolveWalletClientId({ WALLET_CLIENT_ID: "from-env" }, "from-override")).to.equal(
      "from-override",
    );
  });

  it("ignores blank overrides and falls back to the default client_id", () => {
    expect(resolveWalletClientId({}, "   ")).to.equal(DEFAULT_WALLET_CLIENT_ID);
    expect(resolveWalletClientId({ WALLET_CLIENT_ID: "" })).to.equal(DEFAULT_WALLET_CLIENT_ID);
  });

  it("accepts matching client_id and attestation subject", () => {
    expect(() =>
      assertClientIdMatchesAttestationSubject("wallet-client", "wallet-client"),
    ).to.not.throw();
  });

  it("rejects client_id mismatch with attestation subject", () => {
    expect(() =>
      assertClientIdMatchesAttestationSubject("wallet-client", "other-subject"),
    ).to.throw(ClientIdAttestationMismatchError);
  });

  it("validates outbound alignment between client_id and attestation headers", async () => {
    const clientId = "wu-aligned-42";
    const attestationJwt = await signTestJwt({ sub: clientId, iss: "attester.example" });
    const popJwt = await signTestJwt({ iss: clientId, aud: "https://as.example.com" });

    expect(() =>
      assertOutboundClientIdAligned({ clientId, attestationJwt, popJwt }),
    ).to.not.throw();
  });

  it("rejects misaligned outbound client_id before request dispatch", async () => {
    const attestationJwt = await signTestJwt({ sub: "attested-subject", iss: "attester.example" });
    const popJwt = await signTestJwt({ iss: "attested-subject", aud: "https://as.example.com" });

    expect(() =>
      assertOutboundClientIdAligned({
        clientId: "different-client-id",
        attestationJwt,
        popJwt,
      }),
    ).to.throw(/does not match Wallet Unit Attestation sub/);
  });
});
