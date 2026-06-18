import { expect } from "chai";
import { calculateJwkThumbprint } from "jose";
import {
  DpopRequiredError,
  isSenderConstrainingMandatory,
  assertDpopBoundTokenReceived,
  assertDpopHeaderOnRequest,
  assertDpopJwtPresent,
  shouldUseDpopForResourceRequest,
  createTokenRequestDpopBinding,
  assertAccessTokenCnfMatchesWia,
} from "../src/lib/dpopBinding.js";
import { ensureOrCreateEcKeyPair } from "../src/lib/crypto.js";
import { WALLET_PROFILES } from "../src/lib/profile.js";

describe("wallet-client dpopBinding (Phase 6)", () => {
  it("requires sender-constraining only in CS-01 mode", () => {
    expect(isSenderConstrainingMandatory(WALLET_PROFILES.WEBUILD_CS01)).to.equal(true);
    expect(isSenderConstrainingMandatory(WALLET_PROFILES.COMPATIBILITY)).to.equal(false);
  });

  it("requires DPoP proof presence at token request in CS-01 mode", () => {
    expect(() =>
      assertDpopJwtPresent(WALLET_PROFILES.WEBUILD_CS01, null, { stage: "token request" }),
    ).to.throw(DpopRequiredError);
    expect(() =>
      assertDpopJwtPresent(WALLET_PROFILES.COMPATIBILITY, null, { stage: "token request" }),
    ).to.not.throw();
  });

  it("requires DPoP-bound access token in CS-01 mode", () => {
    expect(() =>
      assertDpopBoundTokenReceived(
        WALLET_PROFILES.WEBUILD_CS01,
        { token_type: "Bearer", access_token: "opaque-token" },
        "opaque-token",
      ),
    ).to.throw(/not DPoP-bound/);

    expect(() =>
      assertDpopBoundTokenReceived(
        WALLET_PROFILES.WEBUILD_CS01,
        { token_type: "DPoP", access_token: "opaque-token" },
        "opaque-token",
      ),
    ).to.not.throw();
  });

  it("requires DPoP header on resource requests in CS-01 mode", () => {
    expect(() =>
      assertDpopHeaderOnRequest(WALLET_PROFILES.WEBUILD_CS01, null, {
        stage: "credential request",
      }),
    ).to.throw(/credential request/);
  });

  it("uses DPoP for resource requests in CS-01 even before inspecting token shape", () => {
    expect(
      shouldUseDpopForResourceRequest(
        WALLET_PROFILES.WEBUILD_CS01,
        { token_type: "Bearer" },
        "opaque",
      ),
    ).to.equal(true);
  });

  it("uses DPoP for compatibility mode only when token is DPoP-bound", () => {
    expect(
      shouldUseDpopForResourceRequest(
        WALLET_PROFILES.COMPATIBILITY,
        { token_type: "DPoP" },
        "opaque",
      ),
    ).to.equal(true);
    expect(
      shouldUseDpopForResourceRequest(
        WALLET_PROFILES.COMPATIBILITY,
        { token_type: "Bearer" },
        "opaque",
      ),
    ).to.equal(false);
  });

  it("can create token DPoP from the WIA cnf keypair", async () => {
    const cnfKeyPair = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const binding = await createTokenRequestDpopBinding({
      tokenEndpoint: "https://issuer.example.com/token",
      profile: WALLET_PROFILES.WEBUILD_CS01,
      cnfKeyPair,
    });
    expect(binding.publicJwk).to.deep.equal(cnfKeyPair.publicJwk);
    expect(binding.privateJwk).to.deep.equal(cnfKeyPair.privateJwk);
    expect(binding.dpopJwt).to.be.a("string");
  });

  it("verifies JWT access-token cnf.jkt against the WIA cnf key", async () => {
    const cnfKeyPair = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const jkt = await calculateJwkThumbprint(cnfKeyPair.publicJwk, "sha256");
    const token = minimalJwt({ cnf: { jkt } });
    await assertAccessTokenCnfMatchesWia(WALLET_PROFILES.WEBUILD_CS01, token, cnfKeyPair.publicJwk);
  });

  it("rejects JWT access-token cnf.jkt mismatch in CS-01 mode", async () => {
    const cnfKeyPair = await ensureOrCreateEcKeyPair(undefined, "ES256");
    const token = minimalJwt({ cnf: { jkt: "different-thumbprint" } });
    try {
      await assertAccessTokenCnfMatchesWia(WALLET_PROFILES.WEBUILD_CS01, token, cnfKeyPair.publicJwk);
      expect.fail("expected cnf.jkt mismatch to throw");
    } catch (error) {
      expect(error).to.be.instanceOf(DpopRequiredError);
      expect(error.message).to.match(/cnf\.jkt/);
    }
  });
});

function minimalJwt(payload) {
  const enc = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${enc({ alg: "none" })}.${enc(payload)}.signature`;
}
