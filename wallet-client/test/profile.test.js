import { expect } from "chai";
import {
  WALLET_PROFILES,
  Cs01ProfileError,
  ParRequiredError,
  normalizeWalletProfile,
  resolveWalletProfile,
  isWebuildCs01Profile,
  assertCs01AuthorizationCodeGrant,
  assertPreAuthorizedAllowed,
  selectVciGrantRoute,
  isParMandatory,
  assertParEndpointAvailable,
  assertParResponse,
  assertNoDirectAuthorizationFallback,
} from "../src/lib/profile.js";

describe("wallet-client profile (WE BUILD CS-01 Phase 1)", () => {
  it("defaults to compatibility when WALLET_PROFILE is unset", () => {
    expect(resolveWalletProfile({})).to.equal(WALLET_PROFILES.COMPATIBILITY);
    expect(normalizeWalletProfile(undefined)).to.equal(WALLET_PROFILES.COMPATIBILITY);
    expect(normalizeWalletProfile("default")).to.equal(WALLET_PROFILES.COMPATIBILITY);
  });

  it("accepts webuild-cs01 and cs01 aliases", () => {
    expect(normalizeWalletProfile("webuild-cs01")).to.equal(WALLET_PROFILES.WEBUILD_CS01);
    expect(normalizeWalletProfile("cs01")).to.equal(WALLET_PROFILES.WEBUILD_CS01);
    expect(resolveWalletProfile({ WALLET_PROFILE: "webuild-cs01" })).to.equal(
      WALLET_PROFILES.WEBUILD_CS01,
    );
  });

  it("rejects unknown profile values", () => {
    expect(() => normalizeWalletProfile("unknown-profile")).to.throw(/Unknown WALLET_PROFILE/);
  });

  it("selects authorization_code only in CS-01 mode", () => {
    const grants = { authorization_code: { issuer_state: "abc" } };
    expect(selectVciGrantRoute(WALLET_PROFILES.WEBUILD_CS01, grants)).to.equal(
      "authorization_code",
    );
  });

  it("rejects pre-authorized offers in CS-01 mode", () => {
    const grants = {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "session-123",
      },
    };
    expect(() => selectVciGrantRoute(WALLET_PROFILES.WEBUILD_CS01, grants)).to.throw(
      Cs01ProfileError,
    );
  });

  it("keeps pre-authorized routing in compatibility mode", () => {
    const grants = {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "session-123",
      },
    };
    expect(selectVciGrantRoute(WALLET_PROFILES.COMPATIBILITY, grants)).to.equal(
      "pre-authorized_code",
    );
  });

  it("keeps authorization_code routing in compatibility mode", () => {
    const grants = { authorization_code: {} };
    expect(selectVciGrantRoute(WALLET_PROFILES.COMPATIBILITY, grants)).to.equal(
      "authorization_code",
    );
  });

  it("prefers pre-authorized when both grants exist in compatibility mode", () => {
    const grants = {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "session-123",
      },
      authorization_code: {},
    };
    expect(selectVciGrantRoute(WALLET_PROFILES.COMPATIBILITY, grants)).to.equal(
      "pre-authorized_code",
    );
  });

  it("blocks direct pre-authorized issuance helpers in CS-01 mode", () => {
    expect(() =>
      assertPreAuthorizedAllowed(WALLET_PROFILES.WEBUILD_CS01, { endpoint: "/issue" }),
    ).to.throw(Cs01ProfileError);
    expect(() =>
      assertPreAuthorizedAllowed(WALLET_PROFILES.COMPATIBILITY, { endpoint: "/issue" }),
    ).to.not.throw();
  });

  it("requires authorization_code grant metadata in CS-01 mode", () => {
    expect(() =>
      assertCs01AuthorizationCodeGrant({}, { endpoint: "/session" }),
    ).to.throw(/authorization_code grant/);
    expect(isWebuildCs01Profile(WALLET_PROFILES.WEBUILD_CS01)).to.equal(true);
    expect(isWebuildCs01Profile(WALLET_PROFILES.COMPATIBILITY)).to.equal(false);
  });

  describe("PAR mandatory (Phase 2)", () => {
    it("treats PAR as mandatory in CS-01 mode", () => {
      expect(isParMandatory(WALLET_PROFILES.WEBUILD_CS01, false)).to.equal(true);
      expect(isParMandatory(WALLET_PROFILES.COMPATIBILITY, false)).to.equal(false);
      expect(isParMandatory(WALLET_PROFILES.COMPATIBILITY, true)).to.equal(true);
    });

    it("rejects missing PAR endpoint in CS-01 mode", () => {
      expect(() =>
        assertParEndpointAvailable(WALLET_PROFILES.WEBUILD_CS01, null),
      ).to.throw(ParRequiredError);
      expect(() =>
        assertParEndpointAvailable(WALLET_PROFILES.COMPATIBILITY, null),
      ).to.not.throw();
    });

    it("rejects failed PAR responses in CS-01 mode", () => {
      expect(() =>
        assertParResponse(WALLET_PROFILES.WEBUILD_CS01, {
          ok: false,
          status: 400,
          requestUri: null,
          responseBody: "invalid_client",
        }),
      ).to.throw(/PAR request failed with status 400/);
      expect(() =>
        assertParResponse(WALLET_PROFILES.WEBUILD_CS01, {
          ok: true,
          status: 201,
          requestUri: null,
        }),
      ).to.throw(/missing request_uri/);
    });

    it("allows failed PAR to fall through in compatibility mode when AS does not require PAR", () => {
      expect(() =>
        assertParResponse(WALLET_PROFILES.COMPATIBILITY, {
          ok: false,
          status: 400,
          requestUri: null,
        }),
      ).to.not.throw();
    });

    it("rejects direct authorization fallback in CS-01 mode", () => {
      expect(() =>
        assertNoDirectAuthorizationFallback(WALLET_PROFILES.WEBUILD_CS01, false),
      ).to.throw(/direct front-channel authorization is not permitted/);
      expect(() =>
        assertNoDirectAuthorizationFallback(WALLET_PROFILES.WEBUILD_CS01, true),
      ).to.not.throw();
      expect(() =>
        assertNoDirectAuthorizationFallback(WALLET_PROFILES.COMPATIBILITY, false),
      ).to.not.throw();
    });
  });
});
