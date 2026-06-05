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
  isCs01PreAuthorizedDisabled,
  describeCs01GrantPolicy,
  describeSupportedVciGrants,
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

  it("selects authorization_code in CS-01 mode when offer includes it", () => {
    const grants = { authorization_code: { issuer_state: "abc" } };
    expect(selectVciGrantRoute(WALLET_PROFILES.WEBUILD_CS01, grants)).to.equal(
      "authorization_code",
    );
  });

  it("selects pre-authorized_code in CS-01 mode for pre-auth-only offers", () => {
    const grants = {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "session-123",
      },
    };
    expect(selectVciGrantRoute(WALLET_PROFILES.WEBUILD_CS01, grants)).to.equal(
      "pre-authorized_code",
    );
  });

  it("rejects pre-auth-only offers in CS-01 mode when CS01_DISABLE_PRE_AUTHORIZED is set", () => {
    const grants = {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "session-123",
      },
    };
    expect(() =>
      selectVciGrantRoute(WALLET_PROFILES.WEBUILD_CS01, grants, {
        env: { CS01_DISABLE_PRE_AUTHORIZED: "true" },
      }),
    ).to.throw(Cs01ProfileError);
  });

  it("prefers authorization_code when both grants exist in CS-01 mode", () => {
    const grants = {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "session-123",
      },
      authorization_code: { issuer_state: "abc" },
    };
    expect(selectVciGrantRoute(WALLET_PROFILES.WEBUILD_CS01, grants)).to.equal(
      "authorization_code",
    );
  });

  it("rejects unsupported grants in CS-01 mode", () => {
    expect(() => selectVciGrantRoute(WALLET_PROFILES.WEBUILD_CS01, {})).to.throw(Cs01ProfileError);
    expect(() => selectVciGrantRoute(WALLET_PROFILES.WEBUILD_CS01, { client_credentials: {} })).to.throw(
      /no supported grant/,
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

  it("prefers authorization_code when both grants exist in compatibility mode", () => {
    const grants = {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "session-123",
      },
      authorization_code: {},
    };
    expect(selectVciGrantRoute(WALLET_PROFILES.COMPATIBILITY, grants)).to.equal(
      "authorization_code",
    );
  });

  describe("pre-authorized opt-out (Phase 0)", () => {
    it("allows pre-authorized in CS-01 mode unless CS01_DISABLE_PRE_AUTHORIZED is set", () => {
      expect(() =>
        assertPreAuthorizedAllowed(WALLET_PROFILES.WEBUILD_CS01, { endpoint: "/issue" }),
      ).to.not.throw();
      expect(() =>
        assertPreAuthorizedAllowed(WALLET_PROFILES.WEBUILD_CS01, {
          endpoint: "/issue",
          env: { CS01_DISABLE_PRE_AUTHORIZED: "true" },
        }),
      ).to.throw(Cs01ProfileError);
      expect(() =>
        assertPreAuthorizedAllowed(WALLET_PROFILES.COMPATIBILITY, { endpoint: "/issue" }),
      ).to.not.throw();
    });

    it("parses CS01_DISABLE_PRE_AUTHORIZED opt-out flag", () => {
      expect(isCs01PreAuthorizedDisabled({})).to.equal(false);
      expect(isCs01PreAuthorizedDisabled({ CS01_DISABLE_PRE_AUTHORIZED: "" })).to.equal(false);
      expect(isCs01PreAuthorizedDisabled({ CS01_DISABLE_PRE_AUTHORIZED: "true" })).to.equal(true);
      expect(isCs01PreAuthorizedDisabled({ CS01_DISABLE_PRE_AUTHORIZED: "1" })).to.equal(true);
      expect(isCs01PreAuthorizedDisabled({ CS01_DISABLE_PRE_AUTHORIZED: "yes" })).to.equal(true);
      expect(isCs01PreAuthorizedDisabled({ CS01_DISABLE_PRE_AUTHORIZED: "false" })).to.equal(false);
    });

    it("describes supported VCI grants for error messages", () => {
      expect(describeSupportedVciGrants(WALLET_PROFILES.COMPATIBILITY)).to.deep.equal([
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      ]);
      expect(describeSupportedVciGrants(WALLET_PROFILES.WEBUILD_CS01)).to.deep.equal([
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      ]);
      expect(
        describeSupportedVciGrants(WALLET_PROFILES.WEBUILD_CS01, {
          CS01_DISABLE_PRE_AUTHORIZED: "true",
        }),
      ).to.deep.equal(["authorization_code"]);
    });

    it("describes CS-01 grant policy for health and startup logging", () => {
      expect(describeCs01GrantPolicy(WALLET_PROFILES.COMPATIBILITY)).to.deep.equal({
        profile: WALLET_PROFILES.COMPATIBILITY,
        authorizationCodeEnabled: true,
        preAuthorizedEnabled: true,
        preAuthorizedDisabledByEnv: false,
      });
      expect(describeCs01GrantPolicy(WALLET_PROFILES.WEBUILD_CS01)).to.deep.equal({
        profile: WALLET_PROFILES.WEBUILD_CS01,
        authorizationCodeEnabled: true,
        preAuthorizedEnabled: true,
        preAuthorizedDisabledByEnv: false,
        preAuthorizedDisableEnvVar: "CS01_DISABLE_PRE_AUTHORIZED",
      });
      expect(
        describeCs01GrantPolicy(WALLET_PROFILES.WEBUILD_CS01, {
          CS01_DISABLE_PRE_AUTHORIZED: "true",
        }),
      ).to.deep.equal({
        profile: WALLET_PROFILES.WEBUILD_CS01,
        authorizationCodeEnabled: true,
        preAuthorizedEnabled: false,
        preAuthorizedDisabledByEnv: true,
        preAuthorizedDisableEnvVar: "CS01_DISABLE_PRE_AUTHORIZED",
      });
    });
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
