import { expect } from "chai";
import {
  isAuthHandoffEnabled,
  resolveOAuthRedirectUri,
  resolveRedirectUriForFlow,
  resolveAuthHandoffTtlSeconds,
  AuthHandoffConfigError,
} from "../src/lib/authHandoffConfig.js";
import {
  serializePendingContext,
  deserializePendingContext,
  createAuthorizationCodeIssuance,
} from "../src/lib/authorizationCodeIssuance.js";
import {
  issuersMatch,
  renderCallbackHtml,
  pendingKeyForState,
} from "../src/lib/authHandoffStore.js";
import { OPENID4VP_CS02_URI } from "../src/lib/openid4vpUri.js";
import {
  cs01IssuerMetadata,
  cs01AuthorizationServerMetadata,
  CS01_CLIENT_ID,
} from "./fixtures/cs01Fixtures.js";
import { WALLET_PROFILES } from "../src/lib/profile.js";

describe("auth handoff config", () => {
  it("enables handoff from env or request body override", () => {
    expect(isAuthHandoffEnabled({}, {})).to.equal(false);
    expect(isAuthHandoffEnabled({ WALLET_AUTH_HANDOFF: "true" }, {})).to.equal(true);
    expect(isAuthHandoffEnabled({ WALLET_AUTH_HANDOFF: "true" }, { authHandoff: false })).to.equal(
      false,
    );
    expect(isAuthHandoffEnabled({}, { authHandoff: true })).to.equal(true);
  });

  it("resolves HTTPS redirect URI from explicit env or provider URL", () => {
    expect(
      resolveOAuthRedirectUri({
        WALLET_OAUTH_REDIRECT_URI: "https://wallet.example/oauth/callback",
      }),
    ).to.equal("https://wallet.example/oauth/callback");
    expect(
      resolveOAuthRedirectUri({
        WALLET_PROVIDER_URL: "https://host.example/wallet-client",
      }),
    ).to.equal("https://host.example/wallet-client/oauth/callback");
    expect(() => resolveOAuthRedirectUri({})).to.throw(AuthHandoffConfigError);
    expect(() =>
      resolveOAuthRedirectUri({ WALLET_OAUTH_REDIRECT_URI: "http://insecure.example/cb" }),
    ).to.throw(/HTTPS/);
  });

  it("uses openid4vp redirect in blocking mode and HTTPS in handoff mode", () => {
    expect(resolveRedirectUriForFlow({}, false)).to.equal(OPENID4VP_CS02_URI);
    expect(
      resolveRedirectUriForFlow(
        { WALLET_OAUTH_REDIRECT_URI: "https://wallet.example/oauth/callback" },
        true,
      ),
    ).to.equal("https://wallet.example/oauth/callback");
  });

  it("caps handoff TTL by PAR expires_in when present", () => {
    expect(resolveAuthHandoffTtlSeconds({ WALLET_AUTH_HANDOFF_TTL: "600" }, 120)).to.equal(120);
    expect(resolveAuthHandoffTtlSeconds({ WALLET_AUTH_HANDOFF_TTL: "600" }, 900)).to.equal(600);
  });
});

describe("auth handoff pending context", () => {
  it("round-trips attestation challenge through serialize/deserialize", () => {
    const prepared = {
      profile: WALLET_PROFILES.WEBUILD_CS01,
      walletClientId: CS01_CLIENT_ID,
      apiBase: "https://issuer.example.com",
      issuerMeta: cs01IssuerMetadata,
      configurationId: "VerifiableIdCard",
      codeVerifier: "verifier-secret",
      state: "state-123",
      redirectUri: "https://wallet.example/oauth/callback",
      tokenEndpoint: "https://issuer.example.com/token",
      authorizationServerIssuer: "https://issuer.example.com",
      usedPar: true,
      parExpiresIn: 120,
      scopeResolution: { scope: "VerifiableIdCard", source: "configuration" },
      issuanceContext: { configurationId: "VerifiableIdCard" },
      attestationChallengeState: { current: "challenge-abc" },
    };
    const serialized = serializePendingContext(prepared);
    expect(serialized.codeVerifier).to.equal("verifier-secret");
    expect(serialized.attestationChallenge).to.equal("challenge-abc");
    expect(serialized.attestationChallengeState).to.equal(undefined);

    const restored = deserializePendingContext(serialized);
    expect(restored.attestationChallengeState.current).to.equal("challenge-abc");
  });
});

describe("authorization code prepare (handoff)", () => {
  it("returns authorizationUrl without fetching /authorize", async () => {
    const fetchCalls = [];
    const authCode = createAuthorizationCodeIssuance({
      discoverAuthorizationServerMetadata: async () => cs01AuthorizationServerMetadata,
      httpPostFormWithAttestationChallengeRetry: async ({ url }) => ({
        ok: true,
        status: 201,
        parsedBody: { request_uri: "urn:example:par:req-1", expires_in: 300 },
        headers: { get: () => null, entries: () => [] },
        json: async () => ({ request_uri: "urn:example:par:req-1", expires_in: 300 }),
      }),
      httpPostJson: async () => ({ ok: true, json: async () => ({}) }),
      validateAndStoreCredential: async () => {},
      issueCredentialTargets: async () => ({ credentials: [], proofBindings: [] }),
      wrapIssuanceResult: (credential, ctx) => ({ credential, issuanceContext: ctx }),
      sleep: async () => {},
      fetchImpl: async (url, opts) => {
        fetchCalls.push({ url, opts });
        throw new Error("authorize fetch should not run in prepare-only handoff");
      },
    });

    const prepared = await authCode.prepareAuthorization(
      {
        profile: WALLET_PROFILES.WEBUILD_CS01,
        walletClientId: CS01_CLIENT_ID,
        apiBase: cs01IssuerMetadata.credential_issuer,
        issuerMeta: { ...cs01IssuerMetadata },
        offerConfig: null,
        configurationId: "VerifiableIdCard",
        redirectUri: "https://wallet.example/oauth/callback",
      },
      "session-test-1",
    );

    expect(fetchCalls).to.have.length(0);
    expect(prepared.authorizationUrl).to.include("/authorize");
    expect(prepared.authorizationUrl).to.include("request_uri=");
    expect(prepared.state).to.be.a("string").and.not.empty;
    expect(prepared.redirectUri).to.equal("https://wallet.example/oauth/callback");
    expect(prepared.codeVerifier).to.be.a("string").and.not.empty;
  });

  it("completes token exchange using stored verifier", async () => {
    let tokenParams = null;
    const authCode = createAuthorizationCodeIssuance({
      discoverAuthorizationServerMetadata: async () => cs01AuthorizationServerMetadata,
      httpPostFormWithAttestationChallengeRetry: async ({ url, params }) => {
        if (String(url).includes("/token")) {
          tokenParams = params;
          return {
            ok: true,
            status: 200,
            headers: { get: () => null, entries: () => [], updateFromResponse: () => {} },
            json: async () => ({
              access_token: "at",
              token_type: "Bearer",
              c_nonce: "nonce-1",
              authorization_details: [
                {
                  type: "openid_credential",
                  credential_configuration_id: "VerifiableIdCard",
                  credential_identifiers: ["cred-id-1", "cred-id-2"],
                },
              ],
            }),
          };
        }
        return { ok: false, status: 400, text: async () => "unexpected" };
      },
      httpPostJson: async () => ({ ok: true, json: async () => ({}) }),
      validateAndStoreCredential: async () => {},
      issueCredentialTargets: async () => ({
        credentials: [{ credential: "issued" }],
        proofBindings: [{ senderConstraining: "none" }],
      }),
      wrapIssuanceResult: (credential, ctx) => ({ credential, issuanceContext: ctx }),
      sleep: async () => {},
      fetchImpl: async () => {
        throw new Error("fetch should not run when issueCredentialTargets is mocked");
      },
    });

    const pending = deserializePendingContext({
      profile: WALLET_PROFILES.COMPATIBILITY,
      walletClientId: CS01_CLIENT_ID,
      apiBase: cs01IssuerMetadata.credential_issuer,
      issuerMeta: {
        ...cs01IssuerMetadata,
        _authorizationServerMeta: cs01AuthorizationServerMetadata,
      },
      configurationId: "VerifiableIdCard",
      codeVerifier: "stored-verifier",
      state: "state-abc",
      redirectUri: "https://wallet.example/oauth/callback",
      tokenEndpoint: cs01AuthorizationServerMetadata.token_endpoint,
      authorizationServerIssuer: cs01AuthorizationServerMetadata.issuer,
      scopeResolution: { scope: "VerifiableIdCard", source: "configuration" },
      issuanceContext: { configurationId: "VerifiableIdCard" },
      attestationChallenge: null,
    });

    const result = await authCode.completeAuthorization(
      pending,
      { code: "auth-code-1", state: "state-abc" },
      "session-test-2",
    );

    expect(tokenParams.code_verifier).to.equal("stored-verifier");
    expect(tokenParams.redirect_uri).to.equal("https://wallet.example/oauth/callback");
    expect(result).to.have.property("credential");
  });
});

describe("auth handoff store helpers", () => {
  it("matches authorization server issuers by origin", () => {
    expect(
      issuersMatch("https://issuer.example.com", "https://issuer.example.com/oauth"),
    ).to.equal(true);
    expect(issuersMatch("https://issuer.example.com", "https://other.example.com")).to.equal(
      false,
    );
    expect(issuersMatch("https://issuer.example.com", null)).to.equal(true);
  });

  it("renders HTML callback pages without echoing secrets", () => {
    const html = renderCallbackHtml({
      success: true,
      title: "Done",
      message: "Close this tab",
    });
    expect(html).to.include("Done");
    expect(html).to.include("Close this tab");
    expect(html).to.not.include("code=");
  });

  it("builds deterministic pending redis keys", () => {
    expect(pendingKeyForState("abc")).to.equal("wallet:oauth-pending:abc");
  });
});
