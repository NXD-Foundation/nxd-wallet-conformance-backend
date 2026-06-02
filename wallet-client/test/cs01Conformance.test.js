import { expect } from "chai";
import { decodeProtectedHeader } from "jose";
import { createPkcePair } from "../src/lib/crypto.js";
import { WALLET_PROFILES, Cs01ProfileError, ParRequiredError, selectVciGrantRoute, assertPreAuthorizedAllowed, assertParEndpointAvailable, assertParResponse, assertNoDirectAuthorizationFallback } from "../src/lib/profile.js";
import { resolveCredentialScope, ScopeResolutionError } from "../src/lib/scopeResolution.js";
import { ClientIdAttestationMismatchError, assertOutboundClientIdAligned } from "../src/lib/walletClientId.js";
import { DpopRequiredError, createTokenRequestDpopBinding, assertDpopJwtPresent, createResourceRequestDpopProof } from "../src/lib/dpopBinding.js";
import { createWalletUnitAttestationClientAuth, createLegacyBodyClientAssertionJwt, allowsLegacyBodyClientAssertion } from "../src/lib/walletUnitAttestation.js";
import {
  buildCredentialProofRequest,
  buildCredentialProofBindingContext,
  buildDeferredCredentialPollRequest,
  resolveWalletUnitSubjectKey,
} from "../src/lib/credentialProofBinding.js";
import {
  Cs01ConformanceError,
  assertCs01ParRequestContract,
  assertCs01TokenRequestContract,
  assertCs01CredentialRequestContract,
  assertCs01DeferredRequestContract,
  assertCs01NoBodyClientAssertion,
  buildParAuthorizeUrl,
  compatibilityAllowsBodyClientAssertion,
} from "../src/lib/cs01Conformance.js";
import {
  CS01_CLIENT_ID,
  cs01IssuerMetadata,
  cs01AuthorizationServerMetadata,
  cs01AuthorizationServerMetadataWithoutPar,
  cs01IssuerInitiatedOffer,
  cs01WalletInitiatedOffer,
  cs01PreAuthorizedOffer,
  cs01UnscopedOffer,
  cs01ParSuccessResponse,
  cs01DpopTokenResponse,
  cs01DeferredAcceptedResponse,
} from "./fixtures/cs01Fixtures.js";

const CS01 = WALLET_PROFILES.WEBUILD_CS01;
const COMPAT = WALLET_PROFILES.COMPATIBILITY;

describe("WE BUILD CS-01 conformance suite (Phase 10)", () => {
  describe("success paths", () => {
    it("issuer-initiated authorization-code issuance via Credential Offer", () => {
      const route = selectVciGrantRoute(CS01, cs01IssuerInitiatedOffer.grants);
      expect(route).to.equal("authorization_code");

      const scope = resolveCredentialScope({
        profile: CS01,
        configurationId: "VerifiableIdCard",
        issuerMeta: cs01IssuerMetadata,
        offerConfig: cs01IssuerInitiatedOffer,
        scopesSupported: cs01AuthorizationServerMetadata.scopes_supported,
      });
      expect(scope.scope).to.equal("VerifiableIdCard");
      expect(scope.source).to.equal("offer+metadata");
    });

    it("wallet-initiated issuance resolves scope from issuer metadata", () => {
      const route = selectVciGrantRoute(CS01, cs01WalletInitiatedOffer.grants);
      expect(route).to.equal("authorization_code");

      const scope = resolveCredentialScope({
        profile: CS01,
        configurationId: "VerifiableIdCard",
        issuerMeta: cs01IssuerMetadata,
        offerConfig: cs01WalletInitiatedOffer,
        scopesSupported: cs01AuthorizationServerMetadata.scopes_supported,
      });
      expect(scope.scope).to.equal("VerifiableIdCard");
      expect(scope.source).to.equal("metadata");
    });

    it("PAR success uses Wallet Unit Attestation headers only", async () => {
      const pkce = createPkcePair();
      const scope = resolveCredentialScope({
        profile: CS01,
        configurationId: "VerifiableIdCard",
        issuerMeta: cs01IssuerMetadata,
        offerConfig: cs01IssuerInitiatedOffer,
        scopesSupported: cs01AuthorizationServerMetadata.scopes_supported,
      });
      const parParams = {
        response_type: "code",
        client_id: CS01_CLIENT_ID,
        scope: scope.scope,
        code_challenge: pkce.codeChallenge,
        code_challenge_method: pkce.codeChallengeMethod,
        redirect_uri: "openid4vp://",
        state: "state-123",
      };
      const attestation = await createWalletUnitAttestationClientAuth({
        profile: CS01,
        keyPath: undefined,
        clientId: CS01_CLIENT_ID,
        endpointAudience: cs01AuthorizationServerMetadata.pushed_authorization_request_endpoint,
        authorizationServerIssuer: cs01AuthorizationServerMetadata.issuer,
        stage: "PAR",
      });

      assertCs01ParRequestContract({
        profile: CS01,
        parParams,
        attestationHeaders: attestation.headers,
        usedPar: true,
      });
      expect(allowsLegacyBodyClientAssertion(CS01)).to.equal(false);
    });

    it("token redemption uses PKCE, DPoP, and Wallet Unit Attestation", async () => {
      const pkce = createPkcePair();
      const dpopBinding = await createTokenRequestDpopBinding({
        keyPath: undefined,
        tokenEndpoint: cs01AuthorizationServerMetadata.token_endpoint,
        profile: CS01,
      });
      const attestation = await createWalletUnitAttestationClientAuth({
        profile: CS01,
        keyPath: undefined,
        clientId: CS01_CLIENT_ID,
        endpointAudience: cs01AuthorizationServerMetadata.token_endpoint,
        authorizationServerIssuer: cs01AuthorizationServerMetadata.issuer,
        stage: "Token",
      });
      const tokenParams = {
        grant_type: "authorization_code",
        code: "auth-code-123",
        code_verifier: pkce.codeVerifier,
        client_id: CS01_CLIENT_ID,
        redirect_uri: "openid4vp://",
      };

      assertCs01TokenRequestContract({
        profile: CS01,
        tokenParams,
        attestationHeaders: attestation.headers,
        dpopJwt: dpopBinding.dpopJwt,
        tokenBody: cs01DpopTokenResponse,
        accessToken: cs01DpopTokenResponse.access_token,
      });
    });

    it("credential request includes JWT proof bound to Wallet Unit subject key", async () => {
      const dpopBinding = await createTokenRequestDpopBinding({
        keyPath: undefined,
        tokenEndpoint: cs01AuthorizationServerMetadata.token_endpoint,
        profile: CS01,
      });
      const proofBundle = await buildCredentialProofRequest({
        profile: CS01,
        keyPath: undefined,
        issuerMeta: cs01IssuerMetadata,
        apiBase: cs01IssuerMetadata.credential_issuer,
        configurationId: "VerifiableIdCard",
        cNonce: cs01DpopTokenResponse.c_nonce,
        credentialEndpoint: cs01IssuerMetadata.credential_endpoint,
      });
      const proofBinding = buildCredentialProofBindingContext({
        profile: CS01,
        subjectKey: proofBundle.subjectKey,
        dpopBinding,
        tokenBody: cs01DpopTokenResponse,
        accessToken: cs01DpopTokenResponse.access_token,
        keyAttestation: proofBundle.keyAttestation,
      });
      const credentialDpop = await import("../src/lib/dpopBinding.js").then((m) =>
        m.createResourceRequestDpopProof({
          binding: dpopBinding,
          tokenBody: cs01DpopTokenResponse,
          accessToken: cs01DpopTokenResponse.access_token,
          htu: cs01IssuerMetadata.credential_endpoint,
          profile: CS01,
          stage: "credential request",
        }),
      );

      assertCs01CredentialRequestContract({
        profile: CS01,
        credentialRequest: proofBundle.credentialRequest,
        headers: {
          authorization: `Bearer ${cs01DpopTokenResponse.access_token}`,
          DPoP: credentialDpop,
        },
        proofBinding,
      });

      const header = decodeProtectedHeader(proofBundle.proofJwt);
      expect(header.typ).to.equal("openid4vci-proof+jwt");
      expect(header).to.have.property("key_attestation");
    });

    it("deferred issuance polls with transaction_id and retained sender context", async () => {
      const subjectKey = await resolveWalletUnitSubjectKey({ keyPath: undefined, proofAlg: "ES256" });
      const dpopBinding = await createTokenRequestDpopBinding({
        keyPath: undefined,
        tokenEndpoint: cs01AuthorizationServerMetadata.token_endpoint,
        profile: CS01,
      });
      const poll = await buildDeferredCredentialPollRequest({
        profile: CS01,
        dpopBinding,
        tokenBody: cs01DpopTokenResponse,
        accessToken: cs01DpopTokenResponse.access_token,
        subjectKey,
        deferredEndpoint: cs01IssuerMetadata.credential_deferred_endpoint,
        transactionId: cs01DeferredAcceptedResponse.transaction_id,
      });

      assertCs01DeferredRequestContract({ profile: CS01, pollRequest: poll });
      expect(poll.body.transaction_id).to.equal(cs01DeferredAcceptedResponse.transaction_id);
    });

    it("builds front-channel authorize URL from PAR request_uri only", () => {
      const url = buildParAuthorizeUrl(
        cs01AuthorizationServerMetadata.authorization_endpoint,
        CS01_CLIENT_ID,
        cs01ParSuccessResponse.request_uri,
      );
      const parsed = new URL(url);
      expect(parsed.searchParams.get("client_id")).to.equal(CS01_CLIENT_ID);
      expect(parsed.searchParams.get("request_uri")).to.equal(cs01ParSuccessResponse.request_uri);
      expect(parsed.searchParams.has("scope")).to.equal(false);
    });
  });

  describe("failure paths", () => {
    it("rejects missing PAR endpoint in CS-01 mode", () => {
      expect(() =>
        assertParEndpointAvailable(CS01, null),
      ).to.throw(ParRequiredError);
    });

    it("rejects PAR failure without fallback in CS-01 mode", () => {
      expect(() =>
        assertParResponse(CS01, { ok: false, status: 400, requestUri: null, responseBody: "invalid_client" }),
      ).to.throw(ParRequiredError);
      expect(() =>
        assertNoDirectAuthorizationFallback(CS01, false),
      ).to.throw(/direct front-channel authorization is not permitted/);
    });

    it("rejects client_id mismatch with attestation subject", async () => {
      const attestation = await createWalletUnitAttestationClientAuth({
        profile: CS01,
        keyPath: undefined,
        clientId: CS01_CLIENT_ID,
        endpointAudience: cs01AuthorizationServerMetadata.token_endpoint,
        authorizationServerIssuer: cs01AuthorizationServerMetadata.issuer,
      });
      expect(() =>
        assertOutboundClientIdAligned({
          clientId: "different-client-id",
          attestationJwt: attestation.headers["OAuth-Client-Attestation"],
          popJwt: attestation.headers["OAuth-Client-Attestation-PoP"],
        }),
      ).to.throw(ClientIdAttestationMismatchError);
    });

    it("rejects missing DPoP proof at token request in CS-01 mode", () => {
      expect(() =>
        assertDpopJwtPresent(CS01, null, { stage: "token request" }),
      ).to.throw(DpopRequiredError);
    });

    it("rejects DPoP generation failure in CS-01 mode", async () => {
      try {
        await createResourceRequestDpopProof({
          binding: {},
          tokenBody: cs01DpopTokenResponse,
          accessToken: cs01DpopTokenResponse.access_token,
          htu: cs01IssuerMetadata.credential_endpoint,
          profile: CS01,
          stage: "credential request",
        });
        expect.fail("expected DPoP generation to fail in CS-01 mode");
      } catch (error) {
        expect(error).to.be.instanceOf(DpopRequiredError);
        expect(error.message).to.match(/key material is missing|generation failed/);
      }
    });

    it("rejects missing scope mapping in CS-01 mode", () => {
      expect(() =>
        resolveCredentialScope({
          profile: CS01,
          configurationId: "UnscopedCredential",
          issuerMeta: cs01IssuerMetadata,
          offerConfig: cs01UnscopedOffer,
          scopesSupported: cs01AuthorizationServerMetadata.scopes_supported,
        }),
      ).to.throw(ScopeResolutionError);
    });

    it("rejects attempted pre-authorized flow in CS-01 mode", () => {
      expect(() => selectVciGrantRoute(CS01, cs01PreAuthorizedOffer.grants)).to.throw(Cs01ProfileError);
      expect(() =>
        assertPreAuthorizedAllowed(CS01, { endpoint: "/issue" }),
      ).to.throw(Cs01ProfileError);
    });

    it("rejects accidental body client_assertion in CS-01 mode", () => {
      expect(() =>
        assertCs01NoBodyClientAssertion(CS01, {
          client_assertion: "eyJhbGciOiJIUzI1NiJ9.test",
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }),
      ).to.throw(Cs01ConformanceError);
    });
  });

  describe("compatibility mode contrast", () => {
    it("allows PAR fallback when PAR is not mandatory", () => {
      expect(() =>
        assertParEndpointAvailable(COMPAT, null),
      ).to.not.throw();
      expect(() =>
        assertNoDirectAuthorizationFallback(COMPAT, false),
      ).to.not.throw();
    });

    it("allows pre-authorized grant routing outside CS-01 mode", () => {
      expect(selectVciGrantRoute(COMPAT, cs01PreAuthorizedOffer.grants)).to.equal("pre-authorized_code");
      expect(() => assertPreAuthorizedAllowed(COMPAT)).to.not.throw();
    });

    it("allows legacy body client_assertion in compatibility mode", async () => {
      expect(compatibilityAllowsBodyClientAssertion(COMPAT)).to.equal(true);
      const legacyAssertion = await createLegacyBodyClientAssertionJwt({
        keyPath: undefined,
        audience: cs01AuthorizationServerMetadata.token_endpoint,
      });
      expect(legacyAssertion).to.be.a("string");
      expect(() =>
        assertCs01NoBodyClientAssertion(COMPAT, { client_assertion: legacyAssertion }),
      ).to.not.throw();
    });

    it("allows compatibility scope fallback to configurationId", () => {
      const scope = resolveCredentialScope({
        profile: COMPAT,
        configurationId: "UnscopedCredential",
        issuerMeta: cs01IssuerMetadata,
        offerConfig: cs01UnscopedOffer,
        scopesSupported: null,
      });
      expect(scope.scope).to.equal("UnscopedCredential");
      expect(scope.source).to.equal("compatibility:configurationId-fallback");
    });
  });
});
