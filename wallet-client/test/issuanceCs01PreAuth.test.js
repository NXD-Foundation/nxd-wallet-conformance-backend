/**
 * CS-01 pre-authorized issuance integration-style tests (Phase 6).
 * Chains grant routing, credential selection, DPoP/WUA contracts, credential proof,
 * and deferred polling using mocked issuer HTTP responses.
 */

import { expect } from "chai";
import { WALLET_PROFILES, Cs01ProfileError, selectVciGrantRoute } from "../src/lib/profile.js";
import {
  resolvePreAuthorizedCredentialSelection,
  resolveCredentialRequestTargets,
  CredentialSelectionError,
} from "../src/lib/scopeResolution.js";
import { DpopRequiredError, createTokenRequestDpopBinding, createResourceRequestDpopProof } from "../src/lib/dpopBinding.js";
import { createWalletUnitAttestationClientAuth } from "../src/lib/walletUnitAttestation.js";
import {
  buildCredentialProofRequest,
  buildCredentialProofBindingContext,
  buildDeferredCredentialPollRequest,
  resolveWalletUnitSubjectKey,
} from "../src/lib/credentialProofBinding.js";
import {
  assertCs01TokenRequestContract,
  assertCs01CredentialRequestContract,
  assertCs01DeferredRequestContract,
  describeIssuanceRefreshTokenMetadata,
} from "../src/lib/cs01Conformance.js";
import { pollDeferredCredentialIssuance } from "../src/lib/deferredIssuance.js";
import {
  CS01_CLIENT_ID,
  cs01IssuerMetadata,
  cs01AuthorizationServerMetadata,
  cs01PreAuthorizedOffer,
  cs01PreAuthorizedOfferWithTxCode,
  cs01PreAuthorizedMultiConfigOffer,
  cs01PreAuthorizedUnknownConfigOffer,
  cs01DualGrantOffer,
  cs01DpopTokenResponse,
  cs01DpopTokenResponseWithRefresh,
  cs01DeferredAcceptedResponse,
  cs01CredentialReadyResponse,
} from "./fixtures/cs01Fixtures.js";

const CS01 = WALLET_PROFILES.WEBUILD_CS01;
const PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

function extractPreAuthCode(offer) {
  return offer.grants[PRE_AUTH_GRANT]["pre-authorized_code"];
}

function extractTxCodeConfig(offer) {
  return offer.grants[PRE_AUTH_GRANT]?.tx_code ?? null;
}

function resolvePreAuthTxCode({ txCodeConfig, userPin }) {
  if (userPin) {
    return userPin;
  }
  if (txCodeConfig) {
    throw new Error("tx_code_required: offer indicates tx_code; provide 'pin' in request body");
  }
  return undefined;
}

async function buildCs01PreAuthTokenRequest({
  offerConfig,
  configurationId,
  userPin,
  tokenBody = cs01DpopTokenResponse,
}) {
  const selection = resolvePreAuthorizedCredentialSelection({
    configurationId,
    issuerMeta: cs01IssuerMetadata,
    offerConfig,
  });
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
  const txCodeConfig = extractTxCodeConfig(offerConfig);
  const txCode = resolvePreAuthTxCode({ txCodeConfig, userPin });
  const tokenParams = {
    grant_type: PRE_AUTH_GRANT,
    "pre-authorized_code": extractPreAuthCode(offerConfig),
    ...(txCode ? { tx_code: txCode } : {}),
    ...(selection.includeAuthorizationDetails
      ? { authorization_details: JSON.stringify(selection.authorizationDetails) }
      : {}),
  };

  assertCs01TokenRequestContract({
    profile: CS01,
    tokenParams,
    attestationHeaders: attestation.headers,
    dpopJwt: dpopBinding.dpopJwt,
    tokenBody,
    accessToken: tokenBody.access_token,
  });

  return { selection, dpopBinding, attestation, tokenParams, tokenBody };
}

async function buildCs01PreAuthCredentialRequest({
  configurationId,
  dpopBinding,
  tokenBody = cs01DpopTokenResponse,
}) {
  const proofBundle = await buildCredentialProofRequest({
    profile: CS01,
    keyPath: undefined,
    issuerMeta: cs01IssuerMetadata,
    apiBase: cs01IssuerMetadata.credential_issuer,
    configurationId,
    cNonce: tokenBody.c_nonce,
    credentialEndpoint: cs01IssuerMetadata.credential_endpoint,
  });
  const proofBinding = buildCredentialProofBindingContext({
    profile: CS01,
    subjectKey: proofBundle.subjectKey,
    dpopBinding,
    tokenBody,
    accessToken: tokenBody.access_token,
    keyAttestation: proofBundle.keyAttestation,
  });
  const credentialDpop = await createResourceRequestDpopProof({
    binding: dpopBinding,
    tokenBody,
    accessToken: tokenBody.access_token,
    htu: cs01IssuerMetadata.credential_endpoint,
    profile: CS01,
    stage: "credential request",
  });

  assertCs01CredentialRequestContract({
    profile: CS01,
    credentialRequest: proofBundle.credentialRequest,
    headers: {
      authorization: `DPoP ${tokenBody.access_token}`,
      DPoP: credentialDpop,
    },
    proofBinding,
  });

  return { proofBundle, proofBinding, credentialDpop };
}

describe("wallet-client CS-01 pre-auth issuance (Phase 6)", () => {
  describe("success paths", () => {
  it("issuer-initiated pre-auth offer routes through token (WUA + DPoP) to credential request", async () => {
      const route = selectVciGrantRoute(CS01, cs01PreAuthorizedOffer.grants);
      expect(route).to.equal("pre-authorized_code");

      const { selection, dpopBinding } = await buildCs01PreAuthTokenRequest({
        offerConfig: cs01PreAuthorizedOffer,
        configurationId: "VerifiableIdCard",
      });
      expect(selection.includeAuthorizationDetails).to.equal(false);

      const { proofBundle } = await buildCs01PreAuthCredentialRequest({
        configurationId: "VerifiableIdCard",
        dpopBinding,
      });
      expect(proofBundle.credentialRequest).to.have.property("credential_configuration_id", "VerifiableIdCard");
      expect(proofBundle.credentialRequest.proofs.jwt).to.have.lengthOf(1);
    });

    it("pre-auth offer with tx_code requires PIN and succeeds when PIN is supplied", async () => {
      const txCodeConfig = extractTxCodeConfig(cs01PreAuthorizedOfferWithTxCode);
      expect(txCodeConfig).to.have.property("input_mode", "numeric");

      let pinMissingError = null;
      try {
        await buildCs01PreAuthTokenRequest({
          offerConfig: cs01PreAuthorizedOfferWithTxCode,
          configurationId: "VerifiableIdCard",
        });
      } catch (error) {
        pinMissingError = error;
      }
      expect(pinMissingError).to.be.an("error");
      expect(String(pinMissingError.message)).to.match(/tx_code_required/);

      const { tokenParams } = await buildCs01PreAuthTokenRequest({
        offerConfig: cs01PreAuthorizedOfferWithTxCode,
        configurationId: "VerifiableIdCard",
        userPin: "5678",
      });
      expect(tokenParams.tx_code).to.equal("5678");
    });

    it("pre-auth succeeds without refresh_token in token response", async () => {
      const { tokenBody } = await buildCs01PreAuthTokenRequest({
        offerConfig: cs01PreAuthorizedOffer,
        configurationId: "VerifiableIdCard",
        tokenBody: cs01DpopTokenResponse,
      });
      expect(describeIssuanceRefreshTokenMetadata(tokenBody)).to.deep.equal({ present: false });
    });

    it("pre-auth preserves refresh_token metadata when returned by the AS", async () => {
      const { tokenBody } = await buildCs01PreAuthTokenRequest({
        offerConfig: cs01PreAuthorizedOffer,
        configurationId: "VerifiableIdCard",
        tokenBody: cs01DpopTokenResponseWithRefresh,
      });
      expect(describeIssuanceRefreshTokenMetadata(tokenBody)).to.deep.equal({
        present: true,
        expires_in: 86400,
      });
    });

    it("dual-grant offer routes independently: auth-code preferred, pre-auth available on pre-auth-only grant", () => {
      expect(selectVciGrantRoute(CS01, cs01DualGrantOffer.grants)).to.equal("authorization_code");
      expect(selectVciGrantRoute(CS01, cs01PreAuthorizedOffer.grants)).to.equal("pre-authorized_code");
      expect(selectVciGrantRoute(CS01, cs01DualGrantOffer.grants.authorization_code
        ? { authorization_code: cs01DualGrantOffer.grants.authorization_code }
        : {})).to.equal("authorization_code");
      expect(selectVciGrantRoute(CS01, {
        [PRE_AUTH_GRANT]: cs01DualGrantOffer.grants[PRE_AUTH_GRANT],
      })).to.equal("pre-authorized_code");
    });

    it("pre-auth deferred issuance polls with transaction_id until credential is ready", async () => {
      const subjectKey = await resolveWalletUnitSubjectKey({ keyPath: undefined, proofAlg: "ES256" });
      const { dpopBinding, tokenBody } = await buildCs01PreAuthTokenRequest({
        offerConfig: cs01PreAuthorizedOffer,
        configurationId: "VerifiableIdCard",
      });

      const poll = await buildDeferredCredentialPollRequest({
        profile: CS01,
        dpopBinding,
        tokenBody,
        accessToken: tokenBody.access_token,
        subjectKey,
        deferredEndpoint: cs01IssuerMetadata.credential_deferred_endpoint,
        transactionId: cs01DeferredAcceptedResponse.transaction_id,
      });
      assertCs01DeferredRequestContract({ profile: CS01, pollRequest: poll });

      let pollCount = 0;
      const credential = await pollDeferredCredentialIssuance({
        transactionId: cs01DeferredAcceptedResponse.transaction_id,
        issuerIntervalSeconds: cs01DeferredAcceptedResponse.interval,
        pollTimeoutMs: 5000,
        pollIntervalMs: 1,
        deferredEndpoint: cs01IssuerMetadata.credential_deferred_endpoint,
        buildPollRequest: async () => poll,
        httpPostJson: async () => {
          pollCount += 1;
          if (pollCount < 2) {
            return {
              status: 202,
              text: async () =>
                JSON.stringify({
                  transaction_id: cs01DeferredAcceptedResponse.transaction_id,
                  interval: 0.001,
                }),
            };
          }
          return {
            status: 200,
            text: async () => JSON.stringify(cs01CredentialReadyResponse),
          };
        },
        logSessionId: "phase6-deferred",
        sleep: async () => {},
      });

      expect(credential).to.deep.equal(cs01CredentialReadyResponse);
      expect(pollCount).to.equal(2);
    });

    it("multi-configuration pre-auth includes authorization_details for the selected configuration", async () => {
      const { selection, tokenParams } = await buildCs01PreAuthTokenRequest({
        offerConfig: cs01PreAuthorizedMultiConfigOffer,
        configurationId: "UnscopedCredential",
      });
      expect(selection.includeAuthorizationDetails).to.equal(true);
      expect(tokenParams.authorization_details).to.be.a("string");
      const parsed = JSON.parse(tokenParams.authorization_details);
      expect(parsed[0].credential_configuration_id).to.equal("UnscopedCredential");
    });
  });

    it("uses a credential_identifier returned by the Token Response", async () => {
      const tokenBody = {
        ...cs01DpopTokenResponse,
        authorization_details: [{
          type: "openid_credential",
          credential_configuration_id: "VerifiableIdCard",
          credential_identifiers: ["VerifiableIdCard_0000"],
        }],
      };
      const { dpopBinding } = await buildCs01PreAuthTokenRequest({
        offerConfig: cs01PreAuthorizedOffer,
        configurationId: "VerifiableIdCard",
        tokenBody,
      });
      const target = resolveCredentialRequestTargets({
        configurationId: "VerifiableIdCard",
        tokenResponse: tokenBody,
      })[0];
      const proofBundle = await buildCredentialProofRequest({
        profile: CS01,
        keyPath: undefined,
        issuerMeta: cs01IssuerMetadata,
        apiBase: cs01IssuerMetadata.credential_issuer,
        configurationId: target.credential_configuration_id,
        credentialIdentifier: target.credential_identifier,
        cNonce: tokenBody.c_nonce,
        credentialEndpoint: cs01IssuerMetadata.credential_endpoint,
      });
      expect(proofBundle.credentialRequest.credential_identifier).to.equal("VerifiableIdCard_0000");
      expect(proofBundle.credentialRequest).to.not.have.property("credential_configuration_id");
      expect(dpopBinding.dpopJwt).to.be.a("string");
    });

  describe("failure paths", () => {
    it("treats DPoP generation failure as fatal in CS-01 pre-auth credential requests", async () => {
      let thrown = null;
      try {
        await createResourceRequestDpopProof({
          binding: {},
          tokenBody: cs01DpopTokenResponse,
          accessToken: cs01DpopTokenResponse.access_token,
          htu: cs01IssuerMetadata.credential_endpoint,
          profile: CS01,
          stage: "credential request",
        });
      } catch (error) {
        thrown = error;
      }
      expect(thrown).to.be.instanceOf(DpopRequiredError);
    });

    it("rejects pre-auth offer referencing a credential configuration missing from issuer metadata", () => {
      expect(() =>
        resolvePreAuthorizedCredentialSelection({
          configurationId: "UnknownCredential",
          issuerMeta: cs01IssuerMetadata,
          offerConfig: cs01PreAuthorizedUnknownConfigOffer,
        }),
      ).to.throw(CredentialSelectionError, /not present in issuer metadata/);
    });

    it("rejects multi-configuration pre-auth selection without an explicit configuration id", () => {
      expect(() =>
        resolvePreAuthorizedCredentialSelection({
          configurationId: null,
          issuerMeta: cs01IssuerMetadata,
          offerConfig: cs01PreAuthorizedMultiConfigOffer,
        }),
      ).to.throw(CredentialSelectionError, /configuration id is required/);
    });

    it("rejects pre-auth-only offers when CS01_DISABLE_PRE_AUTHORIZED is set", () => {
      expect(() =>
        selectVciGrantRoute(CS01, cs01PreAuthorizedOffer.grants, {
          env: { CS01_DISABLE_PRE_AUTHORIZED: "true" },
        }),
      ).to.throw(Cs01ProfileError);
    });
  });
});
