/** Shared fixtures for WE BUILD CS-01 conformance tests (Phase 10). */

export const CS01_CLIENT_ID = "wallet-client";

export const cs01IssuerMetadata = {
  credential_issuer: "https://issuer.example.com",
  authorization_servers: ["https://issuer.example.com"],
  credential_endpoint: "https://issuer.example.com/credential",
  credential_deferred_endpoint: "https://issuer.example.com/credential_deferred",
  nonce_endpoint: "https://issuer.example.com/nonce",
  credential_configurations_supported: {
    VerifiableIdCard: {
      scope: "VerifiableIdCard",
      format: "dc+sd-jwt",
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ["ES256"] },
      },
    },
    UnscopedCredential: {
      format: "dc+sd-jwt",
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ["ES256"] },
      },
    },
  },
};

export const cs01AuthorizationServerMetadata = {
  issuer: "https://issuer.example.com",
  authorization_endpoint: "https://issuer.example.com/authorize",
  pushed_authorization_request_endpoint: "https://issuer.example.com/par",
  token_endpoint: "https://issuer.example.com/token",
  scopes_supported: ["openid", "VerifiableIdCard"],
  code_challenge_methods_supported: ["S256"],
  dpop_signing_alg_values_supported: ["ES256"],
};

export const cs01AuthorizationServerMetadataWithoutPar = {
  ...cs01AuthorizationServerMetadata,
  pushed_authorization_request_endpoint: undefined,
};

export const cs01IssuerInitiatedOffer = {
  credential_issuer: cs01IssuerMetadata.credential_issuer,
  credential_configuration_ids: ["VerifiableIdCard"],
  grants: {
    authorization_code: {
      issuer_state: "offer-session-123",
      scope: "VerifiableIdCard",
    },
  },
};

export const cs01WalletInitiatedOffer = {
  credential_issuer: cs01IssuerMetadata.credential_issuer,
  credential_configuration_ids: ["VerifiableIdCard"],
  grants: {
    authorization_code: {},
  },
};

export const cs01TxCodeConfig = {
  length: 4,
  input_mode: "numeric",
  description: "Please provide the one-time code that was sent via e-mail or offline",
};

export const cs01PreAuthorizedOffer = {
  credential_issuer: cs01IssuerMetadata.credential_issuer,
  credential_configuration_ids: ["VerifiableIdCard"],
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "preauth-session-123",
    },
  },
};

/** VCI v1.0-shaped pre-auth offer that advertises tx_code (ITB+ PIN scenarios). */
export const cs01PreAuthorizedOfferWithTxCode = {
  credential_issuer: cs01IssuerMetadata.credential_issuer,
  credential_configuration_ids: ["VerifiableIdCard"],
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "preauth-tx-session-123",
      tx_code: cs01TxCodeConfig,
    },
  },
};

export const cs01PreAuthorizedMultiConfigOffer = {
  credential_issuer: cs01IssuerMetadata.credential_issuer,
  credential_configuration_ids: ["VerifiableIdCard", "UnscopedCredential"],
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "preauth-multi-session-123",
    },
  },
};

export const cs01DualGrantOffer = {
  credential_issuer: cs01IssuerMetadata.credential_issuer,
  credential_configuration_ids: ["VerifiableIdCard"],
  grants: {
    authorization_code: {
      issuer_state: "dual-offer-session-123",
      scope: "VerifiableIdCard",
    },
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "dual-preauth-session-123",
    },
  },
};

export const cs01UnscopedOffer = {
  credential_issuer: cs01IssuerMetadata.credential_issuer,
  credential_configuration_ids: ["UnscopedCredential"],
  grants: {
    authorization_code: {},
  },
};

export const cs01ParSuccessResponse = {
  request_uri: "urn:ietf:params:oauth:request_uri:abc123",
  expires_in: 60,
};

export const cs01DpopTokenResponse = {
  access_token: "test-access-token",
  token_type: "DPoP",
  expires_in: 3600,
  c_nonce: "c-nonce-123",
};

export const cs01DpopTokenResponseWithRefresh = {
  ...cs01DpopTokenResponse,
  refresh_token: "rt-refresh-abc",
  refresh_expires_in: 86400,
};

export const cs01DeferredAcceptedResponse = {
  transaction_id: "tx-deferred-456",
  interval: 5,
};

export const cs01CredentialReadyResponse = {
  credential: "eyJhbGciOiJFUzI1NiJ9.test-credential",
};

/** Pre-auth offer referencing a configuration missing from issuer metadata (failure fixture). */
export const cs01PreAuthorizedUnknownConfigOffer = {
  credential_issuer: cs01IssuerMetadata.credential_issuer,
  credential_configuration_ids: ["UnknownCredential"],
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "preauth-unknown-config-123",
    },
  },
};
