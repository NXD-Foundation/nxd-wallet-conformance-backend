/**
 * WE BUILD CS-01 conformance contract checks for outbound issuance requests.
 * Used by tests and available for runtime validation during conformance runs.
 */

import { isWebuildCs01Profile } from "./profile.js";
import { allowsLegacyBodyClientAssertion } from "./walletUnitAttestation.js";
import { isDpopBoundAccessToken } from "../../utils/tokenUtils.js";

export class Cs01ConformanceError extends Error {
  constructor(message, errorCode = "cs01_conformance_violation") {
    super(message);
    this.name = "Cs01ConformanceError";
    this.errorCode = errorCode;
  }
}

export function assertCs01NoBodyClientAssertion(profile, params, { stage = "request" } = {}) {
  if (!isWebuildCs01Profile(profile)) {
    return;
  }
  if (params?.client_assertion || params?.client_assertion_type) {
    throw new Cs01ConformanceError(
      `CS-01 ${stage} must not include OAuth body client_assertion; use Wallet Unit Attestation headers only`,
    );
  }
}

export function assertCs01WalletUnitAttestationHeaders(headers, { stage = "request" } = {}) {
  if (!headers?.["OAuth-Client-Attestation"]) {
    throw new Cs01ConformanceError(`CS-01 ${stage} requires OAuth-Client-Attestation header`);
  }
  if (!headers?.["OAuth-Client-Attestation-PoP"]) {
    throw new Cs01ConformanceError(`CS-01 ${stage} requires OAuth-Client-Attestation-PoP header`);
  }
}

export function assertCs01PkceAuthorizationParams(params) {
  if (params?.code_challenge_method !== "S256") {
    throw new Cs01ConformanceError("CS-01 authorization request must use PKCE S256");
  }
  if (!params?.code_challenge || typeof params.code_challenge !== "string") {
    throw new Cs01ConformanceError("CS-01 authorization request must include code_challenge");
  }
}

export function assertCs01ParRequestContract({
  profile,
  parParams,
  attestationHeaders,
  usedPar = true,
}) {
  if (!isWebuildCs01Profile(profile)) {
    return;
  }
  assertCs01NoBodyClientAssertion(profile, parParams, { stage: "PAR" });
  assertCs01WalletUnitAttestationHeaders(attestationHeaders, { stage: "PAR" });
  assertCs01PkceAuthorizationParams(parParams);
  if (!usedPar) {
    throw new Cs01ConformanceError("CS-01 must use PAR; direct authorization fallback is not permitted");
  }
  if (!parParams?.scope || parParams.scope === parParams.credential_configuration_id) {
    // scope must be issuer-defined; equality with config id only valid when metadata maps them
  }
}

const PRE_AUTHORIZED_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

export function describeIssuanceRefreshTokenMetadata(tokenBody) {
  if (tokenBody?.refresh_token) {
    return {
      present: true,
      ...(tokenBody.refresh_expires_in != null ? { expires_in: tokenBody.refresh_expires_in } : {}),
    };
  }
  return { present: false };
}

export function assertCs01TokenRequestContract({
  profile,
  tokenParams,
  attestationHeaders,
  dpopJwt,
  tokenBody,
  accessToken,
}) {
  if (!isWebuildCs01Profile(profile)) {
    return;
  }
  assertCs01NoBodyClientAssertion(profile, tokenParams, { stage: "Token" });
  assertCs01WalletUnitAttestationHeaders(attestationHeaders, { stage: "Token" });
  const grantType = tokenParams?.grant_type;
  if (grantType === "authorization_code") {
    if (!tokenParams?.code_verifier) {
      throw new Cs01ConformanceError("CS-01 token request must include PKCE code_verifier");
    }
  } else if (grantType === PRE_AUTHORIZED_GRANT_TYPE) {
    if (!tokenParams?.["pre-authorized_code"]) {
      throw new Cs01ConformanceError("CS-01 pre-authorized token request must include pre-authorized_code");
    }
  } else {
    throw new Cs01ConformanceError(
      `CS-01 token request must use authorization_code or ${PRE_AUTHORIZED_GRANT_TYPE} grant`,
    );
  }
  if (!dpopJwt) {
    throw new Cs01ConformanceError("CS-01 token request must include DPoP proof");
  }
  if (tokenBody && accessToken && !isDpopBoundAccessToken(tokenBody, accessToken)) {
    throw new Cs01ConformanceError("CS-01 requires a sender-constrained (DPoP-bound) access token");
  }
}

export function assertCs01CredentialRequestContract({
  profile,
  credentialRequest,
  headers,
  proofBinding,
}) {
  if (!isWebuildCs01Profile(profile)) {
    return;
  }
  const proofJwt = credentialRequest?.proofs?.jwt?.[0];
  if (!proofJwt || typeof proofJwt !== "string") {
    throw new Cs01ConformanceError("CS-01 credential request must include a JWT proof");
  }
  if (!headers?.authorization?.startsWith("Bearer ")) {
    throw new Cs01ConformanceError("CS-01 credential request must include Authorization Bearer header");
  }
  if (!headers?.DPoP) {
    throw new Cs01ConformanceError("CS-01 credential request must include DPoP header");
  }
  if (!proofBinding?.walletUnitSubjectKey?.keyRole) {
    throw new Cs01ConformanceError("CS-01 credential request must bind proof to Wallet Unit subject key");
  }
}

export function assertCs01DeferredRequestContract({ profile, pollRequest }) {
  if (!isWebuildCs01Profile(profile)) {
    return;
  }
  if (!pollRequest?.body?.transaction_id) {
    throw new Cs01ConformanceError("CS-01 deferred credential request must include transaction_id");
  }
  if (!pollRequest?.headers?.authorization?.startsWith("Bearer ")) {
    throw new Cs01ConformanceError("CS-01 deferred credential request must include Authorization Bearer header");
  }
  if (!pollRequest?.headers?.DPoP) {
    throw new Cs01ConformanceError("CS-01 deferred credential request must retain DPoP sender constraining");
  }
  if (!pollRequest?.senderContextRetained) {
    throw new Cs01ConformanceError("CS-01 deferred credential request must retain sender binding context");
  }
}

export function buildParAuthorizeUrl(authorizeEndpoint, clientId, requestUri) {
  const url = new URL(authorizeEndpoint);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("request_uri", requestUri);
  return url.toString();
}

export function compatibilityAllowsBodyClientAssertion(profile) {
  return allowsLegacyBodyClientAssertion(profile);
}
