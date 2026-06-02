/**
 * Wallet Unit subject key resolution and credential proof JWT construction.
 *
 * The Wallet Unit subject key is the key pair bound in the issued credential (cnf).
 * It is used to:
 * - sign the OpenID4VCI proof JWT at the Credential Endpoint
 * - appear in Wallet Unit Attestation attested_keys
 * - retain binding context through deferred issuance polling
 *
 * DPoP sender-constraining uses a separate key pair; deferred polling must reuse
 * the same DPoP binding established at the token request.
 */

import {
  createProofJwt,
  generateDidJwkFromPrivateJwk,
  ensureOrCreateEcKeyPair,
} from "./crypto.js";
import { createWalletUnitCredentialKeyAttestation } from "./walletUnitAttestation.js";
import { isWebuildCs01Profile } from "./profile.js";
import {
  createResourceRequestDpopProof,
  buildBearerResourceHeaders,
  assertDpopBoundTokenReceived,
  isSenderConstrainingMandatory,
} from "./dpopBinding.js";
import { isDpopBoundAccessToken } from "../../utils/tokenUtils.js";

export const PROOF_ALG_PREFERENCE = Object.freeze(["ES256", "ES384", "ES512", "EdDSA"]);

export const WALLET_UNIT_SUBJECT_KEY_ROLE = "wallet-unit-subject-key";

export class CredentialProofBindingError extends Error {
  constructor(message, errorCode = "invalid_proof_binding") {
    super(message);
    this.name = "CredentialProofBindingError";
    this.errorCode = errorCode;
  }
}

export function selectProofSigningAlgorithm(issuerMeta, configurationId) {
  const supported =
    issuerMeta?.proof_types_supported?.jwt?.proof_signing_alg_values_supported ||
    issuerMeta?.credential_configurations_supported?.[configurationId]?.proof_types_supported?.jwt
      ?.proof_signing_alg_values_supported ||
    [];

  if (Array.isArray(supported) && supported.length > 0) {
    return PROOF_ALG_PREFERENCE.find((alg) => supported.includes(alg)) || supported[0];
  }
  return "ES256";
}

export function resolveProofAudience(issuerMeta, apiBase) {
  return issuerMeta?.credential_issuer || apiBase;
}

/**
 * Resolve the Wallet Unit subject key used for credential binding proofs.
 */
export async function resolveWalletUnitSubjectKey({ keyPath, proofAlg }) {
  const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath, proofAlg);
  return {
    privateJwk,
    publicJwk,
    subjectDidJwk: generateDidJwkFromPrivateJwk(publicJwk),
    proofAlg,
    keyRole: WALLET_UNIT_SUBJECT_KEY_ROLE,
  };
}

export function describeWalletUnitSubjectKey(subjectKey) {
  return {
    keyRole: subjectKey.keyRole,
    proofAlg: subjectKey.proofAlg,
    subjectDidJwk: subjectKey.subjectDidJwk,
    publicJwk: {
      kty: subjectKey.publicJwk.kty,
      crv: subjectKey.publicJwk.crv,
      kid: subjectKey.publicJwk.kid,
    },
  };
}

export function assertCs01CredentialProofRequirements(profile, { subjectKey, keyAttestationJwt, proofJwt }) {
  if (!isWebuildCs01Profile(profile)) {
    return;
  }
  if (!subjectKey?.privateJwk || !subjectKey?.publicJwk) {
    throw new CredentialProofBindingError(
      "WE BUILD CS-01 requires a Wallet Unit subject key for credential binding",
    );
  }
  if (!keyAttestationJwt) {
    throw new CredentialProofBindingError(
      "WE BUILD CS-01 requires Wallet Unit Attestation in the proof JWT key_attestation header",
    );
  }
  if (!proofJwt) {
    throw new CredentialProofBindingError(
      "WE BUILD CS-01 requires a JWT proof at the Credential Endpoint",
    );
  }
}

export function describeSenderConstrainingContext({ profile, dpopBinding, tokenBody, accessToken }) {
  const mandatory = isSenderConstrainingMandatory(profile);
  return {
    mechanism: "dpop",
    mandatory,
    dpopKeyRetained: !!(dpopBinding?.privateJwk && dpopBinding?.publicJwk),
    accessTokenSenderConstrained:
      mandatory || isDpopBoundAccessToken(tokenBody, accessToken),
  };
}

export function assertDeferredIssuanceBindingContext({
  profile,
  dpopBinding,
  tokenBody,
  accessToken,
  subjectKey,
}) {
  if (isSenderConstrainingMandatory(profile)) {
    assertDpopBoundTokenReceived(profile, tokenBody, accessToken);
    if (!dpopBinding?.privateJwk || !dpopBinding?.publicJwk) {
      throw new CredentialProofBindingError(
        "Deferred issuance requires the DPoP binding context from the token request",
      );
    }
  }
  if (isWebuildCs01Profile(profile) && !subjectKey?.privateJwk) {
    throw new CredentialProofBindingError(
      "Deferred issuance requires the Wallet Unit subject key binding from the credential request",
    );
  }
}

export function buildCredentialProofBindingContext({
  profile,
  subjectKey,
  dpopBinding,
  tokenBody,
  accessToken,
  keyAttestation,
}) {
  return {
    walletUnitSubjectKey: describeWalletUnitSubjectKey(subjectKey),
    senderConstraining: describeSenderConstrainingContext({
      profile,
      dpopBinding,
      tokenBody,
      accessToken,
    }),
    keyAttestation: {
      source: keyAttestation?.source,
      trustFrameworkIntegrated: keyAttestation?.trustFrameworkIntegrated ?? false,
    },
    deferredIssuanceUsesSameBinding: true,
  };
}

/**
 * Build the credential request proof JWT using the Wallet Unit subject key.
 */
export async function buildCredentialProofRequest({
  profile,
  keyPath,
  issuerMeta,
  apiBase,
  configurationId,
  cNonce,
  credentialEndpoint,
}) {
  const proofAlg = selectProofSigningAlgorithm(issuerMeta, configurationId);
  const subjectKey = await resolveWalletUnitSubjectKey({ keyPath, proofAlg });
  const audience = resolveProofAudience(issuerMeta, apiBase);

  const keyAttestation = await createWalletUnitCredentialKeyAttestation({
    profile,
    keyPath,
    proofPublicJwk: subjectKey.publicJwk,
    credentialEndpoint,
    subjectPrivateJwk: subjectKey.privateJwk,
    subjectPublicJwk: subjectKey.publicJwk,
    alg: proofAlg,
  });

  const proofJwt = await createProofJwt({
    privateJwk: subjectKey.privateJwk,
    publicJwk: subjectKey.publicJwk,
    audience,
    nonce: cNonce,
    issuer: subjectKey.subjectDidJwk,
    typ: "openid4vci-proof+jwt",
    alg: proofAlg,
    key_attestation: keyAttestation.attestationJwt,
  });

  assertCs01CredentialProofRequirements(profile, {
    subjectKey,
    keyAttestationJwt: keyAttestation.attestationJwt,
    proofJwt,
  });

  return {
    proofJwt,
    subjectKey,
    keyAttestation,
    proofAlg,
    audience,
    credentialRequest: {
      credential_configuration_id: configurationId,
      proofs: { jwt: [proofJwt] },
    },
  };
}

/**
 * Build a deferred credential poll request reusing token DPoP binding context.
 */
export async function buildDeferredCredentialPollRequest({
  profile,
  dpopBinding,
  tokenBody,
  accessToken,
  subjectKey,
  deferredEndpoint,
  transactionId,
}) {
  assertDeferredIssuanceBindingContext({
    profile,
    dpopBinding,
    tokenBody,
    accessToken,
    subjectKey,
  });

  const dpopJwt = await createResourceRequestDpopProof({
    binding: dpopBinding,
    tokenBody,
    accessToken,
    htu: deferredEndpoint,
    profile,
    stage: "deferred credential request",
  });

  return {
    body: { transaction_id: transactionId },
    headers: buildBearerResourceHeaders(accessToken, dpopJwt),
    senderContextRetained: true,
    walletUnitSubjectKeyRetained: !!subjectKey?.privateJwk,
  };
}

export function toKeyBindingMaterial(subjectKey) {
  return {
    privateJwk: subjectKey.privateJwk,
    publicJwk: subjectKey.publicJwk,
    didJwk: subjectKey.subjectDidJwk,
  };
}
