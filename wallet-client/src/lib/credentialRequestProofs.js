/**
 * Credential endpoint proof binding (RFC001): WUA only — not WIA.
 * - proofs.jwt: exactly one proof JWT with WUA in `key_attestation`, signed with keyPairs[0]
 * - proofs.attestation: exactly one WUA JWT
 */
import { createProofJwt } from "./crypto.js";
import { buildWalletUnitAttestationJwt } from "./walletProviderIdentity.js";
import {
  orderedAttestedPublicJwks,
  validateCredentialProofsBeforeDispatch,
} from "./wuaCredentialBinding.js";

export const DEFAULT_EUDI_WALLET_INFO_FOR_WUA = {
  general_info: { name: "Test Wallet Client", version: "1.0.0" },
  key_storage_info: { storage_type: "software", protection_level: "software" },
};

export function redactProofsForLog(proofs) {
  if (!proofs || typeof proofs !== "object") return proofs;
  const o = { ...proofs };
  if (Array.isArray(o.jwt)) o.jwt = o.jwt.map(() => "<redacted>");
  if (Array.isArray(o.attestation)) o.attestation = o.attestation.map(() => "<redacted>");
  return o;
}

/**
 * @param {"jwt"|"attestation"} proofMode
 * @param {{ privateJwk: object, publicJwk: object, didJwk: string }[]} keyPairs — stable order; proof uses index 0
 */
export async function buildCredentialRequestProofs({
  proofMode,
  credentialEndpoint,
  aud,
  c_nonce,
  keyPairs,
  selectedAlg,
}) {
  const attestPub = orderedAttestedPublicJwks(keyPairs);
  const proofKey = keyPairs[0];
  const eudiWalletInfo = DEFAULT_EUDI_WALLET_INFO_FOR_WUA;

  const wuaJwt = await buildWalletUnitAttestationJwt({
    credentialEndpoint,
    proofPublicJwks: attestPub,
    eudiWalletInfo,
    c_nonce,
  });

  if (proofMode === "attestation") {
    const proofs = { attestation: [wuaJwt] };
    await validateCredentialProofsBeforeDispatch({
      proofMode,
      proofs,
      wuaJwt,
      keyPairs,
      expectedCNonce: c_nonce,
    });
    return { proofs, proofJwt: null, wuaJwt };
  }

  const proofJwt = await createProofJwt({
    privateJwk: proofKey.privateJwk,
    publicJwk: proofKey.publicJwk,
    audience: aud,
    nonce: c_nonce,
    issuer: proofKey.didJwk,
    typ: "openid4vci-proof+jwt",
    alg: selectedAlg,
    key_attestation: wuaJwt,
  });
  const proofs = { jwt: [proofJwt] };
  await validateCredentialProofsBeforeDispatch({
    proofMode,
    proofs,
    wuaJwt,
    keyPairs,
    expectedCNonce: c_nonce,
  });
  return { proofs, proofJwt, wuaJwt };
}
