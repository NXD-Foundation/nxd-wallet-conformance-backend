import { createProofJwt } from "./crypto.js";
import { buildWalletUnitAttestationJwt } from "./walletProviderIdentity.js";

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
 * @param {{ privateJwk: object, publicJwk: object, didJwk: string }[]} keyPairs
 */
export async function buildCredentialRequestProofs({
  proofMode,
  credentialEndpoint,
  aud,
  c_nonce,
  keyPairs,
  selectedAlg,
}) {
  const eudiWalletInfo = DEFAULT_EUDI_WALLET_INFO_FOR_WUA;
  const attestPub = keyPairs.map((k) => k.publicJwk);
  let wuaJwt = null;
  try {
    wuaJwt = await buildWalletUnitAttestationJwt({
      credentialEndpoint,
      proofPublicJwks: attestPub,
      eudiWalletInfo,
    });
  } catch (wuaError) {
    console.warn("[proofs] WUA generation failed:", wuaError?.message);
  }
  if (proofMode === "attestation") {
    if (!wuaJwt) {
      throw new Error("wua_required: proofs.attestation requires Wallet Unit Attestation JWT");
    }
    return { proofs: { attestation: [wuaJwt] }, proofJwt: null };
  }
  const proofJwt = await createProofJwt({
    privateJwk: keyPairs[0].privateJwk,
    publicJwk: keyPairs[0].publicJwk,
    audience: aud,
    nonce: c_nonce,
    issuer: keyPairs[0].didJwk,
    typ: "openid4vci-proof+jwt",
    alg: selectedAlg,
    key_attestation: wuaJwt || undefined,
  });
  return { proofs: { jwt: [proofJwt] }, proofJwt };
}
