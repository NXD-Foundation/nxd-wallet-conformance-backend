import { decodeJwt, decodeProtectedHeader, calculateJwkThumbprint } from "jose";

export const WUA_JWT_TYP = "key-attestation+jwt";
export const PROOF_JWT_TYP = "openid4vci-proof+jwt";
export const MAX_WUA_ATTESTED_KEYS = 32;

export function stripPrivateJwkMaterial(jwk) {
  const o = { ...(jwk || {}) };
  for (const k of ["d", "p", "q", "dp", "dq", "qi", "oth"]) {
    delete o[k];
  }
  return o;
}

export async function publicJwksMatch(a, b) {
  const ta = await calculateJwkThumbprint(stripPrivateJwkMaterial(a), "sha256");
  const tb = await calculateJwkThumbprint(stripPrivateJwkMaterial(b), "sha256");
  return ta === tb;
}

/**
 * RFC001 §7.5.1: `attested_keys` order matches the wallet's key pair list; proof JWT uses index 0.
 */
export function assertAttestedKeyPairsForWua(keyPairs) {
  if (!Array.isArray(keyPairs) || keyPairs.length === 0) {
    throw new Error("wua_binding: at least one proof key is required");
  }
  if (keyPairs.length > MAX_WUA_ATTESTED_KEYS) {
    throw new Error(`wua_binding: at most ${MAX_WUA_ATTESTED_KEYS} attested_keys supported`);
  }
  for (let i = 0; i < keyPairs.length; i++) {
    const kp = keyPairs[i];
    if (!kp?.publicJwk?.kty || !kp?.privateJwk?.kty) {
      throw new Error(`wua_binding: keyPairs[${i}] must include publicJwk and privateJwk`);
    }
  }
  return keyPairs;
}

/**
 * Ordered public JWKs for WUA `attested_keys` (stable issuance order).
 */
export function orderedAttestedPublicJwks(keyPairs) {
  return assertAttestedKeyPairsForWua(keyPairs).map((k) => stripPrivateJwkMaterial(k.publicJwk));
}

/**
 * Decode and validate WUA structure; ensure `attested_keys` matches `keyPairs` in order.
 */
export async function validateWuaMatchesAttestedKeyPairs(wuaJwt, keyPairs) {
  if (!wuaJwt || typeof wuaJwt !== "string") {
    throw new Error("wua_binding: WUA JWT is required");
  }
  const header = decodeProtectedHeader(wuaJwt);
  if (header.typ !== WUA_JWT_TYP) {
    throw new Error(`wua_binding: WUA typ must be ${WUA_JWT_TYP}`);
  }
  const payload = decodeJwt(wuaJwt);
  const attested = payload.attested_keys;
  if (!Array.isArray(attested) || attested.length === 0) {
    throw new Error("wua_binding: WUA attested_keys must be a non-empty array");
  }
  const pairs = assertAttestedKeyPairsForWua(keyPairs);
  if (attested.length !== pairs.length) {
    throw new Error(
      `wua_binding: WUA attested_keys length (${attested.length}) must match key count (${pairs.length})`,
    );
  }
  for (let i = 0; i < pairs.length; i++) {
    if (!(await publicJwksMatch(attested[i], pairs[i].publicJwk))) {
      throw new Error(`wua_binding: WUA attested_keys[${i}] must match keyPairs[${i}] public key`);
    }
  }
  return payload;
}

/**
 * Local RFC001 checks on assembled `proofs` before credential request dispatch.
 */
export async function validateCredentialProofsBeforeDispatch({
  proofMode,
  proofs,
  wuaJwt,
  keyPairs,
}) {
  if (proofMode === "attestation") {
    const list = proofs?.attestation;
    if (!Array.isArray(list) || list.length !== 1 || typeof list[0] !== "string" || !list[0].trim()) {
      throw new Error("wua_binding: proofs.attestation must contain exactly one WUA JWT");
    }
    await validateWuaMatchesAttestedKeyPairs(list[0], keyPairs);
    if (wuaJwt && list[0] !== wuaJwt) {
      throw new Error("wua_binding: proofs.attestation WUA must match built WUA");
    }
    return;
  }

  const jwtList = proofs?.jwt;
  if (!Array.isArray(jwtList) || jwtList.length !== 1 || typeof jwtList[0] !== "string" || !jwtList[0].trim()) {
    throw new Error("wua_binding: proofs.jwt must contain exactly one proof JWT");
  }
  const proofJwt = jwtList[0];
  const proofHeader = decodeProtectedHeader(proofJwt);
  if (proofHeader.typ !== PROOF_JWT_TYP) {
    throw new Error(`wua_binding: proof JWT typ must be ${PROOF_JWT_TYP}`);
  }
  if (!proofHeader.key_attestation) {
    throw new Error("wua_binding: proof JWT must include key_attestation (WUA)");
  }
  if (!wuaJwt) {
    throw new Error("wua_binding: WUA is required for proofs.jwt");
  }
  if (proofHeader.key_attestation !== wuaJwt) {
    throw new Error("wua_binding: proof key_attestation header must equal WUA JWT");
  }
  await validateWuaMatchesAttestedKeyPairs(wuaJwt, keyPairs);
}
