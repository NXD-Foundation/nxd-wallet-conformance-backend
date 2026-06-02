import { decodeJwt } from "jose";

/** Default OAuth client_id used when WALLET_CLIENT_ID is not configured. */
export const DEFAULT_WALLET_CLIENT_ID = "wallet-client";

export class ClientIdAttestationMismatchError extends Error {
  constructor(clientId, attestationSubject, context = "attestation") {
    super(
      `client_id '${clientId}' does not match Wallet Unit Attestation ${context} '${attestationSubject}'`,
    );
    this.name = "ClientIdAttestationMismatchError";
    this.errorCode = "client_id_mismatch";
    this.clientId = clientId;
    this.attestationSubject = attestationSubject;
  }
}

export function normalizeWalletClientId(value) {
  const clientId = String(value ?? "").trim();
  if (!clientId) {
    throw new Error("Wallet client_id must not be empty");
  }
  return clientId;
}

/**
 * Resolve the wallet OAuth client_id from an optional override or WALLET_CLIENT_ID env.
 */
export function resolveWalletClientId(env = process.env, override) {
  if (override != null && String(override).trim() !== "") {
    return normalizeWalletClientId(override);
  }
  const fromEnv = env.WALLET_CLIENT_ID;
  if (fromEnv != null && String(fromEnv).trim() !== "") {
    return normalizeWalletClientId(fromEnv);
  }
  return DEFAULT_WALLET_CLIENT_ID;
}

export function extractJwtClaim(jwt, claim) {
  if (!jwt) {
    return null;
  }
  const payload = decodeJwt(jwt);
  return payload?.[claim] ?? null;
}

export function assertClientIdMatchesAttestationSubject(clientId, attestationSubject, { context = "sub" } = {}) {
  normalizeWalletClientId(clientId);
  if (attestationSubject == null || attestationSubject === "") {
    throw new Error(`Wallet Unit Attestation JWT is missing ${context} claim`);
  }
  if (clientId !== attestationSubject) {
    throw new ClientIdAttestationMismatchError(clientId, attestationSubject, context);
  }
}

/**
 * Verify outbound client_id matches the attestation JWT sub before sending PAR/Token requests.
 */
export function assertOutboundClientIdAligned({ clientId, attestationJwt, popJwt }) {
  const attestationSub = extractJwtClaim(attestationJwt, "sub");
  assertClientIdMatchesAttestationSubject(clientId, attestationSub, { context: "sub" });

  const popIss = extractJwtClaim(popJwt, "iss");
  assertClientIdMatchesAttestationSubject(clientId, popIss, { context: "PoP iss" });
}
