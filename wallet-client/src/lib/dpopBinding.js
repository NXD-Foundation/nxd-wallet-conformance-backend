import { createDPoP, ensureOrCreateEcKeyPair } from "./crypto.js";
import { isDpopBoundAccessToken, computeAthForDpop } from "../../utils/tokenUtils.js";
import { isWebuildCs01Profile } from "./profile.js";

export class DpopRequiredError extends Error {
  constructor(message) {
    super(message);
    this.name = "DpopRequiredError";
    this.errorCode = "dpop_required";
  }
}

/** Sender-constrained tokens are mandatory in WE BUILD CS-01 mode. */
export function isSenderConstrainingMandatory(profile) {
  return isWebuildCs01Profile(profile);
}

export function assertDpopJwtPresent(profile, dpopJwt, { stage = "request" } = {}) {
  if (!isSenderConstrainingMandatory(profile)) {
    return;
  }
  if (dpopJwt) {
    return;
  }
  throw new DpopRequiredError(
    `WE BUILD CS-01 profile requires DPoP at ${stage}; DPoP proof was not generated`,
  );
}

export function assertDpopBoundTokenReceived(profile, tokenBody, accessToken) {
  if (!isSenderConstrainingMandatory(profile)) {
    return;
  }
  if (isDpopBoundAccessToken(tokenBody, accessToken)) {
    return;
  }
  throw new DpopRequiredError(
    "WE BUILD CS-01 profile requires a sender-constrained (DPoP-bound) access token; token response is not DPoP-bound",
  );
}

export function assertDpopHeaderOnRequest(profile, dpopJwt, { stage = "request" } = {}) {
  if (!isSenderConstrainingMandatory(profile)) {
    return;
  }
  if (dpopJwt) {
    return;
  }
  throw new DpopRequiredError(
    `WE BUILD CS-01 profile requires DPoP on ${stage}; refusing bearer-only request`,
  );
}

export function shouldUseDpopForResourceRequest(profile, tokenBody, accessToken) {
  if (isSenderConstrainingMandatory(profile)) {
    return true;
  }
  return isDpopBoundAccessToken(tokenBody, accessToken);
}

/**
 * Create and retain the DPoP key binding used for the token request.
 * The same key pair must be reused for credential and deferred credential requests.
 */
export async function createTokenRequestDpopBinding({
  keyPath,
  tokenEndpoint,
  profile,
  alg = "ES256",
}) {
  try {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath, alg);
    const dpopJwt = await createDPoP({
      privateJwk,
      publicJwk,
      htu: tokenEndpoint,
      htm: "POST",
      alg,
    });
    assertDpopJwtPresent(profile, dpopJwt, { stage: "token request" });
    return { privateJwk, publicJwk, dpopJwt };
  } catch (error) {
    if (isSenderConstrainingMandatory(profile)) {
      if (error instanceof DpopRequiredError) {
        throw error;
      }
      throw new DpopRequiredError(
        `WE BUILD CS-01 profile requires DPoP at token request; generation failed: ${error?.message || error}`,
      );
    }
    return { privateJwk: null, publicJwk: null, dpopJwt: null };
  }
}

/**
 * Create a DPoP proof for a resource request (/credential, /credential_deferred).
 */
export async function createResourceRequestDpopProof({
  binding,
  tokenBody,
  accessToken,
  htu,
  htm = "POST",
  profile,
  alg = "ES256",
  stage = "resource request",
}) {
  if (!accessToken) {
    assertDpopHeaderOnRequest(profile, null, { stage });
    return null;
  }

  if (isSenderConstrainingMandatory(profile)) {
    assertDpopBoundTokenReceived(profile, tokenBody, accessToken);
  } else if (!isDpopBoundAccessToken(tokenBody, accessToken)) {
    return null;
  }

  if (!binding?.privateJwk || !binding?.publicJwk) {
    throw new DpopRequiredError(
      `WE BUILD CS-01 profile requires DPoP on ${stage}; token binding key material is missing`,
    );
  }

  try {
    const dpopJwt = await createDPoP({
      privateJwk: binding.privateJwk,
      publicJwk: binding.publicJwk,
      htu,
      htm,
      ath: computeAthForDpop(accessToken),
      alg,
    });
    assertDpopHeaderOnRequest(profile, dpopJwt, { stage });
    return dpopJwt;
  } catch (error) {
    if (isSenderConstrainingMandatory(profile)) {
      if (error instanceof DpopRequiredError) {
        throw error;
      }
      throw new DpopRequiredError(
        `WE BUILD CS-01 profile requires DPoP on ${stage}; generation failed: ${error?.message || error}`,
      );
    }
    return null;
  }
}

export function buildBearerResourceHeaders(accessToken, dpopJwt) {
  return {
    authorization: `Bearer ${accessToken}`,
    ...(dpopJwt ? { DPoP: dpopJwt } : {}),
  };
}
