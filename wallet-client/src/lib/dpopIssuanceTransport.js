import { createDpopNonceState, requestWithDpopNonce } from "./dpopNonce.js";
import { ensureOrCreateEcKeyPair } from "./crypto.js";
import { shouldRetryWithAttestationChallenge } from "./attestationChallenge.js";
import { shouldUseDpopForResourceRequest, isSenderConstrainingMandatory, assertDpopBoundTokenReceived } from "./dpopBinding.js";
import { computeAthForDpop } from "../../utils/tokenUtils.js";

/** Preserve the WE BUILD session WIA/key while refreshing PoP and DPoP. */
export async function postFormWithAttestationNonceRetry({
  url, params, postForm, buildAttestation, keyPath, cnfKeyPair = null,
  reuseAttestationJwt = null, challengeState, nonceState = createDpopNonceState(), log, enabled = true,
}) {
  const keys = cnfKeyPair || await ensureOrCreateEcKeyPair(keyPath, "ES256");
  const budget = { sends: 0, nonceRetries: 0 };
  let attestationJwt = reuseAttestationJwt;
  let lastAttestation;
  const dispatch = () => requestWithDpopNonce({
    url, namespace: "as", state: nonceState, ...keys, budget, log, enabled,
    send: async (proof) => {
      lastAttestation = await buildAttestation({ cnfKeyPair: keys, reuseAttestationJwt: attestationJwt });
      attestationJwt = lastAttestation.headers["OAuth-Client-Attestation"];
      const response = await postForm(url, params, proof, lastAttestation.headers);
      challengeState?.updateFromResponse(response.headers);
      return response;
    },
  });
  let response = await dispatch();
  const text = response.bodyText ?? response._responseText ?? await response.clone().text().catch(() => "");
  const retry = shouldRetryWithAttestationChallenge(response, text);
  if (retry.shouldRetry && retry.challenge) {
    challengeState?.set(retry.challenge);
    response = await dispatch();
  }
  Object.defineProperty(response, "sessionClientAttestation", { value: {
    attestationJwt, cnfKeyPair: keys, nonceState,
  }, enumerable: false });
  return response;
}

export async function requestWithResourceDpop({ url, binding, profile, tokenBody, accessToken, send, log }) {
  if (isSenderConstrainingMandatory(profile)) assertDpopBoundTokenReceived(profile, tokenBody, accessToken);
  binding.nonceState ||= createDpopNonceState();
  return requestWithDpopNonce({
    url, state: binding.nonceState, privateJwk: binding.privateJwk, publicJwk: binding.publicJwk,
    enabled: shouldUseDpopForResourceRequest(profile, tokenBody, accessToken),
    ath: accessToken ? computeAthForDpop(accessToken) : null, send, log,
  });
}

/** The Nonce Endpoint is not an access-token protected resource. */
export function requestCredentialNonce({ url, binding, send, log }) {
  binding.nonceState ||= createDpopNonceState();
  return requestWithDpopNonce({ url, state: binding.nonceState,
    privateJwk: binding.privateJwk, publicJwk: binding.publicJwk, send, log });
}
