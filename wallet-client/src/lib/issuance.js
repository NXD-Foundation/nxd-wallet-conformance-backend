import { resolveWalletProfile, isWebuildCs01Profile } from "./profile.js";
import { createDpopNonceState, requestWithDpopNonce } from "./dpopNonce.js";
import { storeWalletCredentialByType } from "./cache.js";
import { resolveWalletInstanceClientId } from "./walletClientId.js";
import { resolveScopeForCredentialConfigurationOrNull } from "./scopeResolution.js";
import {
  extractNotificationId,
  resolveNotificationEndpoint,
  postCredentialAcceptedNotification,
} from "./credentialNotification.js";
import {
  getNextPollDelayMs,
  resolveDeferredPollResult,
  formatDeferredTerminalError,
} from "./deferredIssuancePoll.js";
import { shouldRetryWithAttestationChallenge } from "./attestationChallenge.js";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * `authorization_details` for OpenID4VCI credential issuance (RFC001).
 */
export function buildOpenIdCredentialAuthorizationDetails(configurationId, credentialIssuer) {
  if (!configurationId) return [];
  return [
    {
      type: "openid_credential",
      credential_configuration_id: configurationId,
      ...(credentialIssuer ? { locations: [credentialIssuer] } : {}),
    },
  ];
}

/**
 * OAuth authorization / token fields: metadata-driven `scope` plus `authorization_details`.
 */
export function buildIssuanceAuthorizationFields({
  configurationId,
  issuerMeta,
  offer = null,
  grantType = null,
  credentialIssuer = null,
}) {
  const authorizationDetails = buildOpenIdCredentialAuthorizationDetails(
    configurationId,
    credentialIssuer ?? issuerMeta?.credential_issuer,
  );
  const scope = resolveScopeForCredentialConfigurationOrNull({
    configurationId,
    issuerMeta,
    offer,
    grantType,
  });
  return {
    ...(scope ? { scope } : {}),
    authorizationDetails,
    authorization_details: JSON.stringify(authorizationDetails),
  };
}

export {
  resolveScopeForCredentialConfiguration,
  resolveScopeForCredentialConfigurationOrNull,
  assertAuthorizationDetailsSupportForCredentialRequest,
} from "./scopeResolution.js";
export { resolveWalletInstanceClientId } from "./walletClientId.js";

export function selectProofSigningAlg(issuerMeta, configurationId) {
  const supportedAlgs =
    issuerMeta?.proof_types_supported?.jwt?.proof_signing_alg_values_supported ||
    issuerMeta?.credential_configurations_supported?.[configurationId]?.proof_types_supported?.jwt?.proof_signing_alg_values_supported ||
    [];
  const preferredOrder = ["ES256", "ES384", "ES512", "EdDSA"];
  return (Array.isArray(supportedAlgs) && supportedAlgs.length)
    ? (preferredOrder.find((alg) => supportedAlgs.includes(alg)) || supportedAlgs[0])
    : "ES256";
}

export async function buildKeyPairs({
  keyPaths,
  selectedAlg,
  ensureOrCreateEcKeyPair,
  generateDidJwkFromPrivateJwk,
}) {
  const keyPairs = [];
  for (const keyPath of keyPaths) {
    const { privateJwk, publicJwk } = await ensureOrCreateEcKeyPair(keyPath, selectedAlg);
    keyPairs.push({
      privateJwk,
      publicJwk,
      didJwk: generateDidJwkFromPrivateJwk(publicJwk),
    });
  }
  return keyPairs;
}

export async function notifyCredentialAcceptedIfNeeded({
  credentialResponse,
  issuerMeta,
  apiBase,
  accessToken,
  tokenBody,
  dpopPrivateJwk,
  dpopPublicJwk,
  dpopNonceState = createDpopNonceState(),
}) {
  const notificationId = extractNotificationId(credentialResponse);
  const notificationEndpoint = resolveNotificationEndpoint(issuerMeta, apiBase);
  if (!notificationId || !accessToken) return;
  await postCredentialAcceptedNotification({
    notificationEndpoint,
    notificationId,
    accessToken,
    tokenBody,
    dpopPrivateJwk,
    dpopPublicJwk,
    dpopNonceState,
  });
}

export async function storeIssuedCredentials(configurationId, credentialResponse, keyPairs, metadataBase = {}) {
  const notificationId = extractNotificationId(credentialResponse);
  const metadata = {
    ...metadataBase,
    ...(notificationId ? { notification_id: notificationId } : {}),
  };
  const entries = Array.isArray(credentialResponse?.credentials)
    ? credentialResponse.credentials
    : null;

  if (entries && entries.length > 1) {
    await storeWalletCredentialByType(configurationId, {
      multi: true,
      entries: entries.map((item, index) => ({
        credential: typeof item?.credential === "string" ? { credential: item.credential } : item,
        keyBinding: {
          privateJwk: keyPairs[index].privateJwk,
          publicJwk: keyPairs[index].publicJwk,
          didJwk: keyPairs[index].didJwk,
        },
        metadata: { ...metadata, attestedKeyIndex: index },
      })),
      metadata,
    });
    return;
  }

  await storeWalletCredentialByType(configurationId, {
    credential: credentialResponse,
    keyBinding: {
      privateJwk: keyPairs[0].privateJwk,
      publicJwk: keyPairs[0].publicJwk,
      didJwk: keyPairs[0].didJwk,
    },
    metadata,
  });
}

export async function exchangeToken({
  tokenEndpoint,
  tokenPayload,
  authorizationServerIssuer,
  ensureOrCreateEcKeyPair,
  createDPoP,
  resolveWiaForParOrToken,
  shouldRetryTokenExchangeAfterRotatingWalletProviderKey,
  rotateWalletProviderKeyPair,
  postForm,
  deviceKeyPath,
  log,
  logPrefix,
  challengeState = null,
  dpopNonceState = null,
  tokenBinding = null,
}) {
  const nonceState = dpopNonceState || createDpopNonceState();
  nonceState.authorizationServer = authorizationServerIssuer || new URL(tokenEndpoint).origin;
  const keys = tokenBinding || await ensureOrCreateEcKeyPair(deviceKeyPath, "ES256");
  const { privateJwk: dpopPrivateJwk, publicJwk: dpopPublicJwk } = keys;
  const walletClientId = tokenPayload?.client_id ?? (await resolveWalletInstanceClientId());
  const budget = { sends: 0, nonceRetries: 0 };
  let attestationRetries = 0;
  let rotated = false;
  while (true) {
    const response = await requestWithDpopNonce({
      url: tokenEndpoint, namespace: "as", state: nonceState,
      privateJwk: dpopPrivateJwk, publicJwk: dpopPublicJwk, signer: createDPoP,
      budget, log,
      send: async (proof) => {
        const wia = await resolveWiaForParOrToken({
          endpointAudience: tokenEndpoint, authorizationServerIssuer, clientId: walletClientId,
          challenge: challengeState?.consume() ?? null, cnfKeyPair: keys,
        });
        const res = await postForm(tokenEndpoint, { ...tokenPayload, client_id: walletClientId }, proof, wia.wiaHeaders);
        challengeState?.updateFromResponse(res.headers);
        return res;
      },
    });
    challengeState?.updateFromResponse(response.headers);
    const text = await response.text().catch(() => "");
    if (response.ok) {
      return { tokenBody: JSON.parse(text), dpopPrivateJwk, dpopPublicJwk, walletClientId, dpopNonceState: nonceState };
    }
    const retry = shouldRetryWithAttestationChallenge(response, text);
    if (retry.shouldRetry && challengeState && attestationRetries < 1) {
      attestationRetries++;
      challengeState.set(retry.challenge);
      continue;
    }
    let errorBody;
    try { errorBody = JSON.parse(text); }
    catch { errorBody = { error: "invalid_response", error_description: text.slice(0, 400) }; }
    if (!rotated && shouldRetryTokenExchangeAfterRotatingWalletProviderKey(response.status, errorBody)) {
      rotated = true;
      if (await rotateWalletProviderKeyPair()) {
        log?.(`${logPrefix} token retry after WP key rotation`);
        continue;
      }
    }
    throw new Error(`token_error ${response.status}: ${JSON.stringify(errorBody)}`);
  }
}

export async function fetchCredentialNonce({
  tokenBody,
  nonceEndpoint,
  accessToken,
  postJson,
  dpopNonceState = createDpopNonceState(),
  dpopPrivateJwk,
  dpopPublicJwk,
  resourceServer = null,
}) {
  let c_nonce = tokenBody?.c_nonce;
  let c_nonce_expires_in = tokenBody?.c_nonce_expires_in;
  if (!nonceEndpoint) {
    throw new Error("nonce_error: issuer did not provide c_nonce and no nonce_endpoint is available");
  }
  dpopNonceState.resourceServer = resourceServer || new URL(nonceEndpoint).origin;
  const response = await requestWithDpopNonce({
    url: nonceEndpoint, state: dpopNonceState,
    privateJwk: dpopPrivateJwk, publicJwk: dpopPublicJwk,
    send: (proof) => postJson(nonceEndpoint, {}, proof, {}),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    let errorBody = {};
    try {
      errorBody = JSON.parse(text);
    } catch {}
    throw new Error(`nonce_error ${response.status}: ${JSON.stringify(errorBody)}`);
  }
  const nonceBody = await response.json();
  c_nonce = nonceBody.c_nonce;
  c_nonce_expires_in = nonceBody.c_nonce_expires_in;
  if (!c_nonce) {
    throw new Error("nonce_error: issuer nonce endpoint did not return c_nonce");
  }
  return { c_nonce, c_nonce_expires_in };
}

export async function buildCredentialRequest({
  issuerMeta,
  profile = resolveWalletProfile(),
  configurationId,
  tokenBody,
  proofMode,
  credentialEndpoint,
  audience,
  c_nonce,
  keyPairs,
  selectedAlg,
  clientId = null,
  anonymousAccess = false,
  buildCredentialRequestProofs,
  buildCredentialRequestSelector,
  prepareCredentialResponseEncryption,
}) {
  const proofMetadata = issuerMeta?.credential_configurations_supported?.[configurationId]?.proof_types_supported?.[proofMode];
  const keyAttestationRequired = isWebuildCs01Profile(profile) ||
    Object.prototype.hasOwnProperty.call(proofMetadata || {}, "key_attestations_required");
  const { proofs, proofJwt } = await buildCredentialRequestProofs({
    keyAttestationRequired,
    proofMode,
    credentialEndpoint,
    aud: audience,
    c_nonce,
    keyPairs,
    selectedAlg,
    clientId,
    anonymousAccess,
  });
  const credentialResponseEncCtx = await prepareCredentialResponseEncryption();
  const credentialRequest = {
    ...buildCredentialRequestSelector(configurationId, tokenBody),
    proofs,
    ...(credentialResponseEncCtx
      ? { credential_response_encryption: credentialResponseEncCtx.credential_response_encryption }
      : {}),
  };
  return {
    credentialRequest,
    proofJwt,
    credentialResponseDecryptionKey: credentialResponseEncCtx?.privateKey || null,
  };
}

export async function postCredentialRequest({
  credentialEndpoint,
  credentialRequest,
  accessToken,
  tokenBody,
  dpopPrivateJwk,
  dpopPublicJwk,
  isDpopBoundAccessToken,
  computeAthForDpop,
  createDPoP,
  fetchImpl,
  parseCredentialResponsePayload,
  dpopNonceState = createDpopNonceState(),
}) {
  let credentialDpopJwt = null;
  const bodyString = JSON.stringify(credentialRequest);
  const response = await requestWithDpopNonce({
    url: credentialEndpoint, state: dpopNonceState,
    privateJwk: dpopPrivateJwk, publicJwk: dpopPublicJwk,
    enabled: isDpopBoundAccessToken(tokenBody, accessToken),
    ath: computeAthForDpop(accessToken), signer: createDPoP,
    send: (proof) => {
      credentialDpopJwt = proof;
      return fetchImpl(credentialEndpoint, {
        method: "POST", headers: {
          "content-type": "application/json",
          authorization: `${proof ? "DPoP" : "Bearer"} ${accessToken}`,
          ...(proof ? { DPoP: proof } : {}),
        }, body: bodyString,
      });
    },
  });

  const responseText = await response.text().catch(() => "");
  const contentType = response.headers.get("content-type") || "";

  if (!response.ok && response.status !== 202) {
    let errorBody = {};
    try {
      errorBody = JSON.parse(responseText);
    } catch {
      errorBody = { error: "invalid_response", error_description: responseText };
    }
    throw new Error(`credential_error ${response.status}: ${JSON.stringify(errorBody)}`);
  }

  const body = await parseCredentialResponsePayload(responseText, contentType);
  if (!body || typeof body !== "object") {
    throw new Error(
      response.status === 202
        ? `credential_error ${response.status}: invalid response (expected JSON inside JWE or plain JSON)`
        : "credential_error: invalid JSON response",
    );
  }

  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body,
    credentialDpopJwt,
  };
}

export async function pollDeferredCredential({
  deferredEndpoint,
  transactionId,
  initialInterval,
  pollTimeoutMs,
  pollIntervalMs,
  accessToken,
  tokenBody,
  dpopPrivateJwk,
  dpopPublicJwk,
  isDpopBoundAccessToken,
  computeAthForDpop,
  createDPoP,
  postJson,
  parseCredentialResponsePayload,
  dpopNonceState = createDpopNonceState(),
}) {
  const start = Date.now();
  const timeout = pollTimeoutMs ?? 30000;
  let nextDelayMs = getNextPollDelayMs(initialInterval, pollIntervalMs);

  while (Date.now() - start < timeout) {
    await sleep(nextDelayMs);

    const response = await requestWithDpopNonce({
      url: deferredEndpoint, state: dpopNonceState,
      privateJwk: dpopPrivateJwk, publicJwk: dpopPublicJwk,
      enabled: isDpopBoundAccessToken(tokenBody, accessToken),
      ath: computeAthForDpop(accessToken), signer: createDPoP,
      send: (proof) => postJson(deferredEndpoint, { transaction_id: transactionId }, proof,
        { Authorization: `${proof ? "DPoP" : "Bearer"} ${accessToken}` }),
    });
    const responseText = await response.text().catch(() => "");
    const contentType = response.headers.get("content-type") || "";

    if (response.ok) {
      const body = await parseCredentialResponsePayload(responseText, contentType);
      if (!body || typeof body !== "object") {
        throw new Error("credential_error: invalid deferred credential response");
      }
      return body;
    }

    const outcome = await resolveDeferredPollResult({
      status: response.status,
      ok: false,
      contentType,
      responseText,
      decryptionPrivateKey: null,
    });

    if (outcome.kind === "success") {
      return outcome.body;
    }
    if (outcome.kind === "pending") {
      nextDelayMs = getNextPollDelayMs(outcome.interval, pollIntervalMs);
      continue;
    }
    throw new Error(formatDeferredTerminalError(outcome));
  }

  throw new Error("timeout: Deferred issuance timed out");
}
